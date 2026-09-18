#!/usr/bin/env python3
"""
regression tests for the connection statistics server.

stdlib only, no docker and no root: the end-to-end tests stand in a fake docker
engine api on a unix socket in a temp dir, so the collector is exercised over the
same http.client path it uses in production. run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import http.client
import json
import os
import queue
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import stats_server as ss  # noqa: E402

GUEST = "attack_playground_image:latest"
NOW = 1_800_000_000.0


def wait_until(predicate, timeout=5.0):
    """poll for a condition the collector thread will bring about."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def container_event(action, container_id, image=GUEST, when=NOW, labels=None, name="guest"):
    """an event as the daemon sends it (the labels ride along in Actor.Attributes)."""
    attributes = {"image": image, "name": name}
    attributes.update(labels or {})
    return {
        "Type": "container",
        "Action": action,
        "Actor": {"ID": container_id, "Attributes": attributes},
        "time": int(when),
        "timeNano": int(when * 1e9),
    }


def running_container(container_id, created=NOW, labels=None, name="guest"):
    """a container as GET /containers/json describes it."""
    return {
        "Id": container_id,
        "Names": ["/" + name],
        "Image": GUEST,
        "Created": int(created),
        "Labels": labels or {},
    }


class ParseWindowTest(unittest.TestCase):
    def test_bare_number_is_seconds(self):
        self.assertEqual(ss.parse_window("3600"), 3600)

    def test_units(self):
        self.assertEqual(ss.parse_window("90s"), 90)
        self.assertEqual(ss.parse_window("15m"), 900)
        self.assertEqual(ss.parse_window("1h"), 3600)
        self.assertEqual(ss.parse_window("2d"), 172800)

    def test_case_and_whitespace_are_forgiven(self):
        self.assertEqual(ss.parse_window(" 1H "), 3600)

    def test_zero_is_rejected(self):
        for zero in ("0", "0m", "00h"):
            with self.assertRaises(ValueError, msg=zero):
                ss.parse_window(zero)

    def test_garbage_is_rejected(self):
        for bad in ("", None, "1h30m", "-5", "1.5h", "5 m", "1w", "h", "١٠", "3600x"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ss.parse_window(bad)


class IsoTest(unittest.TestCase):
    def test_utc_with_z(self):
        self.assertEqual(ss.iso(0), "1970-01-01T00:00:00Z")
        self.assertEqual(ss.iso(1_800_000_000.7), "2027-01-15T08:00:00Z")

    def test_none_stays_none(self):
        self.assertIsNone(ss.iso(None))


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.store = ss.Store(":memory:")
        self.addCleanup(self.store.close)

    def counts(self, window):
        return self.store.counts(NOW, window)

    def test_empty(self):
        self.assertEqual(self.counts(3600), {
            "currently_connected": 0, "connected_in_window": 0, "ever_connected": 0})

    def test_window_counts_every_session_that_overlapped_it(self):
        # ended long before the window: ever only
        self.store.open_session("old", NOW - 5000)
        self.store.close_session("old", NOW - 4000, ss.END_DIE)
        # started before the window and still open: all three
        self.store.open_session("long", NOW - 5000)
        # started and ended inside the window: window and ever
        self.store.open_session("short", NOW - 100)
        self.store.close_session("short", NOW - 50, ss.END_DIE)
        # ended exactly on the window's edge: still inside it
        self.store.open_session("edge", NOW - 3000)
        self.store.close_session("edge", NOW - 3600, ss.END_DIE)

        self.assertEqual(self.counts(3600), {
            "currently_connected": 1, "connected_in_window": 3, "ever_connected": 4})
        # a narrower window drops "edge" but keeps the open one and the recent one
        self.assertEqual(self.counts(60), {
            "currently_connected": 1, "connected_in_window": 2, "ever_connected": 4})

    def test_numbers_nest(self):
        self.store.open_session("a", NOW - 10)
        self.store.open_session("b", NOW - 10)
        self.store.close_session("b", NOW - 5, ss.END_DIE)
        c = self.counts(3600)
        self.assertLessEqual(c["currently_connected"], c["connected_in_window"])
        self.assertLessEqual(c["connected_in_window"], c["ever_connected"])

    def test_opening_the_same_session_twice_counts_once(self):
        # reconciliation and a replayed start event both see the same guest
        self.assertTrue(self.store.open_session("x", NOW - 10, "guest-x", "alice", "10.0.0.5"))
        self.assertFalse(self.store.open_session("x", NOW - 5))
        self.assertEqual(self.counts(3600)["ever_connected"], 1)

    def test_closing_an_unknown_session_is_a_no_op(self):
        self.assertFalse(self.store.close_session("nope", NOW, ss.END_DIE))
        self.assertEqual(self.counts(3600)["ever_connected"], 0)

    def test_an_observed_end_is_final(self):
        self.store.open_session("x", NOW - 100)
        self.assertTrue(self.store.close_session("x", NOW - 50, ss.END_DIE))
        self.assertFalse(self.store.close_session("x", NOW - 10, ss.END_DIE))
        self.assertFalse(self.store.close_session("x", NOW - 10, ss.END_RECONCILE))
        # ended 50s ago: inside a 60s window, outside a 40s one
        self.assertEqual(self.counts(60)["connected_in_window"], 1)
        self.assertEqual(self.counts(40)["connected_in_window"], 0)

    def test_an_observed_end_replaces_a_reconciled_guess(self):
        # the guess is "gone by the time this server looked"; the replayed die
        # event then says when the guest really went, which is earlier
        self.store.open_session("x", NOW - 100)
        self.assertTrue(self.store.close_session("x", NOW - 10, ss.END_RECONCILE))
        self.assertEqual(self.counts(20)["connected_in_window"], 1)
        self.assertTrue(self.store.close_session("x", NOW - 80, ss.END_DIE))
        self.assertEqual(self.counts(20)["connected_in_window"], 0)
        self.assertEqual(self.counts(90)["connected_in_window"], 1)

    def test_open_ids(self):
        self.store.open_session("a", NOW - 10)
        self.store.open_session("b", NOW - 10)
        self.store.close_session("b", NOW - 5, ss.END_DIE)
        self.assertEqual(self.store.open_ids(), {"a"})


class StorePersistenceTest(unittest.TestCase):
    def test_sessions_survive_reopening_the_file(self):
        # "ever connected" is only meaningful if it outlives this process
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work)
        path = os.path.join(work, "nested", "stats.db")

        store = ss.Store(path)
        store.open_session("a", NOW - 10)
        store.open_session("b", NOW - 10)
        store.close_session("b", NOW - 5, ss.END_DIE)
        store.close()

        reopened = ss.Store(path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.counts(NOW, 3600), {
            "currently_connected": 1, "connected_in_window": 2, "ever_connected": 2})


class StubDocker:
    """what the collector asks docker, answered from attributes."""

    def __init__(self, running=()):
        self.running = list(running)

    def running_containers(self, image):
        self.asked_for = image
        return list(self.running)


class CollectorEventTest(unittest.TestCase):
    def setUp(self):
        self.store = ss.Store(":memory:")
        self.addCleanup(self.store.close)
        mock.patch.object(ss, "log", lambda *a, **k: None).start()
        self.addCleanup(mock.patch.stopall)
        self.collector = ss.Collector(StubDocker(), self.store, GUEST, clock=lambda: NOW)

    def counts(self):
        return self.store.counts(NOW + 1, 3600)

    def test_start_opens_and_die_closes(self):
        self.collector.handle_event(container_event("start", "c1", when=NOW - 30))
        self.assertEqual(self.counts()["currently_connected"], 1)
        self.collector.handle_event(container_event("die", "c1", when=NOW - 10))
        self.assertEqual(self.counts(), {
            "currently_connected": 0, "connected_in_window": 1, "ever_connected": 1})

    def test_labels_are_recorded(self):
        labels = {ss.USERNAME_LABEL: "alice", ss.IP_LABEL: "192.168.1.9"}
        self.collector.handle_event(container_event("start", "c1", labels=labels, name="guest-1"))
        row = self.store._db.execute(
            "SELECT container_name, username, client_ip, started_at FROM sessions").fetchone()
        self.assertEqual(row, ("guest-1", "alice", "192.168.1.9", NOW))

    def test_event_time_comes_from_the_daemon(self):
        # timeNano, not our own clock: replayed events happened in the past
        self.collector.handle_event(container_event("start", "c1", when=NOW - 500))
        (started,) = self.store._db.execute("SELECT started_at FROM sessions").fetchone()
        self.assertAlmostEqual(started, NOW - 500, places=3)
        self.assertAlmostEqual(self.collector.last_event_at, NOW - 500, places=3)

    def test_other_images_are_ignored(self):
        # containerssh, the auth webhook and the endpoint containers all emit the
        # same events on the same daemon
        self.collector.handle_event(container_event("start", "c1", image="containerssh/containerssh:v0.5.2"))
        self.collector.handle_event(container_event("start", "c2", image="python:3.11-slim"))
        self.collector.handle_event(container_event("start", "c3", image="attack_playground_image:v2"))
        self.assertEqual(self.counts()["ever_connected"], 0)

    def test_bare_name_means_latest(self):
        self.collector.handle_event(container_event("start", "c1", image="attack_playground_image"))
        self.assertEqual(self.counts()["ever_connected"], 1)

    def test_bare_name_is_not_accepted_for_another_tag(self):
        collector = ss.Collector(StubDocker(), self.store, "attack_playground_image:v2")
        self.assertFalse(collector.is_guest("attack_playground_image"))
        self.assertTrue(collector.is_guest("attack_playground_image:v2"))

    def test_non_container_and_malformed_events_are_ignored(self):
        self.collector.handle_event({"Type": "network", "Action": "connect",
                                     "Actor": {"ID": "n1", "Attributes": {"image": GUEST}}})
        self.collector.handle_event({"Type": "container", "Action": "start"})
        self.collector.handle_event({"Type": "container", "Action": "start", "Actor": {"Attributes": {"image": GUEST}}})
        self.collector.handle_event({"Type": "container", "Action": "start", "Actor": {"ID": "c9"}})
        self.assertEqual(self.counts()["ever_connected"], 0)

    def test_other_actions_change_nothing(self):
        self.collector.handle_event(container_event("start", "c1"))
        for action in ("kill", "exec_start: bash", "destroy", "oom", "pause"):
            self.collector.handle_event(container_event(action, "c1"))
        self.assertEqual(self.counts()["currently_connected"], 1)

    def test_die_for_an_unknown_guest_is_a_no_op(self):
        self.collector.handle_event(container_event("die", "never-seen"))
        self.assertEqual(self.counts()["ever_connected"], 0)

    def test_repeated_start_counts_once(self):
        self.collector.handle_event(container_event("start", "c1"))
        self.collector.handle_event(container_event("start", "c1"))
        self.assertEqual(self.counts()["ever_connected"], 1)


class CollectorReconcileTest(unittest.TestCase):
    def setUp(self):
        self.store = ss.Store(":memory:")
        self.addCleanup(self.store.close)
        mock.patch.object(ss, "log", lambda *a, **k: None).start()
        self.addCleanup(mock.patch.stopall)

    def reconcile(self, running):
        docker = StubDocker(running)
        collector = ss.Collector(docker, self.store, GUEST, clock=lambda: NOW)
        collector.reconcile()
        return collector, docker

    def test_asks_for_the_guest_image_only(self):
        _, docker = self.reconcile([])
        self.assertEqual(docker.asked_for, GUEST)

    def test_running_guests_become_open_sessions(self):
        labels = {ss.USERNAME_LABEL: "bob", ss.IP_LABEL: "10.1.2.3"}
        collector, _ = self.reconcile([running_container("c1", created=NOW - 300, labels=labels, name="guest-1")])
        row = self.store._db.execute(
            "SELECT container_name, username, client_ip, started_at, ended_at FROM sessions").fetchone()
        self.assertEqual(row, ("guest-1", "bob", "10.1.2.3", NOW - 300, None))
        self.assertEqual(collector.reconciled_at, NOW)

    def test_sessions_whose_guest_is_gone_are_closed_as_a_guess(self):
        self.store.open_session("gone", NOW - 900)
        self.store.open_session("still-here", NOW - 900)
        self.reconcile([running_container("still-here")])
        rows = dict(self.store._db.execute("SELECT container_id, end_reason FROM sessions"))
        self.assertEqual(rows, {"gone": ss.END_RECONCILE, "still-here": None})
        (ended,) = self.store._db.execute(
            "SELECT ended_at FROM sessions WHERE container_id = 'gone'").fetchone()
        self.assertEqual(ended, NOW)

    def test_a_known_running_guest_is_left_alone(self):
        self.store.open_session("c1", NOW - 900, "guest-1", "alice", "10.0.0.1")
        self.reconcile([running_container("c1", created=NOW - 100)])
        row = self.store._db.execute(
            "SELECT username, started_at, ended_at FROM sessions").fetchone()
        self.assertEqual(row, ("alice", NOW - 900, None))

    def test_malformed_entries_are_skipped(self):
        self.reconcile([{"Names": ["/no-id"]}, running_container("ok")])
        self.assertEqual(self.store.open_ids(), {"ok"})


# ------------------------------------------------------------------ end to end
#
# a fake docker engine api on a unix socket: answers /containers/json from a list
# the test controls, and streams whatever the test queues on /events, chunked and
# one json object per line like the daemon does.

class FakeDockerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # and client_address is '' on a unix socket, which the default cannot format

    def do_GET(self):
        fake = self.server.fake
        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)
        if url.path == "/containers/json":
            fake.list_queries.append(query)
            self._json(200, fake.running)
        elif url.path == "/events":
            fake.event_queries.append(query)
            with fake.subscribed:
                fake.subscriptions += 1
                fake.subscribed.notify_all()
            self._stream_events(fake)
        else:
            self._json(404, {"message": "page not found"})

    def _json(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _stream_events(self, fake):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            while True:
                try:
                    item = fake.events.get(timeout=0.2)
                except queue.Empty:
                    if fake.closing:
                        break
                    continue
                if item is None:  # the daemon going away
                    break
                data = json.dumps(item).encode() + b"\n"
                self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        except OSError:
            pass  # the collector hung up
        self.close_connection = True


class FakeDockerServer(ThreadingHTTPServer):
    address_family = socket.AF_UNIX
    allow_reuse_address = False

    def server_bind(self):
        self.socket.bind(self.server_address)
        self.server_name = "fake-docker"
        self.server_port = 0


class FakeDocker:
    def __init__(self, socket_path):
        self.running = []
        self.events = queue.Queue()
        self.list_queries = []
        self.event_queries = []
        self.subscriptions = 0
        self.subscribed = threading.Condition()
        self.closing = False
        self.server = FakeDockerServer(socket_path, FakeDockerHandler)
        self.server.fake = self
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()

    def wait_for_subscription(self, count, timeout=5.0):
        with self.subscribed:
            return self.subscribed.wait_for(lambda: self.subscriptions >= count, timeout)

    def end_stream(self):
        self.events.put(None)

    def close(self):
        self.closing = True
        self.server.shutdown()
        self.server.server_close()


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        # a short path: unix socket paths are capped at ~104 bytes
        self.work = tempfile.mkdtemp(prefix="pgst-", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.docker = FakeDocker(os.path.join(self.work, "docker.sock"))
        self.addCleanup(self.docker.close)

        self.quiet = mock.patch.object(ss, "log", lambda *a, **k: None)
        self.quiet.start()
        self.addCleanup(self.quiet.stop)
        mock.patch.object(ss.StatsHandler, "log_message", lambda *a, **k: None).start()
        self.addCleanup(mock.patch.stopall)

        self.store = ss.Store(os.path.join(self.work, "stats.db"))
        self.addCleanup(self.store.close)

        # an exception escaping the collector thread is a test failure, not a
        # line on stderr - registered first so it is checked last, after stop()
        self.thread_errors = []
        self.addCleanup(lambda: self.assertEqual(self.thread_errors, []))
        mock.patch.object(threading, "excepthook",
                          lambda args: self.thread_errors.append(args.exc_value)).start()

    def start(self, default_window=3600, reconnect_delay=0.05):
        self.collector = ss.Collector(ss.DockerClient(self.docker.server.server_address),
                                      self.store, GUEST, reconnect_delay=reconnect_delay)
        self.collector.start()
        self.addCleanup(self.stop_collector)
        self.server = ss.StatsServer(("127.0.0.1", 0), self.store, self.collector, default_window)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.assertTrue(self.docker.wait_for_subscription(1), "collector never subscribed to events")
        self.assertTrue(wait_until(lambda: self.collector.connected), "collector never reconciled")

    def stop_collector(self):
        # stop() has to wake a thread blocked in readline on the event stream
        self.collector.stop()
        self.collector.join(5)
        self.assertFalse(self.collector.is_alive(), "collector did not stop")

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            return resp.status, resp.getheader("Content-Type"), json.loads(resp.read())
        finally:
            conn.close()

    def stats(self, path="/stats"):
        status, ctype, body = self.get(path)
        self.assertEqual(status, 200)
        self.assertEqual(ctype, "application/json")
        return body

    # --------------------------------------------------------------- the numbers

    def test_running_guests_are_picked_up_at_startup(self):
        labels = {ss.USERNAME_LABEL: "alice", ss.IP_LABEL: "10.0.0.5"}
        self.docker.running = [running_container("a" * 64, created=time.time() - 60, labels=labels)]
        self.start()
        body = self.stats()
        self.assertEqual(body["currently_connected"], 1)
        self.assertEqual(body["connected_in_window"], 1)
        self.assertEqual(body["ever_connected"], 1)
        self.assertEqual(body["window_seconds"], 3600)
        self.assertTrue(body["collector"]["connected"])
        self.assertIsNotNone(body["collector"]["reconciled_at"])
        # it asked the daemon for the guest image only
        self.assertEqual(json.loads(self.docker.list_queries[0]["filters"][0]), {"ancestor": [GUEST]})

    def test_events_move_the_numbers(self):
        self.start()
        now = time.time()
        self.docker.events.put(container_event("start", "b" * 64, when=now))
        self.assertTrue(wait_until(lambda: self.stats()["currently_connected"] == 1))
        self.docker.events.put(container_event("start", "c" * 64, when=now))
        self.assertTrue(wait_until(lambda: self.stats()["currently_connected"] == 2))
        self.docker.events.put(container_event("die", "b" * 64, when=now + 1))
        self.assertTrue(wait_until(lambda: self.stats()["currently_connected"] == 1))
        body = self.stats()
        self.assertEqual(body["connected_in_window"], 2)
        self.assertEqual(body["ever_connected"], 2)
        self.assertIsNotNone(body["collector"]["last_event_at"])

    def test_events_are_followed_from_just_before_reconciliation(self):
        # a guest that starts between "list the running guests" and "follow
        # events" must not be lost: the stream is asked for from just before
        self.start()
        since = int(self.docker.event_queries[0]["since"][0])
        self.assertLessEqual(since, int(time.time()))
        self.assertGreaterEqual(since, int(time.time()) - 5)
        filters = json.loads(self.docker.event_queries[0]["filters"][0])
        self.assertEqual(filters, {"type": ["container"], "event": ["start", "die"]})

    def test_a_dropped_stream_is_reopened_and_reconciled_again(self):
        self.start()
        first = self.collector.reconciled_at
        self.docker.running = [running_container("d" * 64, created=time.time() - 5)]
        self.docker.end_stream()  # the daemon restarting
        self.assertTrue(wait_until(lambda: not self.collector.connected))
        self.assertTrue(self.docker.wait_for_subscription(2), "collector did not reconnect")
        self.assertTrue(wait_until(lambda: self.collector.connected))
        self.assertGreater(self.collector.reconciled_at, first)
        self.assertEqual(self.stats()["currently_connected"], 1)

    def test_daemon_going_away_is_reported_not_fatal(self):
        self.start()
        self.docker.end_stream()
        self.assertTrue(wait_until(lambda: not self.stats()["collector"]["connected"]))
        # still serving, still counting what it knows
        self.assertEqual(self.stats()["ever_connected"], 0)

    # ------------------------------------------------------------------ the api

    def test_window_parameter(self):
        self.start()
        self.assertEqual(self.stats("/stats?window=15m")["window_seconds"], 900)
        self.assertEqual(self.stats("/stats?window=120")["window_seconds"], 120)
        self.assertEqual(self.stats("/")["window_seconds"], 3600)

    def test_default_window_is_configurable(self):
        self.start(default_window=600)
        self.assertEqual(self.stats("/stats")["window_seconds"], 600)

    def test_window_narrows_the_count(self):
        self.start()
        now = time.time()
        self.docker.events.put(container_event("start", "e" * 64, when=now - 600))
        self.docker.events.put(container_event("die", "e" * 64, when=now - 300))
        self.assertTrue(wait_until(lambda: self.stats()["ever_connected"] == 1))
        self.assertEqual(self.stats("/stats?window=1h")["connected_in_window"], 1)
        self.assertEqual(self.stats("/stats?window=1m")["connected_in_window"], 0)

    def test_bad_window_is_400(self):
        self.start()
        for bad in ("bad", "0", "", "1h30m"):
            status, _, body = self.get(f"/stats?window={bad}")
            self.assertEqual(status, 400, bad)
            self.assertIn("error", body)

    def test_unknown_path_is_404(self):
        self.start()
        status, _, body = self.get("/sessions")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "not found"})

    def test_keepalive(self):
        # a poller holds the connection open; a wrong Content-Length would only
        # show on the second request
        self.start()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            for path in ("/stats", "/nope", "/stats?window=2h"):
                conn.request("GET", path)
                resp = conn.getresponse()
                body = json.loads(resp.read())
                self.assertEqual(resp.status, 404 if path == "/nope" else 200)
                if path == "/stats?window=2h":
                    self.assertEqual(body["window_seconds"], 7200)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
