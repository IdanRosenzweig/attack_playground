#!/usr/bin/env python3
"""
connection statistics for the playground, served as json over http:

  * how many users are connected right now
  * how many were connected at some point during the last hour (or any window)
  * how many have ever connected

a "user" here is one ssh session. the playground has no identities - the auth
webhook says yes to anybody under any name - so sessions are the only thing that
can be counted honestly, and containerssh turns every ssh connection into exactly
one guest container. the collector below therefore follows docker's event stream:
a guest container starting is a user connecting, and that container dying is the
user leaving. the username and client address containerssh puts on the container
as labels are recorded with each session, for anyone who later wants to slice the
numbers differently (per address, per name).

"connected in the last hour" counts every session that was open at any moment of
the window - the ones still open, and the ones that ended inside it - so the three
numbers nest: currently connected <= connected in the window <= ever connected.

sessions live in a sqlite file so that "ever connected" survives restarts of this
server and of the playground. on startup - and again whenever the event stream has
to be reopened - the store is reconciled against the running guests: guests that
appeared while this server was down are added, and sessions still marked open
whose guest is gone are closed at that moment, marked "reconcile" because their
real end was not observed. a session that both started and ended while this server
was down is not recorded at all.

stdlib only, like the auth webhook: it speaks the docker engine api over the unix
socket with http.client and needs nothing installed. that socket is root on the
host, so this only ever sends GET requests - see the volumes comment in
docker-compose.yaml.

configuration, all through the environment:

  DOCKER_SOCKET      the docker engine socket          (/var/run/docker.sock)
  GUEST_IMAGE        the image guests are created from (attack_playground_image:latest)
  STATS_DB           the sqlite file                   (/data/stats.db)
  STATS_WINDOW       the default window                (1h)
  STATS_LISTEN_PORT  the http port                     (8081)

GET /stats (or /) answers with the numbers for the default window; ?window=15m,
?window=2h, ?window=3600 (seconds) pick another one.
"""

import http.client
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_ADDRESS = "0.0.0.0"
LISTEN_PORT = 8081

DOCKER_SOCKET = "/var/run/docker.sock"
GUEST_IMAGE = "attack_playground_image:latest"
STATS_DB = "/data/stats.db"
STATS_WINDOW = "1h"

# how long the collector waits before reconnecting to a docker daemon that went away
RECONNECT_DELAY = 5.0

STATS_PATHS = ("/", "/stats")

# the labels containerssh's docker backend puts on every guest it creates
USERNAME_LABEL = "containerssh_username"
IP_LABEL = "containerssh_ip"

# how a session came to an end
END_DIE = "die"              # docker reported the guest container exiting
END_RECONCILE = "reconcile"  # the guest was already gone when this server looked

WINDOW_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_WINDOW_RE = re.compile(r"(\d+)([smhd]?)", re.ASCII)


def log(message):
    print(message, flush=True)


def parse_window(text):
    """
    a window in seconds, from "3600" or from a count with a unit: "90s", "15m",
    "1h", "2d". anything else - including zero - is a ValueError; a window of
    nothing is never what was meant.
    """
    match = _WINDOW_RE.fullmatch((text or "").strip().lower())
    if not match:
        raise ValueError(
            f"'{text}' is not a window: give seconds, or a count followed by s, m, h or d")
    seconds = int(match.group(1)) * WINDOW_UNITS.get(match.group(2), 1)
    if seconds <= 0:
        raise ValueError("the window must be longer than zero")
    return seconds


def iso(timestamp):
    """unix seconds -> "2026-09-18T14:03:21Z"; None stays None."""
    if timestamp is None:
        return None
    stamp = datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")
    return stamp.replace("+00:00", "Z")


# ------------------------------------------------------------------------ store

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    container_id   TEXT PRIMARY KEY,
    container_name TEXT,
    username       TEXT,
    client_ip      TEXT,
    started_at     REAL NOT NULL,
    ended_at       REAL,
    end_reason     TEXT
)
"""


class Store:
    """
    one row per session, i.e. per guest container; a session is open while
    ended_at is null.

    a single sqlite connection shared under a lock: the collector thread writes,
    the http threads read, and nothing here is busy enough to need more.
    """

    def __init__(self, path):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        with self._lock, self._db:
            self._db.execute(SCHEMA)

    def close(self):
        with self._lock:
            self._db.close()

    def open_session(self, container_id, started_at, name=None, username=None, client_ip=None):
        """record a session. true if it was new; a repeat for the same guest changes nothing."""
        with self._lock, self._db:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO sessions"
                " (container_id, container_name, username, client_ip, started_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (container_id, name, username, client_ip, started_at))
            return cursor.rowcount == 1

    def close_session(self, container_id, ended_at, reason):
        """
        end a session. true if this call ended it.

        an observed end (die) replaces one that reconciliation guessed: that guess
        only ever meant "gone by the time this server looked", and the event now
        says when the guest actually went.
        """
        with self._lock, self._db:
            cursor = self._db.execute(
                "UPDATE sessions SET ended_at = ?, end_reason = ?"
                " WHERE container_id = ?"
                "   AND (ended_at IS NULL OR (end_reason = ? AND ? = ?))",
                (ended_at, reason, container_id, END_RECONCILE, reason, END_DIE))
            return cursor.rowcount == 1

    def open_ids(self):
        """the container ids of every session still marked open."""
        with self._lock:
            rows = self._db.execute("SELECT container_id FROM sessions WHERE ended_at IS NULL")
            return {row[0] for row in rows}

    def counts(self, now, window_seconds):
        """the three numbers as of `now`, for a window of `window_seconds` ending then."""
        since = now - window_seconds
        with self._lock:
            (current,) = self._db.execute(
                "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL").fetchone()
            (in_window,) = self._db.execute(
                "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL OR ended_at >= ?",
                (since,)).fetchone()
            (ever,) = self._db.execute("SELECT COUNT(*) FROM sessions").fetchone()
        return {
            "currently_connected": current,
            "connected_in_window": in_window,
            "ever_connected": ever,
        }


# ----------------------------------------------------------------- docker api

class DockerError(RuntimeError):
    """the daemon answered, but not with what was asked for."""


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over a unix socket, which is all the engine api needs."""

    def __init__(self, socket_path, timeout=None):
        # the host name only ends up in the Host header, which the daemon ignores
        super().__init__("docker", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class EventStream:
    """
    docker's /events response: one json object per line, kept open by the daemon
    until it goes away. iterating yields the decoded events.
    """

    def __init__(self, conn, resp):
        self._conn = conn
        self._resp = resp

    def __iter__(self):
        while True:
            line = self._resp.readline()
            if not line:
                return
            line = line.strip()
            if line:
                yield json.loads(line)

    def interrupt(self):
        """
        wake a reader blocked in another thread. only the socket is shut down
        here - the reader closes the connection itself once it returns, because
        http.client does not survive being closed under a read in progress.
        """
        sock = self._conn.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self._conn.close()


class DockerClient:
    """the two calls this server makes: list the running guests, and follow events."""

    def __init__(self, socket_path):
        self.socket_path = socket_path

    def _get(self, path, query, timeout):
        conn = UnixHTTPConnection(self.socket_path, timeout)
        conn.request("GET", path + "?" + urllib.parse.urlencode(query))
        resp = conn.getresponse()
        if resp.status != 200:
            detail = resp.read(4096).decode("utf-8", "replace").strip()
            conn.close()
            raise DockerError(f"GET {path}: http {resp.status} {detail}")
        return conn, resp

    def running_containers(self, image):
        """the running containers created from `image`, as the engine describes them."""
        query = {"filters": json.dumps({"ancestor": [image]})}
        conn, resp = self._get("/containers/json", query, timeout=30)
        try:
            return json.loads(resp.read())
        finally:
            conn.close()

    def events(self, since):
        """
        container start and die events from `since` (unix seconds) onwards, then
        live for as long as the daemon keeps the stream open. no timeout: hours can
        pass between events, and a daemon that goes away closes the socket.
        """
        query = {
            "since": str(int(since)),
            "filters": json.dumps({"type": ["container"], "event": ["start", "die"]}),
        }
        conn, resp = self._get("/events", query, timeout=None)
        return EventStream(conn, resp)


def event_time(event, clock):
    """when an event happened, from the daemon's clock; ours if it did not say."""
    nanos = event.get("timeNano")
    if isinstance(nanos, int) and nanos > 0:
        return nanos / 1e9
    seconds = event.get("time")
    if isinstance(seconds, (int, float)) and seconds > 0:
        return float(seconds)
    return clock()


# ------------------------------------------------------------------- collector

class Collector(threading.Thread):
    """
    keeps the store in step with docker: one open session per running guest.

    on every (re)connection the event stream is opened first, from just before
    the moment the running guests are listed, and only then is the store
    reconciled against that list - so a guest that starts or dies while the list
    is being fetched is caught by the replayed events rather than lost. the
    replay is harmless: opening a session is a no-op the second time, and closing
    one only touches a session that is still open (or one reconciliation guessed
    closed, which the observed end then corrects).
    """

    def __init__(self, docker, store, guest_image, clock=time.time,
                 reconnect_delay=RECONNECT_DELAY):
        super().__init__(name="collector", daemon=True)
        self.docker = docker
        self.store = store
        self.guest_image = guest_image
        self.clock = clock
        self.reconnect_delay = reconnect_delay
        self.connected = False
        self.reconciled_at = None
        self.last_event_at = None
        self._stop = threading.Event()
        self._stream = None

    def run(self):
        # anything at all is caught: the alternative is a collector thread that
        # died quietly while the numbers it stopped updating still look live
        while not self._stop.is_set():
            try:
                self.follow()
            except Exception as exc:  # noqa: BLE001 - see above
                self.connected = False
                if not self._stop.is_set():
                    log(f"collector: docker unreachable ({type(exc).__name__}: {exc});"
                        f" retrying in {self.reconnect_delay:g}s")
            else:
                self.connected = False
                if not self._stop.is_set():
                    log(f"collector: docker closed the event stream;"
                        f" reconnecting in {self.reconnect_delay:g}s")
            self._stop.wait(self.reconnect_delay)

    def stop(self):
        self._stop.set()
        stream = self._stream
        if stream is not None:
            stream.interrupt()

    def follow(self):
        """reconcile, then apply events until the stream ends."""
        stream = self.docker.events(int(self.clock()) - 1)
        self._stream = stream
        try:
            self.reconcile()
            self.connected = True
            log("collector: following docker events")
            for event in stream:
                self.handle_event(event)
        finally:
            self._stream = None
            stream.close()

    def reconcile(self):
        """
        bring the store in line with the guests running right now: add the ones
        it does not know, and close the sessions whose guest is gone.
        """
        now = self.clock()
        running = set()
        for container in self.docker.running_containers(self.guest_image):
            container_id = container.get("Id")
            if not container_id:
                continue
            running.add(container_id)
            labels = container.get("Labels") or {}
            names = container.get("Names") or []
            name = names[0].lstrip("/") if names else None
            started = container.get("Created")
            started_at = float(started) if isinstance(started, (int, float)) else now
            if self.store.open_session(container_id, started_at, name,
                                       labels.get(USERNAME_LABEL), labels.get(IP_LABEL)):
                log(f"session found running: {describe(container_id, labels)}")

        for container_id in self.store.open_ids() - running:
            if self.store.close_session(container_id, now, END_RECONCILE):
                log(f"session closed while this server was away: {container_id[:12]}")

        self.reconciled_at = now

    def is_guest(self, image):
        """whether a container's image, as docker names it in events, is the guest image."""
        if not image:
            return False
        if image == self.guest_image:
            return True
        # docker implies :latest when no tag is given, and then reports the bare name
        suffix = ":latest"
        return self.guest_image.endswith(suffix) and image == self.guest_image[:-len(suffix)]

    def handle_event(self, event):
        if event.get("Type") != "container":
            return
        actor = event.get("Actor") or {}
        attributes = actor.get("Attributes") or {}
        if not self.is_guest(attributes.get("image")):
            return
        container_id = actor.get("ID")
        if not container_id:
            return

        when = event_time(event, self.clock)
        self.last_event_at = when
        action = event.get("Action")
        if action == "start":
            if self.store.open_session(container_id, when, attributes.get("name"),
                                       attributes.get(USERNAME_LABEL),
                                       attributes.get(IP_LABEL)):
                log(f"session opened: {describe(container_id, attributes)}")
        elif action == "die":
            if self.store.close_session(container_id, when, END_DIE):
                log(f"session closed: {describe(container_id, attributes)}")


def describe(container_id, labels):
    return (f"{container_id[:12]} user={labels.get(USERNAME_LABEL) or '?'}"
            f" from={labels.get(IP_LABEL) or '?'}")


# ------------------------------------------------------------------------ http

class StatsServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store, collector, default_window, clock=time.time):
        super().__init__(address, StatsHandler)
        self.store = store
        self.collector = collector
        self.default_window = default_window
        self.clock = clock

    def stats(self, window_seconds):
        now = self.clock()
        counts = self.store.counts(now, window_seconds)
        collector = self.collector
        return {
            "currently_connected": counts["currently_connected"],
            "connected_in_window": counts["connected_in_window"],
            "window_seconds": window_seconds,
            "ever_connected": counts["ever_connected"],
            "generated_at": iso(now),
            # whether the numbers are being kept up to date: false means docker's
            # event stream is not being followed right now and they may be stale
            "collector": {
                "connected": collector.connected,
                "reconciled_at": iso(collector.reconciled_at),
                "last_event_at": iso(collector.last_event_at),
            },
        }


class StatsHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 with an accurate Content-Length on every response, so a client that
    # keeps the connection open (a dashboard polling this) is served correctly
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path not in STATS_PATHS:
            self._respond(404, {"error": "not found"})
            return

        window = self.server.default_window
        query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
        if "window" in query:
            try:
                window = parse_window(query["window"][-1])
            except ValueError as exc:
                self._respond(400, {"error": str(exc)})
                return

        self._respond(200, self.server.stats(window))

    def _respond(self, status, body):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main():
    socket_path = os.environ.get("DOCKER_SOCKET", DOCKER_SOCKET)
    guest_image = os.environ.get("GUEST_IMAGE", GUEST_IMAGE)
    db_path = os.environ.get("STATS_DB", STATS_DB)
    try:
        default_window = parse_window(os.environ.get("STATS_WINDOW", STATS_WINDOW))
        listen_port = int(os.environ.get("STATS_LISTEN_PORT", LISTEN_PORT))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    store = Store(db_path)
    collector = Collector(DockerClient(socket_path), store, guest_image)
    collector.start()

    server = StatsServer((LISTEN_ADDRESS, listen_port), store, collector, default_window)
    log(f"serving stats on port {listen_port}: guests are {guest_image},"
        f" default window {default_window}s, sessions in {db_path}")
    server.serve_forever()


if __name__ == "__main__":
    main()
