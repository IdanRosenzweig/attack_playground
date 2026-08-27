#!/usr/bin/env python3
"""
regression tests for the pure logic in network_common_linux.py.

stdlib only, and no iptables/docker/root needed - every call into iptables is
recorded instead of run. run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import network_common_linux as nc  # noqa: E402
import setup_networking_linux as setup  # noqa: E402


def write_config(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
    handle.write(text)
    handle.close()
    return handle.name


class ParseConfigTest(unittest.TestCase):
    def parse(self, text):
        path = write_config(text)
        try:
            return nc.parse_config(path)
        finally:
            os.unlink(path)

    def test_keeps_single_ports_and_ranges(self):
        self.assertEqual(self.parse("1337\n2337-2340\n"), ["1337", "2337-2340"])

    def test_ignores_comments_and_blank_lines(self):
        self.assertEqual(self.parse("# endpoints\n\n  1337  \n"), ["1337"])

    def test_rejects_reversed_range(self):
        self.assertEqual(self.parse("2000-1000\n"), [])

    def test_rejects_ports_above_65535(self):
        # these match the digit patterns but iptables rejects them, which used to
        # abort the chain rebuild part way through and leave it without its DROP
        self.assertEqual(self.parse("70000\n1337-99999\n"), [])

    def test_rejects_port_zero(self):
        self.assertEqual(self.parse("0\n0-100\n"), [])

    def test_rejects_garbage(self):
        self.assertEqual(self.parse("http\n1337/tcp\n-1\n"), [])

    def test_missing_file_is_empty(self):
        self.assertEqual(nc.parse_config("/nonexistent/endpoints.conf"), [])


class PortArgTest(unittest.TestCase):
    def test_range_uses_iptables_colon_syntax(self):
        self.assertEqual(nc.port_arg("1337-1355"), "1337:1355")

    def test_single_port_passes_through(self):
        self.assertEqual(nc.port_arg("1337"), "1337")


class FailClosedTest(unittest.TestCase):
    """the input chain must never be reachable without a terminal DROP."""

    def setUp(self):
        self.calls = []
        patcher = mock.patch.object(nc, "run_iptables", self.record)
        patcher.start()
        self.addCleanup(patcher.stop)

    def record(self, binary, args, ignore_error=False):
        self.calls.append(list(args))
        # pretend the chain does not exist yet, so ensure_chain creates it
        if args[:1] == ["-n"]:
            return False
        return True

    def test_drop_is_installed_before_any_allow_rule(self):
        nc.ensure_chain_closed(nc.INPUT_CHAIN)
        setup.build_input_chain("172.31.0.1", ["1337-1355", "2337-2340"])

        drop_at = next(i for i, c in enumerate(self.calls)
                       if c[:1] == ["-A"] and c[-2:] == ["-j", "DROP"])
        accepts = [i for i, c in enumerate(self.calls) if c[-2:] == ["-j", "ACCEPT"]]

        self.assertTrue(accepts, "expected the allow rules to be recorded")
        self.assertTrue(all(i > drop_at for i in accepts),
                        "allow rules must be added after the terminal DROP exists")

    def test_allow_rules_are_inserted_above_the_drop(self):
        nc.ensure_chain_closed(nc.INPUT_CHAIN)
        setup.build_input_chain("172.31.0.1", ["1337-1355"])

        for call in self.calls:
            if call[-2:] == ["-j", "ACCEPT"]:
                self.assertEqual(call[0], "-I",
                                 "an appended allow rule would land below the DROP")

    def test_allow_rules_keep_config_order(self):
        nc.ensure_chain_closed(nc.INPUT_CHAIN)
        setup.build_input_chain("172.31.0.1", ["1337-1355", "2337-2340", "3337-3345"])

        positions = [int(c[2]) for c in self.calls
                     if c[0] == "-I" and c[-2:] == ["-j", "ACCEPT"]]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
