#!/usr/bin/env python3
"""
regression tests for render_config.py, which fills the docker network's gateway ip
into the containerssh config so guests resolve researchlabs.tech to it.

stdlib only, and no docker or root needed. run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import render_config as rc  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEMPLATE = (
    "docker:\n"
    "  execution:\n"
    "    host:\n"
    "      extrahosts:\n"
    f'        - "{rc.GUEST_HOSTNAME}:{rc.GATEWAY_PLACEHOLDER}"\n'
)


class RenderTest(unittest.TestCase):
    def test_places_the_gateway_next_to_the_hostname(self):
        self.assertIn(f'"{rc.GUEST_HOSTNAME}:172.18.0.1"', rc.render(TEMPLATE, "172.18.0.1"))

    def test_nothing_unrendered_is_left_behind(self):
        # a leftover placeholder is a config the docker daemon only rejects when it
        # creates the first guest, which is at the first ssh login
        self.assertNotIn(rc.GATEWAY_PLACEHOLDER, rc.render(TEMPLATE, "10.9.9.1"))

    def test_every_occurrence_is_replaced(self):
        rendered = rc.render(TEMPLATE + TEMPLATE, "10.9.9.1")
        self.assertEqual(rendered.count("10.9.9.1"), 2)

    def test_template_without_the_placeholder_is_an_error(self):
        # the config and the renderer would silently disagree: the guests would come
        # up with no entry at all and nothing would say so
        with self.assertRaises(ValueError):
            rc.render("docker:\n  execution:\n", "10.9.9.1")

    def test_empty_gateway_is_an_error(self):
        # what "docker network inspect" prints for a network with no ipam config
        with self.assertRaises(ValueError):
            rc.render(TEMPLATE, "")

    def test_garbage_gateway_is_an_error(self):
        for bad in ("not-an-ip", "10.9.9.1/24", "10.9.9", "fe80::1", "10.9.9.1 ", "10.9.9.256"):
            with self.assertRaises(ValueError, msg=bad):
                rc.render(TEMPLATE, bad)


class WriteRenderedTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work)
        self.path = os.path.join(self.work, rc.RENDERED_NAME)

    def test_writes_the_file(self):
        rc.write_rendered(self.path, "rendered\n")
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "rendered\n")

    def test_overwrites_in_place(self):
        # the file may already be bind mounted into a running containerssh, and a
        # bind mount follows the inode it was created on
        rc.write_rendered(self.path, "old\n")
        inode = os.stat(self.path).st_ino
        rc.write_rendered(self.path, "new\n")
        self.assertEqual(os.stat(self.path).st_ino, inode)
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "new\n")

    def test_replaces_the_empty_directory_docker_leaves_behind(self):
        # "docker compose up" without start.sh mounts a missing file by creating a
        # directory in its place
        os.mkdir(self.path)
        rc.write_rendered(self.path, "rendered\n")
        self.assertTrue(os.path.isfile(self.path))

    def test_non_empty_directory_is_an_error_not_a_wipe(self):
        os.mkdir(self.path)
        open(os.path.join(self.path, "keep"), "w", encoding="utf-8").close()
        with self.assertRaises(ValueError):
            rc.write_rendered(self.path, "rendered\n")
        self.assertTrue(os.path.exists(os.path.join(self.path, "keep")))


class RepoTemplateTest(unittest.TestCase):
    """the tracked config.yaml has to stay renderable - it is what start.sh reads."""

    def setUp(self):
        with open(os.path.join(REPO_ROOT, rc.TEMPLATE_NAME), encoding="utf-8") as handle:
            self.template = handle.read()

    def test_config_yaml_still_carries_the_placeholder(self):
        self.assertIn(rc.GATEWAY_PLACEHOLDER, self.template)

    def test_config_yaml_renders_to_a_hosts_entry_on_the_gateway(self):
        rendered = rc.render(self.template, "10.9.9.1")
        self.assertIn(f'- "{rc.GUEST_HOSTNAME}:10.9.9.1"', rendered)

    def test_the_entry_sits_under_the_host_section(self):
        # docker.execution.host maps to docker's HostConfig; under "container" (or
        # anywhere else) containerssh would ignore the key without a word
        host_section = self.template.split("    host:\n", 1)
        self.assertEqual(len(host_section), 2, "no docker.execution.host section")
        self.assertIn("extrahosts:", host_section[1])


if __name__ == "__main__":
    unittest.main()
