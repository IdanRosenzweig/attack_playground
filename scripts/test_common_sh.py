#!/usr/bin/env python3
"""
regression tests for the shell helpers in common.sh.

these cover the host-readiness checks start.sh depends on, so they must not depend
on the host they run on: every external command preflight touches is replaced by a
stub on PATH, so the suite behaves the same on a developer laptop and on the linux
box the playground is actually deployed to.

stdlib only, no docker/iptables/root needed. run with:

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import os
import shutil
import subprocess
import tempfile
import unittest

COMMON_SH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common.sh")

# resolved against the real PATH: the snippets below run with a PATH containing only
# the stub directory, so the interpreter itself has to be named absolutely
BASH = shutil.which("bash") or "/bin/bash"

# commands the helpers call that the stubs should not fake - pass them straight
# through to the real binary so the tests exercise the real control flow
PASSTHROUGH = ("id", "grep", "uniq", "cat", "echo")


def _write_stub(directory, name, body):
    path = os.path.join(directory, name)
    with open(path, "w") as handle:
        handle.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)
    return path


class ShellHelperTest(unittest.TestCase):
    """runs a snippet against common.sh with a fully stubbed PATH."""

    def make_stubs(self, present=(), kernel="Linux", machine="x86_64",
                   compose_v2=True, docker_info=0, docker_info_out=""):
        """
        build a stub directory and return it.

        `present` names the commands that should exist. docker's stub answers
        "compose version" and "info" so resolve_compose() and the daemon check can
        be steered per test.
        """
        stubs = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, stubs)

        for name in PASSTHROUGH:
            real = shutil.which(name)
            if real:
                _write_stub(stubs, name, f'exec {real} "$@"\n')

        _write_stub(stubs, "uname", (
            'case "$1" in\n'
            f'  -s) echo "{kernel}" ;;\n'
            f'  -m) echo "{machine}" ;;\n'
            f'  *) echo "{kernel}" ;;\n'
            'esac\n'
        ))

        if "docker" in present:
            _write_stub(stubs, "docker", (
                'if [ "$1" = "compose" ] && [ "$2" = "version" ]; then\n'
                f'  exit {0 if compose_v2 else 1}\n'
                'fi\n'
                'if [ "$1" = "info" ]; then\n'
                f'  printf "%s" "{docker_info_out}"\n'
                f'  exit {docker_info}\n'
                'fi\n'
                'exit 0\n'
            ))

        for name in ("python3", "iptables", "sudo", "docker-compose"):
            if name in present:
                # the marker proves as_root went through sudo rather than
                # running the command directly
                body = ('echo "via-sudo" >&2\nexec "$@"\n'
                        if name == "sudo" else 'exit 0\n')
                _write_stub(stubs, name, body)

        return stubs

    def run_snippet(self, snippet, **kwargs):
        stubs = self.make_stubs(**kwargs)
        return subprocess.run(
            [BASH, "-c", f'source "{COMMON_SH}"\n{snippet}'],
            env={"PATH": stubs, "HOME": os.environ.get("HOME", "/tmp")},
            capture_output=True, text=True,
        )


class PreflightTest(ShellHelperTest):
    READY = ("docker", "python3", "iptables", "sudo")

    def test_passes_on_a_ready_linux_host(self):
        result = self.run_snippet("preflight", present=self.READY)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_to_run_on_a_non_linux_host(self):
        # the restrictions are iptables chains on the host kernel's docker bridge.
        # on macos the daemon lives in its own vm, so setup would either apply the
        # chains to the wrong kernel or report a missing network - neither of which
        # tells the operator that the playground simply does not run there.
        result = self.run_snippet("preflight", present=self.READY, kernel="Darwin")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only runs on linux", result.stderr)

    def test_missing_docker_is_reported_with_a_fix(self):
        result = self.run_snippet("preflight", present=("python3", "iptables", "sudo"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("docker is not installed", result.stderr)

    def test_missing_python3_is_reported(self):
        result = self.run_snippet("preflight", present=("docker", "iptables", "sudo"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("python3 is not installed", result.stderr)

    def test_missing_iptables_is_reported(self):
        # without iptables there are no restrictions at all, so this has to be fatal
        # rather than a warning
        result = self.run_snippet("preflight", present=("docker", "python3", "sudo"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("iptables is not installed", result.stderr)

    def test_missing_compose_is_reported(self):
        result = self.run_snippet(
            "preflight", present=("docker", "python3", "iptables", "sudo"),
            compose_v2=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("docker compose is not available", result.stderr)

    def test_unreachable_daemon_is_reported(self):
        result = self.run_snippet(
            "preflight", present=self.READY, docker_info=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("docker", result.stderr.lower())

    def test_nftables_backend_is_flagged(self):
        # docker 29 can program nftables directly, and maintains no DOCKER-USER
        # chain in that mode
        result = self.run_snippet(
            "preflight", present=self.READY,
            docker_info_out="Firewall Backend: nftables")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nftables", result.stdout)


class ComposeTest(ShellHelperTest):
    def test_prefers_the_v2_plugin(self):
        result = self.run_snippet(
            'resolve_compose && echo "${COMPOSE_CMD[*]}"', present=("docker",))
        self.assertEqual(result.stdout.strip(), "docker compose")

    def test_falls_back_to_the_standalone_v1_script(self):
        # debian/ubuntu's docker.io package ships no compose plugin; a host set up
        # that way only has the standalone "docker-compose"
        result = self.run_snippet(
            'resolve_compose && echo "${COMPOSE_CMD[*]}"',
            present=("docker", "docker-compose"), compose_v2=False)
        self.assertEqual(result.stdout.strip(), "docker-compose")

    def test_missing_compose_fails_loudly(self):
        result = self.run_snippet("compose down", present=("docker",),
                                  compose_v2=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("docker-compose", result.stderr)


class AsRootTest(ShellHelperTest):
    @unittest.skipIf(os.geteuid() == 0, "already root; there is no sudo path to test")
    def test_uses_sudo_when_not_root(self):
        result = self.run_snippet('as_root echo hello', present=("sudo",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "hello")
        self.assertIn("via-sudo", result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "already root; there is no sudo path to test")
    def test_reports_when_root_is_unreachable(self):
        # a root shell on a minimal debian image has no sudo at all, and "sudo x"
        # there is a command-not-found that kills the calling script
        result = self.run_snippet('as_root echo hello', present=())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sudo is not installed", result.stderr)


if __name__ == "__main__":
    unittest.main()
