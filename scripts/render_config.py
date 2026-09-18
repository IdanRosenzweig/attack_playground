#!/usr/bin/env python3
"""
render the containerssh config for this run, and print the guests' gateway hostname.

guests resolve one playground-only name to the gateway of attack_playground_net - the
address the attack endpoints are exposed on - through an /etc/hosts entry docker writes
into every guest container (config.yaml, docker.execution.host.extrahosts).

that entry is where the name is *defined*, and it is the only place it is written down.
nothing here repeats it: the name is read back out of the template, and

    render_config.py hostname

prints it for the shell scripts, the way endpoints.py prints the configured ports - so
a rename in config.yaml carries everywhere instead of leaving stale copies behind.

docker numbers the network when it creates it, so that gateway address is not known
until then and cannot be written down in a tracked file. config.yaml carries a
placeholder instead, start.sh renders this copy right after creating the network, and
docker-compose.yaml mounts the rendered copy - never config.yaml itself - into
containerssh.

everything unexpected here exits non-zero and start.sh refuses to bring the playground
up: no network, no gateway, no placeholder, or an address that is not an ipv4 address.
a config that containerssh happily loads and that only fails when it creates the first
guest is a failure nobody is watching for.
"""

import ipaddress
import os
import re
import sys

from network_common_linux import DOCKER_NET_NAME, get_gateway_ip

# the token config.yaml carries where the gateway's address belongs
GATEWAY_PLACEHOLDER = "__GATEWAY_IP__"

# authored file -> what compose actually mounts
TEMPLATE_NAME = "config.yaml"
RENDERED_NAME = "config.runtime.yaml"

USAGE = "usage: render_config.py | render_config.py hostname"

# the extrahosts entry that carries the placeholder - '- "<name>:__GATEWAY_IP__"'.
# the hostname is whatever stands in front of the placeholder there; this pattern is
# how it is read rather than a second copy of the name to keep in step.
HOSTS_ENTRY_RE = re.compile(
    r'^\s*-\s*["\']?([^"\'\s:]+):' + re.escape(GATEWAY_PLACEHOLDER) + r'["\']?\s*$',
    re.MULTILINE)


def guest_hostname(template_text):
    """
    the name the guests' /etc/hosts entry points at the gateway, read off the template.

    a template with no such entry is an error, not a default: the renderer and the
    config would otherwise disagree about what the guests resolve, and the guests would
    come up with no entry at all with nothing saying so.
    """
    match = HOSTS_ENTRY_RE.search(template_text)
    if not match:
        raise ValueError(
            f'{TEMPLATE_NAME} carries no \'- "<name>:{GATEWAY_PLACEHOLDER}"\' entry.'
            " the guests' /etc/hosts entry for the gateway is rendered from it - see"
            " docker.execution.host.extrahosts in that file")
    return match.group(1)


def render(template_text, gateway_ip):
    """
    substitute the gateway placeholder.

    the address is validated here rather than trusted: docker's inspect format prints
    an empty string for a network without an IPAM entry, and "extrahosts: name:" is
    rejected by the docker daemon at *guest creation* time - i.e. at the first ssh
    login, long after start.sh said the playground was running.
    """
    try:
        ipaddress.IPv4Address(gateway_ip)
    except ValueError as exc:
        raise ValueError(f"'{gateway_ip}' is not an ipv4 address ({exc})") from exc

    # raises if there is no hosts entry to render in the first place
    guest_hostname(template_text)

    return template_text.replace(GATEWAY_PLACEHOLDER, gateway_ip)


def write_rendered(path, text):
    """
    write the rendered config in place.

    in place, not write-and-rename: a bind mount follows the inode it was created on,
    so renaming over a file containerssh already has mounted would leave it reading the
    old content. (start.sh renders before "compose up", so this only matters for a
    re-run while the playground is up.)

    a "docker compose up" outside start.sh finds no config.runtime.yaml and, like any
    missing bind mount source, leaves an empty *directory* in its place. writing over
    that fails with an IsADirectoryError that explains nothing, so clear it first.
    """
    if os.path.isdir(path):
        try:
            os.rmdir(path)
        except OSError as exc:
            raise ValueError(
                f"{path} is a directory - docker creates one when it is asked to mount a"
                f" file that does not exist yet - and it could not be removed ({exc})"
            ) from exc

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def read_template(path):
    """the tracked config.yaml. errors go to stderr: stdout is the hostname."""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def main(argv):
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_path = os.path.join(repo_root, TEMPLATE_NAME)
    rendered_path = os.path.join(repo_root, RENDERED_NAME)

    if len(argv) == 2 and argv[1] == "hostname":
        # what the verify scripts ask instead of spelling the name out again. no
        # docker and no network needed - it is a read of the tracked template.
        try:
            print(guest_hostname(read_template(template_path)))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if len(argv) != 1:
        print(USAGE, file=sys.stderr)
        return 2

    gateway_ip = get_gateway_ip(DOCKER_NET_NAME)
    if not gateway_ip:
        print(f"error: could not determine the gateway ip of '{DOCKER_NET_NAME}'.", file=sys.stderr)
        print("       the network has to exist before the config can be rendered.", file=sys.stderr)
        return 1

    try:
        template_text = read_template(template_path)
        write_rendered(rendered_path, render(template_text, gateway_ip))
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"  {guest_hostname(template_text)} -> {gateway_ip}, in the guests' /etc/hosts only")
    print(f"  wrote {RENDERED_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
