#!/usr/bin/env python3
"""
render the containerssh config for this run.

guests resolve "researchlabs.tech" to the gateway of attack_playground_net - the
address the attack endpoints are exposed on - through an /etc/hosts entry docker
writes into every guest container (config.yaml, docker.execution.host.extrahosts).

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
import sys

from network_common_linux import DOCKER_NET_NAME, get_gateway_ip

# the name guests resolve to the bridge gateway, and the token config.yaml carries
# where its address belongs
GUEST_HOSTNAME = "researchlabs.tech"
GATEWAY_PLACEHOLDER = "__GATEWAY_IP__"

# authored file -> what compose actually mounts
TEMPLATE_NAME = "config.yaml"
RENDERED_NAME = "config.runtime.yaml"


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

    if GATEWAY_PLACEHOLDER not in template_text:
        raise ValueError(
            f"{TEMPLATE_NAME} contains no {GATEWAY_PLACEHOLDER}. the guests' /etc/hosts"
            f" entry for {GUEST_HOSTNAME} is rendered from it - see"
            " docker.execution.host.extrahosts in that file")

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


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_path = os.path.join(repo_root, TEMPLATE_NAME)
    rendered_path = os.path.join(repo_root, RENDERED_NAME)

    gateway_ip = get_gateway_ip(DOCKER_NET_NAME)
    if not gateway_ip:
        print(f"error: could not determine the gateway ip of '{DOCKER_NET_NAME}'.")
        print("       the network has to exist before the config can be rendered.")
        sys.exit(1)

    try:
        with open(template_path, encoding="utf-8") as handle:
            template_text = handle.read()
    except OSError as exc:
        print(f"error: cannot read {template_path}: {exc}")
        sys.exit(1)

    try:
        write_rendered(rendered_path, render(template_text, gateway_ip))
    except (ValueError, OSError) as exc:
        print(f"error: {exc}")
        sys.exit(1)

    print(f"  {GUEST_HOSTNAME} -> {gateway_ip}, in the guests' /etc/hosts only")
    print(f"  wrote {RENDERED_NAME}")


if __name__ == "__main__":
    main()
