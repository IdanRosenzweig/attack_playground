#!/usr/bin/env python3
"""
apply the network restrictions for the playground guest network.

see network_common_linux.py for why the endpoint allowlist lives in INPUT rather
than in DOCKER-USER.
"""

import sys

from network_common_linux import (
    DOCKER_NET_NAME, INPUT_CHAIN, FORWARD_CHAIN,
    get_bridge_interface, get_gateway_ip,
    iptables_cmd, port_arg,
    ensure_chain, ensure_hook, ensure_docker_user_chain,
    remove_legacy_rules,
    parse_config, find_config, save_rules,
)


def build_input_chain(gateway_ip, ranges):
    """guest -> host: allow only the configured attack endpoints on the gateway."""
    # replies for connections the guest already opened (and host-initiated ones)
    iptables_cmd(["-A", INPUT_CHAIN,
                  "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                  "-j", "ACCEPT"])

    for rng in ranges:
        iptables_cmd(["-A", INPUT_CHAIN,
                      "-d", gateway_ip,
                      "-p", "tcp", "--dport", port_arg(rng),
                      "-j", "ACCEPT"])
        print(f"  allow tcp {rng} -> {gateway_ip}")

    # anything else aimed at the host (any local ip, any protocol) is denied
    iptables_cmd(["-A", INPUT_CHAIN, "-j", "DROP"])


def build_forward_chain(bridge_if):
    """guest -> forwarded: keep traffic inside the playground, drop the rest."""
    # guest-to-guest inside the playground: hand back to docker's own rules
    iptables_cmd(["-A", FORWARD_CHAIN, "-o", bridge_if, "-j", "RETURN"])
    iptables_cmd(["-A", FORWARD_CHAIN,
                  "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                  "-j", "RETURN"])
    # no routing out of the playground (backs up the network's --internal flag)
    iptables_cmd(["-A", FORWARD_CHAIN, "-j", "DROP"])


def main():
    bridge_if = get_bridge_interface(DOCKER_NET_NAME)
    if not bridge_if:
        print(f"error: network '{DOCKER_NET_NAME}' not found.")
        sys.exit(1)

    gateway_ip = get_gateway_ip(DOCKER_NET_NAME)
    if not gateway_ip:
        print("error: could not determine gateway ip for network.")
        sys.exit(1)

    config_path = find_config()
    if not config_path:
        print("warning: endpoints config file not found, no endpoints will be allowed.")
        ranges = []
    else:
        ranges = parse_config(config_path)
        if not ranges:
            print(f"warning: no valid port ranges in {config_path}, "
                  "no endpoints will be allowed.")

    print(f"applying restrictions on {bridge_if} (gateway {gateway_ip})")

    # drop the flat rules written by older versions of this script before rebuilding
    removed = remove_legacy_rules(bridge_if, gateway_ip, ranges)
    if removed:
        print(f"  removed {removed} legacy DOCKER-USER rule(s)")

    # rebuild both chains from scratch - safe to re-run
    ensure_chain(INPUT_CHAIN)
    ensure_chain(FORWARD_CHAIN)

    build_input_chain(gateway_ip, ranges)
    build_forward_chain(bridge_if)

    ensure_docker_user_chain()
    ensure_hook("INPUT", bridge_if, INPUT_CHAIN)
    ensure_hook("DOCKER-USER", bridge_if, FORWARD_CHAIN)

    save_rules()
    print("network restrictions applied")


if __name__ == "__main__":
    main()
