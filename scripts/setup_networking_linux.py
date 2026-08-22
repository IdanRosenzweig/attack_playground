#!/usr/bin/env python3
"""
apply the network restrictions for the playground guest network.

a guest may reach the host on the tcp ports listed in the endpoints config, and
nothing else. see network_common_linux.py for the chain layout and for why the
endpoint allowlist lives in INPUT rather than in DOCKER-USER.
"""

import sys

from network_common_linux import (
    DOCKER_NET_NAME, INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN,
    get_bridge_interface, get_gateway_ip,
    iptables_cmd, port_arg,
    ensure_chain, ensure_hook, ensure_docker_user_chain,
    ensure_bridge_netfilter, remove_legacy_rules,
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

    # anything else aimed at the host (any other local ip, port or protocol) is denied
    iptables_cmd(["-A", INPUT_CHAIN, "-j", "DROP"])


def build_forward_chains():
    """
    guests get no forwarded traffic at all, in either direction.

    outbound covers guest-to-guest on the same bridge, guest -> other docker network
    and guest -> lan. inbound stops any other host reaching a guest. neither affects
    the host itself, whose traffic is routed through INPUT/OUTPUT rather than FORWARD.
    """
    iptables_cmd(["-A", FORWARD_CHAIN, "-j", "DROP"])
    iptables_cmd(["-A", FORWARD_IN_CHAIN, "-j", "DROP"])


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

    # without this, guest-to-guest traffic never reaches iptables and the drop below
    # is silently a no-op
    if not ensure_bridge_netfilter():
        print("  warning: could not enable net.bridge.bridge-nf-call-iptables.")
        print("           guest-to-guest traffic on the bridge may bypass iptables"
              " and stay reachable.")

    # drop the flat rules written by older versions of this script before rebuilding
    removed = remove_legacy_rules(bridge_if, gateway_ip, ranges)
    if removed:
        print(f"  removed {removed} legacy DOCKER-USER rule(s)")

    # rebuild every chain from scratch - safe to re-run
    ensure_chain(INPUT_CHAIN)
    ensure_chain(FORWARD_CHAIN)
    ensure_chain(FORWARD_IN_CHAIN)

    build_input_chain(gateway_ip, ranges)
    build_forward_chains()
    print("  deny everything else (internet, lan, other networks, guest-to-guest)")

    ensure_docker_user_chain()
    ensure_hook("INPUT", bridge_if, INPUT_CHAIN, "-i")
    ensure_hook("DOCKER-USER", bridge_if, FORWARD_CHAIN, "-i")
    ensure_hook("DOCKER-USER", bridge_if, FORWARD_IN_CHAIN, "-o")

    save_rules()
    print("network restrictions applied")


if __name__ == "__main__":
    main()
