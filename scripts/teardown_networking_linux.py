#!/usr/bin/env python3
"""
remove the network restrictions applied by setup_networking_linux.py.
"""

from network_common_linux import (
    DOCKER_NET_NAME, INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN,
    get_bridge_interface, get_gateway_ip,
    remove_hook, delete_chain, remove_legacy_rules,
    parse_config, find_config, save_rules,
)

CHAINS = (INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN)


def main():
    bridge_if = get_bridge_interface(DOCKER_NET_NAME)
    if not bridge_if:
        # the network is already gone; the chains may still be around, so drop them
        print(f"info: network '{DOCKER_NET_NAME}' not found, removing leftover chains.")
        for chain in CHAINS:
            delete_chain(chain)
        save_rules()
        return

    gateway_ip = get_gateway_ip(DOCKER_NET_NAME)

    print(f"removing restrictions on {bridge_if}")

    # unhook first, then the chains can be deleted
    remove_hook("INPUT", bridge_if, INPUT_CHAIN, "-i")
    remove_hook("DOCKER-USER", bridge_if, FORWARD_CHAIN, "-i")
    remove_hook("DOCKER-USER", bridge_if, FORWARD_IN_CHAIN, "-o")

    for chain in CHAINS:
        delete_chain(chain)

    # also clear anything left by older versions of the setup script
    config_path = find_config()
    ranges = parse_config(config_path) if config_path else []
    remove_legacy_rules(bridge_if, gateway_ip, ranges)

    # net.bridge.bridge-nf-call-iptables is left alone on purpose - docker relies on it
    save_rules()
    print("cleanup complete.")


if __name__ == "__main__":
    main()
