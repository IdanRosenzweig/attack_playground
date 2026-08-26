#!/usr/bin/env python3
"""
apply the network restrictions for the playground guest network.

a guest may reach the host on the tcp ports listed in the endpoints config, and
nothing else. see network_common_linux.py for the chain layout, for why the
endpoint allowlist lives in INPUT rather than in DOCKER-USER, and for why the
chains are built deny-first.
"""

import sys

from network_common_linux import (
    DOCKER_NET_NAME, INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN,
    IP6TABLES, IptablesError,
    get_bridge_interface, get_gateway_ip,
    port_arg, insert_rule,
    ensure_chain_closed, ensure_hook, ensure_docker_user_chain,
    ensure_bridge_netfilter, ip6tables_available, remove_legacy_rules,
    parse_config, find_config, save_rules,
)

CHAINS = (INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN)


def build_input_chain(gateway_ip, ranges):
    """
    guest -> host: allow only the configured attack endpoints on the gateway.

    ensure_chain_closed() has already put a terminal DROP in the chain, so every rule
    here is *inserted above* it. the chain therefore denies by default the whole time
    it is being built: if one of these inserts fails, the guests are locked out rather
    than let through.
    """
    position = 1

    # replies for connections the guest already opened (and host-initiated ones)
    insert_rule(INPUT_CHAIN,
                ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                position)
    position += 1

    for rng in ranges:
        insert_rule(INPUT_CHAIN,
                    ["-d", gateway_ip, "-p", "tcp", "--dport", port_arg(rng), "-j", "ACCEPT"],
                    position)
        position += 1
        print(f"  allow tcp {rng} -> {gateway_ip}")


def apply_ipv6_restrictions(bridge_if):
    """
    the same policy, for ipv6.

    iptables only covers ipv4. the playground network is ipv4-only, but as long as the
    host kernel has ipv6 enabled the guest's eth0 and the host side of the bridge both
    still get link-local (fe80::/64) addresses, so a guest can reach any host port over
    ipv6 and walk straight past the ipv4 allowlist. every configured endpoint is a tcp
    port on the ipv4 gateway, so there is nothing to allow over ipv6 - drop the lot.

    docker only maintains DOCKER-USER in ip6tables when its ip6tables support is turned
    on, so hook into FORWARD directly instead of relying on it being there.

    a missing ip6tables is a warning, not a failure: the ipv4 policy is still applied.
    """
    if not ip6tables_available():
        print("  warning: ip6tables unavailable, ipv6 on the bridge is NOT filtered.")
        return False

    try:
        for chain in CHAINS:
            ensure_chain_closed(chain, IP6TABLES)
        ensure_hook("INPUT", bridge_if, INPUT_CHAIN, "-i", IP6TABLES)
        ensure_hook("FORWARD", bridge_if, FORWARD_CHAIN, "-i", IP6TABLES)
        ensure_hook("FORWARD", bridge_if, FORWARD_IN_CHAIN, "-o", IP6TABLES)
    except IptablesError as exc:
        print(f"  warning: could not apply ipv6 restrictions: {exc}")
        return False

    print("  deny all ipv6 on the bridge (link-local would bypass the ipv4 allowlist)")
    return True


def apply_restrictions(bridge_if, gateway_ip, ranges):
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

    # rebuild every chain from scratch - safe to re-run. each one comes back as
    # deny-all first and only then gets its allow rules, so the guests are never
    # briefly unrestricted mid-rebuild.
    for chain in CHAINS:
        ensure_chain_closed(chain)

    build_input_chain(gateway_ip, ranges)
    print("  deny everything else (internet, lan, other networks, guest-to-guest)")

    # a chain nothing jumps to is silently dead, so make sure FORWARD really reaches
    # DOCKER-USER before hanging the forward policy off it
    if not ensure_docker_user_chain():
        print("  error: DOCKER-USER is not reachable from FORWARD.")
        print("         the guest -> lan and lan -> guest drops would be a no-op.")
        return False

    ensure_hook("INPUT", bridge_if, INPUT_CHAIN, "-i")
    ensure_hook("DOCKER-USER", bridge_if, FORWARD_CHAIN, "-i")
    ensure_hook("DOCKER-USER", bridge_if, FORWARD_IN_CHAIN, "-o")

    apply_ipv6_restrictions(bridge_if)

    save_rules()
    return True


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

    try:
        ok = apply_restrictions(bridge_if, gateway_ip, ranges)
    except IptablesError as exc:
        # the chains were built deny-first, so the guests are locked out rather than
        # wide open - but the restrictions are not what the config asked for, and the
        # caller must not go on to advertise a working playground.
        print(f"error: {exc}")
        print("       restrictions are incomplete; the chains are left denying traffic.")
        sys.exit(1)

    if not ok:
        sys.exit(1)

    print("network restrictions applied")


if __name__ == "__main__":
    main()
