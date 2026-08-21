#!/usr/bin/env python3
"""
apply iptables rules based on the config file.
"""

import sys
import os
from common import (
    DOCKER_NET_NAME, CONFIG_FILE,
    get_bridge_interface, get_gateway_ip,
    iptables_cmd, rule_exists, add_rule,
    parse_config, save_rules
)


def main():
    bridge_if = get_bridge_interface(DOCKER_NET_NAME)
    if not bridge_if:
        print(f"error: network '{DOCKER_NET_NAME}' not found.")
        sys.exit(1)

    gateway_ip = get_gateway_ip(DOCKER_NET_NAME)
    if not gateway_ip:
        print("error: could not determine gateway ip for network.")
        sys.exit(1)

    # check if default drop rule exists to avoid duplicate runs
    check_drop = ["-C", "DOCKER-USER", "-i", bridge_if, "-j", "DROP"]
    if iptables_cmd(check_drop, ignore_error=True):
        print(f"info: iptables rules already present for {bridge_if}, skipping.")
        return

    print(f"adding iptables rules for interface {bridge_if}, gateway {gateway_ip}")

    # default deny
    iptables_cmd(["-I", "DOCKER-USER", "-i", bridge_if, "-j", "DROP"])

    # allow established/related
    iptables_cmd([
        "-I", "DOCKER-USER",
        "-i", bridge_if,
        "-m", "state",
        "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT"
    ])

    # read config
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, CONFIG_FILE)
    if not os.path.exists(config_path):
        config_path = os.path.join(os.getcwd(), CONFIG_FILE)
    ranges = parse_config(config_path)

    if not ranges:
        print("warning: no valid port ranges found in config file.")
    else:
        for rng in ranges:
            if rule_exists(bridge_if, gateway_ip, rng):
                print(f"info: rule for {rng} already exists, skipping.")
            else:
                if add_rule(bridge_if, gateway_ip, rng):
                    print(f"added rule for {rng}")
                else:
                    print(f"failed to add rule for {rng}")

    save_rules()

if __name__ == "__main__":
    main()
