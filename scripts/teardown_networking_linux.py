#!/usr/bin/env python3
"""
remove iptables rules based on allowed_ports.conf.
"""

import os
import subprocess
from common import (
    DOCKER_NET_NAME, CONFIG_FILE,
    get_bridge_interface, get_gateway_ip,
    remove_rule, parse_config, save_rules
)


def main():
    bridge_if = get_bridge_interface(DOCKER_NET_NAME)
    if not bridge_if:
        print(f"info: network '{DOCKER_NET_NAME}' not found, skipping.")
        return

    gateway_ip = get_gateway_ip(DOCKER_NET_NAME)
    if not gateway_ip:
        print("warning: could not determine gateway ip, using default 172.20.0.1")
        gateway_ip = "172.20.0.1"

    print(f"removing iptables rules for interface {bridge_if}, gateway {gateway_ip}")

    # remove drop rule (ignore if not present)
    drop_cmd = ["sudo", "iptables", "-D", "DOCKER-USER", "-i", bridge_if, "-j", "DROP"]
    subprocess.run(drop_cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    # remove established/related rule
    est_cmd = [
        "sudo", "iptables", "-D", "DOCKER-USER",
        "-i", bridge_if,
        "-m", "state", "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT"
    ]
    subprocess.run(est_cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    # remove accept rules from config
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, CONFIG_FILE)
    if not os.path.exists(config_path):
        config_path = os.path.join(os.getcwd(), CONFIG_FILE)

    ranges = parse_config(config_path)
    
    for rng in ranges:
        remove_rule(bridge_if, gateway_ip, rng)

    save_rules()
    print("cleanup complete.")

if __name__ == "__main__":
    main()
