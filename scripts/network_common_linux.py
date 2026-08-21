#!/usr/bin/env python3
"""
common functions for iptables management of docker network.
"""

import subprocess
import os
import re


DOCKER_NET_NAME = "attack_playground_net"
CONFIG_FILE = "allowed_ports.conf"

def get_bridge_interface(network_name):
    """return the bridge interface name for the given docker network."""
    try:
        cmd_id = ["docker", "network", "inspect", network_name, "-f", "{{.Id}}"]
        net_id = subprocess.check_output(cmd_id, text=True).strip()
        if not net_id:
            return None
        return f"br-{net_id[:12]}"
    except subprocess.CalledProcessError:
        return None

def get_gateway_ip(network_name):
    """return the gateway ip for the docker network."""
    try:
        cmd = ["docker", "network", "inspect", network_name,
               "-f", "{{(index .IPAM.Config 0).Gateway}}"]
        gateway = subprocess.check_output(cmd, text=True).strip()
        return gateway
    except subprocess.CalledProcessError:
        return None

def iptables_cmd(args, ignore_error=False):
    """run iptables command with sudo. if ignore_error, don't raise."""
    cmd = ["sudo", "iptables"] + args
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        if ignore_error:
            return False
        raise

def rule_exists(bridge_if, gateway_ip, port_range):
    """check if the specific accept rule already exists."""
    if '-' in port_range:
        start, end = port_range.split('-')
        port_arg = f"{start}:{end}"
    else:
        port_arg = port_range
    check_args = [
        "-C", "DOCKER-USER",
        "-i", bridge_if,
        "-d", gateway_ip,
        "-p", "tcp",
        "--dport", port_arg,
        "-j", "ACCEPT"
    ]
    return iptables_cmd(check_args, ignore_error=True)

def add_rule(bridge_if, gateway_ip, port_range):
    """insert accept rule for the given port range."""
    if '-' in port_range:
        start, end = port_range.split('-')
        port_arg = f"{start}:{end}"
    else:
        port_arg = port_range
    insert_args = [
        "-I", "DOCKER-USER",
        "-i", bridge_if,
        "-d", gateway_ip,
        "-p", "tcp",
        "--dport", port_arg,
        "-j", "ACCEPT"
    ]
    return iptables_cmd(insert_args)

def remove_rule(bridge_if, gateway_ip, port_range):
    """delete accept rule for the given port range (ignore if not exists)."""
    if '-' in port_range:
        start, end = port_range.split('-')
        port_arg = f"{start}:{end}"
    else:
        port_arg = port_range
    delete_args = [
        "-D", "DOCKER-USER",
        "-i", bridge_if,
        "-d", gateway_ip,
        "-p", "tcp",
        "--dport", port_arg,
        "-j", "ACCEPT"
    ]
    cmd = ["sudo", "iptables"] + delete_args
    subprocess.run(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def parse_config(config_path):
    """read port ranges from config file, ignoring comments and blank lines."""
    if not os.path.exists(config_path):
        return []

    ranges = []
    with open(config_path, 'r') as f:
        for line in f:
            line = line.strip()

            # comment line
            if not line or line.startswith('#'):
                continue

            # a single port specified
            if re.match(r'^\d+$', line):
                ranges.append(line)

            # port range specified
            elif re.match(r'^\d+-\d+$', line):
                start, end = line.split('-')
                if int(start) <= int(end):
                    ranges.append(line)
                else:
                    print(f"warning: invalid range (start > end): {line}")
                
            else:
                print(f"warning: skipping invalid line: {line}")
    return ranges

def save_rules():
    """save iptables rules if netfilter-persistent is available."""
    try:
        subprocess.run(["sudo", "netfilter-persistent", "save"], check=False)
    except FileNotFoundError:
        pass
