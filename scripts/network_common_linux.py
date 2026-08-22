#!/usr/bin/env python3
"""
common functions for iptables management of the playground docker network.

policy: a guest may open connections to the host on the tcp ports listed in
attack_network_endpoints.conf, and to nothing else. no internet, no other host on
the lan, no other docker network, and no other guest.

the network ("attack_playground_net") is created with --internal, which already stops
docker from routing the guest out to the internet. that alone is not enough:

  * an internal network still leaves the host itself reachable on the bridge gateway
    ip, and that is where the attack endpoints live - so the allowlist has to be
    enforced in INPUT.
  * guests on the same bridge can still reach each other - so intra-bridge traffic
    has to be dropped explicitly.

three dedicated chains are used so that setup is idempotent and teardown is exact:

  ATTACK_PG_INPUT   hooked from INPUT for "-i <bridge>"
                    guest -> host. only the tcp ports from the config file (on the
                    gateway ip) are accepted, everything else is dropped.

  ATTACK_PG_FWD     hooked from DOCKER-USER for "-i <bridge>"
                    guest -> forwarded. dropped outright. this covers guest-to-guest
                    (same bridge), guest -> other docker network and guest -> lan.

  ATTACK_PG_FWD_IN  hooked from DOCKER-USER for "-o <bridge>"
                    forwarded -> guest. dropped, so no other host can reach a guest.
                    the host itself is unaffected: host-originated traffic is routed
                    through OUTPUT, not FORWARD.

note that DOCKER-USER only ever sees FORWARDed packets, so a rule matching the
gateway ip there can never fire - that is why the endpoint allowlist belongs in INPUT.
"""

import os
import re
import subprocess


DOCKER_NET_NAME = "attack_playground_net"
CONFIG_FILE = "attack_network_endpoints.conf"

INPUT_CHAIN = "ATTACK_PG_INPUT"
FORWARD_CHAIN = "ATTACK_PG_FWD"
FORWARD_IN_CHAIN = "ATTACK_PG_FWD_IN"

BRIDGE_NF_SYSCTL = "net.bridge.bridge-nf-call-iptables"


def _privileged_prefix():
    """use sudo only when we are not already root (start.sh already runs us as root)."""
    if os.geteuid() == 0:
        return []
    return ["sudo"]


def iptables_cmd(args, ignore_error=False):
    """run an iptables command. if ignore_error, don't raise."""
    cmd = _privileged_prefix() + ["iptables"] + args
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        if ignore_error:
            return False
        raise


def get_bridge_interface(network_name):
    """return the bridge interface name for the given docker network."""
    try:
        # honour an explicitly configured bridge name if the network sets one
        cmd_opt = ["docker", "network", "inspect", network_name,
                   "-f", '{{index .Options "com.docker.network.bridge.name"}}']
        name = subprocess.check_output(cmd_opt, text=True, stderr=subprocess.DEVNULL).strip()
        if name and name != "<no value>":
            return name

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
        return gateway or None
    except subprocess.CalledProcessError:
        return None


def get_subnet(network_name):
    """return the subnet cidr for the docker network."""
    try:
        cmd = ["docker", "network", "inspect", network_name,
               "-f", "{{(index .IPAM.Config 0).Subnet}}"]
        subnet = subprocess.check_output(cmd, text=True).strip()
        return subnet or None
    except subprocess.CalledProcessError:
        return None


def port_arg(port_range):
    """turn '1337-1355' into iptables' '1337:1355'. a bare port is passed through."""
    if '-' in port_range:
        start, end = port_range.split('-')
        return f"{start}:{end}"
    return port_range


# ---------------------------------------------------------------- chain helpers

def chain_exists(chain):
    return iptables_cmd(["-n", "-L", chain], ignore_error=True)


def ensure_chain(chain):
    """create the chain if needed, then flush it so setup is idempotent."""
    if not chain_exists(chain):
        iptables_cmd(["-N", chain])
    else:
        iptables_cmd(["-F", chain])


def delete_chain(chain):
    """flush and delete the chain (ignore if it doesn't exist)."""
    iptables_cmd(["-F", chain], ignore_error=True)
    iptables_cmd(["-X", chain], ignore_error=True)


def _hook_args(parent, bridge_if, chain, direction="-i"):
    return [parent, direction, bridge_if, "-j", chain]


def ensure_hook(parent, bridge_if, chain, direction="-i"):
    """insert the jump from the parent chain at the top, if not already present."""
    args = _hook_args(parent, bridge_if, chain, direction)
    if iptables_cmd(["-C"] + args, ignore_error=True):
        return False
    iptables_cmd(["-I"] + args)
    return True


def remove_hook(parent, bridge_if, chain, direction="-i"):
    """remove every copy of the jump from the parent chain."""
    args = _hook_args(parent, bridge_if, chain, direction)
    removed = 0
    while iptables_cmd(["-D"] + args, ignore_error=True):
        removed += 1
    return removed


def ensure_docker_user_chain():
    """DOCKER-USER is created by docker, but make sure it's there before hooking into it."""
    if not chain_exists("DOCKER-USER"):
        iptables_cmd(["-N", "DOCKER-USER"], ignore_error=True)


# ----------------------------------------------------------- bridge netfilter

def _sysctl_get(key):
    try:
        out = subprocess.check_output(_privileged_prefix() + ["sysctl", "-n", key],
                                      text=True, stderr=subprocess.DEVNULL)
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def ensure_bridge_netfilter():
    """
    make sure bridged traffic is actually handed to iptables.

    traffic between two guests on the same bridge only traverses the FORWARD chain
    when br_netfilter is loaded and net.bridge.bridge-nf-call-iptables is 1. if it
    is not, the guest-to-guest DROP is silently a no-op and the guests can still
    reach each other. docker normally sets this up itself, but do not rely on it -
    a silent no-op here is exactly the failure mode this whole change is about.

    returns True if bridge netfilter is on by the time we are done.
    """
    value = _sysctl_get(BRIDGE_NF_SYSCTL)

    if value is None:
        # the sysctl only appears once br_netfilter is loaded
        subprocess.run(_privileged_prefix() + ["modprobe", "br_netfilter"],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        value = _sysctl_get(BRIDGE_NF_SYSCTL)

    if value == "1":
        return True

    subprocess.run(_privileged_prefix() + ["sysctl", "-w", f"{BRIDGE_NF_SYSCTL}=1"],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return _sysctl_get(BRIDGE_NF_SYSCTL) == "1"


# ------------------------------------------------------- legacy rule cleanup

def remove_legacy_rules(bridge_if, gateway_ip, ranges):
    """
    remove the flat DOCKER-USER rules written by earlier versions of this script.

    the old blanket "-i <bridge> -j DROP" also killed guest-to-guest traffic inside
    the playground, so it must not be left behind after an upgrade.
    """
    legacy = [
        ["DOCKER-USER", "-i", bridge_if, "-j", "DROP"],
        ["DOCKER-USER", "-i", bridge_if, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]
    if gateway_ip:
        for rng in ranges:
            legacy.append([
                "DOCKER-USER", "-i", bridge_if, "-d", gateway_ip,
                "-p", "tcp", "--dport", port_arg(rng), "-j", "ACCEPT",
            ])

    removed = 0
    for rule in legacy:
        while iptables_cmd(["-D"] + rule, ignore_error=True):
            removed += 1
    return removed


# ------------------------------------------------------------------- config io

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


def find_config():
    """locate the endpoints config: repo root first, then script dir, then cwd."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    for candidate in (
        os.path.join(repo_root, CONFIG_FILE),
        os.path.join(script_dir, CONFIG_FILE),
        os.path.join(os.getcwd(), CONFIG_FILE),
    ):
        if os.path.exists(candidate):
            return candidate
    return None


def save_rules():
    """save iptables rules if netfilter-persistent is available."""
    try:
        subprocess.run(_privileged_prefix() + ["netfilter-persistent", "save"],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        pass
