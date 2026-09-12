#!/bin/bash
# end-to-end verification of the attack playground on a real linux host.
# run from inside the repo directory on the VM. does not abort on first failure -
# the point is a full picture.

cd "$(dirname "$0")"

PASS=0; FAIL=0
ok()   { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
hdr()  { echo; echo "=== $* ==="; }

GUEST_IMAGE="attack_playground_image:latest"
NET="attack_playground_net"

hdr "unit tests"
if python3 -m unittest discover -s scripts -p 'test_*.py' > /tmp/unit.log 2>&1; then
    ok "$(grep -oE 'Ran [0-9]+ tests' /tmp/unit.log) OK"
else
    bad "unit tests failed"; tail -20 /tmp/unit.log
fi

hdr "start.sh"
if ./start.sh > /tmp/start.log 2>&1; then
    ok "start.sh exited 0"
else
    bad "start.sh exited $?"; tail -30 /tmp/start.log
fi
grep -q "playground is running" /tmp/start.log && ok "reported running" || bad "no 'running' line"

hdr "iptables chains"
for c in ATTACK_PG_INPUT ATTACK_PG_FWD ATTACK_PG_FWD_IN; do
    if sudo iptables -n -L "$c" > /tmp/chain.log 2>&1; then
        ok "$c exists"
        # the terminal rule must be a DROP - that is the fail-closed invariant
        if sudo iptables -S "$c" | tail -1 | grep -q -- "-j DROP"; then
            ok "$c ends in DROP"
        else
            bad "$c does NOT end in DROP"; sudo iptables -S "$c"
        fi
    else
        bad "$c missing"
    fi
done

# the allowlist must be in INPUT, and must name the gateway ip
GW=$(docker network inspect "$NET" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)
echo "  (gateway: $GW)"
sudo iptables -S ATTACK_PG_INPUT | grep -q "dports\? 1337:1355" \
    && ok "endpoint range 1337-1355 allowed" || bad "endpoint range not in chain"
sudo iptables -S ATTACK_PG_INPUT | grep -q -- "-d $GW" \
    && ok "allow rules are scoped to the gateway ip" || bad "allow rules not scoped to gateway"

hdr "hooks are live"
sudo iptables -S INPUT | grep -q "ATTACK_PG_INPUT" && ok "INPUT -> ATTACK_PG_INPUT" || bad "INPUT hook missing"
sudo iptables -S DOCKER-USER | grep -q "ATTACK_PG_FWD" && ok "DOCKER-USER -> ATTACK_PG_FWD" || bad "forward hook missing"
sudo iptables -n -L DOCKER-USER | head -1 | grep -q "0 references" \
    && bad "DOCKER-USER has 0 references (chain is dead)" || ok "DOCKER-USER is referenced"

hdr "ipv6 mirror"
if sudo ip6tables -n -L ATTACK_PG_INPUT > /dev/null 2>&1; then
    sudo ip6tables -S ATTACK_PG_INPUT | tail -1 | grep -q -- "-j DROP" \
        && ok "ipv6 ATTACK_PG_INPUT ends in DROP" || bad "ipv6 chain not closed"
else
    bad "ipv6 chain missing"
fi

hdr "bridge netfilter"
V=$(sysctl -n net.bridge.bridge-nf-call-iptables 2>/dev/null)
[ "$V" = "1" ] && ok "bridge-nf-call-iptables=1" || bad "bridge-nf-call-iptables=$V"

hdr "services"
docker ps --format '{{.Names}}' | grep -q containerssh && ok "containerssh up" || bad "containerssh not running"
docker ps --format '{{.Ports}}' | grep -q "127.0.0.1:2223" \
    && ok "auth webhook bound to loopback" || bad "auth webhook not on loopback"

echo
echo "======================================"
echo " passed: $PASS   failed: $FAIL"
echo "======================================"
[ "$FAIL" -eq 0 ]
