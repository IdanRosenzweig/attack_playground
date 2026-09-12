#!/bin/bash
# proves the network policy from inside real guest containers:
# a guest may reach the host on the configured tcp ports and nothing else.
#
# a probe that never ran is an ERROR, never a PASS - otherwise a broken containerssh
# makes the whole suite go green while nothing was tested.
#
# guests are torn down the moment their ssh session ends, so long-lived "hold"
# sessions are opened first and everything is inspected while they are up.

PASS=0; FAIL=0; ERR=0
ok()   { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
err()  { echo "  ERROR (not tested): $*"; ERR=$((ERR+1)); }
hdr()  { echo; echo "=== $* ==="; }

NET="attack_playground_net"
IMG="attack_playground_image:latest"
GW=$(docker network inspect "$NET" -f '{{(index .IPAM.Config 0).Gateway}}')
echo "gateway: $GW"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=30"
guest() { sshpass -p anything ssh $SSH_OPTS -p 2222 guestuser@127.0.0.1 "$1" 2>&1; }
guests_up() { docker ps -q --filter ancestor="$IMG" | grep -c . ; }

hdr "host listener on an allowed endpoint (1337)"
nohup python3 -m http.server 1337 --bind 0.0.0.0 > /tmp/listener.log 2>&1 &
LISTENER=$!
sleep 2
ss -lnt 2>/dev/null | grep -q ":1337" && ok "listener up on 1337" || bad "listener did not bind"

hdr "open two guest sessions"
sshpass -p anything ssh $SSH_OPTS -p 2222 guestuser@127.0.0.1 'sleep 600' > /dev/null 2>&1 &
H1=$!
sshpass -p anything ssh $SSH_OPTS -p 2222 guestuser@127.0.0.1 'sleep 600' > /dev/null 2>&1 &
H2=$!
for i in $(seq 1 60); do
    [ "$(guests_up)" -ge 2 ] && break
    sleep 5
done
N=$(guests_up)
echo "  guests running: $N"
[ "$N" -ge 1 ] && ok "at least one guest container spawned" || bad "no guest spawned"

hdr "ssh into a guest"
CANARY=$(guest 'echo GUEST_OK')
if echo "$CANARY" | grep -q GUEST_OK; then
    ok "ssh exec into guest works"; GUEST_UP=1
else
    bad "cannot open a guest session: $CANARY"; GUEST_UP=0
fi

hdr "guest is on the restricted network only"
# every guest is inspected, not just the first: a guest is torn down the instant
# its ssh session ends, so "docker ps | head -1" can hand back the short-lived
# canary container as it is being removed and the inspect then fails on a
# container that was never the point of the check.
CHECKED=0
for CID in $(docker ps -q --filter ancestor="$IMG"); do
    NETS=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CID" 2>/dev/null)
    [ -z "$NETS" ] && continue          # gone between ps and inspect, try the next
    CHECKED=$((CHECKED + 1))
    if [ "$(echo $NETS)" = "$NET" ]; then
        ok "$CID attached to $NET only"
    else
        bad "$CID has unexpected networks: $NETS"
    fi
done
[ "$CHECKED" -eq 0 ] && err "no guest container stayed up long enough to inspect"
[ "$(docker network inspect "$NET" -f '{{.Internal}}')" = "true" ] \
    && ok "network is --internal" || bad "network is not internal"

hdr "policy from inside the guest"
if [ "$GUEST_UP" -ne 1 ]; then
    for p in "allowed endpoint 1337" "host port 22" "host port 2222" \
             "internet" "lan by ip" "icmp to gateway"; do
        err "$p - no guest session"
    done
else
    PROBES=$(guest "
        nc -w 5 -z $GW 1337 > /dev/null 2>&1; echo ALLOWED=\$?
        nc -w 5 -z $GW 22   > /dev/null 2>&1; echo SSH22=\$?
        nc -w 5 -z $GW 2222 > /dev/null 2>&1; echo CSSH=\$?
        curl -s -m 8 -o /dev/null https://example.com; echo NET=\$?
        nc -w 5 -z 1.1.1.1 443 > /dev/null 2>&1; echo IP=\$?
        ping -c 1 -W 3 $GW > /dev/null 2>&1; echo ICMP=\$?
        echo PROBES_DONE
    ")
    echo "$PROBES" | grep -q PROBES_DONE || echo "  (warning: probe script did not finish)"
    rc() { echo "$PROBES" | grep "^$1=" | cut -d= -f2; }
    check_blocked() {
        local v; v=$(rc "$2")
        if   [ -z "$v" ];   then err "$1 - probe did not report"
        elif [ "$v" = "0" ]; then bad "$1 - REACHABLE (policy not enforced)"
        else ok "$1"; fi
    }
    V=$(rc ALLOWED)
    if   [ -z "$V" ];    then err "allowed endpoint 1337 - probe did not report"
    elif [ "$V" = "0" ]; then ok "allowed endpoint 1337 reachable"
    else bad "allowed endpoint 1337 NOT reachable (rc=$V) - allowlist too strict"; fi

    check_blocked "host port 22 dropped"    SSH22
    check_blocked "host port 2222 dropped"  CSSH
    check_blocked "internet unreachable"    NET
    check_blocked "lan by ip unreachable"   IP
    check_blocked "icmp to gateway dropped" ICMP
fi

hdr "guest to guest"
IPS=$(docker ps -q --filter ancestor="$IMG" \
      | xargs -r -I{} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} 2>/dev/null)
echo "  guest ips: $(echo $IPS)"
if [ "$GUEST_UP" -ne 1 ]; then
    err "guest-to-guest - no guest session"
elif [ "$(echo "$IPS" | grep -c .)" -lt 2 ]; then
    err "guest-to-guest - could not get two guests up"
else
    TARGET=$(echo "$IPS" | tail -1)
    R=$(guest "nc -w 5 -z $TARGET 22 > /dev/null 2>&1; echo G2G=\$?; ping -c 1 -W 3 $TARGET > /dev/null 2>&1; echo G2GP=\$?")
    V=$(echo "$R" | grep "^G2G=" | cut -d= -f2)
    P=$(echo "$R" | grep "^G2GP=" | cut -d= -f2)
    if   [ -z "$V" ];    then err "guest-to-guest tcp - probe did not report"
    elif [ "$V" = "0" ]; then bad "guest reached another guest at $TARGET (tcp)"
    else ok "guest-to-guest tcp blocked ($TARGET)"; fi
    if   [ -z "$P" ];    then err "guest-to-guest icmp - probe did not report"
    elif [ "$P" = "0" ]; then bad "guest pinged another guest at $TARGET"
    else ok "guest-to-guest icmp blocked ($TARGET)"; fi
fi

kill $H1 $H2 $LISTENER 2>/dev/null
echo
echo "=================================================="
echo " guest policy - passed: $PASS  failed: $FAIL  not tested: $ERR"
echo "=================================================="
[ "$FAIL" -eq 0 ] && [ "$ERR" -eq 0 ]
