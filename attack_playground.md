# attack playground
## overview

## repo structure

## running the playground
`start.sh`: start the playground
`stop.sh`: stop the playground
`restart.sh`: restart the playground
`cleanup.sh`: stop and cleanup the playground

`attack_network_endpoints.conf`: configuration file containing all the exposed attack network endpoints within the playground

## network restrictions

**policy: a guest may open connections to the host on the tcp ports listed in
`attack_network_endpoints.conf`, and to nothing else.** no internet, no other host on
the lan, no other docker network, and no other guest.

guest containers are attached to `attack_playground_net`, an `--internal` docker bridge
network. the attachment is configured in `config.yaml` under `docker.execution.host.networkmode`.

> the keys under `docker.execution.container` map to docker's `container.Config` and the
> keys under `docker.execution.host` map to docker's `container.HostConfig`. those docker
> structs have no yaml tags, so containerssh matches them by the **all-lowercase** go field
> name (`networkmode`, not `networkMode`). containerssh **silently ignores** keys it does
> not recognise, so a misplaced or mis-cased key is a no-op and the guest quietly falls
> back to the default bridge with full internet access. double check this section after
> editing it.

`--internal` stops docker from routing the guests out to the internet, but it is not
enough on its own. it still leaves the host reachable on the bridge gateway ip - which is
where the attack endpoints are exposed - and it still lets guests on the same bridge reach
each other. `scripts/setup_networking_linux.py` therefore installs three iptables chains:

| chain              | hooked from   | matches       | effect                                                                 |
| ------------------ | ------------- | ------------- | ---------------------------------------------------------------------- |
| `ATTACK_PG_INPUT`  | `INPUT`       | `-i <bridge>` | guest -> host: only the tcp ports in `attack_network_endpoints.conf` (on the gateway ip) are accepted, everything else is dropped |
| `ATTACK_PG_FWD`    | `DOCKER-USER` | `-i <bridge>` | guest -> forwarded: dropped. covers guest-to-guest, guest -> other docker network and guest -> lan |
| `ATTACK_PG_FWD_IN` | `DOCKER-USER` | `-o <bridge>` | forwarded -> guest: dropped, so no other host can reach a guest |

the split matters: `DOCKER-USER` is only consulted for **forwarded** packets, while traffic
aimed at the gateway ip is delivered locally and hits **`INPUT`**. an endpoint allowlist
placed in `DOCKER-USER` can never match, which leaves the host fully reachable from a guest.

the host itself is not affected by the two forward chains - host-originated traffic is
routed through `OUTPUT`, not `FORWARD` - so the host can still reach the guests normally.

the restrictions are applied **before** `docker compose up`, not after: containerssh starts
accepting ssh connections - and spawning guests on this network - the moment it is running,
so applying them afterwards leaves a window in which a guest is live and unrestricted. if
setup fails, `start.sh` refuses to launch the services at all.

### fail-closed chains

each chain is rebuilt **deny-first**: it is flushed, given its terminal `DROP`, and only
then are the allow rules *inserted above* that drop. the chain therefore denies by default
at every instant - during the rebuild window, and after a rebuild that failed part way
through.

this matters because the allow rules come from a config file. a port like `70000` or a
range like `1337-99999` is rejected by iptables, and building the chain the other way round
(allows first, `DROP` last) meant a single bad entry left a **live hook pointing at a chain
with no `DROP`** - every guest packet then fell straight through to the `ACCEPT` policy of
`INPUT`, i.e. the whole host. ports are now range checked before they reach iptables, and
the deny-first construction means even an unforeseen iptables rejection fails closed.

### ipv6

`iptables` only covers ipv4. the playground network is ipv4-only, but as long as the host
kernel has ipv6 enabled the guest's `eth0` and the host side of the bridge both still get
link-local (`fe80::/64`) addresses, so a guest could reach any host port over ipv6 and walk
straight past the ipv4 allowlist. every configured endpoint is a tcp port on the ipv4
gateway, so there is nothing to allow over ipv6: the same three chain names are created in
`ip6tables` and drop everything on the bridge.

docker only maintains `DOCKER-USER` in `ip6tables` when its ip6tables support is turned on,
so the ipv6 forward chains hook straight into `FORWARD` instead of relying on it. a missing
`ip6tables` is a warning, not a failure - the ipv4 policy still applies.

### bridge netfilter

guest-to-guest traffic on one bridge only traverses `FORWARD` when `br_netfilter` is loaded
and `net.bridge.bridge-nf-call-iptables` is `1`. if it is not, the guest-to-guest drop is
**silently a no-op**. setup loads the module and sets the sysctl, and prints a warning if it
cannot. teardown deliberately leaves the sysctl alone, since docker relies on it.

### hooks are verified, not assumed

a chain nothing jumps to is silently dead. two places this bites:

* `DOCKER-USER` is normally created *and* hooked into `FORWARD` by docker. if docker has not
  done that yet (daemon just started, iptables flushed), merely creating the chain leaves it
  at 0 references and both forward drops become a no-op while setup reports success. setup
  now checks that `FORWARD` really reaches `DOCKER-USER` and fails loudly if it cannot.
* teardown finds our hooks by scanning the parent chains for jumps to our chains, rather
  than by rebuilding the `-i <bridge>` rule. by teardown time the docker network - and with
  it the bridge name - is often already gone, and a hook that cannot be named cannot be
  deleted: the chain would just get flushed and left behind, referenced and live, with no
  later run able to find it. `stop.sh` runs teardown unconditionally for the same reason.

both scripts are idempotent - `setup` rebuilds the chains from scratch on every run and
also clears the flat `DOCKER-USER` rules written by earlier versions.

### verifying

after `./start.sh`, check the rules on the host:

```
sudo iptables -n -L ATTACK_PG_INPUT          # must end in DROP
sudo iptables -n -L ATTACK_PG_FWD
sudo iptables -n -L ATTACK_PG_FWD_IN
sudo iptables -n -L DOCKER-USER              # must NOT say "(0 references)"
sudo ip6tables -n -L ATTACK_PG_INPUT         # ipv6 mirror, drops everything
sysctl net.bridge.bridge-nf-call-iptables    # must be 1
```

then ssh in and confirm the guest is actually restricted:

```
docker inspect -f '{{json .NetworkSettings.Networks}}' <guest-container>   # attack_playground_net only
nc -vz <gateway-ip> 1337        # allowed endpoint, must succeed
nc -vz <gateway-ip> 22          # must fail
nc -6 -vz <host-link-local>%eth0 22   # must fail
curl -m 5 https://example.com   # must fail
nc -vz <other-guest-ip> <port>  # must fail
```

note that icmp to the gateway is dropped as well, so `ping <gateway-ip>` failing is expected.

### tests

the config parsing and the fail-closed chain construction have unit tests. they are stdlib
only and need neither root nor docker:

```
python3 -m unittest discover -s scripts -p 'test_*.py'
```
