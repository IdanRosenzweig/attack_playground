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

### bridge netfilter

guest-to-guest traffic on one bridge only traverses `FORWARD` when `br_netfilter` is loaded
and `net.bridge.bridge-nf-call-iptables` is `1`. if it is not, the guest-to-guest drop is
**silently a no-op**. setup loads the module and sets the sysctl, and prints a warning if it
cannot. teardown deliberately leaves the sysctl alone, since docker relies on it.

both scripts are idempotent - `setup` rebuilds the chains from scratch on every run and
also clears the flat `DOCKER-USER` rules written by earlier versions.

### verifying

after `./start.sh`, check the rules on the host:

```
sudo iptables -n -L ATTACK_PG_INPUT
sudo iptables -n -L ATTACK_PG_FWD
sudo iptables -n -L ATTACK_PG_FWD_IN
sysctl net.bridge.bridge-nf-call-iptables   # must be 1
```

then ssh in and confirm the guest is actually restricted:

```
docker inspect -f '{{json .NetworkSettings.Networks}}' <guest-container>   # attack_playground_net only
nc -vz <gateway-ip> 1337        # allowed endpoint, must succeed
nc -vz <gateway-ip> 22          # must fail
curl -m 5 https://example.com   # must fail
nc -vz <other-guest-ip> <port>  # must fail
```

note that icmp to the gateway is dropped as well, so `ping <gateway-ip>` failing is expected.
