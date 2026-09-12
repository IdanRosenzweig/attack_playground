# attack playground
## overview

## repo structure

## running the playground
`start.sh`: start the playground
`stop.sh`: stop the playground
`restart.sh`: restart the playground
`cleanup.sh`: stop and cleanup the playground

`attack_network_endpoints.conf`: configuration file containing all the exposed attack network endpoints within the playground

`scripts/common.sh`: shared helpers for the lifecycle scripts - the host preflight,
`as_root`, and compose resolution

## host requirements

the playground runs **on linux x86-64 only**. the guest
restrictions are iptables chains on the host kernel's docker bridge, so the daemon has
to be the host's own: on macos and windows docker runs inside its own vm and the chains
would be applied to the wrong kernel, or to none at all. `start.sh` checks `uname` and
refuses to start rather than bringing guests up unrestricted.

on a fresh ubuntu/debian x64 host:

| need                  | notes                                                              |
| --------------------- | ------------------------------------------------------------------ |
| docker engine         | `curl -fsSL https://get.docker.com \| sh`                            |
| docker compose        | v2 plugin (`docker-compose-plugin`); the standalone v1 `docker-compose` also works |
| python3               | stdlib only, no pip packages                                       |
| iptables              | normally pulled in by docker-ce, but not on every host             |
| root                  | either run as root, or as a user with sudo                         |
| docker socket access  | `sudo usermod -aG docker $USER && newgrp docker`, or run as root    |
| x86-64                | required - see below                                               |

`start.sh` verifies all of the above **before** it creates the host key, the guest image
or the network, and prints the fix for whatever is missing. running as root on a minimal
image with no sudo installed is supported - `as_root` in `scripts/common.sh` only reaches
for sudo when it is not already root.

### why x86-64 specifically

this is not a preference. `containerssh/containerssh` is published for **linux/amd64
only**. on any other architecture docker pulls the amd64 image anyway and the container
restart-loops on

```
exec /containerssh: exec format error
```

while `docker compose up -d` still exits 0 - so without a check the playground reports
itself as running with nothing listening on port 2222. verified on an aarch64 ubuntu
24.04 host. the preflight fails on a non-x86-64 host unless the qemu-user binfmt
handlers are registered (`docker run --privileged --rm tonistiigi/binfmt --install
amd64`), in which case it says the emulation is in use and carries on.

guest containers themselves are built from `guest_docker.dockerfile` for the host's
architecture, so on an x86-64 host they are x86-64 and prebuilt x86-64 tooling runs in
them.

### start is not "containers created"

`docker compose up -d` exits 0 once the containers exist, which says nothing about
whether they stayed up. `start.sh` therefore waits for containerssh to actually accept
tcp on 2222 before printing `playground is running`, and dumps the container logs and
exits non-zero if it never does. a crash-looping service - wrong image architecture, bad
config, an unreadable host key - is a loud failure rather than a playground that is
advertised as working.

### docker's firewall backend

docker 29 can be told to program nftables directly (`"firewall-backend": "nftables"`),
and in that mode it maintains **no `DOCKER-USER` chain at all**. the forward drops then
hang off a `DOCKER-USER` chain that `setup_networking_linux.py` creates and hooks into
`FORWARD` itself. the kernel still evaluates them - a `DROP` is a `DROP` whichever table
it lives in - but their ordering against docker's own rules is no longer ours to control,
so the preflight warns and the rules should be verified by hand (see *verifying* below).
the default iptables backend needs none of this.

### the auth webhook

`containerssh-auth` authenticates *anybody* as whatever username they ask for - that is
the point of a playground, but it means the port must not be reachable from the lan. it
is published on `127.0.0.1:2223` only. note that a docker published port is DNATed in the
`nat` table before ufw or firewalld ever sees it, so binding it to `0.0.0.0` would expose
it regardless of the host firewall. containerssh itself reaches the webhook by service
name on `containerssh_net` and does not need the published port at all.

`auth_server.py` is stdlib only (`http.server`). it used to be a flask app whose
container ran `pip install flask` on every start, which meant the auth service needed
working network access each time it booted, and that containerssh - which is held back
until the webhook is healthy - could not start until that install finished. the webhook
now serves within a second of the container being created and works with no network at
all.

it answers `POST /auth/password` and `POST /auth/pubkey` with
`{"success": true, "authenticatedUsername": "<whatever was asked for>"}`. a missing or
malformed body falls back to `guestuser` rather than failing: this webhook says yes to
everyone by design, and a rejected login reads as a broken playground.

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

`./verify.sh` runs the host checks below and reports pass/fail: the unit tests,
`start.sh`, every chain and its terminal `DROP`, the hooks, the ipv6 mirror, the
sysctl and the loopback binding. `./verify_guest.sh` then proves the policy from
inside real guest containers. both need `sshpass` and `netcat-openbsd` on the host,
and a playground that is not already running. a probe that could not run is
reported as "not tested" rather than as a pass.

to check by hand instead, after `./start.sh`, check the rules on the host:

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

the shell helpers in `scripts/common.sh` are covered too - those tests stub every
external command on `PATH`, so they behave the same on a developer laptop as on
the deployment host.
