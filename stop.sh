#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/scripts/common.sh"

# print stopping
echo "stopping playground..."

# stop containerssh first, and only containerssh. it spawns a guest for every ssh
# login, so as long as it is up a guest can appear between "list the guests" and
# "remove them" and be left behind attached to the playground network - which
# then cannot be removed. stopping containerssh does not remove the guests it
# already started, hence the sweep below.
#
# the other services stay up until "compose down" further down. the stats
# collector is one of them, and it records each guest going away as the end of
# that user's session; stopped earlier, it would only find them gone on the next
# start and have to guess when they left.
echo "stopping containerssh..."
compose stop containerssh

# remove all guest containers, running or not.
# "docker ps -q" only lists running ones, which left every exited guest behind: they
# stay attached to the playground network and keep a reference to the guest image, so
# cleanup.sh could not remove either.
GUEST_DOCKER_IMAGE_NAME="attack_playground_image:latest"
GUEST_CONTAINERS=$(docker ps -aq --filter ancestor="$GUEST_DOCKER_IMAGE_NAME")
if [ -n "$GUEST_CONTAINERS" ]; then
    echo "removing guest containers..."
    # a guest that exits on its own between the listing and this rm makes rm fail
    # on that id, which under "set -e" would abort before the teardown below runs.
    # shellcheck disable=SC2086 # word splitting is wanted, this is a list of ids
    docker rm -f $GUEST_CONTAINERS || true
fi

compose down

# remove networking restrictions.
# this is not conditional on the docker network still existing: the iptables chains
# outlive the network, and skipping teardown when the network is already gone just
# leaves them applied with no way to find them later.
echo "removing network restrictions..."
as_root env PYTHONPATH="$SCRIPT_DIR/scripts" python3 "$SCRIPT_DIR/scripts/teardown_networking_linux.py"

# print stopped
echo "playground stopped"
