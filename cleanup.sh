#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# print cleaning up
echo "cleaning up playground..."

# stop
echo "stopping..."
if [ -f ./stop.sh ]; then
    ./stop.sh
else
    echo "error: stop.sh not found"
    exit 1
fi

# remove docker network
# DOCKER_NET_NAME="attack_playground_net"
# if docker network inspect "$DOCKER_NET_NAME" &> /dev/null; then
#     echo "removing docker network \"$DOCKER_NET_NAME\"..."
#     docker network rm "$DOCKER_NET_NAME"
# fi

# remove docker image
GUEST_DOCKER_IMAGE_NAME="attack_playground_image:latest"
if docker image inspect "$GUEST_DOCKER_IMAGE_NAME" &> /dev/null; then
    echo "removing docker image \"$GUEST_DOCKER_IMAGE_NAME\"..."
    docker rmi "$GUEST_DOCKER_IMAGE_NAME"
fi

# remove ssh host key
if [ -f host.key ]; then
    echo "removing ssh host key..."
    rm -f host.key
fi

# print complete
echo "cleanup complete"
