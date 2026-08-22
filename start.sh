#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# print starting
echo "starting playground..."

# ssh host key
if [ ! -f host.key ]; then
    echo "generating ssh host key..."
    ssh-keygen -t ed25519 -f ./host.key -N ""
    chmod a+r ./host.key
else
    echo "ssh host key already exists"
fi

# build the image for the guest docker
GUEST_DOCKER_IMAGE_NAME="attack_playground_image:latest"
if ! docker image inspect "$GUEST_DOCKER_IMAGE_NAME" &> /dev/null; then
    echo "building guest docker image \"$GUEST_DOCKER_IMAGE_NAME\"..."
    docker build -f guest_docker.dockerfile -t "$GUEST_DOCKER_IMAGE_NAME" .
else
    echo "guest docker image already exists"
fi

# stop any existing containers and remove the old network to avoid conflicts
# DOCKER_NET_NAME="attack_playground_net"
# echo "cleaning up existing containers and network..."
# docker compose down 2>/dev/null || true
# docker network rm "$DOCKER_NET_NAME" 2>/dev/null || true

# launch services
echo "launching services..."
docker compose up -d

# apply network restrictions for the docker network
# echo "applying network restrictions for the docker network..."
# sudo env PYTHONPATH="$SCRIPT_DIR/scripts" python3 "$SCRIPT_DIR/scripts/setup_networking_linux.py"

# print running
echo "playground is running"

# print connection info
HOST_IP=$(ip route get 1 | awk '{print $7; exit}')
if [ -z "$HOST_IP" ]; then
    HOST_IP="localhost"
fi
echo "connect with ssh, target: $HOST_IP, port: 2222, user: anyuser, password: <anything> (e.g. ssh -p 2222 anyuser@$HOST_IP)"
