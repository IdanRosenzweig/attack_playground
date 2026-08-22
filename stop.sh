#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# print stopping
echo "stopping playground..."

# stop and delete all running containers
GUEST_DOCKER_IMAGE_NAME="attack_playground_image:latest"
docker rm -f $(docker ps -q --filter ancestor="$GUEST_DOCKER_IMAGE_NAME") || true

# stop services
echo "stopping services..."
docker compose down

# remove networking restrictions
# echo "removing network restrictions..."
# sudo env PYTHONPATH="$SCRIPT_DIR/scripts" python3 "$SCRIPT_DIR/scripts/teardown_networking_linux.py"
DOCKER_NET_NAME="attack_playground_net"
if docker network inspect "$DOCKER_NET_NAME" &> /dev/null; then
    echo "removing network restrictions..."
    sudo env PYTHONPATH="$SCRIPT_DIR/scripts" python3 "$SCRIPT_DIR/scripts/teardown_networking_linux.py"
else
    echo "network '$DOCKER_NET_NAME' not found, skipping teardown."
fi

# print stopped
echo "playground stopped"
