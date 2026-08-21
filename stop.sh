#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# print stopping
echo "stopping playground..."

# stopping services
echo "stopping services..."
docker compose down

# remove networking restrictions
echo "removing network restrictions..."
sudo python3 "$SCRIPT_DIR/scipts/teardown_networking_linux.py"

# print stopped
echo "playground stopped"
