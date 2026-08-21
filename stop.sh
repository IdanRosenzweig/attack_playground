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
source ./scripts/teardown_networking_linux.sh

# print stopped
echo "playground stopped"
