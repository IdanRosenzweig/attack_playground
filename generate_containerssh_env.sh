#!/usr/bin/env bash

set -euo pipefail

# detect User ID
CURRENT_UID=$(id -u)

# detect docker gid
if getent group docker >/dev/null 2>&1; then
    DOCKER_GID=$(getent group docker | cut -d: -f3)
elif [ -S /var/run/docker.sock ]; then
    # Fallback to reading group ownership directly from the socket file
    DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
else
    echo "error: could not determine docker gid. is docker installed and running?" >&2
    exit 1
fi

echo "detected current uid: ${CURRENT_UID}"
echo "detected docker gid: ${DOCKER_GID}"

# generate env file
cat <<EOF > .env
CURRENT_UID=${CURRENT_UID}
DOCKER_GID=${DOCKER_GID}
EOF

echo "successfully generated env"
