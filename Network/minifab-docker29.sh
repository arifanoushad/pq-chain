#!/bin/bash
# Minifab (hyperledger-labs/minifabric, archived 2023-11) on Docker Engine >= 29.
#
# Source this file before running minifab:   source ./minifab-docker29.sh
#
# 1. Docker Engine 29 refuses API versions < 1.44. Minifab's main.sh pins
#    DOCKER_API_VERSION=1.39, so a patched copy (1.44) is mounted over it.
#    Nothing is changed on the host Docker daemon.
# 2. The minifab launcher does not quote $(pwd); run it from a path without
#    spaces (a symlink is created at $FABNET_LINK).
set -e
PATCH_DIR="${PATCH_DIR:-$HOME/pqchain-infra/minifab-patch}"
FABNET_LINK="${FABNET_LINK:-$HOME/pqchain-infra/fabnet}"
MINIFAB_IMAGE=hyperledgerlabs/minifab:latest

mkdir -p "$PATCH_DIR" "$(dirname "$FABNET_LINK")"
docker pull -q "$MINIFAB_IMAGE" >/dev/null
docker run --rm --entrypoint cat "$MINIFAB_IMAGE" /home/main.sh \
  | sed 's/^export DOCKER_API_VERSION=1.39$/export DOCKER_API_VERSION=1.44/' > "$PATCH_DIR/main.sh"
grep -q '^export DOCKER_API_VERSION=1.44' "$PATCH_DIR/main.sh" || { echo "patch failed"; return 1 2>/dev/null || exit 1; }
chmod +x "$PATCH_DIR/main.sh"

if [ ! -x "$PATCH_DIR/minifab" ]; then
  curl -fsSL https://raw.githubusercontent.com/hyperledger-labs/minifabric/main/minifab -o "$PATCH_DIR/minifab"
  chmod +x "$PATCH_DIR/minifab"
fi
export PATH="$PATCH_DIR:$PATH"
export minifab_opt="-v $PATCH_DIR/main.sh:/home/main.sh:ro"

ln -sfn "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" "$FABNET_LINK"
set +e
echo "minifab ready (DOCKER_API_VERSION=1.44); run it from $FABNET_LINK"
