#!/usr/bin/env bash
# Stop and remove the vpntorrent stack.
#   ./uninstall.sh          stop + remove containers/networks (KEEPS your data)
#   ./uninstall.sh --purge  also remove the ClamAV DB volume + built images
# Your downloads (MEDIA_PATH) and config/ are NEVER touched.
set -euo pipefail
cd "$(dirname "$0")"
export DOCKER_CONFIG="$PWD/.docker"

SUDO=""; docker info >/dev/null 2>&1 || SUDO="sudo"
if $SUDO docker compose version >/dev/null 2>&1; then DC="$SUDO docker compose"; else DC="$SUDO docker-compose"; fi

if [ "${1:-}" = "--purge" ]; then
  echo "Removing containers, networks, the ClamAV DB volume, and built images…"
  $DC down -v --rmi local
else
  echo "Stopping + removing containers and networks (data kept)…"
  $DC down
fi
echo "Done. Your downloads and config/ are untouched. Re-install any time with ./install.sh"
