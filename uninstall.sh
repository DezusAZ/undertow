#!/usr/bin/env bash
# Stop and remove the vpntorrent stack.
#   ./uninstall.sh          stop + remove containers/networks (KEEPS your data)
#   ./uninstall.sh --purge  also remove the ClamAV DB volume + built images
# Your downloads (MEDIA_PATH) and config/ are NEVER touched.
set -euo pipefail
cd "$(dirname "$0")"
export DOCKER_CONFIG="$PWD/.docker"

SUDO=""; docker info >/dev/null 2>&1 || SUDO="sudo"
if $SUDO docker compose version >/dev/null 2>&1; then DC="$SUDO docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="$SUDO docker-compose"
else echo "docker compose (v2 plugin or docker-compose) not found." >&2; exit 1; fi

# Remove the boot service first, or a reboot would silently bring the whole stack
# back up after the user thought they had uninstalled it.
if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/undertow.service ]; then
  echo "Removing the boot service (undertow.service)…"
  $SUDO systemctl disable --now undertow.service >/dev/null 2>&1 || true
  $SUDO rm -f /etc/systemd/system/undertow.service
  $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ "${1:-}" = "--purge" ]; then
  # `down -v` removes EVERY named volume, which is both clamav-db AND bitmagnet-pg.
  # bitmagnet-pg is the DHT crawl database built up over days/weeks of crawling; the
  # old wording promised only the ClamAV volume, so people lost it unknowingly.
  echo "Removing containers, networks, built images, and these DATA volumes:"
  echo "   - clamav-db     (virus signatures — re-downloaded automatically)"
  echo "   - bitmagnet-pg  (the DHT crawl database — REBUILDING THIS TAKES DAYS)"
  echo
  printf 'Type "purge" to confirm: '
  read -r _confirm < /dev/tty 2>/dev/null || _confirm=""
  if [ "$_confirm" != "purge" ]; then
    echo "Aborted. (Plain ./uninstall.sh removes containers but keeps all data.)"
    exit 1
  fi
  $DC down -v --rmi local
  # --rmi local only drops untagged builds; our images carry explicit tags, so
  # remove them by name too.
  $SUDO docker rmi vpntorrent vpntorrent-clamav:local 2>/dev/null || true
else
  echo "Stopping + removing containers and networks (data kept)…"
  $DC down
fi
echo "Done. Your downloads and config/ are untouched. Re-install any time with ./install.sh"
