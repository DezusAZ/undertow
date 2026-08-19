#!/usr/bin/env bash
# Bundle the whole project into one tarball you can copy to another machine
# (e.g. the ZimaBlade) and install with ./install.sh.
#
#   ./package.sh                 source bundle (small; builds images on the target)
#   ./package.sh --offline       also bake in the built images (big; no build/internet
#                                needed on the target)
#   ./package.sh --with-config   include config/ too (your proton.conf + password!) —
#                                convenient but the tarball then holds secrets.
#
# Output: vpntorrent-bundle.tar.gz  (extract -> cd vpntorrent -> ./install.sh)
set -euo pipefail
cd "$(dirname "$0")"

OFFLINE=0; WITH_CONFIG=0
for a in "$@"; do
  case "$a" in
    --offline) OFFLINE=1 ;;
    --with-config) WITH_CONFIG=1 ;;
    *) echo "unknown option: $a"; exit 1 ;;
  esac
done

SUDO=""; docker info >/dev/null 2>&1 || SUDO="sudo"
STAGE="$(mktemp -d)/vpntorrent"
mkdir -p "$STAGE"

# Always-included project files (everything needed to build + run). No error
# suppression: under `set -e` a missing required file MUST abort the bundle.
cp -a Dockerfile docker-compose.yml .env.example install.sh uninstall.sh package.sh \
      jackett-resolv.conf undertow-heal.sh verify-anonymity.sh searxng-config app clamav "$STAGE"/
for f in README.md LICENSE .dockerignore; do [ -f "$f" ] && cp -a "$f" "$STAGE"/; done
# The VPN config TEMPLATE must ship — without it a new user has no idea what to put in
# config/proton.conf, and the app stays permanently disabled.
mkdir -p "$STAGE/config"
cp -a config/proton.conf.example "$STAGE/config/"
# strip python bytecode caches
find "$STAGE" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

# NEVER ship our SearXNG secret_key: it is a per-instance secret, and baking one into the
# bundle would give every recipient the SAME key. Blank it so install.sh generates a fresh
# one on the target.
if [ -f "$STAGE/searxng-config/settings.yml" ]; then
  sed -i 's/^\( *secret_key *: *\).*/\1"CHANGE_ME_ON_INSTALL"/' "$STAGE/searxng-config/settings.yml"
fi

if [ "$WITH_CONFIG" -eq 1 ]; then
  if [ -d config ]; then
    cp -a config/. "$STAGE/config/"
    # HARD RULE: the WireGuard private key never leaves this machine in a bundle. It is
    # YOUR VPN identity — anyone holding it can use your account and, more importantly,
    # traffic from it is attributable to you. Recipients must supply their own.
    rm -f "$STAGE/config/proton.conf" "$STAGE/config/proton-"*.conf 2>/dev/null || true
    rm -rf "$STAGE/config/vpn" 2>/dev/null || true
    # Same for the web password and anything else identifying.
    rm -f "$STAGE/config/password.txt" "$STAGE/config/.vpn_pool" 2>/dev/null || true
    # ...and your download/activity history.
    rm -rf "$STAGE/config/resume" "$STAGE/config/hunts" "$STAGE/config/clamav" 2>/dev/null || true
    rm -f "$STAGE/config/torrents.json" 2>/dev/null || true
    echo "Included config/ — WireGuard keys, password and download history were STRIPPED."
    echo "The recipient must add their own config/proton.conf."
  fi
fi

if [ "$OFFLINE" -eq 1 ]; then
  echo "Saving images (this is large)…"
  # Resolve the pulled image tags actually referenced by the compose.
  # Ask COMPOSE which images the stack needs rather than maintaining a hand-written
  # list — the old hardcoded list had drifted and omitted 4 of the 10 images
  # (postgres, bitmagnet, sabnzbd, docker-cli), so an "offline" install still needed
  # the internet and failed on a machine that had none.
  IMAGES="$($SUDO docker compose config --images 2>/dev/null | sort -u | tr '\n' ' ')"
  if [ -z "${IMAGES// /}" ]; then
    echo "Could not determine the image list from docker compose — aborting." >&2
    exit 1
  fi
  echo "  images: $IMAGES"
  # shellcheck disable=SC2086
  $SUDO docker save $IMAGES | gzip > "$STAGE/images.tar.gz"
  echo "Bundled $(du -h "$STAGE/images.tar.gz" | cut -f1) of images (install.sh will load them, skipping build)."
fi

OUT="$PWD/vpntorrent-bundle.tar.gz"
tar -C "$(dirname "$STAGE")" -czf "$OUT" vpntorrent
rm -rf "$(dirname "$STAGE")"
echo
echo "✅ Built: $OUT  ($(du -h "$OUT" | cut -f1))"
echo "   Copy it to the target, then:"
echo "     tar xzf vpntorrent-bundle.tar.gz && cd vpntorrent && ./install.sh"
