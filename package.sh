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

# Always-included project files (everything needed to build + run).
cp -a Dockerfile docker-compose.yml .env.example install.sh uninstall.sh package.sh \
      jackett-resolv.conf app clamav "$STAGE"/ 2>/dev/null || true
for f in README.md MIGRATION.md; do [ -f "$f" ] && cp -a "$f" "$STAGE"/; done
# strip python bytecode caches
find "$STAGE" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

if [ "$WITH_CONFIG" -eq 1 ]; then
  [ -d config ] && cp -a config "$STAGE"/ && echo "Included config/ (contains secrets — handle the tarball carefully)."
fi

if [ "$OFFLINE" -eq 1 ]; then
  echo "Saving images (this is large)…"
  # Resolve the pulled image tags actually referenced by the compose.
  $SUDO docker save \
      vpntorrent vpntorrent-clamav:local \
      lscr.io/linuxserver/jackett:latest \
      ghcr.io/flaresolverr/flaresolverr:latest \
      clamav/clamav:1.4 \
    | gzip > "$STAGE/images.tar.gz"
  echo "Bundled $(du -h "$STAGE/images.tar.gz" | cut -f1) of images (install.sh will load them, skipping build)."
fi

OUT="$PWD/vpntorrent-bundle.tar.gz"
tar -C "$(dirname "$STAGE")" -czf "$OUT" vpntorrent
rm -rf "$(dirname "$STAGE")"
echo
echo "✅ Built: $OUT  ($(du -h "$OUT" | cut -f1))"
echo "   Copy it to the target, then:"
echo "     tar xzf vpntorrent-bundle.tar.gz && cd vpntorrent && ./install.sh"
