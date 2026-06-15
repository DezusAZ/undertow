#!/usr/bin/env bash
# vpntorrent installer — sets up the whole stack on this machine.
# Safe to re-run (idempotent). Works on ZimaOS / any Docker host (amd64).
#
#   ./install.sh                 interactive setup
#   ./install.sh --noninteractive   use existing .env / defaults, no prompts
#
# If an "images.tar.gz" sits next to this script (an offline bundle), the images
# are loaded from it and NOT rebuilt.
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

NONINTERACTIVE=0
[ "${1:-}" = "--noninteractive" ] && NONINTERACTIVE=1

# --- docker + compose detection (with sudo fallback) -----------------------
SUDO=""
if ! docker info >/dev/null 2>&1; then
  if sudo -n true 2>/dev/null || [ -t 0 ]; then SUDO="sudo"; fi
  if ! $SUDO docker info >/dev/null 2>&1; then
    err "Docker isn't available (or needs different permissions). Install/enable Docker first."
    exit 1
  fi
fi
if $SUDO docker compose version >/dev/null 2>&1; then
  DC="$SUDO docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="$SUDO docker-compose"
else
  err "docker compose (v2 plugin) or docker-compose is required."
  exit 1
fi
# /DATA/.docker is root-owned on ZimaOS -> buildx permission denied. Use a local
# config dir so builds work without touching the system one.
export DOCKER_CONFIG="$PWD/.docker"
mkdir -p "$DOCKER_CONFIG"

# --- gather config ---------------------------------------------------------
# defaults (overridden by an existing .env, then by prompts)
MEDIA_PATH="/DATA/Media/vpntorrent"
VT_PASSWORD=""
TMDB_API_KEY=""
TZ_VAL="$(cat /etc/timezone 2>/dev/null || echo UTC)"
WEB_PORT="8722"
HOST_IP=""
SANDBOX_SUBNET=""
TRANSCODER_IP=""
VPNTORRENT_SANDBOX_IP=""
# shellcheck disable=SC1091
[ -f .env ] && . ./.env 2>/dev/null || true
# map .env names onto our locals (TZ collides with the env var name)
[ -n "${TZ:-}" ] && TZ_VAL="$TZ"

detect_ip() {
  if command -v tailscale >/dev/null 2>&1; then
    local t; t="$(tailscale ip -4 2>/dev/null | head -1)"; [ -n "$t" ] && { echo "$t"; return; }
  fi
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' \
    || hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1
}

# Pick a free 172.x.9.0/24 for the decoder sandbox so it can't overlap an existing
# docker network on the target (that "pool overlaps" error bit us once).
pick_sandbox_base() {
  local used n
  used="$($SUDO docker network inspect $($SUDO docker network ls -q 2>/dev/null) \
          --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true)"
  for n in 24 25 26 27 28 23 21 20 19 18 30; do
    case " $used " in *"172.$n."*) continue ;; esac
    echo "172.$n.9"; return
  done
  echo "172.24.9"
}

# WireGuard needs /dev/net/tun; some ZimaOS boxes don't load the module by default.
ensure_tun() {
  [ -c /dev/net/tun ] && return 0
  warn "/dev/net/tun is missing — trying to load the tun module…"
  $SUDO modprobe tun 2>/dev/null || true
  echo tun | $SUDO tee /etc/modules-load.d/tun.conf >/dev/null 2>&1 || true
  [ -c /dev/net/tun ] || warn "Could not enable /dev/net/tun — the VPN may fail to start."
}

[ -z "$HOST_IP" ] && HOST_IP="$(detect_ip)"
[ -z "$VT_PASSWORD" ] && VT_PASSWORD="$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
if [ -z "$SANDBOX_SUBNET" ]; then
  _b="$(pick_sandbox_base)"
  SANDBOX_SUBNET="$_b.0/24"; TRANSCODER_IP="$_b.2"; VPNTORRENT_SANDBOX_IP="$_b.3"
fi

ask() {  # ask VAR "Prompt" "default"
  local __var="$1" __prompt="$2" __def="$3" __ans=""
  printf '%s [%s]: ' "$__prompt" "$__def" > /dev/tty
  read -r __ans < /dev/tty || __ans=""
  printf -v "$__var" '%s' "${__ans:-$__def}"
}

if [ "$NONINTERACTIVE" -eq 0 ]; then
  say "vpntorrent setup — press Enter to accept the [default]."
  ask MEDIA_PATH  "Downloads + media folder (will be created)" "$MEDIA_PATH"
  ask VT_PASSWORD "Web login password"                         "$VT_PASSWORD"
  ask TMDB_API_KEY "TMDB API key for posters (optional)"       "$TMDB_API_KEY"
  ask TZ_VAL      "Timezone"                                   "$TZ_VAL"
  ask WEB_PORT    "Web UI port"                                "$WEB_PORT"
  ask HOST_IP     "IP/hostname for the dashboard tile"         "$HOST_IP"
fi

# --- write .env ------------------------------------------------------------
cat > .env <<EOF
MEDIA_PATH=$MEDIA_PATH
VT_PASSWORD=$VT_PASSWORD
TMDB_API_KEY=$TMDB_API_KEY
TZ=$TZ_VAL
WEB_PORT=$WEB_PORT
HOST_IP=$HOST_IP
SANDBOX_SUBNET=$SANDBOX_SUBNET
TRANSCODER_IP=$TRANSCODER_IP
VPNTORRENT_SANDBOX_IP=$VPNTORRENT_SANDBOX_IP
EOF
say "Wrote .env  (sandbox net $SANDBOX_SUBNET)"

# --- create folders --------------------------------------------------------
mkdir -p config jackett-config
mkdir -p "$MEDIA_PATH"
for d in movies tv music documents software other; do
  mkdir -p "$MEDIA_PATH/$d"
done
chmod -R a+rwX "$MEDIA_PATH" 2>/dev/null || true   # so you can manage files over Samba
say "Media folders ready under $MEDIA_PATH"

if [ ! -f config/proton.conf ]; then
  warn "!! config/proton.conf is missing — downloads stay DISABLED until you add it."
  warn "   Put your ProtonVPN WireGuard config (paid + a P2P server) at:"
  warn "   $PWD/config/proton.conf   then re-run this script (or: $DC up -d)."
fi

# --- images: load offline bundle, or build ---------------------------------
if [ -f images.tar.gz ]; then
  say "Loading bundled images (offline mode)…"
  gunzip -c images.tar.gz | $SUDO docker load
else
  say "Building images (first run downloads base images — a few minutes)…"
  $DC build
fi

# --- launch ----------------------------------------------------------------
ensure_tun
say "Starting the stack…"
$DC up -d

echo
say "✅ vpntorrent is up."
echo "   Web UI:   http://$HOST_IP:$WEB_PORT   (also http://localhost:$WEB_PORT)"
echo "   Login:    the password you set (in .env: VT_PASSWORD)"
echo "   Downloads land in: $MEDIA_PATH/<category>"
[ -f config/proton.conf ] || warn "   Add config/proton.conf, then: $DC up -d   (to enable downloads)"
echo
echo "   Manage:   $DC ps   |   $DC logs -f vpntorrent   |   $DC restart   |   ./uninstall.sh"
