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
# No controlling terminal (e.g. `ssh host ./install.sh`, cron, CI)? ask() reads and
# writes /dev/tty, which under `set -e` would abort the whole install — fall back to
# non-interactive (use existing .env / defaults) automatically.
if [ "$NONINTERACTIVE" -eq 0 ] && ! { : < /dev/tty; } 2>/dev/null; then
  NONINTERACTIVE=1
fi

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
# Read an existing .env LITERALLY (do not `source` it: a VT_PASSWORD/MEDIA_PATH with
# a space, $, ;, #, or quote would be mis-parsed or executed as shell).
if [ -f .env ]; then
  while IFS='=' read -r __k __v; do
    case "$__k" in ''|\#*) continue ;; esac
    printf -v "$__k" '%s' "$__v" 2>/dev/null || true
  done < .env
fi
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
  say "Undertow setup — press Enter to accept the [default]."
  ask MEDIA_PATH  "Downloads + media folder (will be created)" "$MEDIA_PATH"
  ask VT_PASSWORD "Web login password"                         "$VT_PASSWORD"
  ask TMDB_API_KEY "TMDB API key for posters (optional)"       "$TMDB_API_KEY"
  ask TZ_VAL      "Timezone"                                   "$TZ_VAL"
  ask WEB_PORT    "Web UI port"                                "$WEB_PORT"
  ask HOST_IP     "IP/hostname for the dashboard tile"         "$HOST_IP"
fi

# --- optional GPU transcoding ----------------------------------------------
# Only layer in the NVIDIA overlay when the host can actually satisfy it. Declaring a
# GPU reservation on a machine without the NVIDIA container runtime makes `compose up`
# fail outright, so the base stack stays CPU-only and this is purely additive.
COMPOSE_FILE_VAL=""
if $SUDO docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia \
   && command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
  COMPOSE_FILE_VAL="docker-compose.yml:docker-compose.gpu.yml"
  say "NVIDIA runtime detected — enabling hardware transcoding."
else
  say "No NVIDIA container runtime — using CPU transcoding (works everywhere)."
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
UNDERTOW_DIR=$PWD
COMPOSE_FILE=$COMPOSE_FILE_VAL
EOF
chmod 600 .env   # contains the web login password + TMDB key — keep it owner-only
say "Wrote .env  (sandbox net $SANDBOX_SUBNET)"

# --- create folders --------------------------------------------------------
mkdir -p config jackett-config
# Guard the media path before creating or chmod-ing anything under it. This value is
# typed by the operator, and the next lines mkdir -p it and chmod -R it world-writable:
# a stray "/" or "/home" would make a whole filesystem world-writable.
case "$MEDIA_PATH" in
  /|/usr|/etc|/var|/bin|/sbin|/lib|/lib64|/boot|/dev|/proc|/sys|/root|/home|/media|/mnt|/opt|/srv)
    err "MEDIA_PATH='$MEDIA_PATH' is a system directory — refusing to use it."
    err "Pick a dedicated folder, e.g. ${MEDIA_PATH%/}/undertow"
    exit 1 ;;
  /*) : ;;                       # any other absolute path is fine
  *)  err "MEDIA_PATH must be an absolute path (got '$MEDIA_PATH')."; exit 1 ;;
esac
mkdir -p "$MEDIA_PATH"
for d in movies tv music documents software other; do
  mkdir -p "$MEDIA_PATH/$d"
done
# Only relax permissions on the category folders we just made — never recurse over the
# whole tree, which may already hold unrelated files the operator pointed us at.
for d in movies tv music documents software other; do
  chmod a+rwX "$MEDIA_PATH/$d" 2>/dev/null || true   # so you can manage files over Samba
done
chmod a+rwX "$MEDIA_PATH" 2>/dev/null || true
say "Media folders ready under $MEDIA_PATH"

# --- per-install secrets ---------------------------------------------------
# SearXNG's secret_key must be unique per instance. A bundle ships it blanked, so
# generate one here rather than letting every install share the packager's key.
if [ -f searxng-config/settings.yml ]; then
  if grep -q 'CHANGE_ME_ON_INSTALL' searxng-config/settings.yml 2>/dev/null \
     || ! grep -q 'secret_key' searxng-config/settings.yml 2>/dev/null; then
    _sk="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    if grep -q 'secret_key' searxng-config/settings.yml 2>/dev/null; then
      sed -i "s|^\( *secret_key *: *\).*|\1\"$_sk\"|" searxng-config/settings.yml
    fi
    say "Generated a fresh SearXNG secret key for this install."
  fi
fi

# --- VPN config sanity -----------------------------------------------------
if [ ! -f config/proton.conf ]; then
  warn "!! config/proton.conf is missing — downloads stay DISABLED until you add it."
  warn "   Put your ProtonVPN WireGuard config (paid + a P2P server) at:"
  warn "   $PWD/config/proton.conf   then re-run this script (or: $DC up -d)."
  [ -f config/proton.conf.example ] && warn "   A template is at config/proton.conf.example"
else
  # The kill-switch pre-authorises each server's endpoint by IP BEFORE the tunnel exists,
  # so a hostname endpoint can never be allowed through (DNS isn't available yet) and that
  # server silently never connects. Catch it now instead of after a confusing failure.
  _ep="$(grep -i '^[[:space:]]*Endpoint' config/proton.conf 2>/dev/null | head -1 \
         | sed 's/.*=[[:space:]]*//' | tr -d '\r' | sed 's/:[0-9]*$//' | tr -d '[]')"
  case "$_ep" in
    "")            warn "config/proton.conf has no Endpoint line — that server cannot be used." ;;
    *[!0-9.]*)     warn "config/proton.conf Endpoint is '$_ep' (a hostname)."
                   warn "  Use the server's IP address instead — the kill-switch must allow the"
                   warn "  endpoint before DNS exists, so hostname endpoints never connect." ;;
    *)             say "VPN config looks sane (endpoint $_ep)." ;;
  esac
  grep -qi '^[[:space:]]*PrivateKey' config/proton.conf 2>/dev/null \
    || warn "config/proton.conf has no PrivateKey line — the tunnel will not come up."
fi

# --- images: load offline bundle, or build ---------------------------------
if [ -f images.tar.gz ]; then
  say "Loading bundled images (offline mode)…"
  gunzip -c images.tar.gz | $SUDO docker load
else
  say "Building images (first run downloads base images — a few minutes)…"
  $DC build
fi

# --- boot resilience --------------------------------------------------------
# Docker's `restart: unless-stopped` alone is not enough here. Five containers share
# vpntorrent's network namespace, and at boot they can be started by the daemon BEFORE
# vpntorrent owns a namespace — they then sit orphaned against a dead sandbox that a
# plain restart cannot fix. A boot-time `compose up -d` (delayed, retried) re-creates
# them correctly. The watchdog also repairs this, but this makes a clean boot the norm.
install_boot_unit() {
  command -v systemctl >/dev/null 2>&1 || return 0
  [ -d /etc/systemd/system ] || return 0
  _dc_bin="$(command -v docker || echo /usr/bin/docker)"
  _unit=/etc/systemd/system/undertow.service
  $SUDO tee "$_unit" >/dev/null <<UNIT
[Unit]
Description=Undertow — VPN-locked file-discovery stack
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PWD
# let the daemon's own restart burst settle so the namespace-sharing sidecars
# don't race vpntorrent's network namespace at boot
ExecStartPre=/bin/sleep 15
# self-retrying: one transient compose/daemon race at boot must not strand the stack
ExecStart=/bin/sh -c 'for i in 1 2 3 4 5; do $_dc_bin compose up -d && exit 0; echo "undertow: compose up attempt \$i failed, retrying in 20s"; sleep 20; done; exit 1'
ExecStop=$_dc_bin compose stop
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
UNIT
  $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
  if $SUDO systemctl enable undertow.service >/dev/null 2>&1; then
    say "Installed boot service (undertow.service) — the stack comes back after a reboot."
  else
    warn "Could not enable undertow.service; the stack still restarts via Docker's policy."
  fi
}

# --- launch ----------------------------------------------------------------
ensure_tun
say "Starting the stack…"
$DC up -d
install_boot_unit || true

# --- PROVE it is actually protected ----------------------------------------
# Never tell someone "you're anonymous" without checking. If the tunnel didn't come up,
# say so loudly here rather than letting them discover it by leaking.
if [ -f config/proton.conf ] && [ -x ./verify-anonymity.sh ]; then
  echo
  say "Verifying the VPN and kill-switch (waiting for the tunnel to settle)…"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 5
    [ "$($SUDO docker inspect -f '{{.State.Running}}' vpntorrent 2>/dev/null)" = "true" ] && break
  done
  sleep 10
  if ./verify-anonymity.sh; then
    VERIFIED=1
  else
    VERIFIED=0
    warn "Self-test reported problems — see above. Downloads are NOT safe until it passes."
  fi
else
  VERIFIED=0
fi

echo
say "✅ Undertow is up."
echo "   Web UI:   http://$HOST_IP:$WEB_PORT   (also http://localhost:$WEB_PORT)"
echo "   Login:    the password you set (in .env: VT_PASSWORD)"
echo "   Downloads land in: $MEDIA_PATH/<category>"
[ -f config/proton.conf ] || warn "   Add config/proton.conf, then: $DC up -d   (to enable downloads)"
[ "${VERIFIED:-0}" = "1" ] && say "   Anonymity self-test: PASSED (traffic is locked to the VPN)."
echo
echo "   Check anytime:  ./verify-anonymity.sh            (proves you're not leaking)"
echo "   Prove failsafe: ./verify-anonymity.sh --drop-test (kills the tunnel, checks it blocks)"
echo "   Manage:   $DC ps   |   $DC logs -f vpntorrent   |   $DC restart   |   ./uninstall.sh"
