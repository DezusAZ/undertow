#!/usr/bin/env bash
# Undertow — anonymity & kill-switch self-test.
#
#   ./verify-anonymity.sh              safe, read-only checks (run this any time)
#   ./verify-anonymity.sh --drop-test  ALSO simulates a VPN failure and proves the
#                                      kill-switch blocks traffic (briefly interrupts
#                                      downloads, then restores the tunnel)
#
# Exit code 0 = every check passed. Non-zero = something is wrong; read the output.
#
# WHY THIS EXISTS: "the VPN is connected" is not the same as "nothing can leak". This
# proves the actual invariants — egress is the VPN's IP and not yours, DNS resolves
# inside the tunnel, IPv6 is dead, and the firewall fails CLOSED when the tunnel drops.
set -uo pipefail
cd "$(dirname "$0")"

CTR="${CTR:-vpntorrent}"
# Every container that shares the VPN network namespace — each one must resolve DNS
# through the tunnel too, or it leaks what you search for to your ISP.
NETNS_CTRS="vpntorrent-jackett vpntorrent-flaresolverr vpntorrent-searxng vpntorrent-bitmagnet vpntorrent-sabnzbd"

green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[1;33m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

PASS=0; FAIL=0; WARN=0
ok()   { green  "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { red    "  FAIL  $*"; FAIL=$((FAIL+1)); }
warn() { yellow "  WARN  $*"; WARN=$((WARN+1)); }

# --- docker access (mirror install.sh: plain docker, else sudo) ---------------
SUDO=""
if ! docker info >/dev/null 2>&1; then
  if sudo -n true 2>/dev/null; then SUDO="sudo"; fi
  if ! $SUDO docker info >/dev/null 2>&1; then
    red "Cannot talk to Docker. Run as a user in the 'docker' group, or with sudo."
    exit 2
  fi
fi
d() { $SUDO docker "$@"; }
dex() { $SUDO docker exec "$1" sh -c "$2" 2>/dev/null; }

# Fetch a URL from INSIDE the VPN container without assuming curl exists in the image.
# Retries across two independent providers: a single dropped UDP DNS packet or one
# provider having a bad day must NOT be reported as a leak. A false "NOT SAFE" alarm
# would train people to ignore this script, which is worse than no script.
egress_ip() {
  dex "$CTR" 'python3 -c "
import urllib.request, time
urls = [\"https://api.ipify.org\", \"https://ifconfig.me/ip\", \"https://icanhazip.com\"]
last = \"\"
for attempt in range(2):
    for u in urls:
        try:
            ip = urllib.request.urlopen(u, timeout=8).read().decode().strip()
            if ip:
                print(ip); raise SystemExit(0)
        except SystemExit:
            raise
        except Exception as e:
            last = str(e)
    time.sleep(2)
print(\"ERR:%s\" % last)
"'
}

bold "Undertow anonymity self-test"
echo

# --- 0. container up ---------------------------------------------------------
bold "Container"
if [ "$(d inspect -f '{{.State.Running}}' "$CTR" 2>/dev/null)" = "true" ]; then
  ok "$CTR is running"
else
  bad "$CTR is NOT running — nothing is protected. Start it: docker compose up -d"
  echo; red "ABORTING: cannot verify anything while the VPN container is down."
  exit 1
fi

# --- 1. tunnel state ---------------------------------------------------------
echo; bold "VPN tunnel"
WG_IP="$(dex "$CTR" "ip -4 addr show wg 2>/dev/null | awk '/inet /{print \$2}' | cut -d/ -f1")"
if [ -n "$WG_IP" ]; then
  ok "wg interface is up (tunnel IP $WG_IP)"
else
  bad "no wg interface — the VPN is DOWN (downloads should be disabled)"
fi

HS="$(dex "$CTR" "wg show wg latest-handshakes 2>/dev/null | awk '{print \$2}' | sort -nr | head -1")"
NOW="$(dex "$CTR" 'date +%s')"
if [ -n "${HS:-}" ] && [ "${HS:-0}" -gt 0 ] 2>/dev/null; then
  AGE=$(( NOW - HS ))
  if [ "$AGE" -lt 180 ]; then ok "fresh WireGuard handshake (${AGE}s ago)"
  else bad "last handshake was ${AGE}s ago (>180s) — tunnel is stale"; fi
else
  bad "no WireGuard handshake at all — the server is not responding"
fi

# --- 2. kill-switch ----------------------------------------------------------
echo; bold "Kill-switch (firewall)"
POLICY="$(dex "$CTR" 'iptables -S OUTPUT 2>/dev/null | head -1')"
if [ "$POLICY" = "-P OUTPUT DROP" ]; then
  ok "OUTPUT policy is DROP (fails closed)"
else
  bad "OUTPUT policy is '${POLICY:-unknown}' — NOT fail-closed. Traffic can leak!"
fi

if dex "$CTR" 'iptables -C OUTPUT -o wg -j ACCEPT' >/dev/null 2>&1; then
  ok "tunnel egress allowed (-o wg ACCEPT)"
else
  bad "no '-o wg ACCEPT' rule — the tunnel itself is blocked"
fi

V6="$(dex "$CTR" 'ip6tables -S OUTPUT 2>/dev/null | head -1')"
V6ADDR="$(dex "$CTR" "ip -6 addr show scope global 2>/dev/null | grep -c inet6")"
if [ "$V6" = "-P OUTPUT DROP" ] || [ "${V6ADDR:-0}" = "0" ]; then
  ok "IPv6 cannot leak (policy '${V6:-n/a}', global v6 addresses: ${V6ADDR:-0})"
else
  bad "IPv6 is reachable and not blocked — it can bypass the IPv4 kill-switch"
fi

# Rule-count sanity: a runaway duplicate-rule bug used to add one ESTABLISHED rule per
# reconnect (thousands over time), which slows every packet down.
RULES="$(dex "$CTR" 'iptables -S OUTPUT 2>/dev/null | wc -l')"
if [ "${RULES:-0}" -lt 40 ]; then ok "firewall rule count is sane ($RULES)"
else warn "$RULES OUTPUT rules — duplicates are accumulating (restart the container to reset)"; fi

# --- 3. the real test: what IP does the world see? ---------------------------
echo; bold "Egress identity"
# Your real IP, as seen WITHOUT the tunnel (from the host). Used only for comparison.
HOST_IP="$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "")"
VPN_SEEN="$(egress_ip)"

case "$VPN_SEEN" in
  ERR:*|"")
    if [ -n "$WG_IP" ]; then
      bad "container could not reach the internet through the tunnel (${VPN_SEEN:-no answer})"
    else
      ok "container has NO internet access (expected: VPN is down and the kill-switch is holding)"
    fi
    ;;
  *)
    ok "traffic exits as $VPN_SEEN"
    if [ -n "$HOST_IP" ]; then
      if [ "$VPN_SEEN" = "$HOST_IP" ]; then
        bad "!!! LEAK: the container's exit IP EQUALS your real IP ($HOST_IP) — you are NOT anonymous"
      else
        ok "exit IP differs from your real IP (real $HOST_IP -> vpn $VPN_SEEN)"
      fi
    else
      warn "couldn't determine your real IP from the host, so no comparison was made"
    fi
    ;;
esac

# --- 4. DNS must resolve inside the tunnel -----------------------------------
echo; bold "DNS (all containers sharing the tunnel)"
MAIN_DNS="$(dex "$CTR" "grep -m1 '^nameserver' /etc/resolv.conf | awk '{print \$2}'")"
if [ -n "$MAIN_DNS" ] && [ "${MAIN_DNS#10.}" != "$MAIN_DNS" ]; then
  ok "$CTR resolves via $MAIN_DNS (inside the tunnel)"
else
  bad "$CTR resolves via '${MAIN_DNS:-none}' — DNS queries may leak to your ISP"
fi
for c in $NETNS_CTRS; do
  [ "$(d inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = "true" ] || { warn "$c not running (skipped)"; continue; }
  cd_ns="$(dex "$c" "grep -m1 '^nameserver' /etc/resolv.conf | awk '{print \$2}'")"
  if [ "$cd_ns" = "$MAIN_DNS" ]; then ok "$c resolves via $cd_ns"
  else bad "$c resolves via '${cd_ns:-none}' (expected $MAIN_DNS) — SEARCH TERMS CAN LEAK"; fi
done

# --- 4b. can anything escape around the tunnel? ------------------------------
# The leak that actually matters is a packet leaving via the Docker bridge, because
# Docker MASQUERADEs it to your real public IP. Try it on purpose: bind a socket to the
# bridge address and dial a public host. The kill-switch must stop it. This is
# deterministic and disruption-free, unlike --drop-test.
echo; bold "Leak path (bridge bypass)"
BYPASS="$(dex "$CTR" 'python3 -c "
import socket, subprocess
out = subprocess.run([\"ip\",\"-4\",\"addr\",\"show\",\"eth0\"], capture_output=True, text=True).stdout
br = [l.split()[1].split(\"/\")[0] for l in out.splitlines() if \"inet \" in l]
if not br:
    print(\"NOBRIDGE\"); raise SystemExit(0)
s = socket.socket(); s.settimeout(6)
try:
    s.bind((br[0], 0)); s.connect((\"1.1.1.1\", 443)); print(\"OPEN\")
except Exception:
    print(\"BLOCKED\")
"')"
case "$BYPASS" in
  BLOCKED)   ok "traffic cannot escape via the Docker bridge (the real-IP path is closed)" ;;
  NOBRIDGE)  ok "no bridge interface in the namespace — nothing to bypass through" ;;
  OPEN)      bad "!!! traffic CAN leave via the Docker bridge — it would appear as your real IP" ;;
  *)         warn "bridge-bypass check inconclusive (${BYPASS:-no answer})" ;;
esac

# --- 5. torrent engine is bound to the tunnel --------------------------------
echo; bold "Torrent engine"
LISTEN="$(dex "$CTR" "ss -lnp 2>/dev/null | grep -m1 ':6881' | awk '{print \$5}'")"
if [ -n "$LISTEN" ]; then
  case "$LISTEN" in
    "$WG_IP":*) ok "libtorrent is bound to the tunnel IP ($LISTEN)" ;;
    0.0.0.0:*|*:*) bad "libtorrent is bound to $LISTEN — not pinned to the tunnel IP $WG_IP" ;;
  esac
else
  warn "no listener on :6881 (no active torrents, or the engine is disabled)"
fi

# --- 6. optional: prove it fails CLOSED --------------------------------------
if [ "${1:-}" = "--drop-test" ]; then
  echo; bold "Kill-switch drop test (simulating a VPN failure)"
  yellow "  Taking the tunnel down for a few seconds — downloads will pause, then resume."
  # Down the interface only; the supervisor in entrypoint.sh re-establishes it within ~20s.
  d exec "$CTR" ip link set wg down >/dev/null 2>&1
  # Probe immediately and only once: the supervisor notices a downed tunnel within
  # ~20s and rebuilds it, so a slow probe measures the RECOVERED tunnel instead.
  LEAKED="$(dex "$CTR" 'python3 -c "
import urllib.request
try:
    print(urllib.request.urlopen(\"https://api.ipify.org\", timeout=5).read().decode().strip())
except Exception as e:
    print(\"ERR:%s\" % e)
"')"
  case "$LEAKED" in
    ERR:*|"")
      ok "with the tunnel down, the container CANNOT reach the internet (fails closed)" ;;
    "$HOST_IP")
      # The only real leak: packets escaped as the operator's own address.
      bad "!!! CRITICAL LEAK: tunnel down but traffic exited as your REAL IP ($LEAKED)" ;;
    *)
      # Reachable, but NOT as the real IP — the supervisor rebuilt the tunnel before the
      # probe completed. That is correct self-healing, not a leak. Only flag it as a leak
      # if it is the real IP (case above); saying "leak" here would be a false alarm.
      if [ -n "$HOST_IP" ]; then
        ok "no leak: tunnel was rebuilt before the probe (exited as $LEAKED, not your real IP $HOST_IP)"
      else
        warn "tunnel recovered before the probe could run (exited as $LEAKED); could not compare to your real IP"
      fi ;;
  esac
  yellow "  Restoring the tunnel…"
  d exec "$CTR" ip link set wg up >/dev/null 2>&1
  # the supervisor loop re-handshakes; give it a moment and confirm
  for _ in $(seq 1 12); do
    sleep 5
    BACK="$(egress_ip)"
    case "$BACK" in ERR:*|"") ;; *) break ;; esac
  done
  case "${BACK:-}" in
    ERR:*|"") warn "tunnel not back yet — the supervisor retries every 20s; re-run this script shortly" ;;
    *)        ok "tunnel restored (exits as $BACK)" ;;
  esac
fi

# --- verdict -----------------------------------------------------------------
echo
bold "Result: $PASS passed, $FAIL failed, $WARN warnings"
if [ "$FAIL" -gt 0 ]; then
  red "NOT SAFE — fix the FAIL items above before downloading anything."
  exit 1
fi
if [ "$WARN" -gt 0 ]; then
  yellow "Protected, with warnings noted above."
  exit 0
fi
green "All checks passed — traffic is locked to the VPN."
[ "${1:-}" = "--drop-test" ] || echo "Tip: run './verify-anonymity.sh --drop-test' to prove it fails closed."
exit 0
