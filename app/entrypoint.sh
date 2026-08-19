#!/bin/sh
# Bring up the VPN and lock the box to it, then run the downloader — and KEEP the
# tunnel up for the life of the container, FAILING OVER across a pool of servers.
#
# HARD RULE: if the VPN is not up, the app runs in DISABLED mode — it will not (and
# cannot) download anything, and never falls back to unprotected. The kill-switch is
# armed BEFORE the tunnel and stays armed through every retry/rotation, so there is no
# leak window even while re-establishing or switching servers.
#
# FAILOVER: drop one or more WireGuard configs in /config — the primary proton.conf plus
# any proton-<name>.conf and/or vpn/*.conf. Every server's endpoint IP is pre-authorised
# in the kill-switch up front, so rotating between them can never leak. wg-quick "up"
# succeeds even against a DEAD server (it only configures the interface), so a server is
# only accepted once it actually HANDSHAKES; otherwise we rotate to the next one.
# (Endpoints MUST be IPs — the kill-switch can't pre-authorise a hostname before DNS.)
set -e

# ============================================================================
# SLAM THE DOOR FIRST. Nothing above this line may touch the network.
#
# Five sibling containers SHARE this network namespace. Docker makes the namespace
# joinable as soon as this container is "running" — which is before this script has
# done anything. Every millisecond between that moment and the DROP policy is a window
# in which a sibling (bitmagnet's DHT crawler starts 0.34s after its own container
# start) can egress via the bridge and be SNATed to the operator's REAL public IP.
#
# So the very first thing we do is close everything. Note the ORDER: the policy is set
# to DROP *before* the flush — flushing while the policy is still ACCEPT would reopen
# the hole for the duration of the flush. Allow-rules are layered on afterwards, which
# is safe because the default is already deny.
#
# This cannot fully close the window (the container exists for a moment before any of
# our code runs, and on a slow disk the shell/iptables binaries must page in first), so
# it is backed by a healthcheck gate in docker-compose.yml that keeps the siblings from
# starting until this policy is actually live. Both layers are needed.
iptables -P OUTPUT DROP
ip6tables -P OUTPUT DROP 2>/dev/null || true
iptables -F OUTPUT 2>/dev/null || true
ip6tables -F OUTPUT 2>/dev/null || true

CONF_PRIMARY=/config/proton.conf
WORK=/tmp/wg.conf
VPN_IP=""
DNS_SRV=""
ACTIVE_CFG=""
ACTIVE_IDX=0
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go

# ---- build the server POOL: primary first, then proton-*.conf, then vpn/*.conf --------
CONFIGS=""
[ -f "$CONF_PRIMARY" ] && CONFIGS="$CONF_PRIMARY"
for f in /config/proton-*.conf /config/vpn/*.conf; do
    [ -f "$f" ] || continue
    case " $CONFIGS " in *" $f "*) ;; *) CONFIGS="$CONFIGS $f" ;; esac
done
N_CONF=0
for c in $CONFIGS; do N_CONF=$((N_CONF + 1)); done

endpoint_ip_of() {   # bare IP of a config's Endpoint (strips :port, [] brackets, and CR)
    grep -i '^[[:space:]]*Endpoint' "$1" 2>/dev/null | head -1 \
        | sed 's/.*=[[:space:]]*//' | tr -d '\r' | sed 's/:[0-9]*$//' | tr -d '[]'
}
dns_of() {           # \r in the class so a Windows-edited (CRLF) config still parses
    awk -F= 'tolower($1) ~ /dns/ {gsub(/[ \t\r]/,"",$2); print $2; exit}' "$1" | cut -d, -f1
}

# vpn_up CONFIG -> prints the tunnel IP on success (and points resolv.conf + LAN routing at
# it), nothing on failure. Idempotent: tears down any stale wg first. Never exits.
vpn_up() {
    _cfg="$1"
    DNS_SRV=$(dns_of "$_cfg")
    tr -d '\r' < "$_cfg" | grep -vi '^[[:space:]]*dns' > "$WORK"   # strip CR (Windows-edited configs)
    wg-quick down "$WORK" >/dev/null 2>&1 || true
    ip link del wg >/dev/null 2>&1 || true
    wg-quick up "$WORK" >/dev/null 2>&1 || return 1
    _ip=$(ip -4 addr show wg 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
    [ -n "$_ip" ] || return 1
    # Force keepalive so a handshake is actually INITIATED during the wait: WireGuard only
    # handshakes when traffic is queued or a keepalive fires, and NOTHING else egresses at boot
    # (the app starts later) — without this a valid config lacking PersistentKeepalive looks dead.
    for _pk in $(wg show wg peers 2>/dev/null); do
        wg set wg peer "$_pk" persistent-keepalive 25 2>/dev/null || true
    done
    # cap the resolver so a blackholed tunnel DNS can't make getaddrinfo() block tens of seconds
    # attempts:2 — one retry. UDP DNS over a tunnel does drop the occasional packet, and
    # attempts:1 turned a single lost packet into an instant "name resolution failure"
    # (observed in the wild). Worst case is still bounded at ~4s, so a blackholed tunnel
    # DNS can't make getaddrinfo() hang for tens of seconds, which is why the cap exists.
    printf 'nameserver %s\noptions timeout:2 attempts:2\n' "${DNS_SRV:-10.2.0.1}" > /etc/resolv.conf
    # Web-UI replies to LAN/Tailscale go back via the bridge, not into the tunnel.
    # IDEMPOTENT: vpn_up() runs on every reconnect/rotation, so an unconditional -I here
    # appends a duplicate rule forever (observed: 2619 identical ESTABLISHED rules after two
    # weeks of reconnects). Only add what isn't already there.
    iptables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
        || iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    for net in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 100.64.0.0/10; do
        case "$net" in 10.0.0.0/8) [ "${_ip%%.*}" = "10" ] && continue ;; esac
        # same reasoning: `ip rule add` never dedupes, so check before adding
        ip rule show 2>/dev/null | grep -q "to $net lookup main" \
            || ip rule add to "$net" lookup main priority 1000 2>/dev/null || true
    done
    printf '%s' "$_ip"
    return 0
}

# tunnel_healthy -> 0 if wg is up, ROUTING internet traffic, and handshaking recently.
tunnel_healthy() {
    ip link show wg >/dev/null 2>&1 || return 1
    # The interface existing is not enough. If the link flaps (or anything else drops the
    # route), the kernel deletes wg's routes and bringing the link back up does NOT restore
    # them — leaving a tunnel that looks perfectly healthy (interface present, recent
    # handshake) while nothing can actually egress. Observed exactly that in testing.
    # `route get` is a pure kernel lookup: no packets, no latency, but it proves that
    # traffic bound for the internet is genuinely directed into the tunnel.
    case "$(ip -4 route get 1.1.1.1 2>/dev/null)" in
        *"dev wg"*) ;;
        *) return 1 ;;
    esac
    hs=$(wg show wg latest-handshakes 2>/dev/null | awk '{print $2}' | sort -nr | head -1)
    [ -n "$hs" ] && [ "$hs" -gt 0 ] || return 1
    now=$(date +%s)
    [ "$((now - hs))" -lt 180 ] && return 0
    return 1
}

# connect_at INDEX -> bring up the Nth config and WAIT (up to ~14s) for a real handshake.
# Sets VPN_IP/ACTIVE_CFG/ACTIVE_IDX on success (returns 0); returns 1 if it never handshakes.
connect_at() {
    _idx="$1"; _i=0
    for _c in $CONFIGS; do
        _i=$((_i + 1))
        [ "$_i" = "$_idx" ] || continue
        _got=$(vpn_up "$_c") || _got=""
        [ -n "$_got" ] || { echo "[vpntorrent] server $_i: bring-up failed."; return 1; }
        _t=0
        while [ "$_t" -lt 14 ]; do
            if tunnel_healthy; then
                VPN_IP="$_got"; ACTIVE_CFG="$_c"; ACTIVE_IDX="$_i"
                DNS_SRV=$(dns_of "$_c")
                # publish pool status so the app can SHOW "VPN: server X of N" (reassurance)
                printf '{"active":%s,"total":%s,"exit_ip":"%s"}' \
                    "$_i" "$N_CONF" "$_got" > /config/.vpn_pool 2>/dev/null || true
                return 0
            fi
            sleep 2; _t=$((_t + 2))
        done
        echo "[vpntorrent] server $_i: interface up but no handshake (server down?)."
        return 1
    done
    return 1
}

# rotate_connect START -> try every server once, starting at START and wrapping, until one
# handshakes. Returns 0 (VPN_IP set) or 1 if the whole pool is currently unreachable.
rotate_connect() {
    _start="$1"; _tried=0
    _idx="$_start"
    while [ "$_tried" -lt "$N_CONF" ]; do
        [ "$_idx" -gt "$N_CONF" ] && _idx=1
        if connect_at "$_idx"; then
            return 0
        fi
        _idx=$((_idx + 1)); _tried=$((_tried + 1))
    done
    return 1
}

# --- FAIL-CLOSED BASELINE (UNCONDITIONAL) --- armed BEFORE anything, and even when the pool is
# EMPTY, so no code path (e.g. a notify test) can ever egress the real IP. Default-DROP OUTPUT +
# v6 DROP; only loopback, ESTABLISHED/RELATED, and the private LAN are allowed at this stage. The
# wg tunnel + per-server endpoint accepts are layered on top below once we know the pool.
printf 'nameserver 10.2.0.1\noptions timeout:2 attempts:2\n' > /etc/resolv.conf   # DNS fails closed if no tunnel
# The policy is ALREADY DROP and the chain already flushed (top of this file). Only layer
# the allow-rules on here — do NOT flush again, and do not re-set the policy: both would
# briefly widen a firewall that is currently holding traffic closed.
iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
for net in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 100.64.0.0/10; do
    iptables -A OUTPUT -d "$net" -j ACCEPT 2>/dev/null || true
done
iptables -P OUTPUT DROP          # idempotent re-assert (cheap, and proves intent)
ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
ip6tables -P OUTPUT DROP 2>/dev/null || true

if [ -n "$CONFIGS" ]; then
    echo "[vpntorrent] starting VPN — $N_CONF server(s) in the failover pool."
    # Layer the tunnel + EVERY candidate server endpoint onto the baseline (so rotation between
    # servers never opens a leak window). Everything else stays DROP.
    iptables -A OUTPUT -o wg -j ACCEPT 2>/dev/null || true
    EPS=""
    for c in $CONFIGS; do
        eip=$(endpoint_ip_of "$c")
        case "$eip" in
            "") echo "[vpntorrent] WARN: $c has no Endpoint — skipped." ;;
            *[!0-9.]*) echo "[vpntorrent] WARN: $c endpoint '$eip' is not an IP; failover needs IP endpoints — no allow rule (that server can't be used)." ;;
            *) iptables -A OUTPUT -d "$eip" -p udp -j ACCEPT 2>/dev/null || true; EPS="$EPS $eip" ;;
        esac
    done
    echo "[vpntorrent] kill-switch armed (egress locked to tunnel + endpoints [$EPS ] + LAN; v6 blocked)"

    # Bring the tunnel up WITH RETRY + FAILOVER. The kill-switch holds throughout, so retries
    # and rotations never leak.
    set +e
    n=0
    while [ "$n" -lt 6 ]; do
        rotate_connect 1 && [ -n "$VPN_IP" ] && break
        n=$((n + 1))
        echo "[vpntorrent] whole pool unreachable (round $n) — retrying in 6s (kill-switch holds)..."
        sleep 6
    done
    if [ -n "$VPN_IP" ]; then
        echo "[vpntorrent] VPN up on wg ($VPN_IP) via server $ACTIVE_IDX/$N_CONF — protected; DNS via ${DNS_SRV:-10.2.0.1}; LAN reachable."
    else
        echo "[vpntorrent] !! VPN still DOWN after retries — starting DISABLED; supervisor keeps trying + rotating."
    fi
else
    echo "[vpntorrent] !! No VPN config at $CONF_PRIMARY — downloads DISABLED (egress still DROP — no leak)."
fi

set +e
export VPN_IP

# Run the app as a CHILD (not exec) so the supervisor below can keep the tunnel alive and
# restart the app when the VPN transitions down->up or the exit IP changes (the app locks
# its PROTECTED flag + exit IP at startup, so a change requires an app restart to take effect).
start_app() { python3 /app/vt.py & APP=$!; }
on_term() { echo "[vpntorrent] SIGTERM — shutting down"; kill -TERM "$APP" 2>/dev/null; wait "$APP" 2>/dev/null; exit 0; }
trap on_term TERM INT
VPN_IP_BOUND="$VPN_IP"          # the exit IP the app is currently bound to (drives restart-on-change)
start_app
echo "[vpntorrent] app started (pid $APP); tunnel supervisor active."

while true; do
    sleep 20 & wait $!          # interruptible: SIGTERM runs on_term at once (app gets its save window)
    # App gone? exit non-zero so Docker's restart policy recreates the container.
    if ! kill -0 "$APP" 2>/dev/null; then
        echo "[vpntorrent] app process exited — letting Docker restart the container."
        exit 1
    fi
    [ -n "$CONFIGS" ] || continue

    tunnel_healthy && continue

    echo "[vpntorrent] tunnel down/stale — re-establishing (kill-switch holds)..."
    NEW=""
    # 1) try to reconnect the CURRENT server first (a transient drop shouldn't move us).
    if [ "$ACTIVE_IDX" -gt 0 ] && connect_at "$ACTIVE_IDX"; then
        NEW="$VPN_IP"
    # 2) still down -> ROTATE across the pool to the next healthy server.
    elif rotate_connect "$((ACTIVE_IDX + 1))"; then
        echo "[vpntorrent] failed over to server $ACTIVE_IDX/$N_CONF."
        NEW="$VPN_IP"
    fi

    if [ -n "$NEW" ]; then
        if [ "$NEW" != "$VPN_IP_BOUND" ]; then
            echo "[vpntorrent] VPN (re)connected as $NEW (app was bound to '${VPN_IP_BOUND:-none}') — restarting app to bind it."
            VPN_IP_BOUND="$NEW"; VPN_IP="$NEW"; export VPN_IP
            kill -TERM "$APP" 2>/dev/null; wait "$APP" 2>/dev/null
            start_app
        else
            echo "[vpntorrent] tunnel re-established as $NEW (app auto-detects on next check)."
        fi
    else
        echo "[vpntorrent] whole pool unreachable; will retry in 20s (no leak — egress still DROP)."
    fi
done
