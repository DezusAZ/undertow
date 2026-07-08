#!/bin/sh
# Bring up the VPN and lock the box to it, then run the downloader.
# HARD RULE: if the VPN does not come up, the app runs in DISABLED mode —
# it will not (and cannot) download anything. It never falls back to unprotected.
set -e

CONF=/config/proton.conf
VPN_IP=""

# If the host kernel lacks the WireGuard module (some ZimaOS builds don't ship it),
# wg-quick falls back to this userspace implementation automatically. Harmless when
# the kernel module IS present (the kernel path is tried first).
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go

if [ -f "$CONF" ]; then
    echo "[vpntorrent] starting VPN from $CONF ..."

    # wg-quick handles DNS= via `resolvconf` (absent in a slim container and messy
    # on a bind-mounted /etc/resolv.conf). Strip DNS= for wg-quick, apply Proton's
    # DNS ourselves below -> name lookups go through the tunnel too (no DNS leak).
    DNS_SRV=$(awk -F= 'tolower($1) ~ /dns/ {gsub(/[ \t]/,"",$2); print $2; exit}' "$CONF" | cut -d, -f1)
    WORK=/tmp/wg.conf
    grep -vi '^[[:space:]]*dns' "$CONF" > "$WORK"

    # --- KILL-SWITCH (fail-closed) --- set up BEFORE wg-quick so there is never a leak window,
    # and it REMAINS if wg-quick fails, so the app can NEVER reach the internet off-tunnel.
    # Default-DROP egress except: loopback, the WireGuard endpoint (so the tunnel can connect),
    # the wg tunnel itself, and private LAN (web UI). IPv6 egress is fully blocked (WG is v4 here,
    # so any v6 route would be a real-IP leak). Allows are best-effort; the DROP is hard.
    EP=$(grep -i '^[[:space:]]*Endpoint' "$CONF" | head -1 | sed 's/.*=[[:space:]]*//')
    EP_IP=${EP%:*}
    iptables -F OUTPUT 2>/dev/null || true
    iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -o wg -j ACCEPT 2>/dev/null || true
    if [ -n "$EP_IP" ]; then iptables -A OUTPUT -d "$EP_IP" -p udp -j ACCEPT 2>/dev/null || true; fi
    for net in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 100.64.0.0/10; do
        iptables -A OUTPUT -d "$net" -j ACCEPT 2>/dev/null || true
    done
    iptables -P OUTPUT DROP
    ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT DROP 2>/dev/null || true
    echo "[vpntorrent] kill-switch armed (egress locked to tunnel + VPN endpoint + LAN; v6 blocked)"

    if wg-quick up "$WORK"; then
        VPN_IP=$(ip -4 addr show wg | awk '/inet /{print $2}' | cut -d/ -f1)
        if [ -n "$DNS_SRV" ]; then
            printf 'nameserver %s\n' "$DNS_SRV" > /etc/resolv.conf
            echo "[vpntorrent] DNS forced through tunnel ($DNS_SRV)"
        fi
        # Keep the web UI reachable: allow replies to inbound (LAN) connections.
        # New outbound torrent traffic still must traverse the tunnel (killswitch).
        iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

        # wg-quick points the default route at the tunnel, so replies to web-UI
        # clients on the LAN / Tailscale would wrongly go INTO the tunnel and never
        # return (only localhost worked). Send replies to those private ranges back
        # via the normal bridge route instead. Torrent peers are public IPs and are
        # unaffected — they still go through the tunnel, so the killswitch holds.
        for net in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 100.64.0.0/10; do
            case "$net" in
                10.0.0.0/8) [ "${VPN_IP%%.*}" = "10" ] && continue ;;  # skip if VPN uses 10.x
            esac
            ip rule add to "$net" lookup main priority 1000 2>/dev/null || true
        done
        echo "[vpntorrent] VPN up on wg ($VPN_IP) — traffic is protected; LAN/Tailscale reachable."
    else
        echo "[vpntorrent] !! VPN FAILED to come up — downloads DISABLED (no unprotected fallback)."
        VPN_IP=""
    fi
else
    echo "[vpntorrent] !! No VPN config at $CONF — downloads DISABLED until you add it."
fi

export VPN_IP
exec python3 /app/vt.py
