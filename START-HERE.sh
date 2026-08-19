#!/bin/bash
# Start Undertow with the CORRECT VPN wiring (WireGuard kill-switch + the five sidecars
# sharing the VPN network namespace).
#
# ALWAYS start it this way — NOT via casaos-cli and NOT from a CasaOS-managed copy under
# /var/lib/casaos/apps/, which can be reconstructed with BROKEN networking that would
# bypass the tunnel.
cd "$(dirname "$0")" || exit 1

docker compose up -d

# Read the web port from .env if the installer set one.
PORT="$(grep -E '^WEB_PORT=' .env 2>/dev/null | cut -d= -f2)"
PORT="${PORT:-8722}"
HOST="$(grep -E '^HOST_IP=' .env 2>/dev/null | cut -d= -f2)"
HOST="${HOST:-localhost}"

echo
echo "Started. Web UI: http://$HOST:$PORT   (VPN auto-connects; kill-switch armed)"
echo
echo "Verify you are protected:  ./verify-anonymity.sh"
echo "Prove it fails closed:     ./verify-anonymity.sh --drop-test"
