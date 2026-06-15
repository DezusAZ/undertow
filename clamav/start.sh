#!/bin/sh
# On-demand ClamAV scanner entrypoint.
# NOTE: deliberately no `set -e` so a freshclam hiccup (e.g. no internet)
# does not kill the container.
set -u

# Background daily signature updater. Tolerate failure (offline / mirror issues).
freshclam -d --checks=1 &

# Run the polling watcher in the foreground (PID 1 replacement).
exec python3 -u /usr/local/bin/watcher.py
