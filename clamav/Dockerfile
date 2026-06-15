FROM clamav/clamav:1.4

# On-demand scanner: we use one-shot `clamscan`, NOT the resident clamd daemon,
# to keep RAM low. freshclam runs in the background to keep signatures current.
# Limits (max-filesize / max-scansize) are passed as clamscan flags in watcher.py
# so large media isn't silently skipped.

RUN apk add --no-cache python3

COPY start.sh   /usr/local/bin/start.sh
COPY watcher.py /usr/local/bin/watcher.py
RUN chmod +x /usr/local/bin/start.sh

ENTRYPOINT ["/usr/local/bin/start.sh"]
