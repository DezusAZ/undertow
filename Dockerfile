# Tiny single-container torrent downloader with the VPN fused in.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-libtorrent \
        wireguard-tools \
        wireguard-go \
        iproute2 \
        iptables \
        procps \
        ca-certificates \
        ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Docker already applies net.ipv4.conf.all.src_valid_mark=1 (compose `sysctls:`),
# but the kernel blocks wg-quick's redundant in-container re-write. Swallow only
# that call; pass every other sysctl through to the real binary.
RUN printf '#!/bin/sh\ncase "$*" in *src_valid_mark*) exit 0 ;; esac\nexec /sbin/sysctl "$@"\n' > /usr/local/bin/sysctl \
    && chmod +x /usr/local/bin/sysctl

COPY app/ /app/
RUN chmod +x /app/entrypoint.sh

EXPOSE 8722
ENTRYPOINT ["/app/entrypoint.sh"]
