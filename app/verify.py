"""verify.py — LIVENESS verification for search / Deep-Hunt results.

The single biggest trust problem for a hard-to-find file is a result that looks fine but is
DEAD: a rotted open-directory link, a removed Internet Archive item, an empty torrent swarm.
Ranking already sinks 0-seed torrents; this goes further and actually PROBES whether a result
can be retrieved right now, so the app never hands back "download me" links that 404.

Design guarantees:
  * SSRF-safe. URL probes reuse discover.py's pinned-IP opener (redirects re-validated); magnet
    tracker scrapes resolve+validate every tracker host is PUBLIC before touching it. A result
    URL can never be used to reach the LAN or our own services.
  * Conservative about "dead". A result is only marked dead on a definitive signal (HTTP
    404/410/451). Timeouts, 5xx, soft-blocks, and empty tracker replies are 'unknown' — we
    never HIDE a real file on a single ambiguous probe.
  * Torrents are never marked dead here (their seeder ranking already handles that); a live
    tracker scrape only ENRICHES them with a current peer count when one is available.

stdlib only; runs inside the VPN netns; never raises out of the public helpers.
"""
import re
import time
import socket
import struct
import base64
import binascii
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import discover


def _infohash_bytes(magnet):
    """The 20-byte infohash from a magnet (hex-40 or base32-32), or None."""
    m = re.search(r"urn:btih:([0-9A-Za-z]+)", magnet or "")
    if not m:
        return None
    v = m.group(1)
    try:
        if len(v) == 40:
            return binascii.unhexlify(v)
        if len(v) == 32:
            return base64.b32decode(v.upper())
    except Exception:
        return None
    return None


# a bounded, non-crypto transaction id (avoids importing random for this)
_TID = 0x2b1e55a7


def _udp_scrape(host, port, ihash, timeout):
    """BEP-15 UDP tracker scrape -> current seeder count, or None. Public-host validated."""
    ip = discover._resolve_public(host)          # SSRF: only ever touch a public tracker
    if not ip:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        tid = _TID & 0xFFFFFFFF
        s.sendto(struct.pack(">QII", 0x41727101980, 0, tid), (ip, port))   # connect
        buf = s.recv(32)
        if len(buf) < 16:
            return None
        action, rtid, conn_id = struct.unpack(">IIQ", buf[:16])
        if action != 0 or rtid != tid:
            return None
        tid2 = (tid ^ 0x5f5f5f5f) & 0xFFFFFFFF
        s.sendto(struct.pack(">QII", conn_id, 2, tid2) + ihash, (ip, port))  # scrape
        buf2 = s.recv(64)
        if len(buf2) < 20:
            return None
        action2, rtid2 = struct.unpack(">II", buf2[:8])
        if action2 != 2 or rtid2 != tid2:
            return None
        seeders, _completed, _leechers = struct.unpack(">III", buf2[8:20])
        return int(seeders)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def scrape_seeders(magnet, timeout=4, max_trackers=4):
    """Best-effort CURRENT seeder count for a magnet via its UDP trackers, or None if none
    could be scraped (DHT-only magnet, all trackers down/HTTP-only, etc.). Never raises."""
    ih = _infohash_bytes(magnet)
    if not ih or len(ih) != 20:
        return None
    try:
        trs = urllib.parse.parse_qs(urllib.parse.urlsplit(magnet).query).get("tr", [])
    except Exception:
        return None
    # total wall-clock budget so a few slow trackers can't stack (DNS + connect) into a long
    # stall — each tracker gets at most `timeout`, but never past the shared deadline.
    deadline = time.monotonic() + max(timeout, 5)
    best = None
    for tr in trs[:max_trackers]:
        remaining = deadline - time.monotonic()
        if remaining <= 0.5:
            break
        try:
            p = urllib.parse.urlsplit(tr)
        except Exception:
            continue
        if p.scheme != "udp" or not p.hostname or not p.port:
            continue                              # UDP scrape only (HTTP scrape = future)
        n = _udp_scrape(p.hostname, p.port, ih, min(timeout, remaining))
        if n is not None:
            best = max(best or 0, n)
    return best


def probe_result(r, timeout=8):
    """Return {'_live': 'live'|'dead'|'unknown', '_peers': int|None} for one result dict."""
    if not isinstance(r, dict):
        return {"_live": "unknown", "_peers": None}
    magnet = r.get("magnet") or ""
    if magnet or r.get("torrent_url"):
        peers = scrape_seeders(magnet, timeout=min(5, timeout)) if magnet else None
        if peers is not None:
            return {"_live": "live" if peers > 0 else "unknown", "_peers": peers}
        s = r.get("seeders") or 0                 # no scrape -> the indexer count is the signal
        return {"_live": "live" if s > 0 else "unknown", "_peers": None}
    if r.get("nzb_id"):
        return {"_live": "unknown", "_peers": None}   # Usenet is provider-backed (NNTP check = future)
    url = r.get("url") or ""
    if url:
        state, _size = discover.probe_url(url, timeout=timeout)
        return {"_live": state, "_peers": None}
    return {"_live": "unknown", "_peers": None}


def verify_many(results, timeout=8, max_n=25, workers=8):
    """Probe up to max_n results in parallel and annotate each with _live (+ _peers). Bounded
    and best-effort: a slow/failed probe just leaves that result 'unknown'. Returns results."""
    targets = [r for r in results if isinstance(r, dict)][:max_n]
    if not targets:
        return results
    ex = ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets))))
    try:
        futs = {ex.submit(probe_result, r, timeout): r for r in targets}
        try:
            for f in as_completed(futs, timeout=timeout + 8):
                try:
                    info = f.result()
                    r = futs[f]
                    r["_live"] = info.get("_live", "unknown")
                    if info.get("_peers") is not None:
                        r["_peers"] = info["_peers"]
                except Exception:
                    pass
        except Exception:
            pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def filter_live(results, timeout=8, max_n=40):
    """For the Deep Hunt: verify finds and DROP the ones confirmed dead (rotted direct links).
    Torrents / Usenet / unverifiable results are kept — 'dead' is only ever a positive 404/410."""
    results = [r for r in results if isinstance(r, dict)]
    verify_many(results, timeout=timeout, max_n=max_n)
    return [r for r in results if r.get("_live") != "dead"]
