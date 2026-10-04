"""Live BitTorrent tracker list — fetched through the VPN, cached, refreshed ~daily, and
appended to every magnet we add. Bare-infohash magnets from DHT sources (bitmagnet,
torrents-csv, BT4G) often ship with no or few trackers, so they sit at 0 peers / "fetching
info" until DHT alone happens to find peers. Giving every torrent a fat list of KNOWN-GOOD
public trackers makes peers turn up fast — the universal fix for "lots of seeders, but it
never starts". Falls back to a built-in set when offline. stdlib only; never raises.
"""
import os
import time
import threading
import urllib.request

CACHE = os.environ.get("TRACKERS_CACHE", "/config/trackers.txt")
TTL = int(os.environ.get("TRACKERS_TTL", "86400"))          # refresh the live list daily
# Curated, maintained best-tracker lists (plain text, one URL per line). Public hosts, so
# the fetch goes out through the Proton tunnel like everything else — no leak.
SOURCES = [
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt",
    "https://newtrackon.com/api/stable",
]
# Always-on baseline so a magnet is never tracker-less even with no network/cache.
FALLBACK = [
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.tracker.cl:1337/announce",
    "udp://open.demonii.com:1337/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://explodie.org:6969/announce",
    "udp://tracker.dler.org:6969/announce",
]
_UA = "vpntorrent"
_SCHEMES = ("udp://", "http://", "https://", "ws://", "wss://")
_lock = threading.Lock()
_mem = None
_mem_ts = 0.0


def _parse(txt):
    out = []
    for line in (txt or "").splitlines():
        u = line.strip()
        if u.startswith(_SCHEMES) and u not in out:
            out.append(u)
    return out


def _load_cache():
    try:
        if time.time() - os.path.getmtime(CACHE) < TTL:
            t = _parse(open(CACHE).read())
            if t:
                return t
    except OSError:
        pass
    return None


def _refresh():
    merged = []
    for src in SOURCES:
        try:
            req = urllib.request.Request(src, headers={"User-Agent": _UA})
            txt = urllib.request.urlopen(req, timeout=15).read(500000).decode("utf-8", "replace")
            for t in _parse(txt):
                if t not in merged:
                    merged.append(t)
        except Exception:
            pass                     # a dead source is fine; we still have the others + fallback
    if merged:
        try:
            tmp = CACHE + ".tmp"
            with open(tmp, "w") as f:
                f.write("\n".join(merged))
            os.replace(tmp, CACHE)
        except OSError:
            pass
    return merged


def get_trackers(limit=40):
    """Best working public trackers (live list, cached ~daily), fallback set always included.
    Short in-process memo so a burst of adds doesn't re-read the file each time. Never raises."""
    global _mem, _mem_ts
    try:
        with _lock:
            if _mem is not None and time.time() - _mem_ts < 300:
                return _mem
        live = _load_cache()
        if live is None:
            live = _refresh() or []
        out = []
        for t in FALLBACK + live:           # fallback first so the always-on set is never cut
            if t not in out:
                out.append(t)
            if len(out) >= limit:
                break
        with _lock:
            _mem, _mem_ts = out, time.time()
        return out
    except Exception:
        return list(FALLBACK)


def start():
    """Warm the cache in the background at startup (once the tunnel is up). Never blocks."""
    def _w():
        try:
            if _load_cache() is None:
                _refresh()
        except Exception:
            pass
    threading.Thread(target=_w, daemon=True).start()
