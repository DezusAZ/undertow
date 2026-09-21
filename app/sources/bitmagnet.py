"""Self-hosted DHT crawler adapter (bitmagnet).

bitmagnet crawls the BitTorrent DHT directly and indexes infohashes that live only
in the swarm — on no tracker website. We query its Torznab endpoint (same shape as a
Jackett indexer) and return magnets with real seeder counts. Unlike the external BT4G
adapter, this is OUR node: no Cloudflare wall, and its crawl traffic exits through the
same Proton tunnel. NOTE: the DB warms up over hours/days, so results are sparse until
it has crawled for a while.

stdlib only. Raises on a transport error/timeout (the registry's breaker needs to see it);
returns [] for a healthy empty answer.
"""
import os
import re
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NAME = "Bitmagnet (DHT)"
BITMAGNET_URL = os.environ.get("BITMAGNET_URL", "http://127.0.0.1:3333")
_UA = "vpntorrent"
_READ_CAP = 4 * 1024 * 1024

_TRACKERS = [
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.tracker.cl:1337/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
    "udp://exodus.desync.com:6969/announce",
]

_QUAL = [("2160p", "2160p"), ("uhd", "2160p"), ("4k", "2160p"), ("1080p", "1080p"),
         ("720p", "720p"), ("480p", "480p"), ("flac", "FLAC"), ("bluray", "BluRay")]


def _quality(title):
    t = (title or "").lower()
    for pat, label in _QUAL:
        if pat in t:
            return label
    return ""


def _parse(raw):
    out = []
    try:
        root = ET.fromstring(raw)
    except Exception:
        return out
    for item in root.iter():
        if item.tag.split("}")[-1] != "item":
            continue
        title = ""; size = 0; seeders = None; magnet = ""; ih = ""   # None = swarm size unknown (DHT unscraped)
        pub = ""; link = ""; enc = ""
        for ch in item:
            tag = ch.tag.split("}")[-1]
            if tag == "title":
                title = (ch.text or "").strip()
            elif tag == "size":
                try:
                    size = int((ch.text or "0").strip())
                except Exception:
                    pass
            elif tag == "link":
                link = (ch.text or "").strip()
            elif tag == "pubDate":
                pub = (ch.text or "").strip()
            elif tag == "enclosure":
                enc = ch.get("url") or ""
            elif tag == "attr":
                name = (ch.get("name") or "").lower()
                val = ch.get("value") or ""
                if name == "seeders":
                    try:
                        seeders = int(val)
                    except Exception:
                        pass
                elif name == "magneturl" and val.startswith("magnet:"):
                    magnet = val
                elif name == "infohash":
                    ih = val.strip()
                elif name == "size" and not size:
                    try:
                        size = int(val)
                    except Exception:
                        pass
        if not magnet:
            if link.startswith("magnet:"):
                magnet = link
            elif enc.startswith("magnet:"):
                magnet = enc
        if not magnet and ih:
            magnet = ("magnet:?xt=urn:btih:" + ih + "&dn=" + urllib.parse.quote(title)
                      + "".join("&tr=" + urllib.parse.quote(t) for t in _TRACKERS))
        if not magnet:
            continue
        out.append({
            "title": title, "source": NAME, "seeders": seeders, "size": size,
            "magnet": magnet, "torrent_url": "", "url": "", "date": pub,
            "category": "", "quality": _quality(title),
        })
    return out


# Torznab category ids bitmagnet understands, so a scoped search doesn't return off-type
# releases (a music search used to leak videos into the music view).
_TORZNAB_CAT = {"movies": "2000", "tv": "5000", "music": "3000",
                "documents": "7000", "software": "4000"}
# bitmagnet's Postgres full-text search is query-dependent: some queries answer in 20 ms,
# others hang 15-20 s. Every search AND every hunt cycle paid the full fan-out timeout for
# it, so its budget is capped independently of the caller's. A timeout/error is RAISED
# (not swallowed as "no results") so the registry's circuit breaker actually counts it.
_MAX_TIMEOUT = float(os.environ.get("BITMAGNET_TIMEOUT", "5"))


def search(query, category="", timeout=12):
    q = (query or "").strip()
    if not q:
        return []
    params = {"t": "search", "q": q, "limit": "40"}
    cat = _TORZNAB_CAT.get((category or "").lower())
    if cat:
        params["cat"] = cat
    url = BITMAGNET_URL.rstrip("/") + "/torznab/api?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=min(timeout, _MAX_TIMEOUT)) as resp:
            raw = resp.read(_READ_CAP)
    except Exception as e:
        raise RuntimeError("bitmagnet: %s" % (str(e)[:80] or type(e).__name__))
    return _parse(raw)[:40]


if __name__ == "__main__":
    import sys
    for r in search(sys.argv[1] if len(sys.argv) > 1 else "ubuntu"):
        print("%5d seeds | %s" % (r["seeders"] or 0, r["title"][:70]))
