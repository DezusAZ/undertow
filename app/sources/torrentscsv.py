"""torrents-csv.com adapter — a keyless, open torrent index.

torrents-csv is a community-maintained, append-only index of torrents with scraped
seeder/leecher counts, exposed as a dead-simple JSON API (no key, no login, no HTML to
scrape). We query it and build a magnet from the infohash. It's a good generalist
complement to our DHT crawler + Jackett indexers: different corpus, real seed counts,
and it answers fast. The fetch exits through the Proton tunnel like every other adapter.

stdlib only. RAISES on a transport error/timeout (the registry's breaker must see it);
returns [] for a healthy empty answer.
"""
import os
import json
import time
import urllib.parse
import urllib.request

NAME = "torrents-csv"
BASE = os.environ.get("TORRENTSCSV_URL", "https://torrents-csv.com/service/search")
_UA = "vpntorrent"
_READ_CAP = 4 * 1024 * 1024
_MAX_TIMEOUT = float(os.environ.get("TORRENTSCSV_TIMEOUT", "8"))

# A fat tracker set so the bare infohash finds peers fast; add_magnet() merges in the live
# public-tracker list on top of these, and libtorrent de-dupes announce URLs either way.
_TRACKERS = [
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.tracker.cl:1337/announce",
    "udp://open.demonii.com:1337/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://tracker.torrent.eu.org:451/announce",
]

_QUAL = [("2160p", "2160p"), ("uhd", "2160p"), ("4k", "2160p"), ("1080p", "1080p"),
         ("720p", "720p"), ("480p", "480p"), ("flac", "FLAC"), ("bluray", "BluRay")]


def _quality(title):
    t = (title or "").lower()
    for pat, label in _QUAL:
        if pat in t:
            return label
    return ""


def _int(v):
    try:
        return int(v)
    except Exception:
        return 0


def _parse(raw):
    out = []
    try:
        data = json.loads(raw)
    except Exception:
        return out
    # The API returns {"torrents": [...]}; tolerate a bare list from older/self-hosted builds.
    rows = data.get("torrents") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return out
    for r in rows:
        if not isinstance(r, dict):
            continue
        ih = (r.get("infohash") or "").strip()
        title = (r.get("name") or "").strip()
        if not ih or not title:
            continue
        size = _int(r.get("size_bytes"))
        seeders = r.get("seeders")
        try:
            seeders = int(seeders) if seeders is not None else None
        except Exception:
            seeders = None
        created = r.get("created_unix")
        date = ""
        if created:
            try:
                date = time.strftime("%Y-%m-%d", time.gmtime(int(created)))
            except Exception:
                date = ""
        magnet = ("magnet:?xt=urn:btih:" + ih + "&dn=" + urllib.parse.quote(title)
                  + "".join("&tr=" + urllib.parse.quote(t) for t in _TRACKERS))
        out.append({
            "title": title, "source": NAME, "seeders": seeders, "size": size,
            "magnet": magnet, "torrent_url": "", "url": "", "date": date,
            "category": "", "quality": _quality(title),
        })
    return out


def search(query, category="", timeout=12):
    q = (query or "").strip()
    if not q:
        return []
    url = BASE + "?" + urllib.parse.urlencode({"q": q, "size": "40"})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=min(timeout, _MAX_TIMEOUT)) as resp:
            raw = resp.read(_READ_CAP)
    except Exception as e:
        raise RuntimeError("torrentscsv: %s" % (str(e)[:80] or type(e).__name__))
    return _parse(raw)[:40]


if __name__ == "__main__":
    import sys
    for r in search(sys.argv[1] if len(sys.argv) > 1 else "ubuntu"):
        print("%5s seeds | %s" % (r["seeders"] if r["seeders"] is not None else "?", r["title"][:70]))
