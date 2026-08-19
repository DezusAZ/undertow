"""Usenet search adapter (Newznab — e.g. NZBGeek).

Queries a Newznab indexer and returns NZB results. Downloading is handled by the app,
not here: each result carries an `nzb_id`; the app builds the authenticated get-URL
server-side (so the indexer API key is NEVER sent to the browser) and hands it to
SABnzbd, which fetches from the Usenet provider through the VPN.

Requires NEWZNAB_URL + NZBGEEK_APIKEY (set from .env). Returns [] when unconfigured,
so the tool works fine for anyone without a Usenet account.

stdlib only; never raises.
"""
import os
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NAME = "Usenet · NZBGeek"
_URL = os.environ.get("NEWZNAB_URL", "").rstrip("/")
_KEY = os.environ.get("NZBGEEK_APIKEY", "")
_UA = "Undertow"
_READ_CAP = 4 * 1024 * 1024

_QUAL = [("2160p", "2160p"), ("uhd", "2160p"), ("4k", "2160p"), ("1080p", "1080p"),
         ("720p", "720p"), ("flac", "FLAC"), ("epub", "EPUB"), ("pdf", "PDF")]


def _quality(t):
    t = (t or "").lower()
    for pat, label in _QUAL:
        if pat in t:
            return label
    return ""


def _id_from(url):
    m = re.search(r"[?&]id=([^&]+)", url or "")
    return m.group(1) if m else ""


def search(query, category="", timeout=12):
    q = (query or "").strip()
    if not q or not _URL or not _KEY:
        return []
    url = _URL + "/api?" + urllib.parse.urlencode(
        {"t": "search", "q": q, "limit": "60", "apikey": _KEY})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(_READ_CAP)
    except Exception:
        return []
    try:
        root = ET.fromstring(raw)
    except Exception:
        return []
    out = []
    for item in root.iter():
        if item.tag.split("}")[-1] != "item":
            continue
        title = ""; size = 0; pub = ""; nid = ""
        for ch in item:
            tag = ch.tag.split("}")[-1]
            if tag == "title":
                title = (ch.text or "").strip()
            elif tag == "pubDate":
                pub = (ch.text or "").strip()
            elif tag == "guid" and not nid:
                nid = _id_from(ch.text or "") or (ch.text or "").strip()
            elif tag == "enclosure":
                nid = _id_from(ch.get("url") or "") or nid
                try:
                    size = int(ch.get("length") or 0)
                except Exception:
                    pass
            elif tag == "attr":
                n = (ch.get("name") or "").lower(); v = ch.get("value") or ""
                if n == "size" and not size:
                    try:
                        size = int(v)
                    except Exception:
                        pass
        # keep only a clean id we can safely round-trip to SABnzbd server-side
        if not nid or not re.fullmatch(r"[A-Za-z0-9._-]{4,128}", nid):
            continue
        out.append({
            "title": title, "source": NAME, "seeders": 0, "size": size,
            "magnet": "", "torrent_url": "", "url": "", "date": pub,
            "category": "", "quality": _quality(title), "nzb_id": nid,
        })
    return out[:60]


if __name__ == "__main__":
    import sys
    for r in search(sys.argv[1] if len(sys.argv) > 1 else "ubuntu"):
        print("%12s | %s" % (r["nzb_id"][:12], r["title"][:66]))
