"""DOAJ (Directory of Open Access Journals) search source.

Queries the public DOAJ articles search API (JSON, no API key):
    https://doaj.org/api/search/articles/<url-encoded query>?pageSize=40
Each hit's `bibjson` carries the title, publication year, and a
`link[]` array; the entry with type=="fulltext" gives the openable
article URL and its content_type (HTML/PDF/...).

Stdlib only. Never raises: search() returns [] on any error.
"""

import os
import gzip
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "DOAJ"
CATEGORIES = {"documents"}

_HOST = "doaj.org"
_API = "https://" + _HOST + "/api/search/articles/"
# Some of these APIs ask for a contact address in the User-Agent. Default to a
# neutral placeholder and let the OPERATOR set their own via UNDERTOW_CONTACT —
# never ship a personal address, or every user of this tool identifies the packager.
_CONTACT = os.environ.get("UNDERTOW_CONTACT", "undertow@example.com")
_UA = "Undertow/1.0 (+https://undertow.local; contact: %s)" % _CONTACT

_MAX_RESULTS = 40
_MAX_BODY = 4 * 1024 * 1024      # cap raw body read (bytes)
_MAX_INFLATE = 8 * 1024 * 1024   # cap gzip-inflated size (bytes)
_CHUNK = 65536


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any redirect (so we can never leave the host)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _get(url, deadline):
    """HTTPS GET to the intended host, honoring the wall-clock deadline.

    Returns decoded bytes or None. Never raises.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != _HOST:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0.05:
            return None
        req = urllib.request.Request(url, headers={
            "User-Agent": _UA,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        })
        body = io.BytesIO()
        with _OPENER.open(req, timeout=min(remaining, 12.0)) as resp:
            while body.tell() < _MAX_BODY:
                if time.monotonic() >= deadline:
                    return None  # slow-loris body: give up
                chunk = resp.read(min(_CHUNK, _MAX_BODY - body.tell()))
                if not chunk:
                    break
                body.write(chunk)
            enc = (resp.headers.get("Content-Encoding") or "").lower()
        data = body.getvalue()
        if "gzip" in enc:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                data = gz.read(_MAX_INFLATE + 1)
            if len(data) > _MAX_INFLATE:
                return None
        return data
    except Exception:
        return None


def _fulltext_link(bibjson):
    """Return (url, quality) from bibjson.link[] where type=="fulltext"."""
    links = bibjson.get("link")
    if not isinstance(links, list):
        return "", ""
    for link in links:
        if not isinstance(link, dict):
            continue
        if str(link.get("type") or "").lower() != "fulltext":
            continue
        url = str(link.get("url") or "").strip()
        if not url.lower().startswith(("http://", "https://")):
            continue
        ctype = str(link.get("content_type") or "").strip().upper()
        quality = ctype if ctype in ("HTML", "PDF", "EPUB", "XML") else ""
        return url, quality
    return "", ""


def search(query, category="", timeout=12):
    """Search DOAJ articles. Returns a list of result dicts; [] on error."""
    results = []
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))
        url = (_API + urllib.parse.quote(query, safe="") +
               "?" + urllib.parse.urlencode({"pageSize": _MAX_RESULTS}))
        raw = _get(url, deadline)
        if not raw:
            return []
        payload = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(payload, dict):
            return []
        hits = payload.get("results")
        if not isinstance(hits, list):
            return []
        for hit in hits:
            if len(results) >= _MAX_RESULTS:
                break
            try:
                if not isinstance(hit, dict):
                    continue
                bibjson = hit.get("bibjson")
                if not isinstance(bibjson, dict):
                    continue
                title = str(bibjson.get("title") or "").strip()
                if not title:
                    continue
                link_url, quality = _fulltext_link(bibjson)
                if not link_url:
                    continue
                year = str(bibjson.get("year") or "").strip()
                results.append({
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": link_url,
                    "date": year,
                    "category": "documents",
                    "quality": quality,
                })
            except Exception:
                continue
    except Exception:
        return results
    return results


if __name__ == "__main__":
    for q in ("machine learning", "climate change", "zxqjkw-no-such-topic"):
        t0 = time.monotonic()
        rs = search(q, timeout=12)
        dt = time.monotonic() - t0
        print("query=%-24r -> %2d results in %.2fs" % (q, len(rs), dt))
        for r in rs[:3]:
            assert set(r) == {"title", "source", "seeders", "size", "magnet",
                              "torrent_url", "url", "date", "category",
                              "quality"}, r
            assert r["url"], r
            assert isinstance(r["seeders"], int) and isinstance(r["size"], int)
            print("   - %s | %s | %s | %s" %
                  (r["title"][:55], r["date"], r["quality"], r["url"][:60]))
    # never-raise checks
    print("bad category ->", len(search("machine learning", category="movies")))
    print("empty query  ->", len(search("")))
    print("tiny timeout ->", len(search("machine learning", timeout=0.001)))
