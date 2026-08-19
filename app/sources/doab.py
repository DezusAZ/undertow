"""DOAB (Directory of Open Access Books) search source.

Queries the DOAB DSpace legacy REST API:
    https://directory.doabooks.org/rest/search?query=<q>
which returns a JSON list of items. Each result's `url` is the book's
DOAB landing page (https://directory.doabooks.org/handle/<handle>),
where the open-access PDF/download links live.

Stdlib only. Never raises: search() returns [] on any error.
"""

import gzip
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "DOAB"
CATEGORIES = {"documents"}

_HOST = "directory.doabooks.org"
_API = "https://" + _HOST + "/rest/search"
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

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


def search(query, category="", timeout=12):
    """Search DOAB. Returns a list of result dicts; [] on any error."""
    results = []
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))
        url = _API + "?" + urllib.parse.urlencode({"query": query})
        raw = _get(url, deadline)
        if not raw:
            return []
        items = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(items, list):
            return []
        for item in items:
            if len(results) >= _MAX_RESULTS:
                break
            try:
                if not isinstance(item, dict):
                    continue
                if item.get("type") != "item":
                    continue
                if str(item.get("withdrawn", "false")).lower() == "true":
                    continue
                title = str(item.get("name") or "").strip()
                handle = str(item.get("handle") or "").strip()
                if not title or not handle:
                    continue
                landing = ("https://" + _HOST + "/handle/" +
                           urllib.parse.quote(handle, safe="/."))
                date = str(item.get("lastModified") or "")[:10].strip()
                results.append({
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": landing,
                    "date": date,
                    "category": "documents",
                    "quality": "",
                })
            except Exception:
                continue
    except Exception:
        return results
    return results


if __name__ == "__main__":
    for q in ("history", "quantum physics", "zxqjkw-no-such-book"):
        t0 = time.monotonic()
        rs = search(q, timeout=12)
        dt = time.monotonic() - t0
        print("query=%-22r -> %2d results in %.2fs" % (q, len(rs), dt))
        for r in rs[:3]:
            assert set(r) == {"title", "source", "seeders", "size", "magnet",
                              "torrent_url", "url", "date", "category",
                              "quality"}, r
            assert r["url"], r
            print("   - %s | %s | %s" % (r["title"][:60], r["date"], r["url"]))
    # never-raise check against a dead category / bad input
    print("bad category ->", len(search("history", category="movies")))
    print("empty query  ->", len(search("")))
