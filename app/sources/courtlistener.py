"""CourtListener search source — U.S. court opinions & legal documents.

Queries the Free Law Project's CourtListener v4 search API:
    https://www.courtlistener.com/api/rest/v4/search/?q=<q>&type=o
(type=o = case-law opinions). No API key required for search, but
anonymous access is rate-limited: 401/403/429 degrade to [].

Each result's `url` is the opinion cluster's landing page on
courtlistener.com (absolute_url), which serves the full opinion HTML.

Stdlib only. Never raises: search() returns [] on any error.
"""

import gzip
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "CourtListener"
CATEGORIES = {"documents"}

_HOST = "www.courtlistener.com"
_API = "https://" + _HOST + "/api/rest/v4/search/"
_UA = "Undertow/1.0 (+https://undertow.local)"

_MAX_RESULTS = 40
_PAGE_SIZE = 20                  # v4 search returns 20 per page
_MAX_PAGES = 2                   # 2 pages = 40 results max
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

    Returns decoded bytes or None. Never raises. 401/403/429 (rate limit
    or auth-walled) and any other HTTP error come back as None.
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
        # urllib.error.HTTPError (401/403/429/5xx), URLError, timeout, ...
        return None


def _parse_page(raw, results):
    """Append result dicts from one API page; return `next` URL or ""."""
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    items = payload.get("results")
    if not isinstance(items, list):
        return ""
    for item in items:
        if len(results) >= _MAX_RESULTS:
            return ""
        try:
            if not isinstance(item, dict):
                continue
            title = str(item.get("caseName") or
                        item.get("caseNameFull") or "").strip()
            abs_url = str(item.get("absolute_url") or "").strip()
            if not title or not abs_url.startswith("/"):
                continue
            court = str(item.get("court") or "").strip()
            docket = str(item.get("docketNumber") or "").strip()
            extra = " — ".join(p for p in (court, docket) if p)
            if extra:
                title = title + " (" + extra + ")"
            date = str(item.get("dateFiled") or "")[:10].strip()
            results.append({
                "title": title,
                "source": NAME,
                "seeders": 0,
                "size": 0,
                "magnet": "",
                "torrent_url": "",
                "url": "https://" + _HOST + abs_url,
                "date": date,
                "category": "documents",
                "quality": "HTML",
            })
        except Exception:
            continue
    nxt = payload.get("next")
    return nxt if isinstance(nxt, str) else ""


def search(query, category="", timeout=12):
    """Search CourtListener opinions. Returns result dicts; [] on error."""
    results = []
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))
        url = _API + "?" + urllib.parse.urlencode({"q": query, "type": "o"})
        for _ in range(_MAX_PAGES):
            raw = _get(url, deadline)
            if not raw:
                break
            url = _parse_page(raw, results)
            if not url or len(results) >= _MAX_RESULTS:
                break
    except Exception:
        return results
    return results


if __name__ == "__main__":
    for q in ("fair use copyright", "habeas corpus", "zxqjkw-no-such-case"):
        t0 = time.monotonic()
        rs = search(q, timeout=12)
        dt = time.monotonic() - t0
        print("query=%-24r -> %2d results in %.2fs" % (q, len(rs), dt))
        for r in rs[:3]:
            assert set(r) == {"title", "source", "seeders", "size", "magnet",
                              "torrent_url", "url", "date", "category",
                              "quality"}, r
            assert r["url"].startswith("https://www.courtlistener.com/"), r
            assert r["source"] == NAME and r["category"] == "documents", r
            assert r["quality"] == "HTML", r
            print("   - %s | %s | %s" % (r["title"][:70], r["date"], r["url"]))
    print("bad category ->", len(search("copyright", category="movies")))
    print("empty query  ->", len(search("")))
    print("tiny timeout ->", len(search("copyright", timeout=0.001)))
