"""Open Library book search source for vpntorrent.

Queries the public Open Library search API (no key required) and returns
links to book pages, preferring Internet Archive detail pages when an
"ia" identifier is available (those are readable/downloadable).

Stdlib only. Never raises from search(); returns [] on any error.
"""

import gzip
import io
import json
import time
import urllib.parse
import urllib.request
import urllib.error

NAME = "Open Library"
CATEGORIES = {"documents"}

_API_HOST = "openlibrary.org"
_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
       "Gecko/20100101 Firefox/128.0")

_MAX_RESULTS = 40
_MAX_BODY = 3 * 1024 * 1024      # cap raw body read (bytes)
_MAX_INFLATE = 8 * 1024 * 1024   # cap gzip-inflated size (bytes)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse all redirects — we only ever talk to the intended host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _get_json(url, timeout):
    """HTTPS GET returning parsed JSON. Bounded read + bounded inflate."""
    if urllib.parse.urlsplit(url).hostname != _API_HOST:
        raise ValueError("unexpected host")
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
    })
    with _OPENER.open(req, timeout=timeout) as resp:
        raw = resp.read(_MAX_BODY)
    if raw[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            raw = gz.read(_MAX_INFLATE)
    return json.loads(raw.decode("utf-8", "replace"))


def search(query, category="", timeout=12):
    """Search Open Library. Returns a list of result dicts; never raises."""
    try:
        deadline = time.monotonic() + timeout
        if category and category not in CATEGORIES:
            return []
        query = (query or "").strip()
        if not query:
            return []

        params = urllib.parse.urlencode({
            "q": query,
            "limit": _MAX_RESULTS,
            "fields": "title,author_name,first_publish_year,ia,cover_i,key",
        })
        url = "https://%s/search.json?%s" % (_API_HOST, params)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return []
        data = _get_json(url, min(timeout, remaining))

        docs = data.get("docs")
        if not isinstance(docs, list):
            return []

        results = []
        for doc in docs[:_MAX_RESULTS]:
            if time.monotonic() > deadline:
                break
            if not isinstance(doc, dict):
                continue
            title = str(doc.get("title") or "").strip()
            if not title:
                continue

            authors = doc.get("author_name") or []
            if isinstance(authors, list) and authors:
                title += " — " + ", ".join(str(a) for a in authors[:3])

            key = str(doc.get("key") or "").strip()
            ia = doc.get("ia") or []
            link = ""
            quality = ""
            if isinstance(ia, list) and ia and ia[0]:
                link = "https://archive.org/details/" + urllib.parse.quote(
                    str(ia[0]), safe="")
                quality = "EBOOK"
            elif key.startswith("/"):
                link = "https://openlibrary.org" + key
            if not link:
                continue

            year = doc.get("first_publish_year")
            date = str(year) if isinstance(year, int) else ""

            results.append({
                "title": title,
                "source": NAME,
                "seeders": 0,
                "size": 0,
                "magnet": "",
                "torrent_url": "",
                "url": link,
                "date": date,
                "category": "documents",
                "quality": quality,
            })
        return results
    except Exception:
        return []


if __name__ == "__main__":
    for q in ("the count of monte cristo", "python programming"):
        t0 = time.monotonic()
        rows = search(q, "documents")
        dt = time.monotonic() - t0
        print("query=%r -> %d results in %.2fs" % (q, len(rows), dt))
        for r in rows[:5]:
            print("  [%s|%s] %s -> %s" % (
                r["date"], r["quality"] or "-", r["title"][:60], r["url"]))
        assert all(r["url"] for r in rows)
        assert all(r["source"] == NAME for r in rows)
        assert all(r["category"] == "documents" for r in rows)
    # error paths must return [] and not raise
    assert search("", "documents") == []
    assert search("test", "movies") == []
    assert search("test", "documents", timeout=0) == []
    print("self-test OK")
