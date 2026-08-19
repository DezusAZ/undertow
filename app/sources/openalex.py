"""OpenAlex search source.

Queries the OpenAlex works API (open catalog of ~250M scholarly works):
    https://api.openalex.org/works?search=<q>&per-page=40&mailto=...
JSON, no API key required. For each work we take the title, the
publication date/year, and prefer a free full-text link:
    open_access.oa_url  ->  primary_location.pdf_url  ->  landing id URL.
quality is "PDF" when an OA/pdf URL exists.

Stdlib only. Never raises: search() returns [] on any error.
"""

import gzip
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "OpenAlex"
CATEGORIES = {"documents"}

_HOST = "api.openalex.org"
_API = "https://" + _HOST + "/works"
_MAILTO = "undertow@example.com"
_UA = "Undertow/1.0 (+https://undertow.local; mailto:%s)" % _MAILTO

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


def _http_url(value):
    """Return value if it is a plausible http(s) URL string, else ""."""
    try:
        if not isinstance(value, str):
            return ""
        value = value.strip()
        if value.startswith("https://") or value.startswith("http://"):
            return value
    except Exception:
        pass
    return ""


def search(query, category="", timeout=12):
    """Search OpenAlex works. Returns a list of result dicts; [] on error."""
    results = []
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))
        url = _API + "?" + urllib.parse.urlencode({
            "search": query,
            "per-page": str(_MAX_RESULTS),
            "mailto": _MAILTO,
        })
        raw = _get(url, deadline)
        if not raw:
            return []
        data = json.loads(raw.decode("utf-8", "replace"))
        works = data.get("results") if isinstance(data, dict) else None
        if not isinstance(works, list):
            return []
        for work in works:
            if len(results) >= _MAX_RESULTS:
                break
            try:
                if not isinstance(work, dict):
                    continue
                title = str(work.get("display_name") or
                            work.get("title") or "").strip()
                if not title:
                    continue

                # Date: full publication_date if present, else the year.
                date = str(work.get("publication_date") or "").strip()
                if not date:
                    year = work.get("publication_year")
                    date = str(year) if isinstance(year, int) else ""

                # Prefer free full text: oa_url, then pdf_url, then landing.
                oa = work.get("open_access")
                oa_url = _http_url(oa.get("oa_url")) if isinstance(oa, dict) else ""
                loc = work.get("primary_location")
                pdf_url = _http_url(loc.get("pdf_url")) if isinstance(loc, dict) else ""

                landing = _http_url(work.get("id"))
                best = oa_url or pdf_url or landing
                if not best:
                    continue

                quality = "PDF" if (oa_url or pdf_url) else ""

                results.append({
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": best,
                    "date": date,
                    "category": "documents",
                    "quality": quality,
                })
            except Exception:
                continue
    except Exception:
        return results
    return results


if __name__ == "__main__":
    for q in ("machine learning", "dark matter halo",
              "zxqjkwv-no-such-work-9x7q"):
        t0 = time.monotonic()
        rs = search(q, timeout=12)
        dt = time.monotonic() - t0
        n_pdf = sum(1 for r in rs if r["quality"] == "PDF")
        print("query=%-28r -> %2d results (%2d PDF) in %.2fs"
              % (q, len(rs), n_pdf, dt))
        for r in rs[:3]:
            assert set(r) == {"title", "source", "seeders", "size", "magnet",
                              "torrent_url", "url", "date", "category",
                              "quality"}, r
            assert r["url"], r
            assert r["source"] == NAME, r
            assert r["category"] == "documents", r
            print("   - %s | %s | %s | %s"
                  % (r["title"][:55], r["date"], r["quality"], r["url"][:70]))
    # never-raise checks
    print("bad category ->", len(search("machine learning", category="movies")))
    print("empty query  ->", len(search("")))
    print("tiny timeout ->", len(search("machine learning", timeout=0.001)))
