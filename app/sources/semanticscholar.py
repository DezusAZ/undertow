"""Semantic Scholar paper search source.

Queries the Semantic Scholar Academic Graph API (no key required, but
rate-limited — HTTP 429 is treated as "no results"):
    https://api.semanticscholar.org/graph/v1/paper/search
        ?query=<q>&limit=40&fields=title,year,openAccessPdf,url

Each result's `url` is the open-access PDF (openAccessPdf.url) when
available, otherwise the Semantic Scholar landing page. Results with an
open-access PDF are ranked first.

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

NAME = "Semantic Scholar"
CATEGORIES = {"documents"}

_HOST = "api.semanticscholar.org"
_API = "https://" + _HOST + "/graph/v1/paper/search"
_FIELDS = "title,year,openAccessPdf,url"
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

    Returns decoded bytes or None. Never raises. Rate limiting (429)
    and any other HTTP error yield None.
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
        # Includes urllib.error.HTTPError 429 (rate limit) -> treat as [].
        return None


def _clean_url(u):
    """Return u only if it is a plain http(s) URL, else ''."""
    u = str(u or "").strip()
    if u.startswith("https://") or u.startswith("http://"):
        return u
    return ""


def search(query, category="", timeout=12):
    """Search Semantic Scholar papers. Returns list of dicts; [] on error."""
    results = []
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))
        url = _API + "?" + urllib.parse.urlencode({
            "query": query,
            "limit": str(_MAX_RESULTS),
            "fields": _FIELDS,
        })
        raw = _get(url, deadline)
        if not raw:
            return []
        payload = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(payload, dict):
            return []
        papers = payload.get("data")
        if not isinstance(papers, list):
            return []
        with_pdf, without_pdf = [], []
        for paper in papers:
            try:
                if not isinstance(paper, dict):
                    continue
                title = str(paper.get("title") or "").strip()
                if not title:
                    continue
                year = paper.get("year")
                date = str(year) if isinstance(year, int) else ""
                oa = paper.get("openAccessPdf")
                pdf_url = ""
                if isinstance(oa, dict):
                    pdf_url = _clean_url(oa.get("url"))
                landing = _clean_url(paper.get("url"))
                link = pdf_url or landing
                if not link:
                    continue
                row = {
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": link,
                    "date": date,
                    "category": "documents",
                    "quality": "PDF" if pdf_url else "",
                }
                (with_pdf if pdf_url else without_pdf).append(row)
            except Exception:
                continue
        results = (with_pdf + without_pdf)[:_MAX_RESULTS]
    except Exception:
        return results
    return results


if __name__ == "__main__":
    for q in ("transformer attention", "protein folding alphafold",
              "zxqjkw-no-such-paper-xyzzy"):
        t0 = time.monotonic()
        rs = search(q, timeout=12)
        dt = time.monotonic() - t0
        n_pdf = sum(1 for r in rs if r["quality"] == "PDF")
        print("query=%-30r -> %2d results (%d PDF) in %.2fs"
              % (q, len(rs), n_pdf, dt))
        for r in rs[:3]:
            assert set(r) == {"title", "source", "seeders", "size", "magnet",
                              "torrent_url", "url", "date", "category",
                              "quality"}, r
            assert r["url"], r
            assert r["source"] == NAME
            assert r["category"] == "documents"
            print("   - [%s] %s | %s | %s"
                  % (r["quality"] or "-", r["title"][:55], r["date"],
                     r["url"][:70]))
        time.sleep(1.5)  # be gentle with the unkeyed rate limit
    # never-raise checks
    print("bad category ->", len(search("attention", category="movies")))
    print("empty query  ->", len(search("")))
