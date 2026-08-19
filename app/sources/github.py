"""GitHub adapter — public repository search (code/software discovery).

Queries the official GitHub REST search API (unauthenticated) and returns
public repositories as direct ``url`` results (html_url). This is a LEGAL
discovery source: everything surfaced is a public repo page.

Unauthenticated search is rate-limited hard (~10 req/min per IP); a 403/429
from the API is treated as "no results" and degrades to []. No API key is
required or used.

stdlib only; never raises (returns [] on any error).
"""

import gzip
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "GitHub"
CATEGORIES = {"software"}

_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"

_API_HOST = "api.github.com"
_MAX_RESULTS = 40
_MAX_BYTES = 4 * 1024 * 1024  # response body cap (anti slow-loris / bomb)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects that leave api.github.com or drop to plain http."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https" or (parts.hostname or "").lower() != _API_HOST:
            raise urllib.error.HTTPError(
                newurl, code, "redirect off-host blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirect())


def _read_capped(resp, deadline):
    """Read at most _MAX_BYTES, honoring the wall-clock deadline between chunks."""
    buf = bytearray()
    while len(buf) < _MAX_BYTES:
        if time.monotonic() >= deadline:
            return None
        chunk = resp.read(65536)
        if not chunk:
            break
        buf.extend(chunk)
    if len(buf) >= _MAX_BYTES:  # suspiciously large for a JSON search page
        return None
    return bytes(buf)


def _fetch_json(url, deadline):
    """GET https://api.github.com/... -> decoded JSON, or None on any problem."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() != _API_HOST:
        return None
    remaining = deadline - time.monotonic()
    if remaining < 0.5:
        return None
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _UA,
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "gzip",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with _OPENER.open(req, timeout=min(10.0, remaining)) as resp:
            raw = _read_capped(resp, deadline)
            if raw is None:
                return None
            if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
                # Capped inflate: a tiny gzip body must not balloon unbounded.
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                    raw = gz.read(_MAX_BYTES + 1)
                if len(raw) > _MAX_BYTES:
                    return None
            return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        # Covers 403/429 rate-limit responses, timeouts, DNS, bad JSON, ...
        return None


def search(query, category="", timeout=12):
    """Search public GitHub repositories. Never raises; [] on any error."""
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))

        url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode(
            {"q": query, "per_page": 30, "sort": "stars"}
        )
        data = _fetch_json(url, deadline)
        if not isinstance(data, dict):
            return []
        items = data.get("items")
        if not isinstance(items, list):
            return []

        results = []
        for it in items[:_MAX_RESULTS]:
            if not isinstance(it, dict):
                continue
            html_url = it.get("html_url") or ""
            if not isinstance(html_url, str) or not html_url.startswith("https://"):
                continue
            name = it.get("full_name") or it.get("name") or ""
            if not isinstance(name, str) or not name:
                continue
            desc = it.get("description")
            title = name if not isinstance(desc, str) or not desc.strip() \
                else "%s — %s" % (name, desc.strip()[:160])
            stars = it.get("stargazers_count")
            if isinstance(stars, int) and stars > 0:
                title += "  [★%d]" % stars
            try:
                size = int(it.get("size") or 0) * 1024  # API reports KB
            except (TypeError, ValueError):
                size = 0
            date = it.get("pushed_at") or it.get("updated_at") or ""
            if not isinstance(date, str):
                date = ""
            lang = it.get("language")
            quality = lang if isinstance(lang, str) else ""

            results.append({
                "title": title,
                "source": NAME,
                "seeders": 0,
                "size": max(0, size),
                "magnet": "",
                "torrent_url": "",
                "url": html_url,
                "date": date[:10],
                "category": "software",
                "quality": quality,
            })
        return results[:_MAX_RESULTS]
    except Exception:
        return []


if __name__ == "__main__":
    for q in ("wireguard", "video downloader", "zzqqxjkl-no-such-repo-xx"):
        t0 = time.monotonic()
        rs = search(q, timeout=12)
        print("%-28s -> %2d results in %.1fs" % (repr(q), len(rs), time.monotonic() - t0))
        for r in rs[:3]:
            print("   %-70s %10d B  %s  %s" % (r["title"][:70], r["size"], r["date"], r["url"]))
        assert all(
            set(r) == {"title", "source", "seeders", "size", "magnet", "torrent_url",
                       "url", "date", "category", "quality"}
            for r in rs
        ), "bad result shape"
        assert all(r["magnet"] or r["torrent_url"] or r["url"] for r in rs)
        assert all(r["source"] == NAME and r["category"] == "software" for r in rs)
        time.sleep(7)  # stay under the ~10/min unauthenticated search limit
    print("self-test OK")
