"""Software Heritage source plugin.

Searches the Software Heritage archive (the universal source-code archive,
https://www.softwareheritage.org/) for origins (public code repositories)
matching a query.  Purely-public JSON API, no auth required:

    https://archive.softwareheritage.org/api/1/origin/search/{q}/?limit=30

Results link to the origin URL (the public repository) — this is a legal
discovery tool for openly archived source code.

Stdlib only.  search() never raises; returns [] on any error (including
rate limiting, which the API signals with HTTP 429).
"""

from __future__ import annotations

import gzip
import io
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "Software Heritage"
CATEGORIES = {"software"}

_API_HOST = "archive.softwareheritage.org"
_SEARCH_URL = "https://" + _API_HOST + "/api/1/origin/search/{q}/?limit=30"

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
)

_MAX_RESULTS = 40
_MAX_BODY_BYTES = 4 * 1024 * 1024  # cap raw read
_MAX_INFLATE_BYTES = 8 * 1024 * 1024  # cap gzip inflate


class _NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Only allow redirects that stay on the intended HTTPS host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname != _API_HOST:
            raise urllib.error.HTTPError(
                req.full_url, code, "cross-host redirect blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_NoCrossHostRedirect())


def _read_capped(resp, deadline: float) -> bytes:
    """Read a response body in chunks, honoring size cap and wall-clock deadline."""
    buf = io.BytesIO()
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("wall-clock deadline exceeded during read")
        chunk = resp.read(65536)
        if not chunk:
            break
        buf.write(chunk)
        if buf.tell() > _MAX_BODY_BYTES:
            break  # cap reached; use what we have
    return buf.getvalue()


def _fetch_json(url: str, deadline: float):
    remaining = deadline - time.monotonic()
    if remaining <= 0.5:
        raise TimeoutError("no time budget left")
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
        method="GET",
    )
    resp = _OPENER.open(req, timeout=min(remaining, 10.0))
    try:
        body = _read_capped(resp, deadline)
        if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
                body = gz.read(_MAX_INFLATE_BYTES)
    finally:
        resp.close()
    return json.loads(body.decode("utf-8", "replace"))


def _title_from_origin(origin_url: str) -> str:
    """Human-ish title from a repository origin URL."""
    parsed = urllib.parse.urlparse(origin_url)
    path = parsed.path.strip("/")
    if path:
        if path.endswith(".git"):
            path = path[:-4]
        parts = [p for p in path.split("/") if p]
        tail = "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
        host = parsed.hostname or ""
        return f"{tail} ({host})" if host else tail
    return origin_url


def search(query, category="", timeout=12):
    """Search Software Heritage origins.  Never raises; [] on any error."""
    results = []
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))

        url = _SEARCH_URL.format(q=urllib.parse.quote(query, safe=""))
        try:
            data = _fetch_json(url, deadline)
        except urllib.error.HTTPError as e:
            # 429 = rate limited; anything else is also a graceful [].
            try:
                e.close()
            except Exception:
                pass
            return []
        except (urllib.error.URLError, socket.timeout, TimeoutError,
                OSError, ValueError):
            return []

        if not isinstance(data, list):
            return []

        seen = set()
        for item in data:
            if len(results) >= _MAX_RESULTS:
                break
            if not isinstance(item, dict):
                continue
            origin_url = item.get("url") or ""
            link = item.get("origin_visits_url") or origin_url
            if not isinstance(link, str) or not link.strip():
                continue
            link = link.strip()
            if not isinstance(origin_url, str):
                origin_url = ""
            if link in seen:
                continue
            seen.add(link)
            title = _title_from_origin(origin_url or link)
            results.append({
                "title": str(title),
                "source": NAME,
                "seeders": 0,
                "size": 0,
                "magnet": "",
                "torrent_url": "",
                "url": link,
                "date": "",
                "category": "software",
                "quality": "",
            })
    except Exception:
        return results if isinstance(results, list) else []
    return results


if __name__ == "__main__":
    for q in ("wireguard", "ffmpeg", "zzqxnonexistentzzq"):
        t0 = time.monotonic()
        hits = search(q, timeout=12)
        dt = time.monotonic() - t0
        print(f"query={q!r}  results={len(hits)}  ({dt:.1f}s)")
        for h in hits[:3]:
            print(f"  - {h['title']}  ->  {h['url']}")
        assert isinstance(hits, list)
        for h in hits:
            assert set(h) == {"title", "source", "seeders", "size", "magnet",
                              "torrent_url", "url", "date", "category",
                              "quality"}, h
            assert h["source"] == NAME
            assert h["magnet"] or h["torrent_url"] or h["url"]
    print("self-test OK")
