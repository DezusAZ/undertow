"""Federated video adapter — SepiaSearch (search index over the PeerTube network).

SepiaSearch (run by Framasoft) indexes videos from hundreds of PeerTube
instances that opted into indexing; everything it returns is a public,
openly-viewable video on the open web. We query its JSON API and return the
watch-page URL for each hit (``url`` field). No API key required.

stdlib only; search() never raises (returns [] on any error).
"""

import gzip
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "PeerTube (SepiaSearch)"
CATEGORIES = {"movies", "tv", "other"}

_HOST = "sepiasearch.org"
_API = "https://sepiasearch.org/api/v1/search/videos"
_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"

_MAX_RESULTS = 40
_MAX_BYTES = 4 * 1024 * 1024   # cap on raw body AND on gzip-inflated size
_CHUNK = 65536


class _NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Only follow redirects that stay on the intended host, over https."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p = urllib.parse.urlsplit(newurl)
        if p.scheme != "https" or (p.hostname or "").lower() != _HOST:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_NoCrossHostRedirect())


def _read_capped(resp, deadline):
    """Read a response body in chunks, enforcing the byte cap and the
    wall-clock deadline (a slow-loris drip cannot run past the deadline)."""
    buf = io.BytesIO()
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("deadline exceeded mid-read")
        chunk = resp.read(_CHUNK)
        if not chunk:
            break
        if buf.tell() + len(chunk) > _MAX_BYTES:
            raise ValueError("response too large")
        buf.write(chunk)
    return buf.getvalue()


def _fetch_json(url, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0.5:
        raise TimeoutError("no time left")
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _UA,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
    )
    resp = _OPENER.open(req, timeout=min(remaining, 10.0))
    try:
        body = _read_capped(resp, deadline)
        if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
            body = gzip.GzipFile(fileobj=io.BytesIO(body)).read(_MAX_BYTES + 1)
            if len(body) > _MAX_BYTES:
                raise ValueError("gzip body too large")
    finally:
        resp.close()
    return json.loads(body.decode("utf-8", "replace"))


def _fmt_duration(seconds):
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return ""
    if s <= 0:
        return ""
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return ("%dh%02dm" % (h, m)) if h else ("%dm%02ds" % (m, sec))


def _quality(item):
    """Resolution → 'NNNp' when the payload carries one (rare in search hits)."""
    for f in (item.get("files") or []):
        res = (f or {}).get("resolution") or {}
        rid = res.get("id")
        if isinstance(rid, int) and rid > 0:
            return "%dp" % rid
    res = item.get("resolution")
    if isinstance(res, dict) and isinstance(res.get("id"), int) and res["id"] > 0:
        return "%dp" % res["id"]
    if isinstance(res, int) and res > 0:
        return "%dp" % res
    return ""


def search(query, category="", timeout=12):
    """Search the PeerTube fediverse via SepiaSearch. Never raises."""
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1, int(timeout))

        qs = urllib.parse.urlencode(
            {"search": query, "count": 30, "sort": "-match", "nsfw": "false"}
        )
        data = _fetch_json(_API + "?" + qs, deadline)
        items = data.get("data") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []

        out = []
        for item in items:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()
            if not url.startswith("http"):
                continue
            title = str(item.get("name") or "").strip()
            if not title:
                continue
            dur = _fmt_duration(item.get("duration"))
            if dur:
                title = "%s [%s]" % (title, dur)
            date = str(
                item.get("publishedAt")
                or item.get("originallyPublishedAt")
                or item.get("createdAt")
                or ""
            )[:10]
            out.append(
                {
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": url,
                    "date": date,
                    "category": category if category in CATEGORIES else "movies",
                    "quality": _quality(item),
                }
            )
            if len(out) >= _MAX_RESULTS:
                break
        return out
    except Exception:
        return []


if __name__ == "__main__":
    for q in ("nature documentary", "blender open movie", "zzzz-no-such-thing-qqq"):
        t0 = time.monotonic()
        hits = search(q, timeout=12)
        print("%-28r -> %2d hits in %.1fs" % (q, len(hits), time.monotonic() - t0))
        for h in hits[:3]:
            print("   %-58s %s %s %s" % (h["title"][:58], h["date"], h["quality"], h["url"][:60]))
        assert isinstance(hits, list)
        for h in hits:
            assert set(h) == {
                "title", "source", "seeders", "size", "magnet",
                "torrent_url", "url", "date", "category", "quality",
            }, h
            assert h["url"] and h["source"] == NAME
    print("self-test OK")
