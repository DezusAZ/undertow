"""NASA Image and Video Library source adapter — public-domain imagery via the open images-api.nasa.gov JSON API (no key required)."""

import gzip
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "NASA Images"
CATEGORIES = {"other"}

_API_HOST = "images-api.nasa.gov"
_ASSET_HOSTS = {"images-api.nasa.gov", "images-assets.nasa.gov"}
_API_URL = "https://images-api.nasa.gov/search"
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
)
_MAX_RESULTS = 40
_MAX_BODY = 4 * 1024 * 1024  # cap raw response body at 4 MB
_MAX_INFLATED = 8 * 1024 * 1024  # cap gzip inflate at 8 MB
_CHUNK = 65536

_WS_RE = re.compile(r"\s+")


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Only follow redirects that stay on the intended NASA HTTPS hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in _ASSET_HOSTS:
            raise urllib.error.HTTPError(
                newurl, code, "redirect to unexpected host blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirects())


def _read_capped(resp, deadline):
    """Read a response body incrementally, bounded by size and wall clock."""
    buf = io.BytesIO()
    while True:
        if time.monotonic() >= deadline:
            break
        chunk = resp.read(_CHUNK)
        if not chunk:
            break
        buf.write(chunk)
        if buf.tell() >= _MAX_BODY:
            break
    data = buf.getvalue()
    if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                data = gz.read(_MAX_INFLATED)
        except OSError:
            return b""
    return data


def _fetch(url, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0.5:
        return b""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "application/json, */*;q=0.5",
            "Accept-Encoding": "gzip",
        },
    )
    resp = _OPENER.open(req, timeout=min(remaining, 12))
    try:
        return _read_capped(resp, deadline)
    finally:
        resp.close()


def _clean_href(href):
    """Normalize an asset link to HTTPS on a NASA host; '' if unusable."""
    href = (href or "").strip()
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    elif href.startswith("http://"):
        href = "https://" + href[len("http://"):]
    elif not href.startswith("https://"):
        return ""
    parsed = urllib.parse.urlparse(href)
    if parsed.hostname not in _ASSET_HOSTS:
        return ""
    # Some asset filenames contain spaces; keep the URL well-formed.
    return href.replace(" ", "%20")


def _item_url(item):
    """Best asset link for an item: links[0].href, else the collection asset."""
    links = item.get("links")
    if isinstance(links, list):
        for link in links:
            if not isinstance(link, dict):
                continue
            href = _clean_href(link.get("href"))
            if href:
                return href
    return _clean_href(item.get("href"))


def search(query, category="", timeout=12):
    """Search the NASA image library. Returns [] on any error; never raises."""
    try:
        q = _WS_RE.sub(" ", "" if query is None else str(query)).strip()
        if not q:
            return []
        if category and category not in CATEGORIES:
            return []

        deadline = time.monotonic() + max(1, timeout)
        params = urllib.parse.urlencode(
            {
                "q": q,
                "media_type": "image",
                "page": 1,
                "page_size": min(_MAX_RESULTS * 2, 100),
            }
        )
        body = _fetch(_API_URL + "?" + params, deadline)
        if not body:
            return []

        payload = json.loads(body)
        items = payload.get("collection", {}).get("items", [])
        if not isinstance(items, list):
            return []

        results = []
        for item in items:
            if not isinstance(item, dict):
                continue
            data = item.get("data")
            if not isinstance(data, list) or not data or not isinstance(data[0], dict):
                continue
            meta = data[0]
            title = _WS_RE.sub(" ", str(meta.get("title") or "")).strip()
            url = _item_url(item)
            if not title or not url:
                continue
            date = str(meta.get("date_created") or "").strip()
            results.append(
                {
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": url,
                    "date": date[:10] if date else "",
                    "category": "other",
                    "quality": "IMG",
                }
            )
            if len(results) >= _MAX_RESULTS:
                break
        return results
    except Exception:
        return []


if __name__ == "__main__":
    for q in ("apollo 11", "jupiter great red spot"):
        hits = search(q, timeout=15)
        print(f"query={q!r} -> {len(hits)} results")
        for h in hits[:3]:
            print("  ", h["date"], h["title"][:70])
            print("     ", h["url"])
        keys = {
            "title", "source", "seeders", "size", "magnet",
            "torrent_url", "url", "date", "category", "quality",
        }
        assert all(set(h) == keys for h in hits), "bad result keys"
        assert all(h["url"] for h in hits), "empty url"
        assert all(h["source"] == NAME for h in hits), "bad source"
        assert all(h["category"] == "other" and h["quality"] == "IMG" for h in hits)
    print("self-test: mismatched-category ->", len(search("moon", category="music")))
    print("self-test: empty query ->", len(search("")))
    print("self-test: nonsense query ->", len(search("zzqx-no-such-thing-9917")))
    print("OK")
