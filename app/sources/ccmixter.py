"""ccMixter source adapter — Creative-Commons-licensed music via the public query API.

Endpoint: https://ccmixter.org/api/query?f=json&search=<q>&limit=N&offset=M
Returns a JSON list of uploads; each upload carries files[] with direct
download_url links (MP3/FLAC/ZIP), sizes, and a formatted upload date.
No API key required. Direct HTTPS downloads, not torrents.

Server quirk: ccMixter echoes the whole JSON payload in an `X-JSON:` response
header (prototype.js era). With limit >= ~20 that one header line blows past
http.client's 65536-byte header-line cap and Python raises LineTooLong, so we
page with small limits (10/page) and combine pages instead.
"""

import gzip
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "ccMixter"
CATEGORIES = {"music"}

_HOST = "ccmixter.org"
_API_URL = "https://ccmixter.org/api/query"
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
)
_MAX_RESULTS = 40
_PAGE_SIZE = 10  # bigger pages make the server's X-JSON header line explode
_MAX_BODY = 4 * 1024 * 1024  # cap raw response body at 4 MB
_MAX_INFLATED = 8 * 1024 * 1024  # cap gzip inflate at 8 MB
_CHUNK = 65536

_WS_RE = re.compile(r"\s+")
# upload_date_format looks like: "Sun, Jul 5, 2026 @ 3:50 AM"
_DATE_RE = re.compile(r"\b([A-Za-z]{3})\s+(\d{1,2}),\s+(\d{4})")
_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _same_host(host):
    h = (host or "").lower()
    return h == _HOST or h.endswith("." + _HOST)


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Only follow redirects that stay on the intended HTTPS host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or not _same_host(parsed.hostname):
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


def _iso_date(formatted):
    """'Sun, Jul 5, 2026 @ 3:50 AM' -> '2026-07-05' ('' if unparseable)."""
    m = _DATE_RE.search(formatted or "")
    if not m:
        return ""
    month = _MONTHS.get(m.group(1).lower())
    if not month:
        return ""
    return "%s-%02d-%02d" % (m.group(3), month, int(m.group(2)))


def _https_site_url(u):
    """Keep only http(s) URLs on ccmixter.org, upgraded to https."""
    if not isinstance(u, str):
        return ""
    u = u.strip()
    if u.startswith("http://"):
        u = "https://" + u[len("http://"):]
    if not u.startswith("https://"):
        return ""
    if not _same_host(urllib.parse.urlparse(u).hostname):
        return ""
    return u


def _pick_file(files):
    """Choose the primary audio file: lowest file_order with a usable
    download_url, preferring mp3/flac over stems and zip packs."""
    best = None
    best_rank = None
    for f in files or []:
        if not isinstance(f, dict):
            continue
        dl = _https_site_url(f.get("download_url"))
        if not dl:
            continue
        fmt = f.get("file_format_info") or {}
        ext = ""
        if isinstance(fmt, dict):
            ext = str(fmt.get("default-ext") or "").lower()
        if not ext:
            ext = str(f.get("file_name") or "").rsplit(".", 1)[-1].lower()
        pref = {"mp3": 0, "flac": 0}.get(ext, 1)  # audio first, packs later
        try:
            order = int(f.get("file_order") or 0)
        except (TypeError, ValueError):
            order = 0
        rank = (pref, order)
        if best_rank is None or rank < best_rank:
            best_rank = rank
            size = f.get("file_rawsize")
            best = (dl, ext, size if isinstance(size, int) and size > 0 else 0)
    return best  # (download_url, ext, size_bytes) or None


def search(query, category="", timeout=12):
    """Search ccMixter for CC-licensed music. Returns [] on any error; never raises."""
    try:
        q = _WS_RE.sub(" ", "" if query is None else str(query)).strip()
        if not q:
            return []
        if category and category not in CATEGORIES:
            return []

        deadline = time.monotonic() + max(1, timeout)

        uploads = []
        for offset in range(0, _MAX_RESULTS, _PAGE_SIZE):
            if time.monotonic() >= deadline:
                break
            params = urllib.parse.urlencode(
                {"f": "json", "search": q, "limit": _PAGE_SIZE, "offset": offset}
            )
            try:
                body = _fetch(_API_URL + "?" + params, deadline)
                page = json.loads(body) if body else []
            except Exception:
                break  # keep whatever pages we already have
            if not isinstance(page, list) or not page:
                break
            uploads.extend(page)
            if len(page) < _PAGE_SIZE:
                break  # last page

        results = []
        seen_ids = set()
        for up in uploads:
            if not isinstance(up, dict):
                continue
            uid = up.get("upload_id")
            if uid is not None:
                if uid in seen_ids:
                    continue
                seen_ids.add(uid)
            title = _WS_RE.sub(" ", str(up.get("upload_name") or "")).strip()
            if not title:
                continue
            artist = _WS_RE.sub(
                " ", str(up.get("user_real_name") or up.get("user_name") or "")
            ).strip()
            if artist:
                title = "%s - %s" % (artist, title)

            picked = _pick_file(up.get("files"))
            if picked:
                url, ext, size = picked
            else:
                url = _https_site_url(up.get("file_page_url"))
                ext, size = "", 0
            if not url:
                continue

            if ext == "mp3":
                quality = "MP3"
            elif ext == "flac":
                quality = "FLAC"
            elif ext:
                quality = ext.upper()
            else:
                quality = ""

            results.append(
                {
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": size,
                    "magnet": "",
                    "torrent_url": "",
                    "url": url,
                    "date": _iso_date(up.get("upload_date_format")),
                    "category": "music",
                    "quality": quality,
                }
            )
            if len(results) >= _MAX_RESULTS:
                break
        return results
    except Exception:
        return []


if __name__ == "__main__":
    for q in ("jazz", "piano ambient"):
        hits = search(q, timeout=15)
        print(f"query={q!r} -> {len(hits)} results")
        for h in hits[:3]:
            print("  ", h["date"], h["quality"], h["size"], h["title"][:60])
            print("     ", h["url"])
        keys = {
            "title", "source", "seeders", "size", "magnet",
            "torrent_url", "url", "date", "category", "quality",
        }
        assert all(set(h) == keys for h in hits), "bad result keys"
        assert all(h["url"] for h in hits), "empty url"
        assert all(h["source"] == NAME for h in hits), "bad source"
        assert all(h["category"] == "music" for h in hits), "bad category"
        assert all(isinstance(h["size"], int) for h in hits), "bad size type"
    print("self-test: mismatched-category ->", len(search("test", category="movies")))
    print("self-test: empty query ->", len(search("")))
    print("self-test: tiny timeout ->", len(search("jazz", timeout=1)))
    print("OK")
