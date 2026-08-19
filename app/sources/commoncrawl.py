"""Common Crawl CDX index adapter — finds direct-download file URLs the crawler
has seen on the live web (status 200), filtered by file extension.

The CDX API is URL-pattern based (no free-text search), so the query is mapped
to URL patterns:
  * full URL          -> prefix match on host/path
  * bare domain       -> '*.domain' (domain incl. subdomains)
  * plain keyword(s)  -> '*.<token>.com|org|net' candidates, extra tokens
                         become substring regex filters on the URL

Verified live 2026-07-12 (index CC-MAIN-2026-25). NDJSON responses, sometimes
gzipped; reads are streamed against a wall-clock deadline with raw and
decompressed size caps.
"""

import gzip
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "Common Crawl"

_COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
_ALLOWED_HOST = "index.commoncrawl.org"
_FALLBACK_INDEXES = ["https://index.commoncrawl.org/CC-MAIN-2026-25-index"]

_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
       "Gecko/20100101 Firefox/128.0")

_MAX_RESULTS = 40
_PER_QUERY_LIMIT = 40
_RAW_CAP = 4 * 1024 * 1024        # max compressed/raw bytes read per response
_DECOMP_CAP = 8 * 1024 * 1024     # max decompressed bytes kept per response
_CHUNK = 65536

# extension -> our category
_EXT_CATEGORY = {
    "pdf": "book", "epub": "book", "mobi": "book", "djvu": "book",
    "azw3": "book", "cbz": "book", "cbr": "book",
    "mp3": "music", "flac": "music", "ogg": "music", "wav": "music",
    "m4a": "music", "opus": "music", "aac": "music",
    "mp4": "movie", "mkv": "movie", "avi": "movie", "webm": "movie",
    "mov": "movie", "mpg": "movie", "mpeg": "movie", "m4v": "movie",
    "zip": "software", "rar": "software", "7z": "software", "gz": "software",
    "xz": "software", "bz2": "software", "iso": "software", "exe": "software",
    "msi": "software", "dmg": "software", "apk": "software",
    "deb": "software", "rpm": "software", "jar": "software",
    "jpg": "image", "jpeg": "image", "png": "image", "gif": "image",
    "webp": "image", "svg": "image", "bmp": "image", "tiff": "image",
}

# category hint -> extensions to filter on
_HINT_EXTS = {
    "movie": ("mp4", "mkv", "avi", "webm", "mov", "m4v", "mpg"),
    "tv": ("mp4", "mkv", "avi", "webm"),
    "music": ("mp3", "flac", "ogg", "m4a", "opus", "wav"),
    "book": ("pdf", "epub", "mobi", "djvu", "azw3"),
    "software": ("zip", "rar", "7z", "iso", "exe", "msi", "dmg",
                 "apk", "deb", "rpm", "gz", "xz"),
    "image": ("jpg", "jpeg", "png", "gif", "webp"),
}
_DEFAULT_EXTS = ("pdf", "epub", "zip", "mp3", "mp4", "mkv", "flac",
                 "iso", "rar", "7z", "djvu", "mobi")

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.I)
_TOKEN_RE = re.compile(r"[a-z0-9-]+", re.I)


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Only follow redirects that stay on the intended https host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https" or parts.hostname != _ALLOWED_HOST:
            return None  # refuse -> urlopen raises HTTPError
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirects())


def _remaining(deadline):
    return deadline - time.monotonic()


def _http_get(url, deadline):
    """Streamed GET with per-request timeout + deadline checks between reads.

    Returns decompressed body bytes (possibly truncated at the caps), or b''.
    Only ever contacts https://index.commoncrawl.org.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != _ALLOWED_HOST:
        return b""
    budget = _remaining(deadline)
    if budget < 0.7:
        return b""
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept-Encoding": "gzip",
        "Accept": "application/json, text/plain, */*",
    })
    raw = b""
    try:
        resp = _OPENER.open(req, timeout=min(8.0, budget))
    except Exception:
        return b""
    try:
        chunks, total = [], 0
        while total < _RAW_CAP:
            left = _remaining(deadline)
            if left <= 0.2:
                break
            # tighten the socket timeout to what's left so one slow read
            # can't blow the wall-clock budget (best-effort, private attrs)
            try:
                resp.fp.raw._sock.settimeout(min(3.0, left))
            except Exception:
                pass
            try:
                chunk = resp.read(min(_CHUNK, _RAW_CAP - total))
            except Exception:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        enc = (resp.headers.get("Content-Encoding") or "").lower()
    except Exception:
        enc = ""
    finally:
        try:
            resp.close()
        except Exception:
            pass
    if not raw:
        return b""
    if "gzip" in enc or raw[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                return gz.read(_DECOMP_CAP)
        except Exception:
            # truncated gzip stream: salvage what decompressed cleanly
            try:
                dec = gzip._GzipReader(io.BytesIO(raw))  # noqa: SLF001
                out = io.BytesIO()
                while out.tell() < _DECOMP_CAP:
                    try:
                        piece = dec.read(_CHUNK)
                    except Exception:
                        break        # truncated stream: keep what decoded cleanly
                    if not piece:
                        break
                    out.write(piece)
                return out.getvalue()
            except Exception:
                return b""
    return raw


def _fetch_with_retry(url, deadline):
    """One retry with a short backoff — the CDX server sheds load with
    503/connection-refused; a single polite retry usually gets through."""
    body = _http_get(url, deadline)
    if not body and _remaining(deadline) > 3.0:
        time.sleep(min(1.0, _remaining(deadline) - 2.0))
        body = _http_get(url, deadline)
    return body


_collinfo_cache = {"ts": 0.0, "apis": []}


def _discover_indexes(deadline, max_indexes=2):
    """Newest CDX api endpoints from collinfo.json (element 0 = newest).
    Cached for an hour — new indexes only appear ~monthly."""
    now = time.monotonic()
    if _collinfo_cache["apis"] and now - _collinfo_cache["ts"] < 3600:
        return _collinfo_cache["apis"][:max_indexes]
    body = _fetch_with_retry(_COLLINFO_URL, deadline)
    apis = []
    try:
        for coll in json.loads(body.decode("utf-8", "replace")):
            api = coll.get("cdx-api") or ""
            parts = urllib.parse.urlsplit(api)
            if parts.scheme == "https" and parts.hostname == _ALLOWED_HOST:
                apis.append(api)
            if len(apis) >= max_indexes:
                break
    except Exception:
        pass
    if apis:
        _collinfo_cache["ts"] = now
        _collinfo_cache["apis"] = apis
    return apis or list(_FALLBACK_INDEXES)


def _build_patterns(query):
    """Map a free-text query to CDX url patterns + extra url-regex filters."""
    q = (query or "").strip()
    if not q:
        return [], []
    # full URL -> host/path prefix
    if re.match(r"^https?://", q, re.I):
        try:
            p = urllib.parse.urlsplit(q)
            host = (p.hostname or "").strip(".")
            if not host:
                return [], []
            path = p.path.rstrip("*").rstrip("/")
            if path:
                return ["%s%s/*" % (host, path)], []
            return ["*.%s" % host], []
        except Exception:
            return [], []
    tokens = _TOKEN_RE.findall(q.lower())
    first = q.split()[0].rstrip("/").lower()
    # bare domain (possibly with a path) -> domain / prefix match
    if _DOMAIN_RE.match(first.split("/")[0]) and "." in first:
        extra = [re.escape(t) for t in tokens
                 if t not in first.split("/")[0].split(".")
                 and t not in first]
        if "/" in first:
            return [first + "/*"], extra[:2]
        return ["*.%s" % first], extra[:2]
    if not tokens:
        return [], []
    # plain keywords -> guess domains from the first token
    slug = tokens[0]
    extra = [re.escape(t) for t in tokens[1:3]]
    pats = ["*.%s.%s" % (slug, tld) for tld in ("com", "org", "net")]
    return pats, extra


def _cdx_url(api, pattern, exts, extra_filters):
    ext_re = r"(?i).*\.(%s)([?#].*)?$" % "|".join(exts)
    params = [
        ("url", pattern),
        ("output", "json"),
        ("limit", str(_PER_QUERY_LIMIT)),
        ("filter", "=status:200"),
        ("filter", "~url:" + ext_re),
        ("fl", "url,timestamp,mime,status,length"),
    ]
    for f in extra_filters:
        params.append(("filter", "~url:(?i).*%s.*" % f))
    return api + "?" + urllib.parse.urlencode(params)


def _title_from_url(url):
    try:
        path = urllib.parse.urlsplit(url).path
        name = urllib.parse.unquote(path.rsplit("/", 1)[-1]).strip()
        return name or url
    except Exception:
        return url


def _row_to_result(row):
    url = row.get("url") or ""
    if not url.lower().startswith(("http://", "https://")):
        return None
    m = re.search(r"\.([a-z0-9]{1,5})(?:[?#].*)?$", url, re.I)
    ext = m.group(1).lower() if m else ""
    ts = row.get("timestamp") or ""
    date = ""
    if re.match(r"^\d{8}", ts):
        date = "%s-%s-%s" % (ts[0:4], ts[4:6], ts[6:8])
    try:
        size = max(0, int(row.get("length") or 0))  # WARC record size (approx)
    except Exception:
        size = 0
    return {
        "title": _title_from_url(url),
        "source": NAME,
        "seeders": 0,
        "size": size,
        "magnet": "",
        "torrent_url": "",
        "url": url,
        "date": date,
        "category": _EXT_CATEGORY.get(ext, "other"),
        "quality": ext.upper(),
    }


def search(query, category="", timeout=12):
    """Search the Common Crawl CDX index. Never raises; [] on any failure."""
    try:
        deadline = time.monotonic() + max(1, timeout)
        patterns, extra_filters = _build_patterns(query)
        if not patterns:
            return []
        exts = _HINT_EXTS.get((category or "").lower(), _DEFAULT_EXTS)

        apis = _discover_indexes(deadline, max_indexes=2)

        results, seen = [], set()
        first_query = True
        # newest index across all patterns first, then second index
        for api in apis:
            for pattern in patterns:
                if len(results) >= _MAX_RESULTS or _remaining(deadline) < 1.0:
                    return results[:_MAX_RESULTS]
                if not first_query:  # be polite: server 503s under load
                    time.sleep(min(0.4, max(0.0, _remaining(deadline) - 1.5)))
                first_query = False
                body = _fetch_with_retry(
                    _cdx_url(api, pattern, exts, extra_filters), deadline)
                for line in body.splitlines():
                    line = line.strip()
                    if not line.startswith(b"{"):
                        continue
                    try:
                        row = json.loads(line.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    item = _row_to_result(row)
                    if item is None or item["url"] in seen:
                        continue
                    seen.add(item["url"])
                    results.append(item)
                    if len(results) >= _MAX_RESULTS:
                        break
            # only fall through to the older index when the newest one
            # left us short on hits
            if len(results) >= 10:
                break
        return results[:_MAX_RESULTS]
    except Exception:
        return []


if __name__ == "__main__":
    _KEYS = {"title": str, "source": str, "seeders": int, "size": int,
             "magnet": str, "torrent_url": str, "url": str, "date": str,
             "category": str, "quality": str}

    def _check(items):
        for it in items:
            assert set(it) == set(_KEYS), "key mismatch: %s" % sorted(it)
            for k, t in _KEYS.items():
                assert isinstance(it[k], t), "%s not %s" % (k, t)
            assert it["magnet"] or it["torrent_url"] or it["url"]

    for q, cat in [("gutenberg", "book"),
                   ("irs.gov/pub", ""),
                   ("ubuntu", "software"),
                   ("", ""),
                   ("zzqxjvnonexistentdomain12345", "")]:
        t0 = time.monotonic()
        out = search(q, cat, timeout=12)
        dt = time.monotonic() - t0
        _check(out)
        print("query=%-30r cat=%-8r -> %2d results in %4.1fs" %
              (q, cat, len(out), dt))
        for it in out[:3]:
            print("   [%s|%s|%s] %s" % (it["category"], it["quality"],
                                        it["date"], it["url"][:100]))
    print("self-test OK")
