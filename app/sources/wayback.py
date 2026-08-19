"""Wayback Machine (web.archive.org) source adapter — retrieve archived FILES,
including ones long gone from the live web, via the CDX capture index.

Strategy (per the VERIFIED Wayback CDX spec, 2026-07-12):
  * The query is treated as a URL / host / path PATTERN (Wayback CDX has no
    full-text search — it indexes captured URLs). A bare host becomes
    ``host/*`` (prefix); an explicit path keeps its prefix. Free-text queries
    with no host-like token yield [] (nothing sane to seed the CDX with).
  * We ask CDX for captures whose ``original`` URL ends in a file extension
    that matches the requested category (or a broad default set), keeping only
    ``statuscode:200`` rows and collapsing duplicates by ``urlkey``.
  * The returned ``url`` is the raw-bytes replay link
    ``https://web.archive.org/web/{timestamp}id_/{original}`` — the mandatory
    ``id_`` suffix makes Wayback serve the ORIGINAL bytes with no rewriting,
    so files removed from the live web are still downloadable.
  * category & quality are derived from the file extension (plus a resolution
    sniff for video); date comes from the capture timestamp.

Interface (shared by every adapter in this package):
    NAME = "<label>"
    def search(query, category="", timeout=12) -> list[dict]   # NEVER raises

Stdlib only (Python 3.11+). No third-party packages.
"""

import re
import json
import time
import socket
import urllib.parse
import urllib.request
import urllib.error

NAME = "Wayback Machine"

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
_CDX_HOST = "web.archive.org"
_CDX_URL = "https://web.archive.org/cdx/search/cdx"   # https: don't leak the query in cleartext
_REPLAY_FMT = "https://web.archive.org/web/%sid_/%s"

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
)

_MAX_RESULTS = 40
_CDX_LIMIT = 120          # over-fetch a little; collapse + trim down to _MAX_RESULTS
_READ_CAP = 8 * 1024 * 1024   # never buffer more than 8 MiB of CDX JSON
_CHUNK = 65536

# incoming category hint -> ordered list of file extensions to hunt for
_CATEGORY_EXTS = {
    "movie":    ["mkv", "mp4", "avi", "mov", "webm", "m4v"],
    "tv":       ["mkv", "mp4", "avi", "mov", "webm", "m4v"],
    "video":    ["mkv", "mp4", "avi", "mov", "webm", "m4v"],
    "music":    ["flac", "mp3", "m4a", "ogg", "wav", "aac"],
    "audio":    ["flac", "mp3", "m4a", "ogg", "wav", "aac"],
    "book":     ["pdf", "epub", "mobi", "djvu", "azw3", "cbz", "cbr"],
    "text":     ["pdf", "epub", "mobi", "djvu", "azw3", "cbz", "cbr"],
    "software": ["zip", "iso", "7z", "rar", "tar", "gz", "exe", "dmg", "apk"],
    "image":    ["jpg", "jpeg", "png", "gif", "tiff", "webp"],
}
# broad default net when no (or unknown) category hint is given
_DEFAULT_EXTS = [
    "pdf", "epub", "mobi", "djvu", "cbz", "cbr",
    "mp3", "flac", "m4a", "ogg", "wav",
    "mkv", "mp4", "avi", "mov", "webm",
    "zip", "rar", "7z", "iso", "tar", "gz",
]

# extension -> our category label (kept consistent with sibling adapters)
_EXT_CATEGORY = {}
for _c, _exts in {
    "movie":    ["mkv", "mp4", "avi", "mov", "webm", "m4v"],
    "music":    ["flac", "mp3", "m4a", "ogg", "wav", "aac"],
    "book":     ["pdf", "epub", "mobi", "djvu", "azw3", "cbz", "cbr"],
    "software": ["zip", "iso", "7z", "rar", "tar", "gz", "exe", "dmg", "apk"],
    "image":    ["jpg", "jpeg", "png", "gif", "tiff", "webp"],
}.items():
    for _e in _exts:
        _EXT_CATEGORY[_e] = _c

# resolution / release-quality tags worth surfacing for video/audio
_QUALITY_RE = re.compile(
    r"\b(2160p|1440p|1080p|720p|480p|4k|uhd|hdr|bluray|blu-ray|web-?dl|dvdrip|remux)\b",
    re.IGNORECASE,
)

# a host-like token: label(.label)+ with a TLD, optionally scheme + path, no spaces
_HOST_RE = re.compile(
    r"^(?:https?://)?(?P<hostpath>[a-z0-9](?:[a-z0-9\-._]*[a-z0-9])?\.[a-z]{2,}(?:[:/].*)?)$",
    re.IGNORECASE,
)
_EXT_FROM_PATH_RE = re.compile(r"\.([a-z0-9]{1,5})(?:[?#].*)?$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# SSRF guard: allow only same-host (web.archive.org) redirects
# ---------------------------------------------------------------------------
class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parts = urllib.parse.urlsplit(newurl)
        except Exception:
            return None
        # refuse redirects to any other host, and refuse an https->http downgrade
        if (parts.hostname or "").lower() != _CDX_HOST \
                or (parts.scheme or "").lower() != "https":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirect())


# ---------------------------------------------------------------------------
# query -> CDX url pattern
# ---------------------------------------------------------------------------
def _build_pattern(query):
    """Turn a user query into a CDX `url=` pattern, or None if it isn't
    host-like (Wayback can't full-text search arbitrary words)."""
    q = ("" if query is None else str(query)).strip()
    if not q or any(c.isspace() for c in q):
        return None
    m = _HOST_RE.match(q)
    if not m:
        return None
    hostpath = m.group("hostpath")
    # strip a trailing slash so we can append a clean wildcard
    if "*" in hostpath:
        return hostpath                    # caller already gave a wildcard
    if "/" in hostpath:
        base = hostpath.rstrip("/")
        return base + "/*"                 # path prefix
    return hostpath + "/*"                 # bare host -> everything under it


def _ext_list(category):
    exts = _CATEGORY_EXTS.get((category or "").strip().lower())
    return exts if exts else _DEFAULT_EXTS


def _ext_regex(exts):
    # match ...\.ext at the end of the path, tolerating a query/fragment suffix
    alt = "|".join(re.escape(e) for e in exts)
    return r".*\.(?:%s)(?:[?#].*)?$" % alt


# ---------------------------------------------------------------------------
# bounded HTTP GET (per-request socket timeout + total wall-clock deadline)
# ---------------------------------------------------------------------------
def _get(url, deadline):
    """GET `url`, reading in chunks and aborting the moment the wall-clock
    `deadline` passes (defends against a slow-loris server dribbling bytes).
    Returns decoded text, or raises on any failure/timeout."""
    remaining = deadline - time.monotonic()
    if remaining <= 0.5:
        raise TimeoutError("no time budget left")
    # per-recv socket timeout: bounded so a stalled socket can't outlast us
    sock_timeout = max(1.0, min(remaining, 10.0))
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "application/json, text/plain;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    resp = _OPENER.open(req, timeout=sock_timeout)
    try:
        buf = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("wall-clock deadline exceeded mid-read")
            try:
                chunk = resp.read1(_CHUNK)   # read1: one recv, so the deadline check fires
            except socket.timeout:
                raise TimeoutError("socket read timed out")
            if not chunk:
                break
            buf += chunk
            if len(buf) >= _READ_CAP:
                break            # enough; stop pulling more than we'll use
        return bytes(buf).decode("utf-8", "replace")
    finally:
        try:
            resp.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# result-field helpers
# ---------------------------------------------------------------------------
def _ext_of(original):
    m = _EXT_FROM_PATH_RE.search(urllib.parse.urlsplit(original).path or original)
    return m.group(1).lower() if m else ""


def _title_of(original):
    path = urllib.parse.urlsplit(original).path or ""
    name = path.rstrip("/").rsplit("/", 1)[-1]
    if not name:
        name = urllib.parse.urlsplit(original).hostname or original
    try:
        name = urllib.parse.unquote(name)
    except Exception:
        pass
    return name.strip() or original


def _quality_of(ext, original):
    m = _QUALITY_RE.search(original or "")
    if m:
        tag = m.group(1)
        up = tag.upper()
        return up if up in ("4K", "UHD", "HDR", "REMUX") or up.endswith("P") else tag.lower()
    return (ext or "").upper()


def _date_of(timestamp):
    ts = (timestamp or "").strip()
    if len(ts) >= 8 and ts[:8].isdigit():
        return "%s-%s-%s" % (ts[0:4], ts[4:6], ts[6:8])
    return ""


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------
def search(query, category="", timeout=12):
    """Search the Wayback CDX index for archived files. NEVER raises; returns
    a (possibly empty) list of result dicts with the shared schema."""
    try:
        deadline = time.monotonic() + max(1, int(timeout))

        pattern = _build_pattern(query)
        if not pattern:
            return []

        exts = _ext_list(category)
        params = [
            ("url", pattern),
            ("output", "json"),
            ("fl", "original,timestamp,mimetype,statuscode"),
            ("filter", "statuscode:200"),
            ("filter", "original:" + _ext_regex(exts)),
            ("collapse", "urlkey"),
            ("limit", str(_CDX_LIMIT)),
        ]
        # keep only '*' and '/' literal in the url pattern; everything else
        # (incl. the filter regex's ?, #, $, (), \) must be percent-encoded,
        # or a literal '#' would truncate the query string as a fragment.
        url = _CDX_URL + "?" + urllib.parse.urlencode(params, safe="*/")

        text = _get(url, deadline)
        if not text.strip():
            return []
        rows = json.loads(text)
        if not isinstance(rows, list) or len(rows) < 2:
            return []

        # row[0] is the header; map field name -> column index
        header = [str(h) for h in rows[0]]
        try:
            i_orig = header.index("original")
            i_ts = header.index("timestamp")
        except ValueError:
            return []
        i_mime = header.index("mimetype") if "mimetype" in header else -1
        i_stat = header.index("statuscode") if "statuscode" in header else -1

        allowed = set(exts)
        results = []
        seen = set()
        for row in rows[1:]:
            if not isinstance(row, list) or len(row) <= max(i_orig, i_ts):
                continue
            original = str(row[i_orig] or "").strip()
            timestamp = str(row[i_ts] or "").strip()
            if not original or not timestamp:
                continue
            if i_stat >= 0 and str(row[i_stat]).strip() != "200":
                continue
            ext = _ext_of(original)
            if ext not in allowed:
                continue
            replay = _REPLAY_FMT % (timestamp, original)
            if replay in seen:
                continue
            seen.add(replay)
            cat = _EXT_CATEGORY.get(ext, "other")
            mime = str(row[i_mime]).strip() if i_mime >= 0 else ""
            _ = mime  # mimetype is available but extension drives our category
            results.append({
                "title": _title_of(original),
                "source": NAME,
                "seeders": 0,          # HTTP replay, not a swarm
                "size": 0,             # CDX 'length' is compressed WARC bytes, not file size
                "magnet": "",
                "torrent_url": "",
                "url": replay,
                "date": _date_of(timestamp),
                "category": cat,
                "quality": _quality_of(ext, original),
            })
            if len(results) >= _MAX_RESULTS:
                break

        # every kept item has a non-empty url; guard anyway per the contract
        return [r for r in results if r["magnet"] or r["torrent_url"] or r["url"]]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# self-test — runs against the LIVE source
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _cases = [
        ("irs.gov/pub/irs-pdf/*", "book"),
        ("gutenberg.org/files/1342/*", "book"),
        ("nginx.org/download/*", "software"),
        ("not a url just words", ""),   # expect [] (no host-like token)
    ]
    for q, cat in _cases:
        t0 = time.monotonic()
        hits = search(q, category=cat, timeout=12)
        took = time.monotonic() - t0
        print("query=%r cat=%r -> %d results in %.1fs" % (q, cat, len(hits), took))
        for h in hits[:3]:
            assert set(h.keys()) == {
                "title", "source", "seeders", "size", "magnet",
                "torrent_url", "url", "date", "category", "quality",
            }, "bad keys: %r" % sorted(h.keys())
            print("   - %-40s | %-8s | %-6s | %s | %s"
                  % (h["title"][:40], h["category"], h["quality"],
                     h["date"], h["url"][:70]))
