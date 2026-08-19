"""Merged adapter over four large LEGAL open-file repositories:

  * Wikimedia Commons  — 100M+ freely-licensed media files (MediaWiki API)
  * Zenodo (CERN)      — open research datasets/papers/software with direct file links
  * Openverse (WP.org) — 800M+ CC-licensed images + audio (direct file URLs)
  * Project Gutenberg  — 75k+ public-domain books via the Gutendex API

All hits are normalized to the common result shape with a direct-download
``url``. Everything here is public-domain or openly licensed. Stdlib only.
"""

import concurrent.futures
import gzip
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "Open Repositories"

_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"

_MAX_RESULTS = 40      # overall cap
_PER_SOURCE = 12       # per-repository cap
_MAX_BYTES = 6 * 1024 * 1024  # response body cap (anti slow-loris/zip-bomb)

# The ONLY hosts this module will ever talk to (SSRF guard). File URLs we
# *return* may point elsewhere (upload.wikimedia.org, flickr CDN, ...) but we
# never fetch those ourselves.
_ALLOWED_HOSTS = frozenset(
    {
        "commons.wikimedia.org",
        "zenodo.org",
        "api.openverse.org",
        "gutendex.com",
        "www.gutenberg.org",  # gutendex format links host (returned, and safe target)
    }
)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects that leave the allow-listed hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or host not in _ALLOWED_HOSTS:
            raise urllib.error.HTTPError(
                newurl, code, "redirect to disallowed host blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirect())


def _fetch_json(url, deadline):
    """GET an allow-listed https URL, JSON-decode. Returns None on any problem.

    Per-request socket timeout AND a wall-clock deadline checked between
    chunk reads, so a slow-loris server cannot blow the budget.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in _ALLOWED_HOSTS:
        return None
    remaining = deadline - time.monotonic()
    if remaining < 0.5:
        return None
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _UA,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
    )
    try:
        with _OPENER.open(req, timeout=min(8.0, remaining)) as resp:
            chunks, total = [], 0
            while True:
                if time.monotonic() > deadline:
                    return None  # budget exhausted mid-body
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_BYTES:
                    return None
                chunks.append(chunk)
            body = b"".join(chunks)
            if resp.headers.get("Content-Encoding", "") == "gzip":
                import io as _io
                # bounded inflate — a tiny gzip can expand to gigabytes (zip bomb)
                body = gzip.GzipFile(fileobj=_io.BytesIO(body)).read(_MAX_BYTES + 1)
                if len(body) > _MAX_BYTES:
                    return None
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None


def _mk(title, size, url, date, category, quality):
    """Build one normalized result dict (all ten keys, exact shape)."""
    return {
        "title": str(title or "").strip(),
        "source": NAME,
        "seeders": 0,  # HTTP repositories, not swarms
        "size": int(size) if isinstance(size, (int, float)) and size > 0 else 0,
        "magnet": "",
        "torrent_url": "",
        "url": str(url or ""),
        "date": str(date or "")[:10],
        "category": category or "other",
        "quality": quality or "",
    }


_EXT_RE = re.compile(r"\.([A-Za-z0-9]{1,5})(?:$|[?#])")


def _ext_quality(name):
    m = _EXT_RE.search(name or "")
    return m.group(1).upper() if m else ""


# ---------------------------------------------------------------- Wikimedia
_COMMONS_FILETYPE = {
    "": "",
    "image": " filetype:bitmap|drawing",
    "music": " filetype:audio",
    "movie": " filetype:video",
    "tv": " filetype:video",
    "book": " filetype:pdf",
}


def _mime_category(mime):
    mime = (mime or "").lower()
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("audio/"):
        return "music"
    if mime.startswith("video/"):
        return "movie"
    if mime in ("application/pdf", "application/epub+zip"):
        return "book"
    return "other"


def _search_commons(query, category, deadline):
    ft = _COMMONS_FILETYPE.get(category)
    if ft is None:
        return []  # category this repo can't serve
    params = urllib.parse.urlencode(
        {
            "action": "query",
            "generator": "search",
            "gsrsearch": query + ft,
            "gsrnamespace": "6",  # File:
            "gsrlimit": str(_PER_SOURCE),
            "prop": "imageinfo",
            "iiprop": "url|size|timestamp|mime",
            "format": "json",
            "formatversion": "2",
        }
    )
    data = _fetch_json("https://commons.wikimedia.org/w/api.php?" + params, deadline)
    out = []
    for page in ((data or {}).get("query") or {}).get("pages") or []:
        info = (page.get("imageinfo") or [{}])[0]
        file_url = info.get("url") or ""
        if not file_url:
            continue
        title = re.sub(r"^File:", "", page.get("title") or "")
        mime = info.get("mime") or ""
        out.append(
            _mk(
                title,
                info.get("size") or 0,
                file_url,
                info.get("timestamp") or "",
                _mime_category(mime),
                (mime.rsplit("/", 1)[-1] or "").upper()[:8],
            )
        )
    return out


# ------------------------------------------------------------------ Zenodo
_ZENODO_TYPE = {
    "": "",
    "book": "publication",
    "software": "software",
    "image": "image",
    "movie": "video",
    "tv": "video",
    "music": "",  # no audio resource_type; search untyped
    "dataset": "dataset",
}
_ZENODO_CATEGORY = {
    "publication": "book",
    "poster": "book",
    "presentation": "book",
    "lesson": "book",
    "software": "software",
    "image": "image",
    "video": "movie",
    "dataset": "other",
}


def _search_zenodo(query, category, deadline):
    ztype = _ZENODO_TYPE.get(category)
    if ztype is None:
        return []
    params = {"q": query, "size": str(_PER_SOURCE)}
    if ztype:
        params["type"] = ztype
    data = _fetch_json(
        "https://zenodo.org/api/records?" + urllib.parse.urlencode(params), deadline
    )
    out = []
    for hit in ((data or {}).get("hits") or {}).get("hits") or []:
        meta = hit.get("metadata") or {}
        files = hit.get("files") or []
        if not files:
            continue  # closed-access record: no downloadable file
        first = files[0]
        file_url = (first.get("links") or {}).get("self") or ""
        if not file_url:
            continue
        title = meta.get("title") or first.get("key") or ""
        if len(files) > 1:
            title += " (%d files)" % len(files)
        rtype = ((meta.get("resource_type") or {}).get("type") or "").lower()
        out.append(
            _mk(
                title,
                sum(int(f.get("size") or 0) for f in files),
                file_url,
                meta.get("publication_date") or hit.get("created") or "",
                _ZENODO_CATEGORY.get(rtype, "other"),
                _ext_quality(first.get("key") or ""),
            )
        )
    return out


# --------------------------------------------------------------- Openverse
def _search_openverse(query, category, deadline):
    if category not in ("", "image", "music"):
        return []
    kind = "audio" if category == "music" else "images"
    params = urllib.parse.urlencode({"q": query, "page_size": str(_PER_SOURCE)})
    data = _fetch_json(
        "https://api.openverse.org/v1/%s/?%s" % (kind, params), deadline
    )
    out = []
    for item in (data or {}).get("results") or []:
        file_url = item.get("url") or item.get("foreign_landing_url") or ""
        if not file_url:
            continue
        quality = (item.get("filetype") or "").upper()
        if not quality and item.get("width") and item.get("height"):
            quality = "%dx%d" % (item["width"], item["height"])
        if not quality:
            quality = _ext_quality(file_url)
        out.append(
            _mk(
                item.get("title") or "",
                item.get("filesize") or 0,
                file_url,
                item.get("indexed_on") or "",
                "music" if kind == "audio" else "image",
                quality,
            )
        )
    return out


# --------------------------------------------------------------- Gutenberg
_GUTEN_FORMATS = (  # preference order: (mime, quality label)
    ("application/epub+zip", "EPUB"),
    ("application/pdf", "PDF"),
    ("text/plain; charset=us-ascii", "TXT"),
    ("text/plain; charset=utf-8", "TXT"),
    ("text/plain", "TXT"),
)


def _search_gutenberg(query, category, deadline):
    if category not in ("", "book"):
        return []
    data = _fetch_json(
        "https://gutendex.com/books/?"
        + urllib.parse.urlencode({"search": query}),
        deadline,
    )
    out = []
    for book in ((data or {}).get("results") or [])[:_PER_SOURCE]:
        formats = book.get("formats") or {}
        file_url, quality = "", ""
        for mime, label in _GUTEN_FORMATS:
            u = formats.get(mime)
            if u and (urllib.parse.urlsplit(u).hostname or "").lower() in _ALLOWED_HOSTS:
                file_url, quality = u, label
                break
        if not file_url:
            continue
        authors = ", ".join(a.get("name", "") for a in book.get("authors") or [])
        title = book.get("title") or ""
        if authors:
            title = "%s — %s" % (title, authors)
        out.append(_mk(title, 0, file_url, "", "book", quality))
    return out


_SEARCHERS = (_search_commons, _search_zenodo, _search_openverse, _search_gutenberg)


def search(query, category="", timeout=12):
    """Query all four repositories in parallel. Never raises; [] on error."""
    try:
        query = re.sub(r"\s+", " ", str(query or "")).strip()
        if not query:
            return []
        category = str(category or "").strip().lower()
        deadline = time.monotonic() + max(1, timeout)

        buckets = []
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(_SEARCHERS))
        try:
            futures = [
                pool.submit(fn, query, category, deadline) for fn in _SEARCHERS
            ]
            done, _ = concurrent.futures.wait(
                futures, timeout=max(0.0, deadline - time.monotonic())
            )
            for fut in done:
                try:
                    buckets.append(fut.result() or [])
                except Exception:
                    pass
        finally:
            # never block on stragglers past the wall-clock budget
            pool.shutdown(wait=False, cancel_futures=True)

        # Round-robin interleave so no single repo dominates the cap.
        merged, idx = [], 0
        while len(merged) < _MAX_RESULTS and any(idx < len(b) for b in buckets):
            for b in buckets:
                if idx < len(b) and len(merged) < _MAX_RESULTS:
                    merged.append(b[idx])
            idx += 1

        return [r for r in merged if r["magnet"] or r["torrent_url"] or r["url"]]
    except Exception:
        return []


if __name__ == "__main__":
    _KEYS = {
        "title", "source", "seeders", "size", "magnet",
        "torrent_url", "url", "date", "category", "quality",
    }
    for q, cat in (
        ("beethoven", ""),
        ("sherlock holmes", "book"),
        ("aurora borealis", "image"),
        ("climate model output", "dataset"),
    ):
        t0 = time.monotonic()
        hits = search(q, category=cat, timeout=12)
        took = time.monotonic() - t0
        assert all(set(h) == _KEYS for h in hits), "result shape drifted"
        assert all(h["url"] for h in hits), "empty-link item leaked through"
        print("query=%r cat=%r -> %d results in %.1fs" % (q, cat, len(hits), took))
        for h in hits[:4]:
            print(
                "   - %-55s | %-8s | %-8s | %11d B | %s"
                % (h["title"][:55], h["category"], h["quality"], h["size"], h["url"][:60])
            )
