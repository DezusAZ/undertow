"""Internet Archive (archive.org) source adapter — legal library of movies, audio, texts and software."""

import json
import re
import time
import socket
import urllib.parse
import urllib.request
import urllib.error
import concurrent.futures

NAME = "Internet Archive"

_SEARCH_URL = "https://archive.org/advancedsearch.php"
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
)
_MAX_RESULTS = 40

# incoming category hint -> archive.org mediatype filter
_HINT_TO_MEDIATYPE = {
    "movie": "movies",
    "tv": "movies",  # IA files TV under mediatype:movies
    "music": "audio",
    "book": "texts",
    "software": "software",
    "image": "image",
}

# archive.org mediatype -> our category
_MEDIATYPE_TO_CATEGORY = {
    "movies": "movie",
    "audio": "music",
    "texts": "book",
    "software": "software",
    "image": "image",
}

_QUALITY_RE = re.compile(
    r"\b(2160p|1440p|1080p|720p|480p|4k|uhd|flac|mp3|24[- ]?bit|dvdrip|bluray|blu-ray|web-?dl|pdf|epub)\b",
    re.IGNORECASE,
)

# Strip Solr/Lucene special characters that would break the query syntax.
_SOLR_SPECIALS_RE = re.compile(r'[+\-!(){}\[\]^"~*?:\\/&|]')


def _clean_query(query):
    q = _SOLR_SPECIALS_RE.sub(" ", "" if query is None else str(query))
    # Bare AND/OR/NOT are Solr operators; lowercase them so they act as words.
    words = [w.lower() if w in ("AND", "OR", "NOT") else w for w in q.split()]
    return " ".join(words)


def _first(value):
    """Fields like title occasionally come back as a list -> take first element."""
    if isinstance(value, list):
        return value[0] if value else ""
    return value


def _guess_quality(title):
    m = _QUALITY_RE.search(title or "")
    if not m:
        return ""
    tag = m.group(1)
    up = tag.upper()
    if up in ("4K", "UHD", "FLAC", "MP3", "PDF", "EPUB"):
        return up
    return tag.lower() if tag.lower().endswith("p") else tag


def _torrent_exists(url, timeout):
    """HEAD the .torrent URL (follows redirects); True only on a 2xx final answer."""
    try:
        req = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": _USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def search(query, category="", timeout=12):
    """Search archive.org. Returns a list of result dicts; never raises."""
    try:
        deadline = time.monotonic() + max(1, timeout)

        q = _clean_query(query)
        if not q:
            return []
        mediatype = _HINT_TO_MEDIATYPE.get((category or "").lower())
        if mediatype:
            q = "(%s) AND mediatype:%s" % (q, mediatype)

        params = [
            ("q", q),
            ("fl[]", "identifier"),
            ("fl[]", "title"),
            ("fl[]", "mediatype"),
            ("fl[]", "downloads"),
            ("fl[]", "item_size"),
            ("fl[]", "publicdate"),
            ("fl[]", "year"),
            ("sort[]", "downloads desc"),
            ("rows", str(_MAX_RESULTS)),
            ("page", "1"),
            ("output", "json"),
        ]
        url = _SEARCH_URL + "?" + urllib.parse.urlencode(params)

        req_timeout = min(8.0, max(2.0, deadline - time.monotonic() - 1.0))
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=req_timeout) as resp:
            buf, total = [], 0                 # bounded read: cap size AND wall-clock
            while total < 4 * 1024 * 1024:
                if time.monotonic() > deadline:
                    break
                chunk = resp.read(65536)
                if not chunk:
                    break
                buf.append(chunk)
                total += len(chunk)
            data = json.loads(b"".join(buf).decode("utf-8", "replace"))

        docs = (data.get("response") or {}).get("docs") or []

        results = []
        for doc in docs[:_MAX_RESULTS]:
            identifier = str(_first(doc.get("identifier")) or "").strip()
            if not identifier:
                continue
            title = str(_first(doc.get("title")) or identifier).strip()
            try:
                size = int(_first(doc.get("item_size")) or 0)
            except (TypeError, ValueError):
                size = 0
            date = str(
                _first(doc.get("publicdate")) or _first(doc.get("year")) or ""
            )
            mt = str(_first(doc.get("mediatype")) or "").lower()
            results.append(
                {
                    "title": title,
                    "source": NAME,
                    "seeders": 0,  # IA is HTTP/webseed-backed, not swarm-seeded
                    "size": size,
                    "magnet": "",
                    "torrent_url": "",  # filled in below only if verified to exist
                    "url": "https://archive.org/details/"
                    + urllib.parse.quote(identifier),
                    "date": date,
                    "category": _MEDIATYPE_TO_CATEGORY.get(mt, "other"),
                    "quality": _guess_quality(title),
                    "_identifier": identifier,  # temp, stripped before return
                }
            )

        # Verify the <id>_archive.torrent pattern per item (parallel HEADs),
        # bounded by whatever is left of the wall-clock budget.
        remaining = deadline - time.monotonic() - 0.5
        if results and remaining > 1.0:
            per_req = min(4.0, remaining)
            futures = {}
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=10)
            try:
                for r in results:
                    ident = r["_identifier"]
                    t_url = (
                        "https://archive.org/download/"
                        + urllib.parse.quote(ident)
                        + "/"
                        + urllib.parse.quote(ident)
                        + "_archive.torrent"
                    )
                    futures[pool.submit(_torrent_exists, t_url, per_req)] = (r, t_url)
                try:
                    for fut in concurrent.futures.as_completed(
                        futures, timeout=remaining
                    ):
                        r, t_url = futures[fut]
                        try:
                            if fut.result():
                                r["torrent_url"] = t_url
                        except Exception:
                            pass
                except concurrent.futures.TimeoutError:
                    pass  # unverified items keep torrent_url "" and rely on url
            finally:
                # Do NOT wait for stragglers — that would blow the wall-clock
                # budget (a `with` block's shutdown(wait=True) did exactly that).
                pool.shutdown(wait=False, cancel_futures=True)

        for r in results:
            r.pop("_identifier", None)
        # every result already has a non-empty url; keep the guard anyway
        return [r for r in results if r["magnet"] or r["torrent_url"] or r["url"]]
    except Exception:
        return []


if __name__ == "__main__":
    for q, cat in (("big buck bunny", "movie"), ("grateful dead 1977", "music")):
        t0 = time.monotonic()
        hits = search(q, category=cat, timeout=12)
        took = time.monotonic() - t0
        with_torrent = sum(1 for h in hits if h["torrent_url"])
        print(
            "query=%r cat=%r -> %d results (%d with .torrent) in %.1fs"
            % (q, cat, len(hits), with_torrent, took)
        )
        for h in hits[:3]:
            print(
                "   - %s | %s | %d bytes | torrent=%s"
                % (h["title"][:60], h["category"], h["size"], bool(h["torrent_url"]))
            )
