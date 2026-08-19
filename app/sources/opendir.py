"""Open-directory + dork-driven FILE discovery — the flagship adapter.

WHAT IT DOES
------------
Uses the sibling dork library (:mod:`_dorks`) to form ``open_directory`` and
``filetype`` search dorks for the user's query, runs them through the headless
``transport_search`` back-ends, then for each promising open-directory hit it
FETCHES and PARSES the Apache/nginx/IIS/http.server autoindex listing to
enumerate the *real, directly-downloadable files* inside (URL per file, plus
size/date when the listing shows them, and a category+quality guessed from the
extension and name). The direct ``filetype:`` hits the transports return are
emitted too. This surfaces files that never appear on the surface web.

SCOPE — LEGAL FILE/CONTENT DISCOVERY ONLY
-----------------------------------------
This finds openly-shared, non-copyright/public files: open directories, public
documents, datasets, public-domain media, research data, software. It is built
strictly for FILE discovery. It deliberately does NOT include or facilitate any
technique aimed at exposed credentials, API keys, .env/.git, secret database
dumps, admin/login panels, vuln/CVE endpoints, unsecured cameras/IoT/SCADA, or
PII. The dork templates it uses (from :mod:`_dorks`) are file-finding only, and
this module only ever enumerates ordinary downloadable file extensions.

SAFETY
------
* stdlib only (Python 3.11): urllib, json, re, html, time, socket, gzip, io,
  ipaddress, urllib.parse, concurrent.futures.
* NEVER raises — returns [] on any error (per the adapter contract).
* SSRF-hardened: every URL fetched (and every redirect target) must be http(s)
  AND resolve to a *globally-routable* IP — loopback/private/link-local/CGNAT/
  reserved addresses are refused, so a hostile search result cannot pivot the
  request at internal services.
* Slow-loris-proof: each request honours a per-request socket timeout AND the
  overall wall-clock deadline is re-checked between every read, with a hard cap
  on bytes read, so a trickling server can never exceed the time budget.
* Only outbound HTTP(S) GETs; no shell, no non-HTTP schemes, bounded redirects.

INTERFACE
---------
NAME = "Open Directories"
search(query, category="", timeout=12) -> list[dict]
Each dict has EXACTLY: title, source, seeders, size, magnet, torrent_url, url,
date, category, quality. At least one of magnet/torrent_url/url is non-empty.
"""

import gzip
import html as _html
import io
import ipaddress
import re
import socket
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import _dorks

NAME = "Open Directories"

_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
       "Gecko/20100101 Firefox/128.0")

# --- tuning knobs -----------------------------------------------------------
_MAX_RESULTS = 40           # hard cap on returned items
_PER_DIR_CAP = 20           # max files harvested from a single directory tree
_MAX_CANDIDATE_DIRS = 8     # how many open-dir hits we bother to fetch
_MAX_DIRECT = 25            # cap on direct filetype: hits kept
_MAX_FETCHES = 15           # global page-fetch budget (top dirs + descents)
_PER_REQ = 6.0              # per-request socket timeout ceiling (seconds)
_MAX_PAGE_BYTES = 3_000_000  # never read more than this from one page
_DESCEND_DEPTH = 1          # how many subdirectory levels to follow

# --- extension -> (category, downloadable?) --------------------------------
_AUDIO = "mp3 flac m4a aac ogg oga wav wma opus alac ape aiff aif".split()
_VIDEO = "mkv mp4 avi mov webm wmv flv m4v mpg mpeg mpe ts ogv vob divx".split()
_BOOK = ("pdf epub mobi azw azw3 djvu djv cbz cbr fb2 lit txt "
         "doc docx rtf odt").split()
_DATA = ("csv tsv json xml parquet xlsx xls ods sqlite db sql "
         "geojson yaml yml").split()
_IMAGE = "jpg jpeg png gif webp bmp tif tiff svg heic".split()
_SOFT = "iso img exe msi dmg apk deb rpm appimage pkg jar bin".split()
_ARCHIVE = "zip rar 7z tar gz tgz bz2 xz zst".split()

_CATEGORY_BY_EXT = {}
for _e in _AUDIO:
    _CATEGORY_BY_EXT[_e] = "music"
for _e in _VIDEO:
    _CATEGORY_BY_EXT[_e] = "movie"
for _e in _BOOK:
    _CATEGORY_BY_EXT[_e] = "book"
for _e in _DATA:
    _CATEGORY_BY_EXT[_e] = "dataset"
for _e in _IMAGE:
    _CATEGORY_BY_EXT[_e] = "image"
for _e in _SOFT:
    _CATEGORY_BY_EXT[_e] = "software"
for _e in _ARCHIVE:
    _CATEGORY_BY_EXT[_e] = "other"
_ALL_EXTS = frozenset(_CATEGORY_BY_EXT)

# category hint -> extensions to build filetype dorks for
_EXTS_FOR_HINT = {
    "movie": ["mkv", "mp4", "avi"],
    "tv": ["mkv", "mp4", "avi"],
    "music": ["flac", "mp3", "m4a"],
    "book": ["pdf", "epub", "mobi"],
    "software": ["iso", "zip", "exe"],
    "image": ["jpg", "png", "gif"],
    "dataset": ["csv", "json", "xlsx"],
    "data": ["csv", "json", "xml"],
}
_DEFAULT_EXTS = ["pdf", "zip", "mp3"]

_QUALITY_RE = re.compile(
    r"\b(2160p|1440p|1080p|720p|480p|4k|uhd|hdr|flac|mp3|24[- ]?bit|"
    r"dvdrip|bluray|blu-ray|web-?dl|remux|hevc|x265|x264|pdf|epub)\b",
    re.IGNORECASE,
)

_TAG_RE = re.compile(r"<[^>]+>")
_A_RE = re.compile(
    r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)
_DATE_APACHE = re.compile(
    r"\d{1,2}[- ][A-Za-z]{3}[- ]\d{4}\s+\d{2}:\d{2}")
_DATE_ISO = re.compile(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}")
_SIZE_SUF = re.compile(r"(\d+(?:\.\d+)?)\s*([KMGTP])i?B?\b", re.I)
_SIZE_BYTES = re.compile(r"(?<!\d)(\d{3,})(?!\d)\s*$")
_MULT = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3,
         "T": 1024 ** 4, "P": 1024 ** 5}

_SKIP_NAMES = frozenset((
    "parent directory", "..", ".", "name", "last modified", "size",
    "description", "[to parent directory]", "modified",
))


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _clean(s):
    if not s:
        return ""
    return re.sub(r"\s+", " ", _html.unescape(_TAG_RE.sub(" ", s))).strip()


def _ext_of(url):
    try:
        path = urllib.parse.urlsplit(url).path
    except Exception:
        return ""
    seg = path.rstrip("/").rsplit("/", 1)[-1]
    if "." not in seg:
        return ""
    ext = seg.rsplit(".", 1)[-1].lower()
    if 1 <= len(ext) <= 6 and ext.isalnum():
        return ext
    return ""


def _guess_quality(title):
    m = _QUALITY_RE.search(title or "")
    if not m:
        return ""
    tag = m.group(1)
    up = tag.upper()
    if up in ("4K", "UHD", "HDR", "FLAC", "MP3", "PDF", "EPUB", "HEVC",
              "X265", "X264", "REMUX"):
        return up
    return tag.lower()


def _tokens(query):
    return [t for t in re.findall(r"[a-z0-9]+", (query or "").lower())
            if len(t) >= 3]


# ---------------------------------------------------------------------------
# SSRF-safe HTTP GET (public hosts only, bounded reads, no arbitrary redirects)
# ---------------------------------------------------------------------------
def _ip_is_public(ip):
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    # is_global excludes private, loopback, link-local, reserved,
    # unspecified and shared (100.64/10 CGNAT / Tailscale) ranges.
    return bool(addr.is_global)


def _host_is_public(host):
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        ip = info[4][0]
        if not _ip_is_public(ip):
            return False
    return True


def _url_is_safe(url):
    try:
        sp = urllib.parse.urlsplit(url)
    except Exception:
        return False
    if sp.scheme not in ("http", "https"):
        return False
    return _host_is_public(sp.hostname)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to public http(s) hosts; refuse anything else."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _url_is_safe(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirect())


def _fetch(url, deadline):
    """GET `url` safely. Return decoded text or None. Never raises.

    Enforces both a per-request socket timeout AND the overall wall-clock
    `deadline`, re-checking it between reads and capping total bytes, so a
    slow-loris server cannot blow the time budget.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0.3:
        return None
    if not _url_is_safe(url):
        return None
    per_req = max(1.0, min(_PER_REQ, remaining))
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip",
    })
    try:
        resp = _OPENER.open(req, timeout=per_req)
    except Exception:
        return None
    try:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        # only parse markup; skip binary bodies (a file the URL points AT)
        if ctype and not any(t in ctype for t in
                             ("html", "xml", "text", "plain")):
            return None
        buf = io.BytesIO()
        while True:
            if time.monotonic() >= deadline:
                break
            try:
                chunk = resp.read(65536)
            except Exception:
                break
            if not chunk:
                break
            buf.write(chunk)
            if buf.tell() >= _MAX_PAGE_BYTES:
                break
        raw = buf.getvalue()
    finally:
        try:
            resp.close()
        except Exception:
            pass
    if not raw:
        return None
    if (resp.headers.get("Content-Encoding") or "").lower() == "gzip" \
            or raw[:2] == b"\x1f\x8b":
        try:
            import io as _io
            # bounded inflate so a gzip bomb can't blow up memory
            raw = gzip.GzipFile(fileobj=_io.BytesIO(raw)).read(_MAX_PAGE_BYTES)
        except Exception:
            pass
    return raw.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# autoindex listing parser
# ---------------------------------------------------------------------------
def _meta(tail):
    """Pull (size_bytes, date_str) out of the text trailing a listing link."""
    date = ""
    m = _DATE_APACHE.search(tail) or _DATE_ISO.search(tail)
    if m:
        date = m.group(0)
        tail = tail.replace(date, " ")
    size = 0
    sm = _SIZE_SUF.search(tail)
    if sm:
        try:
            size = int(float(sm.group(1)) *
                       _MULT.get(sm.group(2).upper(), 1))
        except Exception:
            size = 0
    else:
        bm = _SIZE_BYTES.search(tail.strip())
        if bm:
            try:
                size = int(bm.group(1))
            except Exception:
                size = 0
    return size, date


def _parse_listing(base, text):
    """Return [(name, abs_url, is_dir, size, date), ...] for a directory page.

    Same-host links only; parent/sort/self links dropped; files kept only when
    their extension is a recognised downloadable type.
    """
    # keyed by abs_url so an icon-link + name-link pair for the same file
    # (common in Apache/IIS listings) merges into one entry that keeps the
    # row with the real size/date rather than the size-0 icon anchor.
    merged = {}
    order = []
    try:
        base_host = (urllib.parse.urlsplit(base).hostname or "").lower()
    except Exception:
        return []
    anchors = list(_A_RE.finditer(text))
    n = len(anchors)
    for i, a in enumerate(anchors):
        href = (a.group(1) or "").strip()
        if not href:
            continue
        low = href.lower()
        if href[0] in "#?" or low.startswith(
                ("mailto:", "javascript:", "data:", "tel:")):
            continue
        if href in ("../", "./", "/", ".."):
            continue
        try:
            abs_url = urllib.parse.urljoin(base, href)
            sp = urllib.parse.urlsplit(abs_url)
        except Exception:
            continue
        if sp.scheme not in ("http", "https"):
            continue
        if (sp.hostname or "").lower() != base_host:
            continue
        abs_url = urllib.parse.urlunsplit(
            (sp.scheme, sp.netloc, sp.path, sp.query, ""))
        if abs_url.rstrip("/") == base.rstrip("/"):
            continue
        is_dir = sp.path.endswith("/")
        name = _clean(a.group(2))
        if not name:
            name = urllib.parse.unquote(
                sp.path.rstrip("/").rsplit("/", 1)[-1])
        if name.lower() in _SKIP_NAMES:
            continue
        tail_start = a.end()
        tail_end = anchors[i + 1].start() if i + 1 < n \
            else min(len(text), a.end() + 160)
        tail = _clean(text[tail_start:tail_end])
        if is_dir:
            size, date = 0, _meta(tail)[1]
        else:
            if _ext_of(abs_url) not in _ALL_EXTS:
                continue
            size, date = _meta(tail)
        prev = merged.get(abs_url)
        if prev is None:
            merged[abs_url] = [name, abs_url, is_dir, size, date]
            order.append(abs_url)
        else:
            # merge: keep the larger size, first non-empty date, best name
            if size > prev[3]:
                prev[3] = size
            if not prev[4] and date:
                prev[4] = date
            if (not prev[0] or prev[0].lower() in _SKIP_NAMES) and name:
                prev[0] = name
    return [tuple(merged[u]) for u in order]


# ---------------------------------------------------------------------------
# result builders
# ---------------------------------------------------------------------------
def _blank():
    return {"title": "", "source": NAME, "seeders": 0, "size": 0,
            "magnet": "", "torrent_url": "", "url": "", "date": "",
            "category": "other", "quality": ""}


def _mk_file(name, abs_url, size, date):
    r = _blank()
    ext = _ext_of(abs_url)
    title = name or urllib.parse.unquote(abs_url.rsplit("/", 1)[-1])
    r["title"] = title
    r["url"] = abs_url
    r["size"] = int(size) if isinstance(size, int) else 0
    r["date"] = date or ""
    r["category"] = _CATEGORY_BY_EXT.get(ext, "other")
    r["quality"] = _guess_quality(title)
    return r


def _mk_direct(hit):
    url = (hit.get("url") or "").strip()
    if not url:
        return None
    r = _blank()
    ext = _ext_of(url)
    title = (hit.get("title") or "").strip() or \
        urllib.parse.unquote(url.rsplit("/", 1)[-1])
    r["title"] = title
    r["url"] = url
    r["category"] = _CATEGORY_BY_EXT.get(ext, "other")
    r["quality"] = _guess_quality(title + " " + (hit.get("snippet") or ""))
    return r


def _mk_dir_lead(url, title):
    r = _blank()
    r["title"] = title or ("Open directory: " + url)
    r["url"] = url
    r["category"] = "other"
    return r


# ---------------------------------------------------------------------------
# directory harvesting (bounded BFS, shared fetch budget)
# ---------------------------------------------------------------------------
class _Budget:
    def __init__(self, n):
        import threading
        self._lock = threading.Lock()
        self.left = n

    def take(self):
        with self._lock:
            if self.left <= 0:
                return False
            self.left -= 1
            return True


def _dir_matches(name, tokens):
    if not tokens:
        return False
    low = name.lower()
    return any(t in low for t in tokens)


def _file_matches(name, abs_url, tokens):
    if not tokens:
        return True
    hay = (name + " " + urllib.parse.unquote(abs_url)).lower()
    return any(t in hay for t in tokens)


def _process_dir(top_url, tokens, deadline, budget):
    """Fetch/parse an open directory (one descent level). Returns
    (file_results, top_fetched_ok)."""
    results = []
    top_ok = False
    visited = set()
    queue = [(top_url, 0)]
    while queue and len(results) < _PER_DIR_CAP:
        if time.monotonic() >= deadline - 0.3:
            break
        cur, depth = queue.pop(0)
        key = cur.rstrip("/")
        if key in visited:
            continue
        visited.add(key)
        if not budget.take():
            break
        text = _fetch(cur, deadline)
        if cur == top_url:
            top_ok = text is not None
        if not text:
            continue
        entries = _parse_listing(cur, text)
        files = [e for e in entries if not e[2]]
        subdirs = [e for e in entries if e[2]]
        matched = [e for e in files if _file_matches(e[0], e[1], tokens)]
        chosen = matched if matched else files
        for name, abs_url, _is_dir, size, date in chosen:
            if len(results) >= _PER_DIR_CAP:
                break
            results.append(_mk_file(name, abs_url, size, date))
        if depth < _DESCEND_DEPTH and len(results) < _PER_DIR_CAP:
            for name, abs_url, _is_dir, _s, _d in subdirs:
                if abs_url.rstrip("/") in visited:
                    continue
                if _dir_matches(name, tokens):
                    queue.append((abs_url, depth + 1))
    return results, top_ok


# ---------------------------------------------------------------------------
# dork building + transport fan-out
# ---------------------------------------------------------------------------
def _build_dorks(q, exts, category):
    dorks = []

    def add(d):
        d = (d or "").strip()
        if d and d not in dorks:
            dorks.append(d)

    cat = (category or "").lower()
    # canonical open-directory operator dork (targets Apache/nginx autoindex)
    add(_dorks.build_dork("open_directory", q))
    # plain keyword variants: some transports (e.g. Marginalia, a keyword-only
    # small-web index rich in open directories) return nothing for heavy
    # operator syntax but surface real dir/file URLs for bare keywords, which
    # our classifier then picks up.
    add(q)
    if exts:
        add("%s %s" % (q, exts[0]))
    # direct filetype: hits
    for e in exts[:2]:
        add(_dorks.build_dork("filetype", q, e))
    # open-dir narrowed by extension keyword
    if exts:
        add(_dorks.build_dork("open_directory", q + " " + exts[0]))
    if cat in ("movie", "tv", "music", "image", "software"):
        add(_dorks.build_dork("media", q))
    if cat in ("dataset", "data"):
        add(_dorks.build_dork("dataset", q))
    return [d for d in dorks if d][:6]


def _run_dorks(dorks, deadline):
    """Fan the dorks across transport_search in parallel; merge unique hits."""
    if not dorks:
        return []
    remaining = deadline - time.monotonic()
    if remaining <= 1.0:
        return []
    per_call = max(3, min(8, int(remaining)))
    rows = []
    seen = set()
    pool = ThreadPoolExecutor(max_workers=min(5, len(dorks)))
    try:
        futs = {pool.submit(_dorks.transport_search, d, per_call): d
                for d in dorks}
        try:
            for f in as_completed(futs, timeout=max(1.0, remaining)):
                try:
                    got = f.result() or []
                except Exception:
                    got = []
                for r in got:
                    u = (r.get("url") or "").strip()
                    if not u or u in seen:
                        continue
                    seen.add(u)
                    rows.append(r)
        except Exception:
            pass  # deadline reached — keep whatever arrived
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return rows


def _classify(hits, tokens):
    """Split transport hits into (open-dir candidates, direct file hits)."""
    dir_urls = []
    dir_titles = {}
    direct = []
    seen_dir = set()
    for h in hits:
        u = (h.get("url") or "").strip()
        if not u.startswith(("http://", "https://")):
            continue
        title = (h.get("title") or "")
        blob = (title + " " + u).lower()
        ext = _ext_of(u)
        indexish = ("index of" in blob or "directory listing" in blob
                    or u.rstrip().endswith("/"))
        if ext in _ALL_EXTS and not u.rstrip().endswith("/"):
            direct.append(h)
        elif indexish:
            key = u.rstrip("/")
            if key not in seen_dir:
                seen_dir.add(key)
                dir_urls.append(u)
                dir_titles[u] = title
    return dir_urls, dir_titles, direct


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------
def _finalize(results):
    seen = set()
    out = []
    for r in results:
        if not isinstance(r, dict):
            continue
        u = (r.get("url") or "").strip()
        mag = (r.get("magnet") or "").strip()
        tor = (r.get("torrent_url") or "").strip()
        if not (u or mag or tor):
            continue
        key = u or mag or tor
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "title": str(r.get("title") or "")[:300],
            "source": NAME,
            "seeders": 0,
            "size": int(r.get("size") or 0),
            "magnet": mag,
            "torrent_url": tor,
            "url": u,
            "date": str(r.get("date") or ""),
            "category": str(r.get("category") or "other"),
            "quality": str(r.get("quality") or ""),
        })
        if len(out) >= _MAX_RESULTS:
            break
    return out


def search(query, category="", timeout=12):
    """Discover openly-shared files via dorks + open-directory harvesting.

    Returns a list of result dicts (see module docstring). Never raises.
    """
    try:
        q = (query or "").strip()
        if not q:
            return []
        deadline = time.monotonic() + max(3, int(timeout))
        toks = _tokens(q)
        exts = _EXTS_FOR_HINT.get((category or "").lower(), _DEFAULT_EXTS)

        # phase 1: dorks -> transports (spend ~half the budget here)
        transport_deadline = min(
            deadline, time.monotonic() + max(3, timeout * 0.5))
        dorks = _build_dorks(q, exts, category)
        hits = _run_dorks(dorks, transport_deadline)
        if not hits:
            return []

        dir_urls, dir_titles, direct = _classify(hits, toks)

        results = []
        # direct filetype: hits (files linked on the surface web)
        for h in direct[:_MAX_DIRECT]:
            r = _mk_direct(h)
            if r:
                results.append(r)

        # phase 2: fetch + parse open directories to enumerate real files
        cand = dir_urls[:_MAX_CANDIDATE_DIRS]
        if cand and (deadline - time.monotonic()) > 1.5:
            budget = _Budget(_MAX_FETCHES)
            pool = ThreadPoolExecutor(max_workers=min(4, len(cand)))
            try:
                futs = {pool.submit(_process_dir, u, toks, deadline, budget): u
                        for u in cand}
                try:
                    for f in as_completed(
                            futs, timeout=max(1.0, deadline - time.monotonic())):
                        u = futs[f]
                        try:
                            files, ok = f.result()
                        except Exception:
                            files, ok = [], False
                        if files:
                            results.extend(files)
                        elif ok:
                            # real page but no enumerable files -> keep the lead
                            results.append(
                                _mk_dir_lead(u, dir_titles.get(u, "")))
                except Exception:
                    pass  # deadline hit — keep what we have
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        return _finalize(results)
    except Exception:
        return []


if __name__ == "__main__":
    import sys

    def _human(n):
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024 or unit == "TB":
                return "%.0f%s" % (n, unit) if unit == "B" else "%.1f%s" % (n, unit)
            n /= 1024.0

    queries = [("nasa apollo", "book"),
               ("public domain jazz", "music"),
               ("global temperature", "dataset")]
    if len(sys.argv) > 1:
        queries = [(" ".join(sys.argv[1:]), sys.argv[1] if False else "")]
    for q, cat in queries:
        t0 = time.monotonic()
        hits = search(q, category=cat, timeout=15)
        took = time.monotonic() - t0
        withsize = sum(1 for h in hits if h["size"] > 0)
        print("\nquery=%r cat=%r -> %d results (%d with size) in %.1fs"
              % (q, cat, len(hits), withsize, took))
        cats = {}
        for h in hits:
            cats[h["category"]] = cats.get(h["category"], 0) + 1
        if cats:
            print("   categories:", dict(sorted(cats.items())))
        for h in hits[:6]:
            sz = _human(h["size"]) if h["size"] else "-"
            print("   - [%s/%s %s] %s" % (
                h["category"], h["quality"] or "-", sz, h["title"][:70]))
            print("       %s" % h["url"][:100])
