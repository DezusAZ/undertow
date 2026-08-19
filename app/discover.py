"""Sources mode — find the *places files live*, then CRAWL OUTWARD from them.

Two-stage engine:

  1. SEED  — run open-directory dorks through our self-hosted SearXNG node and keep
             only hits we can CONFIRM are real autoindex open directories.
  2. EXPAND — this is the part surface search can't do: a search engine indexes a
             *page*, not the *tree*. So from every confirmed directory we climb to its
             PARENT and enumerate every SIBLING directory, and we walk one level of
             its own children. The overwhelming majority of that tree is in no search
             index — it's reachable only by crawling out from a seed. Each result is
             tagged with how it was found: "search" (indexed) vs "crawl" (discovered
             by traversal, i.e. NOT in the search index we started from).

Scope: intentionally-public open directories and anonymous FTP only. It never scans
IP ranges or probes hosts nothing pointed us to — it only walks the neighbourhood of
directories a search already surfaced.

stdlib only; never raises (returns [] on any error).
"""
import os
import re
import ssl
import time
import socket
import http.client
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

SEARX_URL = os.environ.get("SEARX_URL", "http://127.0.0.1:8080")
FLARESOLVERR_URL = os.environ.get("FLARESOLVERR_URL", "http://127.0.0.1:8191")
_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/121.0 Safari/537.36")
# Rotate UA a little so we trip fewer rate-limits/bot walls (captcha AVOIDANCE, ask ④).
_UAS = [
    _UA,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]
# Signs a page is a bot-wall / captcha challenge rather than the content we asked for.
_CHALLENGE = re.compile(
    r"(cf-browser-verification|challenge-platform|just a moment|checking your browser|"
    r"attention required|captcha|hcaptcha|recaptcha|cf-chl-|please enable (?:js|javascript))",
    re.IGNORECASE)

# Crawl bounds (keep it bounded + polite; a dead server can't blow the budget).
_MAX_SEEDS_TO_EXPAND = 14     # confirmed seeds we climb out from, per round
_MAX_CANDIDATES = 90          # sibling/child dirs we probe per expansion round
_SNOWBALL_HOSTS = 8          # hosts we re-dork (site:host) to find MORE open dirs
_FETCH_TIMEOUT = 6
_READ_CAP = 1_000_000

_DORKS_Q = [
    'intitle:"index of" {q}',
    '"index of /" {q}',
    '-inurl:(jsp|pl|php|html|aspx|htm|cf|shtml) intitle:"index.of" {q}',
]
_DORKS_QE = [
    'intitle:"index of" {q} {ext}',
    'intitle:"index of" {ext} {q}',
    '"index of /" {q} {ext}',
]

_INDEX_SIG = re.compile(
    r'(<title>\s*index of\s*/|<h1>\s*index of\s*/|directory listing for|'
    r'\?C=[NMSD];O=[AD]|\[to parent directory\]|<address>\s*(apache|nginx))',
    re.IGNORECASE)
_HREF = re.compile(r'<a\s+[^>]*href="([^"#][^"]*)"', re.IGNORECASE)
_TITLE = re.compile(r'<title>(.*?)</title>', re.IGNORECASE | re.DOTALL)
_EXT_RE = re.compile(r'\.([A-Za-z0-9]{1,6})$')

_FILE_EXTS = set("""
mp3 flac wav aac ogg m4a opus wma
mp4 mkv avi mov wmv flv webm m4v mpg mpeg
pdf epub mobi djvu doc docx ppt pptx xls xlsx txt rtf csv
zip rar 7z tar gz bz2 xz iso img
jpg jpeg png gif webp tiff bmp svg
json xml sqlite db sql nfo cue log
""".split())


# getaddrinfo() takes no timeout and honours resolv.conf, so a blackholed resolver (a real
# failure mode inside a wedged VPN netns) can block a thread for the full glibc retry cycle
# (10-40s), uncancellably. Run every lookup on a small dedicated pool with a hard result
# timeout so a DNS stall can never pin a probe/crawl thread — the caller gets None fast and
# the straggler is contained. (entrypoint also caps resolv.conf at timeout:2 attempts:1.)
_DNS_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="dns")
_DNS_TIMEOUT = float(os.environ.get("DNS_RESOLVE_TIMEOUT", "3"))


def _getaddrinfo_bounded(host):
    try:
        return _DNS_POOL.submit(socket.getaddrinfo, host, None).result(timeout=_DNS_TIMEOUT)
    except Exception:
        return None


def _resolve_public(host):
    """Resolve a hostname and return ONE vetted PUBLIC ip, or None. Rejects the host if
    ANY resolved address is private/loopback/link-local/reserved/etc. Returning the exact
    ip we vetted lets callers CONNECT to it — closing the DNS-rebinding TOCTOU where the
    validation lookup and the fetch lookup could differ."""
    host = (host or "").split(":")[0]
    if not host or host.lower() == "localhost":
        return None
    infos = _getaddrinfo_bounded(host)
    if not infos:
        return None
    ip = None
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return None
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return None                    # any non-public address in the set => reject
        if ip is None:
            ip = info[4][0]
    return ip


def _is_public_host(host):
    return _resolve_public(host) is not None


# ---- SSRF-safe fetch: pin the vetted IP + re-validate every redirect hop ---------------
# The crawl fetches URLs surfaced by web dorks (attacker-influenceable), from inside the
# VPN netns which can reach the LAN + our own services (SearX, FlareSolverr, the app). So:
#  * we CONNECT to the exact public IP we validated (no DNS-rebind between check and use), and
#  * each redirect hop is re-validated, so a 302 -> 127.0.0.1 / 169.254.169.254 is refused.
class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        ip = _resolve_public(self.host)
        if not ip:
            raise OSError("blocked non-public host: %s" % self.host)
        self.sock = socket.create_connection((ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        ip = _resolve_public(self.host)
        if not ip:
            raise OSError("blocked non-public host: %s" % self.host)
        sock = socket.create_connection((ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req, context=self._context)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            if not _is_public_host(urllib.parse.urlsplit(newurl).hostname):
                return None                # refuse to follow a redirect to a private host
        except Exception:
            return None
        return urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl)


_SAFE_OPENER = urllib.request.build_opener(
    _PinnedHTTPHandler, _PinnedHTTPSHandler(context=ssl.create_default_context()),
    _SafeRedirect)


def _searx(query, timeout):
    """Query the local SearXNG node -> list of {url, title}. Never raises."""
    url = SEARX_URL.rstrip("/") + "/search?" + urllib.parse.urlencode(
        {"q": query, "format": "json", "safesearch": "0"})
    try:
        import json
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(2_000_000))
        out = []
        for r in data.get("results", []):
            u = r.get("url") or ""
            if u.startswith("http") or u.startswith("ftp"):
                out.append({"url": u, "title": r.get("title") or ""})
        return out
    except Exception:
        return []


def _flaresolverr_get(url, timeout):
    """Render a URL through FlareSolverr (a real headless browser) to get past Cloudflare/
    JS bot-walls. Returns the HTML, or None. Never raises. SSRF-guarded: the target host is
    re-validated just before the call, and if the browser was redirected onto a non-public
    host the result is refused."""
    try:
        if not _is_public_host(urllib.parse.urlsplit(url).hostname):
            return None
    except Exception:
        return None
    try:
        import json
        payload = json.dumps({"cmd": "request.get", "url": url,
                              "maxTimeout": int(timeout * 1000) + 20000}).encode()
        req = urllib.request.Request(FLARESOLVERR_URL.rstrip("/") + "/v1", payload,
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout + 25) as resp:
            d = json.loads(resp.read(6_000_000))
        sol = d.get("solution") or {}
        final = sol.get("url") or url          # where the browser actually landed
        if not _is_public_host(urllib.parse.urlsplit(final).hostname):
            return None                        # redirected onto an internal host -> refuse
        html = sol.get("response")
        if not html:
            return None
        # a real listing is never a bot-wall (don't drop a dir named 'captcha')
        return html if (_INDEX_SIG.search(html) or not _CHALLENGE.search(html[:4000])) else None
    except Exception:
        return None


def _fetch(url, timeout=None, ua_seed=0, allow_solver=True):
    """Fetch a page's HTML. Plain request first (via the SSRF-safe opener: pinned IP + every
    redirect re-validated); if it's a Cloudflare/JS bot-wall (403/429/503 or a challenge
    body), transparently retry through FlareSolverr. Undertow's free captcha AVOIDANCE for
    the crawl. Returns HTML or None; never raises."""
    timeout = timeout or _FETCH_TIMEOUT
    ua = _UAS[ua_seed % len(_UAS)]
    blocked = False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
        with _SAFE_OPENER.open(req, timeout=timeout) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if ctype and "text/html" not in ctype and "text/plain" not in ctype:
                return None                    # not a listing page
            body = resp.read(_READ_CAP).decode("utf-8", "replace")
        # accept a genuine autoindex even if a filename/path contains a challenge keyword;
        # only a NON-listing that trips _CHALLENGE is treated as a bot-wall.
        if _INDEX_SIG.search(body) or not _CHALLENGE.search(body[:4000]):
            return body
        blocked = True                          # got a challenge page
    except urllib.error.HTTPError as e:
        if e.code in (403, 429, 503):
            blocked = True
        else:
            return None
    except Exception:
        return None
    if blocked and allow_solver:
        return _flaresolverr_get(url, timeout)
    return None


def probe_url(url, timeout=8):
    """LIVENESS probe for a direct link (open-dir file, Internet Archive item, direct
    download): is it still actually there? SSRF-safe — reuses the pinned-IP opener so a
    result URL can't be used to reach the LAN / our own services, and redirects are
    re-validated. Tries HEAD first, then a 1-byte ranged GET (many hosts reject HEAD).
    Returns (state, size_bytes):
      'live'    -> reachable (2xx/206/416); size = Content-Length if the server gave one
      'dead'    -> the file is GONE (404/410) or legally removed (451)
      'unknown' -> ambiguous (timeout, 5xx, 403/401 soft-block, network flake) — we never
                   punish a result on a single ambiguous signal, so a real file behind a
                   cranky server is never wrongly hidden.
    Never raises."""
    if not url or not str(url).startswith(("http://", "https://")):
        return ("unknown", 0)

    def _len(resp):
        try:
            return max(0, int(resp.headers.get("Content-Length") or 0))
        except Exception:
            return 0

    dead_codes = (404, 410)      # NOT 451: a legal block is jurisdiction-scoped (retrievable from
                                 # another VPN exit) -> 'unknown', never a definitive 'gone'.
    for method, extra in (("HEAD", {}), ("GET", {"Range": "bytes=0-0"})):
        try:
            req = urllib.request.Request(
                url, method=method,
                headers=dict({"User-Agent": _UAS[0], "Accept": "*/*"}, **extra))
            with _SAFE_OPENER.open(req, timeout=timeout) as resp:
                return ("live", _len(resp))
        except urllib.error.HTTPError as e:
            if e.code == 416:                  # range unsatisfiable => the resource EXISTS
                return ("live", 0)
            if method == "HEAD":
                continue                       # HEAD is unreliable (WAFs 404/405 it) -> confirm via GET;
                                               # a HEAD error is NEVER definitive 'dead'.
            if e.code in dead_codes:
                return ("dead", 0)             # only a GET 404/410 is a confirmed 'gone'
            return ("unknown", 0)
        except Exception:
            if method == "HEAD":
                continue                       # HEAD blocked at socket level -> try GET
            return ("unknown", 0)
    return ("unknown", 0)


def _root_of(url):
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:
        return None
    if not p.scheme or not p.netloc:
        return None
    path = p.path or "/"
    last = path.rsplit("/", 1)[-1]
    if _EXT_RE.search(last):
        path = path[: path.rfind("/") + 1]
    if not path.endswith("/"):
        path += "/"
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, "", ""))


def _parent(url):
    """One directory level up, or None if already at the host root."""
    p = urllib.parse.urlsplit(url)
    path = (p.path or "/").rstrip("/")
    if not path:
        return None
    parent = path[: path.rfind("/") + 1] or "/"
    if parent == (p.path or "/"):
        return None
    return urllib.parse.urlunsplit((p.scheme, p.netloc, parent, "", ""))


def _scan(url, ext, via):
    """Fetch a candidate dir. If it's a confirmed open directory, return
    (source_dict, [child_dir_urls]); else (None, []). The source dict carries the actual
    file entries in `_files` ([{name,url}]) so the crawler can judge real filenames, not
    just counts. Never raises."""
    p = urllib.parse.urlsplit(url)
    if p.scheme == "ftp":
        if not _is_public_host(p.netloc):
            return None, []
        return ({"url": url, "host": p.netloc, "title": "FTP: " + p.netloc,
                 "files": 0, "matched": 0, "kind": "ftp", "via": via, "_files": []}, [])
    if p.scheme not in ("http", "https") or not _is_public_host(p.netloc):
        return None, []
    body = _fetch(url, ua_seed=abs(hash(p.netloc)))   # per-host UA; plain -> FlareSolverr
    if not body or not _INDEX_SIG.search(body):
        return None, []                    # not an autoindex -> not an open directory

    base = url if url.endswith("/") else url + "/"
    files = 0
    matched = 0
    children = []
    entries = []
    want = (ext or "").lower().lstrip(".")
    for href in _HREF.findall(body):
        h = href.strip()
        if not h or h.startswith("?") or h in ("../", "./") or h.startswith("mailto:"):
            continue
        child = urllib.parse.urljoin(base, h)
        cp = urllib.parse.urlsplit(child)
        if cp.netloc != p.netloc:
            continue                       # stay on the same host
        if h.endswith("/"):
            files += 1
            if child.startswith(base) and child.rstrip("/") != base.rstrip("/"):
                children.append(child)
        else:
            name = urllib.parse.unquote(cp.path.rsplit("/", 1)[-1])
            m = _EXT_RE.search(name)
            if m and m.group(1).lower() in _FILE_EXTS:
                files += 1
                entries.append({"name": name, "url": child})
                if want and m.group(1).lower() == want:
                    matched += 1
    if files == 0:
        return None, []
    tm = _TITLE.search(body)
    title = re.sub(r"\s+", " ", tm.group(1)).strip()[:120] if tm else p.netloc
    src = {"url": url, "host": p.netloc, "title": title or p.netloc,
           "files": files, "matched": matched, "kind": "http", "via": via,
           "_files": entries[:500]}
    return src, children


def _scan_many(items, ext, deadline):
    """items: list of (url, via). Returns {url: (src, children)} for confirmed ones."""
    got = {}
    if not items:
        return got
    budget = max(1.0, deadline - time.monotonic())
    # NOT a context manager: `with` would call shutdown(wait=True) on exit and join
    # every queued fetch, blowing the deadline. We drop stragglers instead.
    ex = ThreadPoolExecutor(max_workers=12)
    try:
        futs = {ex.submit(_scan, u, ext, via): u for (u, via) in items}
        try:
            for f in as_completed(futs, timeout=budget):
                try:
                    src, kids = f.result()
                    if src:
                        got[src["url"]] = (src, kids)
                except Exception:
                    pass
        except Exception:
            pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return got


_STOP = set("the a an of and or to in on for with at by index files file download downloads "
            "pub public data http https www com net org".split())


def _terms(want):
    """Tokenise a target into meaningful lowercase terms for filename matching."""
    if isinstance(want, (list, tuple, set)):
        want = " ".join(str(t) for t in want)
    toks = re.findall(r"[a-z0-9]+", str(want or "").lower())
    return [t for t in toks if len(t) >= 3 and t not in _STOP]


def _name_score(name, terms):
    """0-1: how well a filename/dirname matches the target terms (fraction present,
    with a small bonus for hitting several)."""
    if not terms:
        return 0.0
    n = str(name or "").lower()
    hit = sum(1 for t in terms if t in n)
    if not hit:
        return 0.0
    frac = hit / len(terms)
    return min(1.0, frac + 0.1 * (hit - 1))         # multi-term hits edge higher


def crawl_tree(seed_url, want_terms=None, ext="", timeout=25, skip=None):
    """Deep-crawl the neighbourhood of ONE url: climb to its PARENT (whose listing gives
    the SIBLING dirs), and descend into CHILD dirs — always preferring dirs whose NAMES
    match the target — collecting the actual FILES found along the way. This is the
    'route laterally + up and down the tree, guided by what we're looking for' crawl.
    `skip` is a set of dir URLs already crawled in earlier pivot cycles of the same hunt;
    they aren't re-fetched (avoids re-scanning the shared parent every cycle). Returns
    {"files":[{name,url,dir,via,score}], "subdirs":[{url,score}], "scanned":[url,...]}.
    Bounded + polite; never raises."""
    seed_url = (seed_url or "").strip()
    if not seed_url or not seed_url.startswith(("http://", "https://", "ftp://")):
        return {"files": [], "subdirs": [], "scanned": []}
    terms = _terms(want_terms)
    ext = (ext or "").strip().lstrip(".").lower()
    deadline = time.monotonic() + max(8, timeout)
    root = _root_of(seed_url) or seed_url

    to_scan = [(root, "seed")]
    par = _parent(root)
    if par:
        to_scan.append((par, "parent"))            # up -> gives us the siblings
    skip = set(skip or ())
    scanned = set(skip)                             # never re-fetch a dir crawled before
    n_scanned = 0                                   # THIS call's fetches (MAX_DIRS is per-call)
    files = {}                                      # url -> file dict (deduped)
    subdirs = {}                                    # url -> best name-score (crawl next)
    MAX_DIRS = 45

    while to_scan and n_scanned < MAX_DIRS and time.monotonic() < deadline:
        batch = []
        while to_scan and len(batch) < 10:
            u, via = to_scan.pop(0)
            if u in scanned:
                continue
            scanned.add(u)
            n_scanned += 1
            batch.append((u, via))
        if not batch:
            break
        for url, (src, kids) in _scan_many(batch, ext, deadline).items():
            # A file INHERITS its directory's relevance: a track named "07.flac" inside a
            # matching "Radiohead - OK Computer" dir must not score 0 (and get filtered as
            # garbage), while a file in an unrelated sibling dir stays 0.
            dscore = _name_score(urllib.parse.unquote(url.rstrip("/").rsplit("/", 1)[-1]), terms)
            for fe in src.get("_files", []):
                fu = fe.get("url")
                if fu and fu not in files:
                    files[fu] = {"name": fe.get("name", ""), "url": fu, "dir": url,
                                 "via": src.get("via", "crawl"),
                                 "score": max(_name_score(fe.get("name", ""), terms), dscore)}
            for c in kids:                          # children + (via parent) siblings
                if c in scanned:
                    continue
                nm = urllib.parse.unquote(c.rstrip("/").rsplit("/", 1)[-1])
                subdirs[c] = max(subdirs.get(c, 0.0), _name_score(nm, terms))
        # descend next into the best-matching unexplored dirs (guided, not blind BFS)
        nxt = sorted((u for u in subdirs if u not in scanned),
                     key=lambda u: subdirs[u], reverse=True)[:10]
        for u in nxt:
            to_scan.append((u, "crawl"))

    fl = sorted(files.values(), key=lambda f: (f["score"], f["name"]), reverse=True)
    sd = sorted(({"url": u, "score": s} for u, s in subdirs.items() if u not in scanned),
                key=lambda x: x["score"], reverse=True)
    return {"files": fl[:400], "subdirs": sd[:30], "scanned": sorted(scanned - skip)}


def open_dir_seeds(query, ext="", timeout=16):
    """Dork for open directories and CONFIRM them (no expansion — the caller drives the
    deeper crawl via crawl_tree). Returns confirmed source dicts, best (ext-match, files)
    first. Lighter than discover(); meant for the Deep Hunt executor. Never raises."""
    q = (query or "").strip()
    if not q:
        return []
    ext = (ext or "").strip().lstrip(".").lower()
    deadline = time.monotonic() + max(6, timeout)
    dorks = [t.replace("{q}", q).replace("{ext}", ext)
             for t in (_DORKS_QE if ext else _DORKS_Q)]
    hits = []
    ex = ThreadPoolExecutor(max_workers=min(6, len(dorks)))
    try:
        futs = [ex.submit(_searx, d, 10) for d in dorks]
        try:
            for f in as_completed(futs, timeout=13):
                try:
                    hits.extend(f.result() or [])
                except Exception:
                    pass
        except Exception:
            pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    roots, seen = [], set()
    for h in hits:
        r = _root_of(h.get("url", ""))
        if r and r not in seen:
            seen.add(r)
            roots.append(r)
        if len(roots) >= 30:
            break
    confirmed = [src for _, (src, _k)
                 in _scan_many([(r, "search") for r in roots], ext, deadline).items()]
    return sorted(confirmed, key=lambda s: (s.get("matched", 0), s.get("files", 0)),
                  reverse=True)


def _expand_once(seeds, ext, deadline, confirmed, children_of):
    """From seed dirs: climb to each PARENT (its listing gives us SIBLING dirs) and
    also take each seed's own CHILD dirs, then probe them all. Adds confirmed ones to
    `confirmed`/`children_of` and returns the newly-confirmed sources. This is the
    step that surfaces the un-indexed tree around a hit."""
    new = {}
    if time.monotonic() >= deadline:
        return []
    parents = []
    seen = set(confirmed)
    for s in seeds:
        pu = _parent(s["url"])
        if pu and pu not in seen:
            seen.add(pu)
            parents.append((pu, "crawl"))
    pscan = _scan_many(parents, ext, deadline)
    for url, (src, kids) in pscan.items():
        if url not in confirmed:
            confirmed[url] = src
            children_of[url] = kids
            new[url] = src

    candidates = []
    cseen = set(confirmed)
    for _, (psrc, kids) in pscan.items():          # siblings (parent's children)
        for c in kids:
            if c not in cseen:
                cseen.add(c)
                candidates.append((c, "crawl"))
    for s in seeds:                                 # seeds' own children
        for c in children_of.get(s["url"], []):
            if c not in cseen:
                cseen.add(c)
                candidates.append((c, "crawl"))
        if len(candidates) >= _MAX_CANDIDATES:
            break
    for url, (src, kids) in _scan_many(candidates[:_MAX_CANDIDATES], ext, deadline).items():
        if url not in confirmed:
            confirmed[url] = src
            children_of[url] = kids
            new[url] = src
    return list(new.values())


def _snowball(confirmed, ext, deadline):
    """One host can hold MANY separate open directories the first search never
    returned. Re-dork `site:<host> index of` for the strongest hosts to surface the
    rest. Returns new (root, via) candidates to scan."""
    if time.monotonic() >= deadline:
        return []
    hosts, seenh = [], set()
    for s in sorted(confirmed.values(),
                    key=lambda x: (x.get("matched", 0), x.get("files", 0)), reverse=True):
        h = (s.get("host") or "").split(":")[0]
        if h and h not in seenh:
            seenh.add(h)
            hosts.append(h)
        if len(hosts) >= _SNOWBALL_HOSTS:
            break
    dorks = []
    for h in hosts:
        dorks.append('site:%s intitle:"index of"' % h)
        if ext:
            dorks.append('site:%s "index of" %s' % (h, ext))
    if not dorks:
        return []
    hits = []
    ex = ThreadPoolExecutor(max_workers=min(8, len(dorks)))
    try:
        futs = [ex.submit(_searx, d, 10) for d in dorks]
        try:
            for f in as_completed(futs, timeout=max(1.0, deadline - time.monotonic())):
                try:
                    hits.extend(f.result() or [])
                except Exception:
                    pass
        except Exception:
            pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    roots, seen = [], set(confirmed)
    for hh in hits:
        r = _root_of(hh.get("url", ""))
        if r and r not in seen:
            seen.add(r)
            roots.append((r, "crawl"))
    return roots


def discover(query, ext="", timeout=32):
    """Find open directories for <query>/<ext>, then crawl outward (parent + siblings
    + children) to surface the un-indexed tree around each hit. Returns a list of
    {url, host, title, files, matched, kind, via}, best first. via is "search"
    (came from the index) or "crawl" (found only by traversal)."""
    q = (query or "").strip()
    if not q:
        return []
    ext = (ext or "").strip().lstrip(".").lower()
    deadline = time.monotonic() + max(8, timeout)

    # ---- STAGE 1: SEED via dorks -----------------------------------------
    dorks = [t.replace("{q}", q).replace("{ext}", ext)
             for t in (_DORKS_QE if ext else _DORKS_Q)]
    hits = []
    ex = ThreadPoolExecutor(max_workers=min(6, len(dorks)))
    try:
        futs = [ex.submit(_searx, d, 10) for d in dorks]
        try:
            for f in as_completed(futs, timeout=13):
                try:
                    hits.extend(f.result() or [])
                except Exception:
                    pass
        except Exception:
            pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    roots, seen_roots = [], set()
    for h in hits:
        r = _root_of(h.get("url", ""))
        if r and r not in seen_roots:
            seen_roots.add(r)
            roots.append(r)
        if len(roots) >= 40:
            break

    confirmed = {}          # url -> src
    children_of = {}        # url -> [child dir urls]
    for url, (src, kids) in _scan_many([(r, "search") for r in roots], ext, deadline).items():
        confirmed[url] = src
        children_of[url] = kids

    def _seeds(pool):
        return sorted(pool, key=lambda s: (s.get("matched", 0), s.get("files", 0)),
                      reverse=True)[:_MAX_SEEDS_TO_EXPAND]

    # ---- STAGE 2: EXPAND round 1 (climb/enumerate the tree around each hit) ----
    round1 = _expand_once(_seeds(confirmed.values()), ext, deadline, confirmed, children_of)

    # ---- STAGE 3: SNOWBALL — find OTHER open dirs on the same hosts -----------
    snow_roots = _snowball(confirmed, ext, deadline)
    snow_new = []
    for url, (src, kids) in _scan_many(snow_roots, ext, deadline).items():
        if url not in confirmed:
            confirmed[url] = src
            children_of[url] = kids
            snow_new.append(src)

    # ---- STAGE 4: EXPAND round 2 (go deeper — crawl around the new finds) -----
    _expand_once(_seeds(round1 + snow_new), ext, deadline, confirmed, children_of)

    # ---- rank: extension matches, then file count; note how each was found
    out = sorted(confirmed.values(),
                 key=lambda s: (s.get("matched", 0), s.get("files", 0)),
                 reverse=True)
    return out[:200]


if __name__ == "__main__":
    import sys
    q = sys.argv[1] if len(sys.argv) > 1 else "flac"
    e = sys.argv[2] if len(sys.argv) > 2 else ""
    res = discover(q, e)
    ncrawl = sum(1 for s in res if s.get("via") == "crawl")
    print("%d open dirs (%d from search, %d found by CRAWLING beyond the index)"
          % (len(res), len(res) - ncrawl, ncrawl))
    for s in res[:25]:
        print(" [%-6s] %3d files (%2d match) | %s"
              % (s["via"], s["files"], s["matched"], s["url"][:80]))
