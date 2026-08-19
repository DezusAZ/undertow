"""File-discovery dork library + headless search transport (stdlib-only).

SCOPE: LEGAL open/public FILE discovery only. Every template here targets
openly-shared, non-secret FILES and open-directory listings (documents, audio,
video, archives, public datasets, public-domain media, research data,
software). There are deliberately NO templates for credentials, API keys,
.env/.git, secret DB dumps, admin/login panels, vuln/CVE endpoints, exposed
cameras/IoT/SCADA, or PII. If you extend this list, keep it to finding FILES,
never to finding secrets or a way in.

Public API
----------
DORKS          : list[dict]  -> {"category","template","note"}
TRANSPORTS     : list[dict]  -> describes each empirically-tested backend
build_dork(category, q, ext="") -> str
transport_search(dork, timeout=12) -> list[dict]  (NEVER raises)

`template` uses ``{q}`` for the user query and optionally ``{ext}`` for a file
extension.  ``transport_search`` returns a list of
``{"url","title","snippet","transport"}`` dicts; on any failure it returns [].

Transport reality (empirically tested from a datacenter/VPN IP, 2026-07-12
— google.com itself CAPTCHAs such IPs, hence this indirection):

  * Marginalia public JSON API .... WORKS, rock-solid. JSON, no key, no visible
                                    rate limit. Small-web index — excellent for
                                    open-directory / "index of" listings. Treats
                                    Google operators as plain keywords.
  * Mojeek HTML .................... WORKS, HTTP 200 reliably. Broad index.
                                    Honors intitle:/inurl:/filetype-ish
                                    operators (verified intitle:"index of").
  * DuckDuckGo lite HTML ........... FLAKY. First hit 200 then 202 "anomaly"
                                    challenge within seconds. Last-resort only.
  * SearXNG public JSON ............ MOSTLY BLOCKED right now (429/403/JS bot
                                    walls/redirects across ~15 instances).
                                    Kept as opportunistic rotation, low trust.
  * Brave / DDG html ............... JS-shell or 202 challenge — NOT headless-
                                    usable, intentionally omitted.

Recommendation: PRIMARY = Marginalia (reliability + open-dir specialty),
FALLBACK = Mojeek (operator support + broad index), then DDG lite, then a
SearXNG rotation as an opportunistic last resort.
"""

import html as _html
import json as _json
import re as _re
import urllib.parse as _uparse
import urllib.request as _ureq

__all__ = ["DORKS", "TRANSPORTS", "build_dork", "transport_search"]

_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
       "Gecko/20100101 Firefox/128.0")

# ---------------------------------------------------------------------------
# PART A — categorized file-discovery dork library (70 templates)
# ---------------------------------------------------------------------------
DORKS = [
    # ----- open_directory: generic index-of / listing signatures ----------
    {"category": "open_directory", "template": 'intitle:"index of" {q}',
     "note": "Canonical open-directory dork; matches most Apache/nginx autoindex pages."},
    {"category": "open_directory", "template": 'intitle:"index of /" {q}',
     "note": "Tighter form; the trailing slash favours real directory roots."},
    {"category": "open_directory", "template": 'intitle:"index of" "parent directory" {q}',
     "note": '"Parent directory" link is a strong autoindex fingerprint.'},
    {"category": "open_directory", "template": 'intitle:"index of" "last modified" {q}',
     "note": "The 'Last modified' column header confirms a live file listing."},
    {"category": "open_directory", "template": 'intitle:"index of" "name" "size" "description" {q}',
     "note": "Apache column headers together strongly imply an open index."},
    {"category": "open_directory", "template": 'inurl:"index of" {q}',
     "note": "Some listings put the phrase in the URL path rather than title."},
    {"category": "open_directory", "template": '"index of /" {q} -html -htm -php -asp -jsp',
     "note": "Excludes rendered app pages to bias toward raw file listings."},
    {"category": "open_directory", "template": 'intitle:"directory listing for" {q}',
     "note": "Apache Tomcat / Jetty directory-listing title signature."},
    {"category": "open_directory", "template": '"Directory listing for /" {q}',
     "note": "Python http.server / SimpleHTTPServer listing signature."},
    {"category": "open_directory", "template": 'intitle:"index of" "server at" {q}',
     "note": "'Apache/nginx Server at ...' footer of a default autoindex page."},
    {"category": "open_directory", "template": 'intext:"parent directory" {q}',
     "note": "Body-text variant for listings whose title was customised."},
    {"category": "open_directory", "template": '"index of" "[to parent directory]" {q}',
     "note": "Microsoft IIS directory-browsing listing signature."},
    {"category": "open_directory", "template": 'intitle:"index of" inurl:{q}',
     "note": "Open index whose path contains the query token."},
    {"category": "open_directory", "template": 'intitle:"index of" {q} {ext}',
     "note": "Open index narrowed to a file extension keyword (uses {ext})."},
    {"category": "open_directory", "template": 'intitle:"index of" {q} -inurl:(jsp|pl|php|html|aspx|htm|cf|shtml)',
     "note": "Classic open-dir filter that drops dynamic app pages."},

    # ----- filetype: documents ------------------------------------------
    {"category": "filetype", "template": "{q} filetype:{ext}",
     "note": "Generic filetype targeting; {ext} = pdf/epub/flac/mkv/zip/csv/..."},
    {"category": "filetype", "template": "{q} ext:{ext}",
     "note": "Alias of filetype: honored by Mojeek/Bing-style back-ends."},
    {"category": "filetype", "template": "{q} filetype:pdf",
     "note": "Public PDF documents, papers, manuals, reports."},
    {"category": "filetype", "template": "{q} filetype:epub",
     "note": "Openly shared EPUB e-books."},
    {"category": "filetype", "template": "{q} filetype:djvu",
     "note": "DjVu scans — common for public-domain books and archives."},
    {"category": "filetype", "template": "{q} filetype:mobi",
     "note": "MOBI/Kindle e-book files."},
    {"category": "filetype", "template": "{q} filetype:txt",
     "note": "Plain-text books, logs of releases, track lists, READMEs."},
    {"category": "filetype", "template": "{q} filetype:xlsx",
     "note": "Spreadsheets / tabular public data."},

    # ----- filetype: audio ----------------------------------------------
    {"category": "filetype", "template": "{q} filetype:flac",
     "note": "Lossless audio files."},
    {"category": "filetype", "template": "{q} filetype:mp3",
     "note": "MP3 audio files."},
    {"category": "filetype", "template": "{q} (filetype:flac OR filetype:m4a OR filetype:ogg OR filetype:wav)",
     "note": "Broad lossless/lossy audio net in one query."},

    # ----- filetype: video ----------------------------------------------
    {"category": "filetype", "template": "{q} filetype:mkv",
     "note": "Matroska video files."},
    {"category": "filetype", "template": "{q} filetype:mp4",
     "note": "MP4 video files."},
    {"category": "filetype", "template": "{q} (filetype:mkv OR filetype:mp4 OR filetype:avi OR filetype:mov)",
     "note": "Broad video-container net in one query."},

    # ----- filetype: archives -------------------------------------------
    {"category": "filetype", "template": "{q} filetype:zip",
     "note": "ZIP archives."},
    {"category": "filetype", "template": "{q} filetype:rar",
     "note": "RAR archives."},
    {"category": "filetype", "template": "{q} filetype:7z",
     "note": "7-Zip archives."},
    {"category": "filetype", "template": "{q} filetype:iso",
     "note": "ISO disc images (Linux distros, public software, game demos)."},
    {"category": "filetype", "template": "{q} (filetype:zip OR filetype:rar OR filetype:7z OR filetype:tar OR filetype:gz)",
     "note": "Broad archive net in one query."},

    # ----- filetype: data -----------------------------------------------
    {"category": "filetype", "template": "{q} filetype:csv",
     "note": "CSV tabular data."},
    {"category": "filetype", "template": "{q} filetype:json",
     "note": "JSON data files."},
    {"category": "filetype", "template": "{q} filetype:sqlite -inurl:(login|admin)",
     "note": "Public SQLite datasets; excludes app/admin paths by design."},
    {"category": "filetype", "template": "{q} filetype:xml",
     "note": "XML data / feeds / sitemaps of file collections."},
    {"category": "filetype", "template": "{q} filetype:parquet",
     "note": "Apache Parquet columnar datasets."},

    # ----- open-dir narrowed by media group -----------------------------
    {"category": "open_directory", "template": 'intitle:"index of" {q} (mp3|flac|m4a|ogg|wav)',
     "note": "Open directory that clearly contains audio files."},
    {"category": "open_directory", "template": 'intitle:"index of" {q} (mkv|mp4|avi|mov|webm)',
     "note": "Open directory that clearly contains video files."},
    {"category": "open_directory", "template": 'intitle:"index of" {q} (pdf|epub|mobi|djvu|cbz|cbr)',
     "note": "Open directory of documents / e-books / comics."},
    {"category": "open_directory", "template": 'intitle:"index of" {q} (zip|rar|7z|tar|gz|iso)',
     "note": "Open directory of archives / disc images."},
    {"category": "open_directory", "template": 'inurl:.{ext} intitle:"index of" {q}',
     "note": "Open index whose URL ends in a given extension (uses {ext})."},

    # ----- ftp_index -----------------------------------------------------
    {"category": "ftp_index", "template": "inurl:ftp {q} filetype:{ext}",
     "note": "Files exposed over FTP-style paths, narrowed by extension."},
    {"category": "ftp_index", "template": '"ftp://" {q}',
     "note": "Directly harvest ftp:// links to public file servers."},
    {"category": "ftp_index", "template": 'inurl:"ftp://" intitle:"index of" {q}',
     "note": "FTP roots that also render an HTTP index page."},
    {"category": "ftp_index", "template": 'intitle:"index of" inurl:ftp {q}',
     "note": "Open index served from an /ftp/ path."},
    {"category": "ftp_index", "template": '"index of /pub" {q}',
     "note": "Classic public /pub mirror tree (distros, docs, datasets)."},
    {"category": "ftp_index", "template": 'inurl:"/pub/" intitle:"index of" {q}',
     "note": "Public mirror /pub subtree as an open index."},
    {"category": "ftp_index", "template": '"index of /ftp" {q}',
     "note": "Web-facing /ftp export listing."},

    # ----- media / dataset-specific collection patterns -----------------
    {"category": "media", "template": 'intitle:"index of" {q} "discography"',
     "note": "Full-artist audio collections in an open directory."},
    {"category": "media", "template": 'intitle:"index of" {q} (OST|soundtrack)',
     "note": "Soundtrack / score collections."},
    {"category": "media", "template": 'intitle:"index of" {q} (audiobook|audiobooks)',
     "note": "Audiobook trees in open directories."},
    {"category": "media", "template": 'intitle:"index of" {q} (1080p|2160p|bluray|web-dl)',
     "note": "Higher-quality video in open directories."},
    {"category": "media", "template": 'intitle:"index of" {q} (comics|cbz|cbr)',
     "note": "Comic-book collections (CBZ/CBR) in open directories."},
    {"category": "media", "template": 'intitle:"index of" {q} (ebooks|ebook|epub)',
     "note": "E-book libraries in open directories."},
    {"category": "media", "template": 'intitle:"index of" {q} (magazines|magazine)',
     "note": "Magazine / periodical scans in open directories."},
    {"category": "media", "template": 'intitle:"index of" {q} (roms|iso|firmware)',
     "note": "Public software / firmware / preservation trees."},

    {"category": "dataset", "template": "{q} dataset filetype:{ext}",
     "note": "Named datasets in a chosen format (uses {ext})."},
    {"category": "dataset", "template": '{q} "open data" filetype:csv',
     "note": "Open-data CSV publications."},
    {"category": "dataset", "template": "{q} filetype:csv (site:.gov OR site:.edu)",
     "note": "Government / academic CSV data releases."},
    {"category": "dataset", "template": 'intitle:"index of" {q} (csv|json|xml|parquet|tsv)',
     "note": "Open directory of raw data files."},
    {"category": "dataset", "template": '{q} "public domain" filetype:{ext}',
     "note": "Explicitly public-domain material in a chosen format (uses {ext})."},
    {"category": "dataset", "template": "{q} filetype:json data -inurl:(login|admin|api-key)",
     "note": "Public JSON data dumps; excludes app/admin/secret paths by design."},

    # ----- public hosting / CDN file patterns ---------------------------
    {"category": "media", "template": "site:archive.org {q} {ext}",
     "note": "Internet Archive items in a chosen format (uses {ext})."},
    {"category": "media", "template": 'inurl:"/uploads/" {q} filetype:{ext}',
     "note": "Publicly linked upload folders, narrowed by extension."},
    {"category": "media", "template": 'inurl:"/files/" intitle:"index of" {q}',
     "note": "Open /files/ directory trees."},
    {"category": "media", "template": "site:drive.google.com {q}",
     "note": "Openly-shared Google Drive files that were made public."},
    {"category": "media", "template": "site:mega.nz {q}",
     "note": "Openly-shared MEGA links that were made public."},
    {"category": "media", "template": 'intitle:"index of" {q} (backup|mirror|releases)',
     "note": "Public release/mirror trees of software and media."},
]

# ---------------------------------------------------------------------------
# PART B — transports (priority order = try order in transport_search)
# ---------------------------------------------------------------------------
TRANSPORTS = [
    {
        "name": "marginalia",
        "priority": 1,
        "kind": "json_api",
        "status": "working",
        "url": "https://api.marginalia.nu/public/search/{q}?count={n}",
        "method": "GET",
        "operators": "keywords-only (operators treated as plain terms)",
        "rate_limit": "no visible limit; be polite (~1 req/s)",
        "note": ("Rock-solid public JSON API. Small-web index — ideal for "
                 "open-directory 'index of' listings. No key required."),
    },
    {
        "name": "mojeek",
        "priority": 2,
        "kind": "html",
        "status": "working",
        "url": "https://www.mojeek.com/search?q={q}",
        "method": "GET",
        "operators": "honors intitle:/inurl: and filetype-style terms (verified)",
        "rate_limit": "lenient; independent crawler, no obvious block seen",
        "note": "Broad independent index; parse <a class=\"title\" href>.",
    },
    {
        "name": "ddg_lite",
        "priority": 3,
        "kind": "html",
        "status": "flaky",
        "url": "https://lite.duckduckgo.com/lite/?q={q}",
        "method": "GET",
        "operators": "partial (filetype:/site: pass through to Bing back-end)",
        "rate_limit": "aggressive: 200 'anomaly' challenge after a few hits",
        "note": "Last-resort fallback only; frequently returns a 202 challenge.",
    },
    {
        "name": "searxng",
        "priority": 0,
        "kind": "json_api",
        "status": "opportunistic",
        "url": "{base}/search?q={q}&format=json",
        "method": "GET",
        "operators": "full (proxies Google/Bing/etc.) when an instance answers",
        "rate_limit": "most public instances 429/403/JS-wall JSON right now",
        "note": ("Rotates a list of public instances; low trust — nearly all "
                 "block datacenter JSON today, but occasionally one answers."),
        "instances": [
            "https://priv.au",
            "https://search.inetol.net",
            "https://baresearch.org",
            "https://opnxng.com",
            "https://paulgo.io",
        ],
    },
]

_PRIMARY = "marginalia"
_FALLBACK = "mojeek"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def build_dork(category, q, ext=""):
    """Return a ready-to-run dork string for the first template in `category`.

    Fills ``{q}`` with the query and ``{ext}`` with the extension. If no
    template exists for the category, falls back to the canonical open-dir
    form. Never raises.
    """
    q = "" if q is None else str(q).strip()
    ext = "" if ext is None else str(ext).strip().lstrip(".")
    template = 'intitle:"index of" {q}'
    for d in DORKS:
        if d.get("category") == category:
            template = d.get("template", template)
            break
    try:
        out = template.format(q=q, ext=ext)
    except Exception:
        out = "%s %s" % (q, ext)
    return _re.sub(r"\s+", " ", out).strip()


def _get(url, timeout, accept=None):
    headers = {"User-Agent": _UA, "Accept-Language": "en-US,en;q=0.9"}
    if accept:
        headers["Accept"] = accept
    req = _ureq.Request(url, headers=headers)
    with _ureq.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(4 * 1024 * 1024)      # cap: a transport reply is never this big
    enc = "utf-8"
    return raw.decode(enc, "replace")


def _dedup(rows, limit=25):
    seen = set()
    out = []
    for r in rows:
        u = (r.get("url") or "").strip()
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(r)
        if len(out) >= limit:
            break
    return out


def _search_marginalia(dork, timeout):
    q = _uparse.quote(dork, safe="")
    url = "https://api.marginalia.nu/public/search/%s?count=25" % q
    txt = _get(url, timeout, accept="application/json")
    data = _json.loads(txt)
    rows = []
    for r in data.get("results", []):
        rows.append({
            "url": r.get("url", ""),
            "title": (r.get("title") or "").strip(),
            "snippet": (r.get("description") or "").strip(),
            "transport": "marginalia",
        })
    return rows


_MOJEEK_RE = _re.compile(
    r'<a\s+class="title"[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
    _re.I | _re.S)
_TAG_RE = _re.compile(r"<[^>]+>")


def _search_mojeek(dork, timeout):
    q = _uparse.quote_plus(dork)
    url = "https://www.mojeek.com/search?q=%s" % q
    txt = _get(url, timeout, accept="text/html")
    rows = []
    for m in _MOJEEK_RE.finditer(txt):
        u = m.group(1)
        title = _html.unescape(_TAG_RE.sub("", m.group(2))).strip()
        rows.append({"url": u, "title": title, "snippet": "",
                     "transport": "mojeek"})
    return rows


_DDG_RE = _re.compile(r'class="result-link"\s+href="([^"]+)"[^>]*>(.*?)</a>',
                      _re.I | _re.S)


def _search_ddg_lite(dork, timeout):
    q = _uparse.quote_plus(dork)
    url = "https://lite.duckduckgo.com/lite/?q=%s&kl=us-en" % q
    txt = _get(url, timeout, accept="text/html")
    rows = []
    for m in _DDG_RE.finditer(txt):
        href = m.group(1)
        # DDG wraps targets as //duckduckgo.com/l/?uddg=<encoded>
        real = href
        mm = _re.search(r"uddg=([^&]+)", href)
        if mm:
            real = _uparse.unquote(mm.group(1))
        if not real.startswith("http"):
            continue
        title = _html.unescape(_TAG_RE.sub("", m.group(2))).strip()
        rows.append({"url": real, "title": title, "snippet": "",
                     "transport": "ddg_lite"})
    return rows


def _search_searxng(dork, timeout):
    import os as _os
    instances = []
    for t in TRANSPORTS:
        if t.get("name") == "searxng":
            instances = list(t.get("instances", []))
            break
    # Prefer our OWN self-hosted SearXNG node (reliable, unrate-limited) over the
    # public instances, which almost always block datacenter JSON.
    local = _os.environ.get("SEARX_URL", "http://127.0.0.1:8080").rstrip("/")
    instances = [local] + [i for i in instances if i.rstrip("/") != local]
    q = _uparse.quote_plus(dork)
    for base in instances:
        try:
            url = "%s/search?q=%s&format=json" % (base, q)
            txt = _get(url, timeout, accept="application/json")
            data = _json.loads(txt)
        except Exception:
            continue
        rows = []
        for r in data.get("results", []):
            u = r.get("url", "")
            if not u:
                continue
            rows.append({
                "url": u,
                "title": (r.get("title") or "").strip(),
                "snippet": (r.get("content") or "").strip(),
                "transport": "searxng:" + base,
            })
        if rows:
            return rows
    return []


# name -> callable, tried in TRANSPORTS priority order
_BACKENDS = {
    "marginalia": _search_marginalia,
    "mojeek": _search_mojeek,
    "ddg_lite": _search_ddg_lite,
    "searxng": _search_searxng,
}


def transport_search(dork, timeout=12):
    """Query the best working transport for `dork`. NEVER raises.

    Tries transports in TRANSPORTS priority order and returns the first
    non-empty, de-duplicated result set as a list of
    ``{"url","title","snippet","transport"}`` dicts. Returns [] if every
    transport fails or yields nothing.
    """
    if not dork:
        return []
    order = sorted(TRANSPORTS, key=lambda t: t.get("priority", 99))
    for t in order:
        fn = _BACKENDS.get(t.get("name"))
        if fn is None:
            continue
        try:
            rows = fn(dork, timeout)
        except Exception:
            rows = []
        rows = _dedup(rows or [])
        if rows:
            return rows
    return []


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    import sys
    query = sys.argv[1] if len(sys.argv) > 1 else "index of flac"
    print("build_dork(open_directory):", build_dork("open_directory", query))
    print("build_dork(filetype, pdf):", build_dork("filetype", query, "pdf"))
    print("DORKS:", len(DORKS), "templates")
    res = transport_search(build_dork("open_directory", query), timeout=15)
    print("results:", len(res))
    for r in res[:5]:
        print(" -", r["transport"], r["url"][:90])
