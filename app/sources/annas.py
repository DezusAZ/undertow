"""Books/documents adapter for the Library Genesis / Anna's Archive ecosystem (direct-download links, not torrents)."""

import html as _html
import ipaddress
import re
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "Anna's Archive / LibGen"


def _redirect_host_unsafe(host):
    """True if a redirect target is loopback/private/an IP literal — an SSRF risk
    (a churn-prone mirror could 302 us to 127.0.0.1:9117 / a LAN box)."""
    h = (host or "").strip().lower()
    if not h or h == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(h)          # bare IP literal
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False                          # a hostname (resolution TOCTOU out of scope)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p = urllib.parse.urlsplit(newurl)
        if p.scheme not in ("http", "https") or _redirect_host_unsafe(p.hostname):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirect())

# Mirrors, most reliable first. Two HTML flavours exist:
#   "li"      -> libgen.li family: /index.php?req=..., table id="tablelibgen"
#   "classic" -> libgen.is family: /search.php?req=..., table class="c"
_MIRRORS = [
    ("https://libgen.li", "li"),
    ("https://libgen.gs", "li"),
    ("https://libgen.vg", "li"),
    ("https://libgen.la", "li"),
    ("https://libgen.bz", "li"),
    ("https://libgen.is", "classic"),
    ("https://libgen.rs", "classic"),
    ("https://libgen.st", "classic"),
]

_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
       "Gecko/20100101 Firefox/128.0")

_MAX_RESULTS = 40

_SIZE_RE = re.compile(r"([\d.,]+)\s*([kKmMgG]?)[bB]")
_TAG_RE = re.compile(r"<[^>]+>")
_MD5_RE = re.compile(r"md5=([0-9a-fA-F]{32})")
_TD_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.S | re.I)
_TR_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S | re.I)
_YEAR_RE = re.compile(r"\b(1[5-9]\d{2}|20\d{2})\b")


def _text(fragment):
    """Strip tags, unescape entities, collapse whitespace."""
    t = _TAG_RE.sub(" ", fragment or "")
    t = _html.unescape(t)
    return re.sub(r"\s+", " ", t).strip()


def _parse_size(s):
    m = _SIZE_RE.search(s or "")
    if not m:
        return 0
    try:
        n = float(m.group(1).replace(",", ""))
    except ValueError:
        return 0
    mult = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}
    return int(n * mult.get(m.group(2).lower(), 1))


def _fetch(url, deadline):
    """GET url, enforcing the wall-clock deadline even across slow chunked reads."""
    per_timeout = max(1.0, min(6.0, deadline - time.monotonic()))
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.5",
    })
    chunks, total = [], 0
    with _OPENER.open(req, timeout=per_timeout) as resp:
        while total < 3 * 1024 * 1024:
            if time.monotonic() > deadline:
                break  # keep whatever arrived; parser copes with truncation
            chunk = resp.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _mk_result(title, base, md5, year, size, ext):
    return {
        "title": title,
        "source": NAME,
        "seeders": 0,
        "size": size,
        "magnet": "",
        "torrent_url": "",
        "url": "%s/ads.php?md5=%s" % (base, md5),
        "date": year,
        "category": "documents",   # part of the document fleet — must match the Documents scope
        "quality": (ext or "").strip().upper()[:8],
    }


def _parse_li(body, base):
    """libgen.li-family results: <table id="tablelibgen"> rows.
    Cells: title | author | series/alt | year | lang | pages | size | ext | mirrors
    """
    out = []
    i = body.find('id="tablelibgen"')
    if i < 0:
        return out
    for row in _TR_RE.findall(body[i:]):
        md5m = _MD5_RE.search(row)
        if not md5m:
            continue
        cells = _TD_RE.findall(row)
        if len(cells) < 9:
            continue
        # Title: prefer the edition.php anchor text over series/badge noise.
        tm = re.search(r'href="/?edition\.php[^"]*"[^>]*>(.*?)</a>',
                       cells[0], re.S)
        title = _text(tm.group(1) if tm else cells[0])
        if not title:
            continue
        author = _text(cells[1])
        ym = _YEAR_RE.search(_text(cells[3]))
        if author:
            title = "%s — %s" % (title, author)
        out.append(_mk_result(
            title, base, md5m.group(1).lower(),
            ym.group(1) if ym else "",
            _parse_size(_text(cells[6])),
            _text(cells[7]),
        ))
    return out


def _parse_classic(body, base):
    """libgen.is-family results: <table class="c"> rows.
    Cells: id | author | title | publisher | year | pages | lang | size | ext | ...
    """
    out = []
    i = body.find('<table')
    i = body.find('class="c"', i if i >= 0 else 0)
    if i < 0:
        return out
    for row in _TR_RE.findall(body[i:]):
        md5m = _MD5_RE.search(row)
        if not md5m:
            continue
        cells = _TD_RE.findall(row)
        if len(cells) < 9:
            continue
        title = _text(re.sub(r"<br\s*/?>.*", "", cells[2], flags=re.S))
        if not title:
            continue
        author = _text(cells[1])
        ym = _YEAR_RE.search(_text(cells[4]))
        if author:
            title = "%s — %s" % (title, author)
        r = _mk_result(
            title, base, md5m.group(1).lower(),
            ym.group(1) if ym else "",
            _parse_size(_text(cells[7])),
            _text(cells[8]),
        )
        r["url"] = "%s/book/index.php?md5=%s" % (base, md5m.group(1).lower())
        out.append(r)
    return out


def search(query, category="", timeout=12):
    """Search LibGen mirrors for books/documents. Never raises; [] on failure."""
    try:
        if not query or not str(query).strip():
            return []
        if category and category not in ("all", "documents", "book", "other"):
            return []
        deadline = time.monotonic() + max(3, float(timeout))
        q = urllib.parse.quote_plus(str(query).strip())
        for base, flavour in _MIRRORS:
            remaining = deadline - time.monotonic()
            if remaining < 2:
                break
            if flavour == "li":
                url = "%s/index.php?req=%s&res=25" % (base, q)
            else:
                url = "%s/search.php?req=%s&res=25&view=simple" % (base, q)
            try:
                body = _fetch(url, deadline - 0.3)
            except Exception:
                continue
            try:
                if flavour == "li":
                    results = _parse_li(body, base)
                    if not results:
                        results = _parse_classic(body, base)
                else:
                    results = _parse_classic(body, base)
                    if not results:
                        results = _parse_li(body, base)
            except Exception:
                results = []
            results = [r for r in results
                       if r["magnet"] or r["torrent_url"] or r["url"]]
            if results:
                return results[:_MAX_RESULTS]
        return []
    except Exception:
        return []


if __name__ == "__main__":
    for q in ("python programming", "dune frank herbert"):
        t0 = time.monotonic()
        rs = search(q)
        print("query=%r -> %d results in %.1fs" % (q, len(rs), time.monotonic() - t0))
        for r in rs[:3]:
            print("   [%s|%s|%d bytes] %s" % (r["quality"], r["date"], r["size"], r["title"]))
            print("      %s" % r["url"])
