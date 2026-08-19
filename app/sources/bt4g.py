"""BT4G (bt4gprx.com) adapter — DHT-indexed torrent meta-search that surfaces magnets by infohash."""

import json
import re
import html as _html
import time
import socket
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET

NAME = "BT4G (DHT)"

# All known domains funnel to bt4gprx.com (bt4g.org / bt4g.com 301 there).
# Regional mirrors (us./es./kr./jp.) sit behind the same Cloudflare zone.
_MIRRORS = (
    "https://bt4gprx.com",
    "https://bt4g.org",
    "https://bt4g.com",
)

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# Trackers appended when we only have a bare infohash.
_TRACKERS = (
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.tracker.cl:1337/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
    "udp://exodus.desync.com:6969/announce",
)

# Optional FlareSolverr proxy for Cloudflare challenges. Inside the vpntorrent
# container a FlareSolverr instance shares the netns at 127.0.0.1:8191. Set to
# None (or an unreachable URL) to disable. NOTE (2026-07-12): FlareSolverr
# 3.5.0 currently CANNOT solve bt4gprx.com's challenge — this hook exists so a
# future FlareSolverr upgrade makes the adapter work without code changes.
FLARESOLVERR_URL = "http://127.0.0.1:8191/v1"

# Post-mortem status of the last search() call, for logging/diagnostics:
# "ok", "blocked" (Cloudflare challenge on every path), "error", "no-results".
LAST_STATUS = ""

_MAX_RESULTS = 40
_HEX40 = re.compile(r"\b([0-9a-fA-F]{40})\b")


def _remaining(deadline):
    return deadline - time.time()


def _http_get(url, deadline, cap=6.0):
    """GET url within budget. Returns (status_code, body_text). Never raises."""
    tmo = min(cap, _remaining(deadline))
    if tmo <= 0.5:
        return 0, ""
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    try:
        with urllib.request.urlopen(req, timeout=tmo) as r:
            return r.getcode() or 200, r.read(2 * 1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(256 * 1024).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except (urllib.error.URLError, socket.timeout, OSError, ValueError):
        return 0, ""
    except Exception:
        return 0, ""


def _is_cf_challenge(status, body):
    if status in (403, 503):
        return True
    low = body[:4000].lower()
    return ("just a moment" in low or "cf-chl" in low or "__cf_chl" in low
            or "challenges.cloudflare.com" in low)


def _flaresolverr_get(url, deadline):
    """Fetch url through FlareSolverr (if configured). Returns body or ""."""
    if not FLARESOLVERR_URL:
        return ""
    budget = _remaining(deadline) - 1.5
    if budget < 4.0:
        return ""
    payload = json.dumps({
        "cmd": "request.get",
        "url": url,
        "maxTimeout": int(budget * 1000),
    }).encode()
    req = urllib.request.Request(FLARESOLVERR_URL, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=budget + 1.0) as r:
            data = json.loads(r.read(4 * 1024 * 1024))
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read(1024 * 1024))
        except Exception:
            return ""
    except Exception:
        return ""
    if data.get("status") != "ok":
        return ""
    sol = data.get("solution") or {}
    if (sol.get("status") or 0) >= 400:
        return ""
    return sol.get("response") or ""


_SIZE_RE = re.compile(r"([\d.,]+)\s*([KMGTP]?I?B)\b", re.I)
_MULT = {"B": 1, "KB": 1024, "KIB": 1024, "MB": 1024**2, "MIB": 1024**2,
         "GB": 1024**3, "GIB": 1024**3, "TB": 1024**4, "TIB": 1024**4,
         "PB": 1024**5, "PIB": 1024**5}


def _parse_size(text):
    """'1.2 GB' / '3.63GB' -> bytes (int). 0 if unparseable."""
    m = _SIZE_RE.search(text or "")
    if not m:
        return 0
    try:
        num = float(m.group(1).replace(",", ""))
        return int(num * _MULT.get(m.group(2).upper(), 1))
    except (ValueError, KeyError):
        return 0


_QUALITY_TOKENS = (
    "2160p", "4K", "1080p", "720p", "480p", "REMUX", "BluRay", "BDRip",
    "WEB-DL", "WEBRip", "HDTV", "DVDRip", "CAMRip", "HDR", "x265", "HEVC",
    "x264", "FLAC", "MP3 320", "320kbps", "EPUB", "PDF", "MOBI", "AZW3",
)


def _quality_from_title(title):
    low = (title or "").lower()
    for tok in _QUALITY_TOKENS:
        if tok.lower() in low:
            return "4K" if tok == "2160p" else tok
    return ""


_TV_RE = re.compile(r"\bS\d{1,2}\s?E\d{1,3}\b|\bSeason\s*\d+\b|\bComplete\s+Series\b", re.I)


def _map_category(site_cat, title, hint):
    c = (site_cat or "").strip().lower()
    if c in ("movie", "video"):
        return "tv" if _TV_RE.search(title or "") else "movie"
    if c in ("audio", "music"):
        return "music"
    if c in ("doc", "document", "ebook", "book"):
        return "book"
    if c in ("app", "application", "software"):
        return "software"
    if c in ("image", "picture", "photo"):
        return "image"
    if hint in ("movie", "tv", "music", "book", "software", "image", "other"):
        return hint
    return "other"


def _magnet_from_hash(infohash, title):
    parts = ["magnet:?xt=urn:btih:" + infohash.lower()]
    if title:
        parts.append("dn=" + urllib.parse.quote(title[:200]))
    for tr in _TRACKERS:
        parts.append("tr=" + urllib.parse.quote(tr, safe=""))
    return "&".join(parts)


def _norm_title(t):
    return re.sub(r"\W+", "", (t or "").lower())[:120]


def _parse_rss(body, base, hint):
    """Parse BT4G search RSS (…&page=rss). Returns list of result dicts.

    Item layout (verified against live captures):
      <title>NAME</title>
      <link>magnet:?xt=urn:btih:HEX40&…</link>
      <guid isPermaLink="true">https://bt4gprx.com/magnet/HEX40</guid>
      <pubDate>Thu,13 Jun 2024 19:14:48 -0000</pubDate>
      <description><![CDATA[NAME<br>2.52GB<br>Movie<br>HEX40]]></description>
    """
    out = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return out
    for item in root.iter("item"):
        try:
            title = _html.unescape((item.findtext("title") or "").strip())
            link = (item.findtext("link") or "").strip()
            guid = (item.findtext("guid") or "").strip()
            date = (item.findtext("pubDate") or "").strip()
            desc = item.findtext("description") or ""
            # description CDATA: NAME<br>SIZE<br>CATEGORY<br>HASH
            dparts = [p.strip() for p in re.split(r"<br\s*/?>", desc)]
            size = 0
            site_cat = ""
            infohash = ""
            for p in dparts[1:]:
                if not p:
                    continue
                if not infohash and _HEX40.fullmatch(p):
                    infohash = p
                    continue
                if not size and len(p) < 16:
                    s = _parse_size(p)
                    if s:
                        size = s
                        continue
                if not site_cat and len(p) < 24 and not _SIZE_RE.search(p):
                    site_cat = p
            if not infohash:
                m = _HEX40.search(guid) or _HEX40.search(link) or _HEX40.search(desc)
                if m:
                    infohash = m.group(1)
            magnet = link if link.startswith("magnet:") else ""
            if not magnet and infohash:
                magnet = _magnet_from_hash(infohash, title)
            page = guid if guid.startswith("http") else (
                base + "/magnet/" + infohash if infohash else "")
            if not title or not (magnet or page):
                continue
            out.append({
                "title": title,
                "source": NAME,
                "seeders": None,          # RSS carries no swarm count; enriched from HTML below
                "size": size,
                "magnet": magnet,
                "torrent_url": "",
                "url": page,
                "date": date,
                "category": _map_category(site_cat, title, hint),
                "quality": _quality_from_title(title),
            })
        except Exception:
            continue
    return out


_A_RE = re.compile(
    r'<a\s+title="([^"]*)"\s+href="(/magnet/[^"]+)"', re.S)
_SEED_RE = re.compile(r'Seeders:\s*<b[^>]*>\s*(\d+)', re.S)
_TSIZE_RE = re.compile(r'Total\s+Size:\s*<b[^>]*>\s*([^<]+?)\s*<', re.S)
_DATE_RE = re.compile(r'Creation\s+Time:(?:&nbsp;|\s)*([\d-]{8,10})', re.S)
_CAT_RE = re.compile(r'class="cpill\s+fileType\d+"[^>]*>\s*([^<]+?)\s*<', re.S)


def _parse_html(body, base, hint):
    """Defensive regex parse of the HTML results page.

    Verified anchors (2025 layout): results are chunks after
    '<div class="list-group-item result-item">'; each has
    <a title="NAME" href="/magnet/OBFUSCATED_ID">, a
    'Total Size: <b class="cpill red-pill">3.63GB</b>' span, a
    'Seeders: <b id="seeders">23</b>' span, 'Creation Time:&nbsp;YYYY-MM-DD',
    and a '<span class="cpill fileType1">Video</span>' category pill.
    The /magnet/<id> path on this page is an obfuscated id (NOT the hex
    infohash), so HTML-only results carry a page url but no magnet.
    """
    out = []
    chunks = re.split(r'class="[^"]*result-item[^"]*"', body)
    for chunk in chunks[1:]:
        try:
            am = _A_RE.search(chunk)
            if not am:
                continue
            title = _html.unescape(am.group(1)).strip()
            href = _html.unescape(am.group(2))
            sm = _SEED_RE.search(chunk)
            zm = _TSIZE_RE.search(chunk)
            dm = _DATE_RE.search(chunk)
            cm = _CAT_RE.search(chunk)
            hm = _HEX40.search(href)
            magnet = _magnet_from_hash(hm.group(1), title) if hm else ""
            if not title:
                continue
            out.append({
                "title": title,
                "source": NAME,
                "seeders": int(sm.group(1)) if sm else None,   # None = not found on the page (unknown)
                "size": _parse_size(zm.group(1)) if zm else 0,
                "magnet": magnet,
                "torrent_url": "",
                "url": base + href,
                "date": dm.group(1) if dm else "",
                "category": _map_category(cm.group(1) if cm else "", title, hint),
                "quality": _quality_from_title(title),
            })
        except Exception:
            continue
    return out


def search(query, category="", timeout=12):
    """Search BT4G. Returns a list of result dicts; [] on any failure."""
    global LAST_STATUS
    LAST_STATUS = "error"
    try:
        deadline = time.time() + max(1.0, float(timeout))
        q = urllib.parse.quote_plus((query or "").strip())
        if not q:
            LAST_STATUS = "no-results"
            return []
        blocked_everywhere = True
        results = []
        html_body_for_seeders = ""
        base_used = _MIRRORS[0]

        for base in _MIRRORS:
            if _remaining(deadline) < 2.0:
                break
            rss_url = f"{base}/search?q={q}&orderby=seeders&p=1&page=rss"
            status, body = _http_get(rss_url, deadline)
            if status == 0:
                continue  # unreachable — not necessarily a CF block
            if _is_cf_challenge(status, body):
                continue  # blocked on this mirror; try next
            blocked_everywhere = False
            results = _parse_rss(body, base, category)
            base_used = base
            if results:
                break
            # RSS empty/unparseable but mirror alive — try the HTML page
            h_url = f"{base}/search?q={q}&orderby=seeders&p=1"
            hstatus, hbody = _http_get(h_url, deadline)
            if hstatus and not _is_cf_challenge(hstatus, hbody):
                results = _parse_html(hbody, base, category)
                if results:
                    break

        if not results and blocked_everywhere:
            # Cloudflare challenge on every mirror: last resort, FlareSolverr
            # (works only if the local FlareSolverr build can solve BT4G's
            # challenge AND enough budget remains — see FLARESOLVERR_URL note).
            body = _flaresolverr_get(
                f"{_MIRRORS[0]}/search?q={q}&orderby=seeders&p=1&page=rss",
                deadline)
            if body and not _is_cf_challenge(200, body):
                # FlareSolverr wraps XML in an HTML shell sometimes; try both.
                results = _parse_rss(body, _MIRRORS[0], category)
                if not results:
                    m = re.search(r"<rss\b.*</rss>", body, re.S)
                    if m:
                        results = _parse_rss(m.group(0), _MIRRORS[0], category)
                if not results:
                    results = _parse_html(body, _MIRRORS[0], category)
                if results:
                    blocked_everywhere = False
            if not results:
                LAST_STATUS = "blocked" if blocked_everywhere else "no-results"
                return []

        # Enrich RSS results (which carry no seeder counts) from the HTML page.
        if results and not results[0]["seeders"] and _remaining(deadline) > 2.5:   # None (RSS) or 0 -> enrich
            h_url = f"{base_used}/search?q={q}&orderby=seeders&p=1"
            hstatus, hbody = _http_get(h_url, deadline, cap=4.0)
            if hstatus and not _is_cf_challenge(hstatus, hbody):
                seed_map = {}
                for r in _parse_html(hbody, base_used, category):
                    seed_map[_norm_title(r["title"])] = r["seeders"]
                for r in results:
                    r["seeders"] = seed_map.get(_norm_title(r["title"]), r["seeders"])

        results = [r for r in results if r["magnet"] or r["torrent_url"] or r["url"]]
        LAST_STATUS = "ok" if results else "no-results"
        return results[:_MAX_RESULTS]
    except Exception:
        LAST_STATUS = "error"
        return []


if __name__ == "__main__":
    for q in ("ubuntu", "big buck bunny"):
        t0 = time.time()
        res = search(q, timeout=12)
        print(f"query={q!r} -> {len(res)} results in {time.time()-t0:.1f}s "
              f"(status={LAST_STATUS})")
        for r in res[:3]:
            print("   ", r["seeders"], "seeds |", r["size"], "B |",
                  r["title"][:70], "|", (r["magnet"][:60] or r["url"][:60]))
