"""arXiv source adapter — open-access academic paper PDFs via the public Atom API."""

import gzip
import io
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NAME = "arXiv"
CATEGORIES = {"documents"}

_HOST = "export.arxiv.org"
_API_URL = "https://export.arxiv.org/api/query"
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
)
_MAX_RESULTS = 40
_MAX_BODY = 4 * 1024 * 1024  # cap raw response body at 4 MB
_MAX_INFLATED = 8 * 1024 * 1024  # cap gzip inflate at 8 MB
_CHUNK = 65536

_ATOM_NS = "{http://www.w3.org/2005/Atom}"

_WS_RE = re.compile(r"\s+")


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Only follow redirects that stay on the intended HTTPS host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname != _HOST:
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
            "Accept": "application/atom+xml, application/xml;q=0.9, */*;q=0.5",
            "Accept-Encoding": "gzip",
        },
    )
    resp = _OPENER.open(req, timeout=min(remaining, 12))
    try:
        return _read_capped(resp, deadline)
    finally:
        resp.close()


def _text(entry, tag):
    el = entry.find(_ATOM_NS + tag)
    if el is None or el.text is None:
        return ""
    return _WS_RE.sub(" ", el.text).strip()


def _pdf_link(entry):
    fallback = ""
    for link in entry.findall(_ATOM_NS + "link"):
        href = (link.get("href") or "").strip()
        if not href.lower().startswith(("http://", "https://")):
            continue
        if href.startswith("http://"):
            href = "https://" + href[len("http://"):]
        if link.get("title") == "pdf":
            return href
        if link.get("rel") == "alternate" and not fallback:
            fallback = href
    return fallback


def search(query, category="", timeout=12):
    """Search arXiv. Returns [] on any error; never raises."""
    try:
        q = _WS_RE.sub(" ", "" if query is None else str(query)).strip()
        if not q:
            return []
        if category and category not in CATEGORIES:
            return []

        deadline = time.monotonic() + max(1, timeout)
        params = urllib.parse.urlencode(
            {
                "search_query": "all:" + q,
                "start": 0,
                "max_results": _MAX_RESULTS,
            }
        )
        body = _fetch(_API_URL + "?" + params, deadline)
        if not body:
            return []

        root = ET.fromstring(body)
        results = []
        for entry in root.findall(_ATOM_NS + "entry"):
            title = _text(entry, "title")
            url = _pdf_link(entry)
            if not title or not url:
                continue
            published = _text(entry, "published")
            results.append(
                {
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": url,
                    "date": published[:10] if published else "",
                    "category": "documents",
                    "quality": "PDF",
                }
            )
            if len(results) >= _MAX_RESULTS:
                break
        return results
    except Exception:
        return []


if __name__ == "__main__":
    for q in ("quantum error correction", "large language models"):
        hits = search(q, timeout=15)
        print(f"query={q!r} -> {len(hits)} results")
        for h in hits[:3]:
            print("  ", h["date"], h["title"][:70])
            print("     ", h["url"])
        keys = {
            "title", "source", "seeders", "size", "magnet",
            "torrent_url", "url", "date", "category", "quality",
        }
        assert all(set(h) == keys for h in hits), "bad result keys"
        assert all(h["url"] for h in hits), "empty url"
    print("self-test: mismatched-category ->", len(search("test", category="music")))
    print("self-test: empty query ->", len(search("")))
    print("OK")
