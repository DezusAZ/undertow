"""PubMed source adapter — biomedical literature via NCBI E-utilities (no API key).

Two bounded calls against eutils.ncbi.nlm.nih.gov:
  1. esearch  -> list of PubMed IDs for the query
  2. esummary -> title + pubdate for those IDs
Landing page for each hit is https://pubmed.ncbi.nlm.nih.gov/{id}/ .

NCBI requires a descriptive User-Agent with a contact string; no key is needed
for the light (<=3 req/s) usage here.
"""

import gzip
import io
import json
import re
import socket  # noqa: F401  (documented stdlib-only surface)
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "PubMed"
CATEGORIES = {"documents"}

_HOST = "eutils.ncbi.nlm.nih.gov"
_ESEARCH_URL = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
_ESUMMARY_URL = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"

# NCBI E-utilities policy requires a descriptive UA with a contact string.
_USER_AGENT = "Undertow/1.0 (+https://undertow.local; contact: undertow@undertow.local)"

_MAX_RESULTS = 40
_MAX_BODY = 4 * 1024 * 1024  # cap raw response body at 4 MB
_MAX_INFLATED = 8 * 1024 * 1024  # cap gzip inflate at 8 MB
_CHUNK = 65536

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
            "Accept": "application/json, */*;q=0.5",
            "Accept-Encoding": "gzip",
        },
    )
    resp = _OPENER.open(req, timeout=min(remaining, 12))
    try:
        # Reject a redirect that landed us on any other host.
        if urllib.parse.urlparse(resp.geturl()).hostname != _HOST:
            return b""
        return _read_capped(resp, deadline)
    finally:
        resp.close()


def _fetch_json(url, deadline):
    body = _fetch(url, deadline)
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None


def _clean(text):
    if not text:
        return ""
    return _WS_RE.sub(" ", str(text)).strip()


def _pubdate(rec):
    """Normalize an esummary pubdate ('2021 Jun', '2021', ...) to a date string."""
    raw = _clean(rec.get("pubdate") or rec.get("epubdate") or rec.get("sortpubdate"))
    if not raw:
        return ""
    # sortpubdate looks like '2021/06/01 00:00' -> take the date half
    m = re.match(r"(\d{4})/(\d{2})/(\d{2})", raw)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    # pubdate looks like '2021 Jun 15' or '2021 Jun' or '2021'
    months = {
        "jan": "01", "feb": "02", "mar": "03", "apr": "04", "may": "05",
        "jun": "06", "jul": "07", "aug": "08", "sep": "09", "oct": "10",
        "nov": "11", "dec": "12",
    }
    parts = raw.split()
    if not parts or not re.fullmatch(r"\d{4}", parts[0]):
        return raw[:10]
    year = parts[0]
    mon = ""
    if len(parts) >= 2:
        mon = months.get(parts[1][:3].lower(), "")
    if mon and len(parts) >= 3 and re.fullmatch(r"\d{1,2}", parts[2]):
        return f"{year}-{mon}-{int(parts[2]):02d}"
    if mon:
        return f"{year}-{mon}"
    return year


def search(query, category="", timeout=12):
    """Search PubMed. Returns [] on any error; never raises."""
    try:
        q = _clean(query if query is not None else "")
        if not q:
            return []
        if category and category not in CATEGORIES:
            return []

        deadline = time.monotonic() + max(1, timeout)

        # --- Call 1: esearch -> ID list ---
        params = urllib.parse.urlencode(
            {
                "db": "pubmed",
                "retmode": "json",
                "retmax": _MAX_RESULTS,
                "term": q,
            }
        )
        data = _fetch_json(_ESEARCH_URL + "?" + params, deadline)
        if not isinstance(data, dict):
            return []
        idlist = (data.get("esearchresult") or {}).get("idlist") or []
        ids = [str(i) for i in idlist if re.fullmatch(r"\d+", str(i))]
        ids = ids[:_MAX_RESULTS]
        if not ids:
            return []

        # --- Call 2: esummary -> titles + pubdates ---
        params = urllib.parse.urlencode(
            {
                "db": "pubmed",
                "retmode": "json",
                "id": ",".join(ids),
            }
        )
        data = _fetch_json(_ESUMMARY_URL + "?" + params, deadline)
        if not isinstance(data, dict):
            return []
        result = data.get("result") or {}
        uids = result.get("uids") or ids

        out = []
        for uid in uids:
            uid = str(uid)
            if not re.fullmatch(r"\d+", uid):
                continue
            rec = result.get(uid)
            if not isinstance(rec, dict):
                continue
            title = _clean(rec.get("title"))
            if not title:
                continue
            out.append(
                {
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": f"https://pubmed.ncbi.nlm.nih.gov/{uid}/",
                    "date": _pubdate(rec),
                    "category": "documents",
                    "quality": "HTML",
                }
            )
            if len(out) >= _MAX_RESULTS:
                break
        return out
    except Exception:
        return []


if __name__ == "__main__":
    _KEYS = {
        "title", "source", "seeders", "size", "magnet",
        "torrent_url", "url", "date", "category", "quality",
    }
    for q in ("crispr gene editing", "sars-cov-2 vaccine efficacy"):
        hits = search(q, timeout=15)
        print(f"query={q!r} -> {len(hits)} results")
        for h in hits[:3]:
            print("  ", h["date"], h["title"][:70])
            print("     ", h["url"])
        assert all(set(h) == _KEYS for h in hits), "bad result keys"
        assert all(h["url"] for h in hits), "empty url"
        assert all(h["source"] == NAME for h in hits), "bad source"
        assert all(h["category"] == "documents" for h in hits), "bad category"
    print("self-test: mismatched-category ->", len(search("cancer", category="music")))
    print("self-test: empty query ->", len(search("")))
    print("self-test: None query ->", len(search(None)))
    print("OK")
