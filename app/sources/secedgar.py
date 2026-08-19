"""SEC EDGAR full-text search source.

Queries the SEC's EDGAR full-text search backend (no API key; SEC fair-access
policy REQUIRES a User-Agent that identifies you with contact info):

    https://efts.sec.gov/LATEST/search-index?q=<q>&forms=

It returns an Elasticsearch-style JSON body; each hit's ``_id`` is
``<accession-with-dashes>:<filename>`` and ``_source`` carries the company
(``display_names``), CIK list, form type and filing date. The openable
document URL is built as:

    https://www.sec.gov/Archives/edgar/data/<cik>/<accession-no-dashes>/<filename>

Covers 10-K, 10-Q, 8-K, prospectuses, exhibits, etc. (filings since 2001).
Stdlib only. Never raises: search() returns [] on any error.
"""

import os
import gzip
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "SEC EDGAR"
CATEGORIES = {"documents"}

_API_HOST = "efts.sec.gov"
_API = "https://" + _API_HOST + "/LATEST/search-index"
_DOC_BASE = "https://www.sec.gov/Archives/edgar/data"

# SEC requires a UA with contact information (https://www.sec.gov/os/accessing-edgar-data)
# Some of these APIs ask for a contact address in the User-Agent. Default to a
# neutral placeholder and let the OPERATOR set their own via UNDERTOW_CONTACT —
# never ship a personal address, or every user of this tool identifies the packager.
_CONTACT = os.environ.get("UNDERTOW_CONTACT", "undertow@example.com")
_UA = "Undertow/1.0 (research tool; contact: %s)" % _CONTACT

_MAX_RESULTS = 40
_MAX_BODY = 4 * 1024 * 1024      # cap raw body read (bytes)
_MAX_INFLATE = 8 * 1024 * 1024   # cap gzip-inflated size (bytes)
_CHUNK = 65536

_QUALITY_BY_EXT = {
    "htm": "HTML", "html": "HTML",
    "pdf": "PDF",
    "xml": "XML", "xsd": "XML",
    "txt": "TXT",
    "epub": "EPUB",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any redirect (so we can never leave the host)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _get(url, deadline):
    """HTTPS GET pinned to the API host, honoring the wall-clock deadline.

    Retries once (briefly) on SEC rate limiting (429/503).
    Returns decoded bytes or None. Never raises.
    """
    for attempt in (0, 1):
        try:
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname != _API_HOST:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0.05:
                return None
            req = urllib.request.Request(url, headers={
                "User-Agent": _UA,
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
            })
            body = io.BytesIO()
            with _OPENER.open(req, timeout=min(remaining, 12.0)) as resp:
                while body.tell() < _MAX_BODY:
                    if time.monotonic() >= deadline:
                        return None  # slow-loris body: give up
                    chunk = resp.read(min(_CHUNK, _MAX_BODY - body.tell()))
                    if not chunk:
                        break
                    body.write(chunk)
                enc = (resp.headers.get("Content-Encoding") or "").lower()
            data = body.getvalue()
            if "gzip" in enc:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                    data = gz.read(_MAX_INFLATE + 1)
                if len(data) > _MAX_INFLATE:
                    return None
            return data
        except urllib.error.HTTPError as exc:
            # Graceful rate-limit handling: one short back-off retry.
            if attempt == 0 and exc.code in (429, 503):
                pause = min(1.5, max(0.0, deadline - time.monotonic() - 0.5))
                if pause <= 0:
                    return None
                time.sleep(pause)
                continue
            return None
        except Exception:
            return None
    return None


def _doc_url(hit_id, ciks):
    """Build the www.sec.gov Archives URL from a hit _id + CIK list.

    Returns "" if the pieces don't look right.
    """
    try:
        adsh, _, fname = hit_id.partition(":")
        adsh_clean = adsh.replace("-", "")
        if not re.fullmatch(r"\d{18}", adsh_clean):
            return ""
        cik = ""
        for c in ciks or []:
            c = str(c).strip()
            if c.isdigit():
                cik = str(int(c))  # strip leading zeros
                break
        if not cik:
            return ""
        base = "%s/%s/%s/" % (_DOC_BASE, cik, adsh_clean)
        fname = fname.strip().lstrip("/")
        if fname and re.fullmatch(r"[A-Za-z0-9._\-]+", fname):
            return base + urllib.parse.quote(fname)
        return base  # directory index of the filing — still openable
    except Exception:
        return ""


def _quality(hit_id):
    fname = hit_id.partition(":")[2]
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    return _QUALITY_BY_EXT.get(ext, "")


def search(query, category="", timeout=12):
    """Full-text search SEC EDGAR filings. Returns list of dicts; [] on error."""
    results = []
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))
        url = _API + "?" + urllib.parse.urlencode({"q": query, "forms": ""})
        raw = _get(url, deadline)
        if not raw:
            return []
        payload = json.loads(raw.decode("utf-8", "replace"))
        hits = (payload.get("hits") or {}).get("hits") or []
        if not isinstance(hits, list):
            return []
        seen = set()
        for hit in hits:
            if len(results) >= _MAX_RESULTS:
                break
            try:
                if not isinstance(hit, dict):
                    continue
                hit_id = str(hit.get("_id") or "")
                src = hit.get("_source") or {}
                if not hit_id or not isinstance(src, dict):
                    continue
                doc = _doc_url(hit_id, src.get("ciks"))
                if not doc or doc in seen:
                    continue
                seen.add(doc)
                names = src.get("display_names") or []
                company = str(names[0]).strip() if names else ""
                # trim the trailing "(CIK 0001234567)" noise
                company = re.sub(r"\s*\(CIK \d+\)\s*$", "", company)
                form = str(src.get("form") or "").strip()
                desc = str(src.get("file_description") or "").strip()
                ftype = str(src.get("file_type") or "").strip()
                bits = [b for b in (company, form, desc or ftype) if b]
                title = " — ".join(bits) or hit_id
                date = str(src.get("file_date") or "")[:10].strip()
                results.append({
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": doc,
                    "date": date,
                    "category": "documents",
                    "quality": _quality(hit_id),
                })
            except Exception:
                continue
    except Exception:
        return results
    return results


if __name__ == "__main__":
    for q in ('"lithium mining"', "artificial intelligence risk factors",
              "zxqjkw-no-such-filing-9317"):
        t0 = time.monotonic()
        rs = search(q, timeout=12)
        dt = time.monotonic() - t0
        print("query=%-40r -> %2d results in %.2fs" % (q, len(rs), dt))
        for r in rs[:3]:
            assert set(r) == {"title", "source", "seeders", "size", "magnet",
                              "torrent_url", "url", "date", "category",
                              "quality"}, r
            assert r["url"].startswith(_DOC_BASE), r
            assert r["source"] == NAME and r["category"] == "documents", r
            print("   - %s | %s | %s | %s" %
                  (r["title"][:58], r["date"], r["quality"], r["url"]))
    print("bad category ->", len(search("lithium", category="movies")))
    print("empty query  ->", len(search("")))
    print("tiny timeout ->", len(search("lithium", timeout=0.01)))
