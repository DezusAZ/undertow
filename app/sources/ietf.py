"""IETF Datatracker search source — RFCs / internet standards.

Queries the public IETF Datatracker document API (JSON, no API key):
    https://datatracker.ietf.org/api/v1/doc/document/?format=json
        &type=rfc&title__icontains=<q>&limit=40
Each object carries `name` (e.g. "rfc9312"), `title`, `time` (ISO
timestamp of the last update) and `rfc_number`. The openable document
is the canonical plain-text at https://www.rfc-editor.org/rfc/<name>.txt
so quality is reported as "TXT".

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

NAME = "IETF"
CATEGORIES = {"documents"}

_HOST = "datatracker.ietf.org"
_API = "https://" + _HOST + "/api/v1/doc/document/"
# Some of these APIs ask for a contact address in the User-Agent. Default to a
# neutral placeholder and let the OPERATOR set their own via UNDERTOW_CONTACT —
# never ship a personal address, or every user of this tool identifies the packager.
_CONTACT = os.environ.get("UNDERTOW_CONTACT", "undertow@example.com")
_UA = "Undertow/1.0 (+https://undertow.local; contact: %s)" % _CONTACT

_MAX_RESULTS = 40
_MAX_BODY = 4 * 1024 * 1024      # cap raw body read (bytes)
_MAX_INFLATE = 8 * 1024 * 1024   # cap gzip-inflated size (bytes)
_CHUNK = 65536

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,80}$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any redirect (so we can never leave the host)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _get(url, deadline):
    """HTTPS GET to the intended host, honoring the wall-clock deadline.

    Returns decoded bytes or None. Never raises.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != _HOST:
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
    except Exception:
        return None


def _doc_date(obj):
    """Extract YYYY-MM-DD from the object's `time` ISO timestamp."""
    stamp = str(obj.get("time") or "").strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", stamp)
    return m.group(1) if m else ""


def search(query, category="", timeout=12):
    """Search IETF RFCs by title. Returns a list of result dicts; [] on error."""
    results = []
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1.0, float(timeout))
        url = _API + "?" + urllib.parse.urlencode({
            "format": "json",
            "type": "rfc",
            "title__icontains": query,
            "limit": _MAX_RESULTS,
        })
        raw = _get(url, deadline)
        if not raw:
            return []
        payload = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(payload, dict):
            return []
        objects = payload.get("objects")
        if not isinstance(objects, list):
            return []
        for obj in objects:
            if len(results) >= _MAX_RESULTS:
                break
            try:
                if not isinstance(obj, dict):
                    continue
                title = str(obj.get("title") or "").strip()
                name = str(obj.get("name") or "").strip().lower()
                if not title or not _NAME_RE.match(name):
                    continue
                rfc_number = obj.get("rfc_number")
                if isinstance(rfc_number, int) and rfc_number > 0:
                    title = "RFC %d: %s" % (rfc_number, title)
                doc_url = "https://www.rfc-editor.org/rfc/%s.txt" % name
                results.append({
                    "title": title,
                    "source": NAME,
                    "seeders": 0,
                    "size": 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": doc_url,
                    "date": _doc_date(obj),
                    "category": "documents",
                    "quality": "TXT",
                })
            except Exception:
                continue
    except Exception:
        return results
    return results


if __name__ == "__main__":
    for q in ("quic", "http/2", "zxqjkw-no-such-topic"):
        t0 = time.monotonic()
        rs = search(q, timeout=12)
        dt = time.monotonic() - t0
        print("query=%-24r -> %2d results in %.2fs" % (q, len(rs), dt))
        for r in rs[:3]:
            assert set(r) == {"title", "source", "seeders", "size", "magnet",
                              "torrent_url", "url", "date", "category",
                              "quality"}, r
            assert r["url"], r
            assert isinstance(r["seeders"], int) and isinstance(r["size"], int)
            print("   - %s | %s | %s | %s" %
                  (r["title"][:55], r["date"], r["quality"], r["url"][:60]))
    # never-raise checks
    print("bad category ->", len(search("quic", category="movies")))
    print("empty query  ->", len(search("")))
    print("tiny timeout ->", len(search("quic", timeout=0.001)))
