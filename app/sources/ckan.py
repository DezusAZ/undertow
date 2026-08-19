"""Open-government dataset discovery via data.gov (catalog.data.gov).

Legal, public, no-auth API.  The classic CKAN endpoint
(/api/3/action/package_search) was retired in the 2025 data.gov redesign
and now returns 404; the new catalog serves native JSON at /search?q=...
(DCAT records).  This module tries the legacy CKAN action API first (in
case it returns) and falls back to the new /search endpoint.

Results point at dataset landing pages on catalog.data.gov and, when a
record carries a direct-file distribution, the top resource download URL.

Stdlib only.  search() never raises.
"""

import gzip
import io
import json
import re
import socket  # noqa: F401  (kept for callers that tune socket defaults)
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "data.gov"
CATEGORIES = {"documents", "other"}

_API_HOST = "catalog.data.gov"
_LEGACY_API = "https://catalog.data.gov/api/3/action/package_search"
_SEARCH_API = "https://catalog.data.gov/search"
_DATASET_BASE = "https://catalog.data.gov/dataset/"

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
)

_MAX_RESULTS = 40
_MAX_BODY_BYTES = 4 * 1024 * 1024     # cap raw body read
_MAX_INFLATE_BYTES = 8 * 1024 * 1024  # cap gzip inflate output


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: we only ever talk to the intended host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect refused", headers, fp
        )


_OPENER = urllib.request.build_opener(_NoRedirect())


def _read_capped(resp, cap, deadline):
    """Read at most `cap` bytes in chunks; bail out at the wall-clock deadline."""
    buf = io.BytesIO()
    while buf.tell() < cap:
        if time.monotonic() > deadline:
            break
        chunk = resp.read(min(65536, cap - buf.tell()))
        if not chunk:
            break
        buf.write(chunk)
    return buf.getvalue()


def _http_get_json(url, deadline):
    """GET a JSON document from the intended host only. Returns obj or None."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != _API_HOST:
        return None
    budget = deadline - time.monotonic()
    if budget <= 0.5:
        return None
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
        method="GET",
    )
    try:
        with _OPENER.open(req, timeout=min(budget, 10.0)) as resp:
            raw = _read_capped(resp, _MAX_BODY_BYTES, deadline)
            if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                    raw = gz.read(_MAX_INFLATE_BYTES)
        if time.monotonic() > deadline:
            return None
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None


# --- format / quality helpers ------------------------------------------------

_MEDIA_TO_FMT = {
    "text/csv": "CSV",
    "application/json": "JSON",
    "application/ld+json": "JSON",
    "application/geo+json": "GEOJSON",
    "application/vnd.geo+json": "GEOJSON",
    "application/xml": "XML",
    "text/xml": "XML",
    "application/rdf+xml": "RDF",
    "application/zip": "ZIP",
    "application/pdf": "PDF",
    "text/plain": "TXT",
    "text/html": "HTML",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "XLSX",
    "application/vnd.ms-excel": "XLS",
    "application/vnd.google-earth.kml+xml": "KML",
    "application/x-netcdf": "NETCDF",
}

_RANK_ORDER = ["CSV", "JSON", "GEOJSON", "XLSX", "XLS", "ZIP", "XML",
               "KML", "NETCDF", "RDF", "PDF", "TXT"]


def _norm_fmt(fmt, media_type=""):
    fmt = (fmt or "").strip().upper()
    if not fmt and media_type:
        fmt = _MEDIA_TO_FMT.get((media_type or "").strip().lower(), "")
    return re.sub(r"[^A-Z0-9+.-]", "", fmt)[:12]


def _fmt_rank(fmt):
    try:
        return len(_RANK_ORDER) - _RANK_ORDER.index(fmt)
    except ValueError:
        return 0


def _is_http_url(u):
    return isinstance(u, str) and u.lower().startswith(("http://", "https://"))


# --- legacy CKAN parsing ------------------------------------------------------

def _pick_ckan_resource(resources):
    """Best direct-file resource from CKAN resources: (url, fmt)."""
    best, best_rank = ("", ""), -1
    for res in resources or []:
        if not isinstance(res, dict):
            continue
        rurl = (res.get("url") or "").strip()
        fmt = _norm_fmt(res.get("format"), res.get("mimetype"))
        if not _is_http_url(rurl) or not fmt:
            continue
        rank = _fmt_rank(fmt)
        if rank > best_rank:
            best_rank, best = rank, (rurl, fmt)
    return best


def _ckan_res_size(resources):
    total = 0
    for res in resources or []:
        if not isinstance(res, dict):
            continue
        try:
            sz = res.get("size")
            if sz is not None:
                n = int(float(str(sz).replace(",", "")))
                if 0 < n < 10 ** 14:
                    total += n
        except Exception:
            pass
    return total


def _parse_legacy(data):
    """CKAN action-API response -> list of (title, slug, date, res_url, fmt, size)."""
    if not isinstance(data, dict) or not data.get("success"):
        return None
    pkgs = (data.get("result") or {}).get("results")
    if not isinstance(pkgs, list):
        return None
    rows = []
    for pkg in pkgs:
        if not isinstance(pkg, dict):
            continue
        name = (pkg.get("name") or "").strip()
        title = (pkg.get("title") or name or "").strip()
        if not name or not title:
            continue
        resources = pkg.get("resources") or []
        res_url, fmt = _pick_ckan_resource(resources)
        date = pkg.get("metadata_modified") or pkg.get("metadata_created") or ""
        date = date[:10] if isinstance(date, str) else ""
        rows.append((title, name, date, res_url, fmt,
                     _ckan_res_size(resources)))
    return rows


# --- new /search (DCAT) parsing ----------------------------------------------

def _pick_dcat_distribution(dists):
    """Best direct-file distribution: (url, fmt)."""
    best, best_rank = ("", ""), -1
    for dist in dists or []:
        if not isinstance(dist, dict):
            continue
        durl = (dist.get("downloadURL") or "").strip()
        fmt = _norm_fmt(dist.get("format"), dist.get("mediaType"))
        if not _is_http_url(durl) or not fmt:
            continue
        rank = _fmt_rank(fmt)
        if rank > best_rank:
            best_rank, best = rank, (durl, fmt)
    return best


def _parse_new(data):
    """New /search JSON -> list of (title, slug, date, res_url, fmt, size)."""
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return None
    rows = []
    for rec in data["results"]:
        if not isinstance(rec, dict):
            continue
        slug = (rec.get("slug") or "").strip()
        dcat = rec.get("dcat") if isinstance(rec.get("dcat"), dict) else {}
        title = (rec.get("title") or dcat.get("title") or slug or "").strip()
        if not slug or not title:
            continue
        res_url, fmt = _pick_dcat_distribution(dcat.get("distribution"))
        date = dcat.get("modified") or dcat.get("issued") or ""
        date = date[:10] if isinstance(date, str) else ""
        rows.append((title, slug, date, res_url, fmt, 0))
    return rows


# --- public API ---------------------------------------------------------------

def search(query, category="", timeout=12):
    """Search data.gov datasets.  Never raises; [] on any error."""
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(3, min(int(timeout), 60))

        rows = None
        # 1) legacy CKAN action API (retired 2025; kept in case it returns)
        data = _http_get_json(
            _LEGACY_API + "?" + urllib.parse.urlencode({"q": query, "rows": 30}),
            deadline,
        )
        if data is not None:
            rows = _parse_legacy(data)
        # 2) new catalog JSON search
        if not rows:
            data = _http_get_json(
                _SEARCH_API + "?" + urllib.parse.urlencode(
                    {"q": query, "per_page": 30, "sort": "relevance"}
                ),
                deadline,
            )
            rows = _parse_new(data)
        if not rows:
            return []

        out = []
        for title, slug, date, res_url, fmt, size in rows:
            if len(out) >= _MAX_RESULTS:
                break
            page_url = _DATASET_BASE + urllib.parse.quote(slug, safe="-_.~")
            out.append({
                "title": title[:300],
                "source": NAME,
                "seeders": 0,
                "size": int(size) if isinstance(size, int) else 0,
                "magnet": "",
                "torrent_url": "",
                "url": page_url,
                "date": date,
                "category": "other",
                "quality": fmt,
            })
            # Also surface the top direct-file resource as its own entry.
            if res_url and len(out) < _MAX_RESULTS:
                out.append({
                    "title": title[:280] + " [" + (fmt or "file") + "]",
                    "source": NAME,
                    "seeders": 0,
                    "size": int(size) if isinstance(size, int) else 0,
                    "magnet": "",
                    "torrent_url": "",
                    "url": res_url,
                    "date": date,
                    "category": "other",
                    "quality": fmt,
                })
        # Drop anything with no link at all (defensive; shouldn't happen).
        return [r for r in out if r["magnet"] or r["torrent_url"] or r["url"]]
    except Exception:
        return []


if __name__ == "__main__":
    REQUIRED = {"title": str, "source": str, "seeders": int, "size": int,
                "magnet": str, "torrent_url": str, "url": str,
                "date": str, "category": str, "quality": str}
    for q in ("climate", "census population", "zzqxjunkzz"):
        t0 = time.monotonic()
        rows = search(q, timeout=12)
        dt = time.monotonic() - t0
        print(f"query={q!r:22} results={len(rows):3d} in {dt:.1f}s")
        for r in rows:
            assert set(r) == set(REQUIRED), f"bad keys: {set(r) ^ set(REQUIRED)}"
            for k, typ in REQUIRED.items():
                assert isinstance(r[k], typ), f"{k} is {type(r[k])}"
            assert r["magnet"] or r["torrent_url"] or r["url"]
            assert r["source"] == NAME
            assert r["category"] == "other"
        for r in rows[:4]:
            print("   ", r["title"][:58], "|", r["quality"] or "-", "|",
                  r["date"], "|", r["url"][:70])
    print("timeout=0  ->", len(search("water", timeout=0)), "results (no raise)")
    print("empty query ->", len(search("")))
    print("bad category ->", len(search("water", category="tv")))
    print("good category ->", len(search("water", category="documents")))
    print("OK")
