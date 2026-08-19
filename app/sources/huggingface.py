"""Hugging Face source — public datasets + models discovery.

Uses the public (no-auth) Hugging Face Hub JSON API:
  https://huggingface.co/api/datasets?search={q}&limit=30&full=true
  https://huggingface.co/api/models?search={q}&limit=15

Datasets -> category "other", models -> category "software".
Stdlib only. search() never raises; returns [] on any error.
"""

import gzip
import io
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "HuggingFace"
CATEGORIES = {"software", "documents", "other"}

_HOST = "huggingface.co"
_BASE = "https://huggingface.co"
_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:127.0) "
       "Gecko/20100101 Firefox/127.0")
_MAX_BODY = 3 * 1024 * 1024      # cap raw body read
_MAX_INFLATE = 6 * 1024 * 1024   # cap gzip inflate
_MAX_RESULTS = 40


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse all redirects — never follow to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _get_json(path, params, deadline):
    """HTTPS GET to huggingface.co, return parsed JSON or None."""
    remaining = deadline - time.monotonic()
    if remaining <= 0.5:
        return None
    url = _BASE + path + "?" + urllib.parse.urlencode(params)
    # Paranoia: only ever talk to the intended host over https.
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != _HOST:
        return None
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
    })
    try:
        with _OPENER.open(req, timeout=max(1.0, remaining)) as resp:
            if resp.status != 200:
                return None
            # Chunked read with wall-clock enforcement (slow-loris guard).
            buf = io.BytesIO()
            while buf.tell() < _MAX_BODY:
                if time.monotonic() >= deadline:
                    return None
                chunk = resp.read(65536)
                if not chunk:
                    break
                buf.write(chunk)
            raw = buf.getvalue()
            if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                        raw = gz.read(_MAX_INFLATE)
                except OSError:
                    return None
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout,
            OSError, ValueError):
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, ValueError):
        return None


def _mk(title, url, cat, date):
    return {
        "title": str(title),
        "source": NAME,
        "seeders": 0,
        "size": 0,
        "magnet": "",
        "torrent_url": "",
        "url": url,
        "date": str(date or ""),
        "category": cat,
        "quality": "",
    }


def _fmt_date(value):
    # API dates look like "2024-05-01T12:34:56.000Z" — keep the date part.
    if isinstance(value, str) and len(value) >= 10:
        return value[:10]
    return ""


def _datasets(query, deadline):
    data = _get_json("/api/datasets",
                     {"search": query, "limit": 30, "full": "true"},
                     deadline)
    out = []
    if not isinstance(data, list):
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        ds_id = item.get("id") or ""
        if not ds_id:
            continue
        url = _BASE + "/datasets/" + urllib.parse.quote(str(ds_id))
        date = _fmt_date(item.get("lastModified") or item.get("createdAt"))
        out.append(_mk(ds_id, url, "other", date))
    return out


def _models(query, deadline):
    data = _get_json("/api/models",
                     {"search": query, "limit": 15},
                     deadline)
    out = []
    if not isinstance(data, list):
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id") or item.get("modelId") or ""
        if not model_id:
            continue
        url = _BASE + "/" + urllib.parse.quote(str(model_id))
        date = _fmt_date(item.get("lastModified") or item.get("createdAt"))
        out.append(_mk(model_id, url, "software", date))
    return out


def search(query, category="", timeout=12):
    """Search Hugging Face datasets/models. Never raises; [] on error."""
    try:
        query = (query or "").strip()
        if not query:
            return []
        if category and category not in CATEGORIES:
            return []
        deadline = time.monotonic() + max(1, int(timeout))
        results = []
        if category in ("", "documents", "other"):
            results.extend(_datasets(query, deadline))
        if category in ("", "software"):
            results.extend(_models(query, deadline))
        # Drop anything with no link at all (shouldn't happen, but enforce).
        results = [r for r in results
                   if r["magnet"] or r["torrent_url"] or r["url"]]
        return results[:_MAX_RESULTS]
    except Exception:
        return []


if __name__ == "__main__":
    t0 = time.monotonic()
    for q, cat in (("wikipedia", ""), ("llama", "software"),
                   ("common crawl", "other")):
        res = search(q, cat)
        print(f"query={q!r} category={cat!r} -> {len(res)} results "
              f"({time.monotonic() - t0:.1f}s elapsed)")
        for r in res[:3]:
            print("   ", r["category"], "|", r["title"], "|", r["url"],
                  "|", r["date"])
        # sanity: exact key set
        want = {"title", "source", "seeders", "size", "magnet",
                "torrent_url", "url", "date", "category", "quality"}
        assert all(set(r) == want for r in res), "key-shape mismatch"
    print("self-test OK")
