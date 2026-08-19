"""Deep Hunt — the executor (Phase 3).

Runs ONE strategy {method, query} against Undertow's REAL search infrastructure and
returns a list of result dicts (the same shape the UI search uses, so finds are
downloadable like any other result). Injected into the hunt runtime via
hunt.set_backends(execute=...).

The search entry points live in vt.py (meta_search) and discover.py; they are INJECTED
here at startup to avoid an import cycle (vt.py already imports hunt/hunt_exec). If
nothing is injected, execute() returns [] and the hunt simply idles — never raises.

Method routing:
  search   -> meta_search(query, category)     (Jackett + Usenet + adapters + DHT)
  academic -> meta_search(query, "documents")  (the scholarly/document fleet leads)
  dork     -> raw SearXNG query (the brain already crafted a Google-operator string),
              falling back to the open-directory finder for a plain query
  pivot    -> same as dork (deeper crawl-expansion is Phase 4)
stdlib only.
"""
import os
import re
import threading
import urllib.parse

import hunt

_CATS = {"movies", "tv", "music", "documents", "software", "other"}
_EXT_HINTS = {"music": "flac", "movies": "mkv", "tv": "mkv",
              "documents": "pdf", "software": "iso"}

# Bound how many HUNT searches hit the indexers at once (across all hunts), so a fleet
# of background hunts can't stampede Jackett/flaresolverr. User-initiated /search is NOT
# gated — this wraps only the hunt executor. Tunable for a beefier box.
_EXEC_GATE = threading.Semaphore(max(1, int(os.environ.get("HUNT_EXEC_CONCURRENCY", "2"))))

_meta_search = None      # callable (q, category) -> {"ready": bool, "results": [...]}
_discover = None         # the discover MODULE (uses .discover and ._searx)


def set_search(meta_search=None, discover=None):
    """Wire in the real search functions from vt.py at startup (avoids an import cycle)."""
    global _meta_search, _discover
    if meta_search is not None:
        _meta_search = meta_search
    if discover is not None:
        _discover = discover


def _run_search(q, category, h=None, strategy=None):
    if not _meta_search:
        return []
    try:
        with _EXEC_GATE:
            out = _meta_search(q, category if category in _CATS else "") or {}
    except Exception:
        return []
    results = list(out.get("results", []))
    # Distinguish "engine not ready yet" (Jackett still warming at boot) from "no results".
    # If it wasn't ready and found nothing, DON'T burn this strategy — requeue it so the
    # prime queries still run once the infra is up (otherwise a stub-mode hunt can idle
    # forever with zero results).
    if not results and not out.get("ready", True) and h is not None and strategy is not None:
        hunt._requeue(h, strategy)
    return results


def _host(u):
    try:
        return urllib.parse.urlparse(u).netloc
    except Exception:
        return ""


def _norm_dir_hit(u, title, category):
    """A browsable open directory (not a file) — surfaced so the user can open it too."""
    h = _host(u)
    return {"title": (title or h or u) + "  [open dir]", "url": u, "magnet": "",
            "torrent_url": "", "nzb_id": "", "source": ("Open dir · " + h) if h else "Open dir",
            "seeders": 0, "size": 0, "date": "", "quality": "",
            "category": category if category in _CATS else "other"}


def _norm_file_hit(f, category):
    """An actual FILE found by crawling an open directory tree."""
    u = f.get("url", "")
    h = _host(u)
    return {"title": f.get("name") or u, "url": u, "magnet": "", "torrent_url": "",
            "nzb_id": "", "source": ("Open dir · " + h) if h else "Open dir",
            "seeders": 0, "size": 0, "date": "", "quality": "",
            "category": category if category in _CATS else "other",
            "_match": round(float(f.get("score", 0.0)), 3)}


def _goal_terms(h):
    return (h or {}).get("goal", "") if isinstance(h, dict) else ""


def _enqueue_pivots(h, items, why):
    """Feed the best unexplored directories back into the frontier as `pivot` strategies —
    the best-first queue then crawls the most promising branches first. This is what makes
    the crawl go DEEP + lateral over cycles instead of one shallow pass."""
    if not isinstance(h, dict) or not items:
        return
    leads = []
    for it in items[:8]:
        u = it.get("url") if isinstance(it, dict) else it
        if not u:
            continue
        sc = float(it.get("score", 0.5)) if isinstance(it, dict) else 0.5
        if sc <= 0:
            continue                       # a non-matching dir isn't worth a deep pivot-crawl
        # priority scales with the dir's relevance (no fixed 0.45 floor that made even
        # zero-relevance dirs compete with real search strategies for crawl time).
        leads.append({"method": "pivot", "query": u, "why": why,
                      "score": max(0.3, min(0.9, 0.2 + 0.7 * sc))})
    try:
        hunt._add_strategies(h, leads)
    except Exception:
        pass


def _run_dork(q, category, h=None):
    """Find open DIRECTORIES for the query, surface them, and queue the promising ones for
    a deep crawl (as `pivot` strategies). The brain's dork queries + the target drive it."""
    if not _discover:
        return _run_search(q, category)
    ext = _EXT_HINTS.get((category or "").lower(), "")
    seeds = []
    try:
        with _EXEC_GATE:
            seeds = _discover.open_dir_seeds(q, ext, 16) or []
    except Exception:
        seeds = []
    out = []
    for s in seeds[:12]:
        u = s.get("url")
        if u:
            out.append(_norm_dir_hit(u, s.get("title") or s.get("host") or "", category))
    # queue the best dirs (most ext-matches/files) for a deep crawl next
    _enqueue_pivots(h, [{"url": s.get("url"),
                         "score": min(1.0, 0.3 + 0.05 * s.get("matched", 0))}
                        for s in seeds[:8] if s.get("url")], "crawl open dir found by dork")
    return out


def _run_pivot(q, category, h=None):
    """Deep-crawl ONE directory/site: climb to its parent (siblings) and descend into
    matching children, returning the actual FILES, and queue deeper subdirs to chase.
    If the query isn't a URL, treat it as a dork."""
    if not _discover:
        return _run_search(q, category)
    if not q.startswith(("http://", "https://", "ftp://")):
        return _run_dork(q, category, h)                # e.g. a site: dork
    ext = _EXT_HINTS.get((category or "").lower(), "")
    terms = _goal_terms(h)
    crawled = h.get("_crawled_dirs", []) if isinstance(h, dict) else []
    try:
        with _EXEC_GATE:
            tree = _discover.crawl_tree(q, want_terms=terms, ext=ext, timeout=22,
                                        skip=set(crawled)) or {}
    except Exception:
        tree = {}
    files = tree.get("files", []) or []
    # remember what we just crawled so a sibling-pivot next cycle doesn't re-fetch the same
    # parent/dirs (bounded so a weeks-long hunt can't grow this without limit).
    if isinstance(h, dict):
        newly = tree.get("scanned", []) or []
        if newly:
            h["_crawled_dirs"] = list(dict.fromkeys(list(crawled) + list(newly)))[-800:]
    _enqueue_pivots(h, tree.get("subdirs", []), "go deeper into open-dir subtree")
    # Drop files that share NO goal term AND sit in a non-matching dir (score 0) — the
    # unrelated open-dir filler that used to flood results. Legit album tracks inherit their
    # dir's relevance (crawl_tree), so real contents survive; keep everything only if we have
    # no goal terms to judge by.
    if terms:
        files = [f for f in files if float(f.get("score", 0)) > 0]
    return [_norm_file_hit(f, category) for f in files[:200]]


def execute(strategy, h):
    """The injected hunt executor. Never raises; returns a list of result dicts."""
    try:
        method = (strategy.get("method") or "search").lower()
        q = (strategy.get("query") or "").strip()
        if not q:
            return []
        category = (h.get("category") or "all").lower()
        if method == "academic":
            return _run_search(q, "documents", h, strategy)
        if method == "pivot":
            return _run_pivot(q, category, h)           # deep-crawl a dir/site tree
        if method == "dork":
            return _run_dork(q, category, h)            # find open dirs -> queue crawls
        return _run_search(q, category, h, strategy)    # "search" (default)
    except Exception:
        return []
