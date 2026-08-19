"""Pluggable external media sources for the meta-search.

Each sibling module in this package exposes:
    NAME = "<short source label>"
    def search(query, category="", timeout=12) -> list[dict]
where every result dict has the keys:
    title, source, seeders, size, magnet, torrent_url, url, date, category, quality

search_all() fans out to every adapter IN PARALLEL and tolerates any that hang,
error, or return junk — one bad source can never stall or break the search. The
adapters run inside the VPN-locked container, so their outbound HTTP(S) goes out
through the Proton tunnel just like torrent traffic (no IP leak).
"""
import os
import time
import pkgutil
import importlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

_ADAPTERS = None
_lock = threading.Lock()

# ---- source-health circuit breaker -----------------------------------------------------
# An adapter that keeps ERRORING (network dead, site gone, parser broken, CF-walled) wastes
# a search slot + the deadline budget every query. We track consecutive failures per source
# and, past a threshold, put it in a COOLDOWN (skip it) with escalating backoff — then let ONE
# probe through when the cooldown expires (half-open), which either recovers it or re-opens the
# breaker. A source returning 0 results is NOT a failure (it may just be empty for that query).
_health = {}                       # name -> {fails, last_ok, last_try, disabled_until, last_status}
_health_lock = threading.Lock()
_HEALTH_FAIL_THRESHOLD = 3         # consecutive fails before the breaker opens
_HEALTH_BACKOFFS = [300, 900, 1800, 3600]   # 5m -> 15m -> 30m -> 1h (then capped)
_FANOUT_GRACE = 3                  # seconds past an adapter's own timeout before the fan-out abandons it


def _record_health(name, ok, status=""):
    with _health_lock:
        h = _health.setdefault(name, {"fails": 0, "last_ok": 0.0, "last_try": 0.0,
                                      "disabled_until": 0.0, "last_status": ""})
        h["last_try"] = time.time()
        h["last_status"] = status or ("ok" if ok else "error")
        if ok:
            h["fails"] = 0
            h["last_ok"] = time.time()
            h["disabled_until"] = 0.0
        else:
            # If the breaker is ALREADY open, don't let a burst of concurrent failures (several
            # searches in flight) or an expiry herd escalate the backoff by concurrency — only a
            # failure seen while CLOSED/half-open (disabled_until elapsed) advances the index.
            if h["disabled_until"] > time.time():
                return
            h["fails"] += 1
            if h["fails"] >= _HEALTH_FAIL_THRESHOLD:
                idx = min(h["fails"] - _HEALTH_FAIL_THRESHOLD, len(_HEALTH_BACKOFFS) - 1)
                h["disabled_until"] = time.time() + _HEALTH_BACKOFFS[idx]


def _cooling(name):
    """True while a source is in an OPEN breaker (skip it). When the cooldown expires the
    breaker is half-open (returns False) so exactly the next query re-probes it."""
    with _health_lock:
        h = _health.get(name)
        return bool(h and h["disabled_until"] > time.time())


def health_report():
    """Per-adapter health for the UI. state: ok | degraded (some recent fails) | cooldown (skipped)."""
    now = time.time()
    with _health_lock:
        rep = []
        for n, h in sorted(_health.items()):
            state = ("cooldown" if h["disabled_until"] > now
                     else ("degraded" if h["fails"] > 0 else "ok"))
            rep.append({"name": n, "state": state, "fails": h["fails"],
                        "cooldown_s": max(0, int(h["disabled_until"] - now)),
                        "last_status": h["last_status"]})
        return rep


def _load():
    global _ADAPTERS
    with _lock:
        if _ADAPTERS is not None:
            return _ADAPTERS
        mods = []
        for m in pkgutil.iter_modules([os.path.dirname(__file__)]):
            if m.name.startswith("_"):
                continue
            try:
                mod = importlib.import_module(__name__ + "." + m.name)
                if hasattr(mod, "search"):
                    mods.append(mod)
            except Exception:
                pass          # a broken adapter is simply skipped
        _ADAPTERS = mods
        return mods


def adapter_names():
    return [getattr(m, "NAME", m.__name__.rsplit(".", 1)[-1]) for m in _load()]


def _safe_search(mod, query, category, timeout):
    name = getattr(mod, "NAME", mod.__name__.rsplit(".", 1)[-1])
    t0 = time.time()
    try:
        out = mod.search(query, category=category, timeout=timeout) or []
        out = out if isinstance(out, list) else []
        # Health from RELIABLE, THREAD-LOCAL signals only: raised = fail; a return that overran the
        # fan-out deadline = 'slow' fail (its results were already abandoned, so it just wasted a
        # slot). We deliberately do NOT read the adapter's LAST_STATUS module global — it's shared
        # and races across concurrent searches. A returned-in-time call (even 0 results) is healthy.
        slow = (time.time() - t0) > timeout + _FANOUT_GRACE
        _record_health(name, not slow, "slow" if slow else ("ok" if out else "no-results"))
        return out
    except Exception:
        _record_health(name, False, "error")     # raised -> a real failure (counts toward the breaker)
        return []


# "deep" adapters are noisy / browse-only (open-directory & crawl discovery). They
# are EXCLUDED from normal search so torrent results stay clean, and only included
# when deep=True (Deep mode). A module can also self-declare TIER = "deep".
_DEEP = {"opendir", "commoncrawl", "wayback"}


def _is_deep(m):
    return (getattr(m, "TIER", "") == "deep"
            or m.__name__.rsplit(".", 1)[-1] in _DEEP)


def _serves(m, category):
    """Category routing. Adapters WITHOUT a CATEGORIES attribute are generalists
    (broad content) and always run. Adapters WITH a CATEGORIES set are narrow (e.g.
    arXiv=documents, GitHub=software) and run ONLY when the user scopes the search to
    one of their categories — so the default 'All types' stays broad-but-relevant,
    and picking 'Documents' unleashes the academic sources."""
    cats = getattr(m, "CATEGORIES", None)
    if not cats:
        return True
    if not category or category == "all":
        return False
    return category in cats


def search_all(query, category="", timeout=12, deep=False):
    """Query adapters in parallel; return the merged (un-ranked) list. By default
    only 'default'-tier adapters run; deep=True also includes the noisy discovery
    adapters (open directories / crawl / archive). Narrow adapters are gated by
    category (see _serves)."""
    mods = _load()
    if not deep:
        mods = [m for m in mods if not _is_deep(m)]
    mods = [m for m in mods if _serves(m, category)]
    if not mods:
        return []
    # Skip adapters whose breaker is OPEN (persistently failing) — don't burn a slot + the deadline
    # on a dead source. BUT if EVERYTHING eligible is cooling (a network blip likely tripped them
    # all at once), probe them all anyway so a global outage self-heals on the very next query
    # instead of being starved for the full backoff.
    live = [m for m in mods
            if not _cooling(getattr(m, "NAME", m.__name__.rsplit(".", 1)[-1]))]
    mods = live or mods
    out = []
    ex = ThreadPoolExecutor(max_workers=min(20, len(mods)))
    futs = [ex.submit(_safe_search, m, query, category, timeout) for m in mods]
    try:
        for f in as_completed(futs, timeout=timeout + _FANOUT_GRACE):
            try:
                out.extend(f.result() or [])
            except Exception:
                pass
    except Exception:
        pass                  # deadline hit — keep whatever arrived
    ex.shutdown(wait=False)
    return out
