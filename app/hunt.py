"""Deep Hunt — the persistent background search-agent runtime (Phase 1).

A "hunt" is a long-running background search: given a goal + category, it grinds
through a FRONTIER of untried search strategies, executes each, accumulates results,
and keeps going — for days/weeks — until you stop it. State is checkpointed to disk
so a reboot RESUMES every running hunt exactly where it left off.

This module is the RUNTIME only. The two pieces of intelligence are INJECTED so later
phases can make them smart without touching this file:
  • generate(hunt)  -> list of {method, query, why}   (the "brain": new strategies)
  • execute(strategy, hunt) -> list of result dicts     (runs a strategy on the infra)
  • judge(strategy, results, hunt) -> (matches, new_strategies)  (leads/pivoting)
Until injected, safe deterministic stubs keep the loop working (Phase 1 is testable
on its own). stdlib only; every cycle is wrapped so one bad cycle can't kill a hunt.
"""
import os
import re
import json
import math
import time
import threading
import unicodedata

HUNTS_DIR = os.environ.get("HUNTS_DIR", "/config/hunts")
PACES = {"gentle": 45, "normal": 20, "aggressive": 8}
# WATCH mode: once a hunt exhausts its ideas (goes idle), re-sweep on this cadence so content
# uploaded LATER is still caught. "off" = a normal one-shot hunt (idles when exhausted).
SWEEPS = {"off": 0, "6h": 21600, "daily": 86400, "weekly": 604800}
_MAX_RESULTS = 5000            # cap the accumulating store so a hunt can't grow forever
_MAX_TRIED = 20000
_MAX_FRONTIER = 2000

# A hunt is a POLITE background citizen. If the box is under heavy load — e.g. the
# local LLM fell back to CPU and is pegging every core, or other containers are busy —
# hunts BACK OFF (nap longer, and the brain skips the expensive LLM in favour of the
# cheap stub) so a background hunt can NEVER starve other services. Tunable via env.
_BUSY_LOAD_PER_CORE = float(os.environ.get("HUNT_BUSY_LOAD", "0.9"))
_NCPU = os.cpu_count() or 1


def load_per_core():
    """1-minute load average normalised by core count (0.0 if unavailable)."""
    try:
        return os.getloadavg()[0] / _NCPU
    except Exception:
        return 0.0


def box_busy():
    """True when the machine is near-saturated — callers should ease off (worker PACING)."""
    return load_per_core() >= _BUSY_LOAD_PER_CORE


# The LLM runs FULLY on the GPU (num_gpu:999 forces full offload, and _gpu_ok() guarantees it
# isn't spilling to CPU), so it barely touches the CPU cores — gating it on the same 0.9/core
# CPU-pacing threshold left it perpetually switched off on a busy multi-container box (the "AI
# never uses the GPU" symptom). Use a much higher bar: only refuse the GPU model under genuine
# whole-box saturation.
_LLM_BUSY_LOAD = float(os.environ.get("HUNT_LLM_BUSY_LOAD", "2.5"))


def _box_overloaded():
    """True only under EXTREME load — the (GPU-bound) hunt LLM eases off just short of a meltdown."""
    return load_per_core() >= _LLM_BUSY_LOAD

_reg_lock = threading.Lock()
_hunts = {}                    # id -> hunt dict (in-memory source of truth)
_stops = {}                    # id -> threading.Event (the CURRENT worker's stop)
_threads = {}                  # id -> Thread
_worker_gen = {}               # id -> generation int; a worker exits once superseded

# Injected backends (see module docstring). None => use the built-in stub.
_generate_fn = None
_execute_fn = None
_judge_fn = None
_verify_fn = None      # optional: (matches) -> matches with dead results dropped + _live tagged
_notify_fn = None      # optional: (hunt, new_count, new_titles) -> push a notification


def set_backends(generate=None, execute=None, judge=None, verify=None, notify=None):
    global _generate_fn, _execute_fn, _judge_fn, _verify_fn, _notify_fn
    if generate is not None:
        _generate_fn = generate
    if execute is not None:
        _execute_fn = execute
    if judge is not None:
        _judge_fn = judge
    if verify is not None:
        _verify_fn = verify
    if notify is not None:
        _notify_fn = notify


def _notify(h, new_count, new_titles):
    """Fire a 'new finds' notification (debounced downstream). No-op if unwired; never raises."""
    if not _notify_fn or not new_count:
        return
    try:
        _notify_fn(h, new_count, new_titles)
    except Exception:
        pass


def _verify(matches):
    """Liveness-check the picked matches (latency is fine — the hunt is a background agent) and
    drop the ones confirmed dead, so a hunt never accumulates rotted links. No-op if unwired."""
    if not _verify_fn:
        return matches
    try:
        out = _verify_fn(list(matches))
        return out if isinstance(out, list) else matches
    except Exception:
        return matches


# --------------------------------------------------------------------------- persistence
def _ensure_dir():
    try:
        os.makedirs(HUNTS_DIR, exist_ok=True)
    except OSError:
        pass


def _path(hid):
    return os.path.join(HUNTS_DIR, hid + ".json")


def _safe_path(hid):
    """Path for a hunt id, or None if it would escape HUNTS_DIR.

    Hunt ids arrive straight from a JSON request body, and this module writes and
    DELETES files by them. Without containment an id like "../torrents" resolves to
    /config/torrents.json — the app runs as root and /config is a host bind mount, so
    that is arbitrary deletion of the operator's state.

    Containment is enforced with realpath rather than an id-format regex on purpose:
    an older release generated a different id format, and a strict regex would make
    any pre-upgrade hunt permanently undeletable from the UI.
    """
    if not hid or not isinstance(hid, str):
        return None
    if "/" in hid or "\\" in hid or "\x00" in hid:
        return None
    p = os.path.realpath(_path(hid))
    base = os.path.realpath(HUNTS_DIR)
    if p != base and not p.startswith(base + os.sep):
        return None
    return p


def _save(h):
    """Atomic checkpoint (tmp + fsync + replace) so power loss can't corrupt it."""
    # A DELETED hunt must never be re-created on disk by a lingering worker's checkpoint
    # (delete_hunt pops it from _hunts, then removes the file; a worker mid-cycle would
    # otherwise re-write it → an orphaned file resume_all revives as a zombie hunt).
    if h.get("id") not in _hunts:
        return
    _ensure_dir()
    try:
        tmp = _path(h["id"]) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(h, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _path(h["id"]))
    except Exception:
        pass


def _strat_key(s):
    return (str(s.get("method", "")).lower().strip() + "|"
            + re.sub(r"\s+", " ", str(s.get("query", "")).lower().strip()))


def _result_key(r):
    m = re.search(r"btih:([0-9A-Za-z]+)", r.get("magnet", "") or "")
    if m:
        return "ih:" + m.group(1).lower()
    return (r.get("nzb_id") or r.get("torrent_url") or r.get("url")
            or ("t:" + (r.get("title", "") or "").lower().strip()))


# --------------------------------------------------------------------------- built-in stubs
_STOP = set("the a an of and or to in on for with at by from rare obscure original "
            "records record album vinyl cassette tape".split())


def _keyterms(g, n=4):
    """The most distinctive few words of a goal — used for a SHORT open-directory dork
    (a dork of the whole verbose goal matches no dir; a 2-4 keyword one can)."""
    toks = re.findall(r"[A-Za-z0-9]+", g)
    key = [t for t in toks if len(t) >= 3 and t.lower() not in _STOP]
    return " ".join((key or toks)[:n])


# Only TRUE function words are dropped for the RELEVANCE test — content words like
# records/album/vinyl are exactly what distinguishes a match, so (unlike the dork stoplist
# _STOP) they are KEPT here. This is what stops the hunt recording off-goal garbage.
_STOP_REL = set("the a an of and or to in on for with at by from feat ft vs".split())


def _fold(s):
    s = unicodedata.normalize("NFKD", s or "")
    return "".join(c for c in s if not unicodedata.combining(c)).lower()


_BIGRAM = "\x00"                              # sentinel prefix marking a joined-scene-name term


def _goal_terms(h):
    """The meaningful goal words for the relevance test — content words KEPT, only true function
    words dropped, diacritic-folded + deduped. Also emits the JOINED form of adjacent SHORT tokens
    (AC/DC -> 'acdc', 50 Cent -> '50cent'), TAGGED, so scene releases that drop the separator still
    match — without letting an ordinary word match mid-word."""
    toks = [t for t in re.findall(r"[^\W_]+", _fold(h.get("goal", "") if isinstance(h, dict) else ""))
            if len(t) >= 2 and t not in _STOP_REL]
    out = list(dict.fromkeys(toks))
    bigs = []
    for a, b in zip(toks, toks[1:]):
        if len(a) <= 4 and len(b) <= 4:          # <=4 so '50'+'cent' fuse (bigrams only match at a word start)
            bigs.append(_BIGRAM + a + b)
    return out + list(dict.fromkeys(bigs))


def _title_rel(title, terms):
    """0..1 fraction of goal terms present in a title, matched at a WORD BOUNDARY. Long terms (>=4)
    match as a prefix ('radiohead' hits 'radioheads' but 'cream' does NOT hit 'scream'); SHORT terms
    must be a WHOLE word ('sun' of 'Sun Ra' hits 'Sun' not 'Sunset'); only TAGGED bigrams match the
    separator-stripped title (so 'acdc' hits 'AC-DC' without an ordinary word matching mid-word).
    0.5 when there are no usable terms."""
    if not terms:
        return 0.5
    t = _fold(title)
    tsq = None
    starts = None
    hit = 0
    for term in terms:
        if term.startswith(_BIGRAM):
            if tsq is None:                        # separator-stripped title + each word's start offset
                words = re.findall(r"[^\W_]+", t)
                tsq = "".join(words)
                starts, _p = set(), 0
                for w in words:
                    starts.add(_p); _p += len(w)
            bg, idx = term[1:], -1
            while True:                            # a bigram counts ONLY if it begins at a word start,
                idx = tsq.find(bg, idx + 1)        # so 'acdc' matches 'AC-DC' but not a 'chicaGO GOod' junction
                if idx < 0:
                    break
                if idx in starts:
                    hit += 1
                    break
        elif len(term) >= 4:
            if re.search(r"(?<![^\W_])" + re.escape(term), t):
                hit += 1
        elif re.search(r"(?<![^\W_])" + re.escape(term) + r"(?![^\W_])", t):
            hit += 1
    return hit / len(terms)


def _downloadable(r):
    """Can the user actually GET this find? A magnet/torrent with a live/unknown swarm, a
    Usenet id, or a direct URL. (A magnet-only torrent with an explicit 0-seed count is not.)"""
    if r.get("nzb_id"):
        return True
    if (r.get("seeders") or 0) > 0:
        return True
    if r.get("magnet") or r.get("torrent_url"):
        return r.get("_seed_known") is False or bool(r.get("url"))
    return bool(r.get("url"))


def _result_rank(r, terms):
    """Rank a stored hunt find: relevance to the goal first, then whether it's downloadable,
    then swarm size. Mirrors the search ranking so the hunt's results view is quality-first
    (not the raw order they happened to be found in)."""
    m = r.get("_match")
    rel = float(m) if m is not None else _title_rel(r.get("title", ""), terms)
    return (round(rel, 2), 1 if _downloadable(r) else 0,
            math.log10((r.get("seeders") or 0) + 1))


def _stub_generate(h):
    """Deterministic fallback strategies so the loop works before the LLM brain is wired
    in (and whenever AI is off). Scored so best-first has signal from cycle 1."""
    g = h["goal"].strip()
    key = _keyterms(g)
    cands = [
        {"method": "search", "query": g, "why": "the goal verbatim", "score": 0.8},
        {"method": "dork", "query": 'intitle:"index of" %s' % key,
         "why": "open directories (key terms)", "score": 0.6},
        {"method": "search", "query": '"%s"' % g, "why": "exact phrase", "score": 0.6},
    ]
    if h.get("category") and h["category"] not in ("all", "other"):
        cands.append({"method": "search", "query": "%s %s" % (key, h["category"]),
                      "why": "key terms + category", "score": 0.55})
    return cands


def _stub_execute(strategy, h):
    return []                  # Phase 3 injects the real executor


def _stub_judge(strategy, results, h):
    """The relevance filter used whenever the LLM brain is NOT running (GPU-gated, box busy,
    or AI off — a COMMON state). Formerly accept-all, which recorded every hit of every
    deliberately-broad query as a 'match' → piles of garbage. Now: keep downloadable torrents/
    Usenet (relevance is handled by the results-view ranking), and for undownloadable open-dir
    hits require the title to actually share a distinctive goal term. If that leaves nothing,
    keep the top few by relevance so an alternate-title release isn't fully starved."""
    results = [r for r in results if isinstance(r, dict)]
    terms = _goal_terms(h)
    if not terms:
        return results, []
    # keep finds whose title shares a goal term, or whose filename/dir name-scored (_match).
    # This drops the off-goal torrents that broad DIVERGE queries pull AND the score-0
    # open-dir filler (cover.jpg/readme.txt) — the two big garbage sources when AI is off.
    keep = [r for r in results
            if _title_rel(r.get("title", ""), terms) > 0 or (r.get("_match") or 0) > 0]
    if not keep:                          # nothing shares a term (foreign/alt title?) -> keep top few
        keep = sorted(results, key=lambda r: _result_rank(r, terms), reverse=True)[:5]
    return keep, []


def _gen(h):
    try:
        return (_generate_fn or _stub_generate)(h) or []
    except Exception:
        return []


def _exec(strategy, h):
    try:
        out = (_execute_fn or _stub_execute)(strategy, h) or []
        return out if isinstance(out, list) else []
    except Exception:
        return []


def _judge(strategy, results, h):
    try:
        m, leads = (_judge_fn or _stub_judge)(strategy, results, h)
        return (m or []), (leads or [])
    except Exception:
        return list(results), []


# --------------------------------------------------------------------------- frontier ops
def _add_strategies(h, strategies):
    """Add only NEW (never-queued, never-tried) strategies to the frontier. Each carries a
    `score` (0-1, the brain's estimate of how likely it surfaces the target)."""
    have = set(h["_tried_keys"]) | {_strat_key(s) for s in h["frontier"]}
    added = 0
    for s in strategies:
        if not isinstance(s, dict) or not s.get("query"):
            continue
        try:
            sc = max(0.0, min(1.0, float(s.get("score"))))
        except (TypeError, ValueError):
            sc = 0.5                       # unscored -> neutral
        s = {"method": s.get("method", "search"), "query": str(s["query"])[:300],
             "why": str(s.get("why", ""))[:200], "score": sc}
        k = _strat_key(s)
        if k in have:
            continue
        h["frontier"].append(s)
        have.add(k)
        added += 1
        if len(h["frontier"]) >= _MAX_FRONTIER:
            break
    return added


def _affinity(h, method):
    """How productive a method/source has been THIS hunt — a smoothed expected yield per
    try (Beta(1,1) prior), squashed into a multiplier. Unknown method => willing-to-try."""
    ms = h.get("method_stats", {}).get(method)
    if not ms:
        return 0.9
    tries = ms.get("tries", 0)
    found = ms.get("found", 0)
    yield_ = (found + 1.0) / (tries + 2.0)          # smoothed hits-per-try
    return 0.4 + min(1.6, yield_)                    # ~[0.4 dead .. 2.0 hot]


def _pop_best(h, explore=False):
    """Pop a strategy from the frontier.

    explore=False (EXPLOIT): the most promising = brain-score × learned source-affinity ×
    a novelty nudge. explore=True (EXPLORE): the best-scored strategy from the LEAST-tried
    METHOD. The worker alternates (~1 in 3 cycles explore) so a hot method (e.g. 'search')
    can't monopolise the hunt and STARVE the deep-crawl methods (dork/pivot/academic) — the
    live symptom that killed the open-directory crawl before this. Realises best-first over
    strategies with guaranteed diversity across sources."""
    fr = h.get("frontier") or []
    if not fr:
        return None
    ms = h.get("method_stats", {})
    if explore:
        best_i, best_key = 0, None
        for i, s in enumerate(fr):
            t = ms.get(s.get("method", "search"), {}).get("tries", 0)
            key = (t, -float(s.get("score", 0.5)))  # fewest tries, then best score
            if best_key is None or key < best_key:
                best_key, best_i = key, i
        return fr.pop(best_i)
    best_i, best_v = 0, -1.0
    for i, s in enumerate(fr):
        method = s.get("method", "search")
        tries = ms.get(method, {}).get("tries", 0)
        novelty = 1.0 / (1.0 + tries)               # untried methods get explored
        v = float(s.get("score", 0.5)) * _affinity(h, method) * (1.0 + 0.4 * novelty)
        if v > best_v:
            best_v, best_i = v, i
    return fr.pop(best_i)


def _note_method(h, method, new_found):
    """Adapt the source-affinity: record a try for this method + how much it found."""
    ms = h.setdefault("method_stats", {}).setdefault(method, {"tries": 0, "found": 0})
    ms["tries"] += 1
    ms["found"] += max(0, int(new_found))


def _requeue(h, strategy):
    """Put a strategy BACK to be retried because the engine wasn't ready to run it (e.g.
    Jackett still warming at boot). The worker marks a strategy 'tried' BEFORE executing,
    so without this a prime query burned during warmup would never run against the real
    infra — leaving a stub-mode hunt permanently idle with zero results. Called by the
    executor from the worker thread (single-writer on these fields), so no lock needed."""
    try:
        k = _strat_key(strategy)
        tk = h.get("_tried_keys")
        if tk and tk[-1] == k:              # undo the 'tried' mark the worker just added
            tk.pop()
        fr = h.setdefault("frontier", [])
        if len(fr) < _MAX_FRONTIER and not any(_strat_key(s) == k for s in fr):
            fr.insert(0, strategy)          # retry it first, next cycle (after a pace nap)
    except Exception:
        pass


def _resweep(h):
    """Re-arm a long-term WATCH hunt: clear the tried-strategy memory, frontier, and crawled-dir
    memory, then re-seed fresh strategies — so search/academic queries run AGAIN against the (now
    updated) indexers and open dirs get re-crawled, catching anything uploaded since the last
    sweep. RESULTS + their dedup keys are KEPT (so only genuinely NEW finds get recorded and
    notified), and learned source-affinities (method_stats) are kept so best-first still has signal."""
    h["_tried_keys"] = []
    h["frontier"] = []
    h["tried_recent"] = []
    h["_crawled_dirs"] = []
    _add_strategies(h, _stub_generate(h))


def _record(h, strategy, matches, leads):
    seen = set(h["_result_keys"])
    terms = _goal_terms(h)
    for r in matches:
        if not isinstance(r, dict):
            continue
        # Floor (final safety net): drop score-0 open-dir filler (cover.jpg/readme.txt) —
        # a NON-torrent/Usenet find with no relevance signal at all. Real torrents/Usenet are
        # always kept (the results-view ranking orders them); crawled files must match.
        if not (r.get("magnet") or r.get("torrent_url") or r.get("nzb_id")):
            m = r.get("_match")
            if m is not None:
                if float(m) <= 0:
                    continue
            elif terms and _title_rel(r.get("title", ""), terms) <= 0:
                continue
        if len(h["results"]) >= _MAX_RESULTS:
            break                          # hard cap BEFORE appending (never exceed)
        k = _result_key(r)
        if k in seen:
            continue
        seen.add(k)
        r = dict(r)
        r["_via"] = strategy.get("query", "")
        h["results"].append(r)
    # keep dedup keys in exact lockstep with the surviving (capped) results, in a
    # deterministic order — no arbitrary set-slice that could drop a live key.
    h["_result_keys"] = [_result_key(r) for r in h["results"]]
    if leads:
        n = _add_strategies(h, leads)
        h["stats"]["leads"] = h["stats"].get("leads", 0) + n


# --------------------------------------------------------------------------- the grind loop
def _worker(hid, stop, mygen):
    idle_streak = 0                              # consecutive exhausted rounds (drives idle backoff)
    while True:
        if stop.is_set():
            break
        with _reg_lock:
            if _worker_gen.get(hid) != mygen:
                return                       # superseded by a newer worker -> exit silently
            h = _hunts.get(hid)
        if not h or h.get("status") == "stopped":
            break
        pace = max(3, int(h.get("pace_seconds", 20)))
        try:
            if not h["frontier"]:
                now_ts = int(time.time())
                sweep_s = h.get("sweep_seconds", 0)
                saturated = len(h.get("results", [])) >= _MAX_RESULTS
                last_sweep = h.get("last_sweep", h.get("created", now_ts))
                # A WATCH hunt re-sweeps on its CADENCE regardless of whether the brain can still
                # invent new angles — checked BEFORE _gen, because with AI on the frontier is
                # almost never truly "exhausted", so a gate nested behind exhaustion would never
                # fire. Re-runs everything to catch content uploaded since the last sweep.
                if h.get("watch") and sweep_s > 0 and not saturated \
                        and (now_ts - last_sweep) >= sweep_s:
                    _resweep(h)
                    h["last_sweep"] = now_ts
                    h.setdefault("stats", {})["sweeps"] = h["stats"].get("sweeps", 0) + 1
                    h["status"] = "running"
                    idle_streak = 0
                    _save(h)
                    continue
                # Already idled once and nothing can change until the next sweep (a watch hunt's
                # _tried_keys only clears on _resweep) -> DON'T re-run the expensive LLM diverge
                # every wake; sleep until the sweep is due (capped so a stop still lands promptly).
                if idle_streak and h.get("watch") and sweep_s > 0 and not saturated:
                    remain = sweep_s - (now_ts - last_sweep)
                    stop.wait(max(pace, min(remain, 1800)))
                    continue
                added = 0
                if not saturated:                 # at the result cap, inventing more is pointless
                    new = _gen(h)
                    added = _add_strategies(h, new) if new else 0
                if added:
                    idle_streak = 0
                    if h.get("status") != "running":
                        h["status"] = "running"
                    _save(h)
                    continue
                # Nothing new -> idle with EXPONENTIAL BACKOFF so an exhausted (non-watch) hunt
                # stops re-running the model every pace*4. A saturated watch hunt lands here too
                # (no more sweeps) with a visible flag so the user sees why notifications stopped.
                idle_streak += 1
                if saturated and h.get("watch"):
                    h.setdefault("stats", {})["saturated"] = True
                if h.get("status") != "idle":
                    h["status"] = "idle"
                    _save(h)
                stop.wait(min(1800, pace * 4 * (2 ** min(idle_streak - 1, 5))))
                continue

            idle_streak = 0                       # frontier has work -> we're active again
            if h.get("status") != "running":
                h["status"] = "running"
            # ~1 in 3 cycles EXPLORE (least-tried method) so the deep-crawl methods keep
            # getting turns; the rest EXPLOIT (best-first). Prevents source monopolisation.
            explore = (h.get("stats", {}).get("cycles", 0) % 3 == 2)
            strategy = _pop_best(h, explore=explore)
            h["_tried_keys"].append(_strat_key(strategy))
            if len(h["_tried_keys"]) > _MAX_TRIED:
                h["_tried_keys"] = h["_tried_keys"][-_MAX_TRIED:]
            h["tried_recent"] = ([strategy] + h.get("tried_recent", []))[:12]

            results = _exec(strategy, h)
            matches, leads = _judge(strategy, results, h)
            matches = _verify(matches)          # drop rotted/dead finds before recording
            # _exec/_judge/_verify can take many seconds; a stop+resume in that window may have
            # started a NEWER worker on this same hunt. Bail before mutating so two workers can't
            # both write the hunt dict (the single-writer assumption _record relies on).
            with _reg_lock:
                if _worker_gen.get(hid) != mygen or stop.is_set():
                    return
            before = len(h["results"])
            _record(h, strategy, matches, leads)
            st = h["stats"]
            st["cycles"] = st.get("cycles", 0) + 1
            st["executed"] = st.get("executed", 0) + 1
            st["found"] = len(h["results"])
            st["new_last"] = len(h["results"]) - before
            st["last"] = int(time.time())
            _note_method(h, strategy.get("method", "search"), st["new_last"])  # adapt affinity
            if st["new_last"] > 0:              # tell the user their background hunt found something
                _notify(h, st["new_last"], [r.get("title", "") for r in h["results"][before:]])
            _save(h)
        except Exception as e:
            h.setdefault("stats", {})["last_error"] = str(e)[:200]
            _save(h)
        # polite pacing: nap the normal interval, but 4x longer if the box is under
        # heavy load, so a background hunt can never hog the machine.
        stop.wait(pace * 4 if box_busy() else pace)
    # ---- exit reconcile: if we're still THE current worker and we're exiting on a
    #      stop, make the in-memory (and disk) status say 'stopped' so the UI can
    #      never show a dead worker as still 'running'. If a newer worker superseded
    #      us (gen bumped by resume), leave status alone — that worker owns it.
    with _reg_lock:
        if _worker_gen.get(hid) == mygen:
            h = _hunts.get(hid)
            if h is not None and stop.is_set() and h.get("status") != "stopped":
                h["status"] = "stopped"
                _save(h)


# --------------------------------------------------------------------------- public API
def _new_id():
    # ms timestamp + random suffix so two hunts created in the same millisecond
    # can't collide (a bare-ms id silently overwrote one hunt & double-ran a worker).
    return "hunt-%x-%s" % (int(time.time() * 1000), os.urandom(3).hex())


def create_hunt(goal, category="all", description="", pace="normal", watch=False, sweep="daily"):
    goal = (goal or "").strip()
    if not goal:
        raise ValueError("empty goal")
    hid = _new_id()
    sweep = sweep if sweep in SWEEPS else "daily"
    sweep_seconds = SWEEPS.get(sweep, 0)
    watch = bool(watch) and sweep_seconds > 0        # "watch off" or sweep=off => a one-shot hunt
    h = {
        "id": hid, "goal": goal[:300], "category": (category or "all").strip().lower(),
        "description": (description or "")[:500],
        "pace": pace if pace in PACES else "normal",
        "pace_seconds": PACES.get(pace, PACES["normal"]),
        "watch": watch, "sweep": sweep if watch else "off", "sweep_seconds": sweep_seconds,
        "last_sweep": int(time.time()),
        "status": "running", "created": int(time.time()),
        "frontier": [], "tried_recent": [], "results": [],
        "_tried_keys": [], "_result_keys": [], "method_stats": {},
        "stats": {"cycles": 0, "executed": 0, "found": 0, "leads": 0, "sweeps": 0,
                  "started": int(time.time()), "last": 0, "new_last": 0},
    }
    # Seed INSTANTLY with the deterministic stub so create_hunt returns immediately —
    # the (possibly slow) LLM brain enriches the frontier later, inside the worker,
    # when these first strategies run low. Never block the HTTP create on an LLM call.
    _add_strategies(h, _stub_generate(h))
    with _reg_lock:
        while hid in _hunts:             # astronomically unlikely, but never overwrite
            hid = _new_id()
        h["id"] = hid
        _hunts[hid] = h
    _save(h)
    _start_thread(hid)
    return _public(h)


def _start_thread(hid):
    """(Re)start the worker for a hunt. Always binds a FRESH stop event and bumps the
    generation so any prior worker exits cleanly — never leaves a duplicate grinder."""
    with _reg_lock:
        gen = _worker_gen.get(hid, 0) + 1
        _worker_gen[hid] = gen
        old = _stops.get(hid)
        stop = threading.Event()
        _stops[hid] = stop
        t = threading.Thread(target=_worker, args=(hid, stop, gen), daemon=True)
        _threads[hid] = t
    if old is not None:
        old.set()                        # signal any prior worker to wind down
    t.start()


def stop_hunt(hid):
    with _reg_lock:
        h = _hunts.get(hid)
        ev = _stops.get(hid)
        if not h:
            return False
        h["status"] = "stopped"          # set + persist atomically under the lock
        _save(h)
    if ev:
        ev.set()
    return True


def resume_hunt(hid):
    with _reg_lock:
        h = _hunts.get(hid)
        if not h:
            return False
        h["status"] = "running"
        _save(h)
    _start_thread(hid)                    # always rebind a fresh event + worker; the
    return True                          # gen bump makes any stale/alive worker exit


def delete_hunt(hid):
    # Validate BEFORE touching anything: the id comes from a request body, and this
    # function removes a file by it.
    target = _safe_path(hid)
    if target is None:
        return False
    stop_hunt(hid)
    with _reg_lock:
        _worker_gen.pop(hid, None)       # drop gen so any live worker exits on next check
        _hunts.pop(hid, None)
        _stops.pop(hid, None)
        _threads.pop(hid, None)
    try:
        os.remove(target)
    except OSError:
        pass
    return True


def _public(h):
    """A view safe to send to the UI (drops the big internal dedup lists)."""
    return {
        "id": h["id"], "goal": h["goal"], "category": h["category"],
        "description": h["description"], "pace": h["pace"], "status": h["status"],
        "watch": bool(h.get("watch")), "sweep": h.get("sweep", "off"),
        "sweep_seconds": h.get("sweep_seconds", 0), "last_sweep": h.get("last_sweep", 0),
        "created": h["created"], "stats": h.get("stats", {}),
        "frontier_size": len(h.get("frontier", [])),
        "tried_recent": h.get("tried_recent", [])[:12],
        "result_count": len(h.get("results", [])),
        "method_stats": h.get("method_stats", {}),   # which sources are producing
    }


def list_hunts():
    with _reg_lock:
        hs = list(_hunts.values())
    return sorted((_public(h) for h in hs), key=lambda x: x["created"], reverse=True)


def get_hunt(hid, with_results=True, limit=300):
    with _reg_lock:
        h = _hunts.get(hid)
    if not h:
        return None
    pub = _public(h)
    if with_results:
        # Quality-first, not raw found-order: a late-cycle zero-seed/off-goal find must not
        # bury an early perfect match. Rank by relevance -> downloadable -> seeders, with
        # most-recently-found breaking ties so fresh finds still surface among equals.
        terms = _goal_terms(h)
        res = h.get("results", [])
        ordered = [r for _, r in sorted(
            enumerate(res), key=lambda ir: (_result_rank(ir[1], terms), ir[0]), reverse=True)]
        pub["results"] = ordered[:limit]
    return pub


def resume_all():
    """On startup: load every hunt from disk and restart the ones that were running."""
    _ensure_dir()
    try:
        files = [f for f in os.listdir(HUNTS_DIR) if f.endswith(".json")]
    except OSError:
        files = []
    for fn in files:
        try:
            h = json.load(open(os.path.join(HUNTS_DIR, fn)))
        except Exception:
            continue
        if not isinstance(h, dict) or "id" not in h:
            continue
        h.setdefault("_tried_keys", [])
        h.setdefault("_result_keys", [_result_key(r) for r in h.get("results", [])])
        h.setdefault("frontier", [])
        h.setdefault("tried_recent", [])
        h.setdefault("results", [])
        h.setdefault("stats", {})
        h.setdefault("method_stats", {})
        h.setdefault("watch", False)
        h.setdefault("sweep_seconds", 0)
        h.setdefault("last_sweep", h.get("created", 0))
        h.setdefault("pace_seconds", PACES.get(h.get("pace", "normal"), 20))
        with _reg_lock:
            _hunts[h["id"]] = h
        if h.get("status") in ("running", "idle"):
            h["status"] = "running"
            _start_thread(h["id"])


if __name__ == "__main__":
    # Phase-1 self-test with a FAKE executor: proves the loop grinds, dedupes,
    # accumulates, checkpoints, and that state can be reloaded from disk.
    import tempfile
    HUNTS_DIR = tempfile.mkdtemp()
    calls = {"n": 0}

    def fake_exec(strategy, h):
        calls["n"] += 1
        # each strategy "finds" 2 items; some overlap to test dedup
        base = abs(hash(strategy["query"])) % 1000
        return [{"title": "test target item %d" % (base + i), "url": "http://x/%d" % (base + i),
                 "source": "fake", "seeders": 0, "size": 0, "magnet": "",
                 "torrent_url": "", "nzb_id": "", "date": "", "category": "other",
                 "quality": ""} for i in range(2)]

    set_backends(execute=fake_exec)
    hp = create_hunt("test target", category="music", pace="aggressive")
    hp2 = dict(hp); hp2["pace_seconds"] = 1
    with _reg_lock:
        _hunts[hp["id"]]["pace_seconds"] = 1
    time.sleep(6)
    got = get_hunt(hp["id"])
    print("cycles:", got["stats"]["cycles"], "results:", got["result_count"],
          "frontier:", got["frontier_size"], "status:", got["status"])
    stop_hunt(hp["id"])
    # reload from disk into a fresh registry -> resume must restore state
    _hunts.clear()
    resume_all()
    r2 = get_hunt(hp["id"])
    print("after reload -> results:", r2["result_count"], "status:", r2["status"])
    assert got["stats"]["cycles"] > 0, "loop did not grind"
    assert r2["result_count"] == got["result_count"], "state did not persist"
    print("PHASE 1 SELF-TEST PASSED")
