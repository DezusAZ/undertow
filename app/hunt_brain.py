"""Deep Hunt — the LLM brain (Phase 2).

Two functions, INJECTED into the hunt runtime (hunt.set_backends): they are the
"intelligence" the Phase-1 loop calls between executions. Both use ONLY the local
Ollama server (via ai._chat) — no outside AI — so a shipped hunt is fully offline.

  • generate(hunt)  -> [ {method, query, why}, ... ]   (DIVERGE: invent new angles)
  • judge(strategy, results, hunt) -> (matches, leads)  (CONVERGE: pick real hits +
                                                          pull new leads to pivot on)

Standalone-safe: if AI is OFF or the model is unreachable/garbles its JSON, each
function FALLS BACK to hunt.py's deterministic stub so the hunt keeps grinding on a
box with no GPU. Never raises. stdlib only (ai._chat does the HTTP).
"""
import os
import json
import re
import time
import threading

import ai
import hunt

# Only ever run a bounded number of LLM calls at once ACROSS ALL HUNTS. On a GPU this
# just serialises cheap calls; on a CPU-bound model it is what stops N concurrent hunts
# from pegging every core at the same time. Tunable for a beefier box.
_LLM_GATE = threading.Semaphore(max(1, int(os.environ.get("HUNT_LLM_CONCURRENCY", "1"))))

# GPU health flag, published by the watchdog (it can see the GPU; the app container
# can't). We refuse to run the model unless this says the GPU is healthy + fresh.
_GPU_FLAG = os.environ.get("GPU_HEALTH_FILE", "/config/gpu_health.json")
_GPU_FLAG_MAX_AGE = int(os.environ.get("GPU_HEALTH_MAX_AGE", "180"))
# Force the model ENTIRELY onto the GPU. If it can't fully fit (VRAM pressure from other
# consumers), Ollama errors instead of silently splitting layers onto the CPU — ai._chat
# swallows the error and the caller falls back to the stub. Belt to the watchdog's braces.
_LLM_OPTS = {"num_gpu": int(os.environ.get("HUNT_NUM_GPU", "999"))}


def _gpu_ok():
    """True only if the watchdog RECENTLY confirmed the model will run on the GPU, AND the
    certified endpoint is the one we'll actually hit. Missing / stale / future-dated /
    not-ok / wrong-endpoint => False. FAIL-SAFE by design: we never run the local model
    unless we can prove it's GPU-backed, because CPU inference of a 7B pegs every core and
    starves the other containers. Absent flag (watchdog not up) => grind CPU-free on the stub."""
    try:
        d = json.load(open(_GPU_FLAG))
        if not d.get("ok"):
            return False
        age = time.time() - float(d.get("ts", 0))
        if not (0 <= age <= _GPU_FLAG_MAX_AGE):        # stale OR future-dated (clock glitch)
            return False
        # the flag certifies a SPECIFIC endpoint — require it to match the URL inference
        # will use, so repointing ai.json at a CPU box can't sail through a green gate.
        ep = str(d.get("endpoint", "")).rstrip("/")
        if not ep or ep != str(ai.get_config().get("url", "")).rstrip("/"):
            return False
        return True
    except Exception:
        return False


def _use_llm():
    """Run the local model only when AI is on, the GPU is confirmed healthy, AND the box
    has spare capacity. Any doubt => False, and the caller falls back to the cheap stub,
    so a background hunt can never bog the machine down or run inference on CPU."""
    try:
        # GPU-offloaded model -> gate on _box_overloaded (extreme load only), NOT box_busy (CPU
        # pacing), so a busy-but-not-melting box still gets the smart AI brain + real GPU use.
        return ai.is_enabled() and _gpu_ok() and not hunt._box_overloaded()
    except Exception:
        return False


_last_llm_ts = 0.0            # when the local model last actually ran (proves the AI is working)


def _mark_llm():
    global _last_llm_ts
    try:
        _last_llm_ts = time.time()
    except Exception:
        pass


def brain_status():
    """What the hunt's AI brain is doing, for the UI to show. reason: active | ai-off |
    gpu-not-ready | box-busy — so the user can SEE whether the local LLM is running and, if not, why."""
    try:
        enabled = bool(ai.is_enabled())
    except Exception:
        enabled = False
    gpu = bool(_gpu_ok())
    try:
        busy = bool(hunt._box_overloaded())
    except Exception:
        busy = False
    using = enabled and gpu and not busy
    reason = ("active" if using else "ai-off" if not enabled
              else "gpu-not-ready" if not gpu else "box-busy" if busy else "off")
    last = None
    try:
        if _last_llm_ts:
            last = int(time.time() - _last_llm_ts)
    except Exception:
        pass
    return {"using_llm": using, "reason": reason, "ai_enabled": enabled,
            "gpu_ok": gpu, "box_busy": busy, "last_used_s": last}

# How many fresh strategies to ask for per diverge call, and how much memory to show
# the model (bounded so the prompt can't grow without limit over a weeks-long hunt).
_N_NEW = 6
_SHOW_TRIED = 30
_SHOW_LEADS = 12
_SHOW_RESULTS = 40          # titles handed to the converge step per strategy

# The menu of methods the brain may choose. Kept in sync with what the Phase-3
# executor will actually know how to run.
_METHODS = "search, dork, academic, pivot"

_DIVERGE_SYS = (
    "You are the strategy engine of a relentless, never-bored file-hunting agent. Your "
    "one job: invent NEW ways to search for a target that have NOT been tried yet. A "
    "strategy is an object {method, query, why}.\n"
    "METHODS you may use:\n"
    "  search   — torrent/Usenet indexers (normal keyword queries)\n"
    "  dork     — Google 'index of' / open-directory operators (e.g.  intitle:index of X )\n"
    "  academic — scholarly / document / archive databases (papers, books, filings)\n"
    "  pivot    — go deeper into a specific site or directory already found\n"
    "Be genuinely creative and DIVERSE — go BEYOND the surface. Pull from ALL of these:\n"
    "  - alternate & ORIGINAL titles, subtitles, working titles, mistranslations\n"
    "  - the target in other LANGUAGES + transliterations (romaji<->kanji, cyrillic<->latin)\n"
    "  - identifiers: catalog/matrix numbers, ISBN/ISRC/DOI/arXiv id, model/part numbers\n"
    "  - release-scene naming (group tags, YEAR, quality/codec, rip type) and common MISSPELLINGS / OCR errors\n"
    "  - PIVOTS: the artist's other works, the label/publisher's catalog, collaborators, the series/era\n"
    "  - dork operators varied: intitle:index of, inurl:, filetype:, site:<likely host>, and target FILE EXTENSIONS\n"
    "Favor obscure, non-surface angles other searches miss. Do NOT repeat or trivially "
    "reword anything in the already-tried list. Keep each query under 10 words.\n"
    "For EACH strategy add a \"score\" 0.0-1.0 = how likely THIS angle/source actually "
    "contains the target, given its nature (e.g. rare vinyl -> discogs/archive/blogs score "
    "high, academic DBs ~0; a paper -> the opposite). Be discriminating; don't score all 0.9.\n"
    "IMPORTANT: never put a double-quote (\") or backslash inside a query value — use "
    "plain words and bare operators only (write  intitle:index of X  with no quotes).\n"
    'Reply with ONLY a JSON object: {"strategies":[{"method":"...","query":"...","score":0.7}]}'
)

_CONVERGE_SYS = (
    "You judge search results for a running hunt. You are given the goal and a numbered "
    "list of result TITLES. Do two things:\n"
    "1. MATCHES: list the indices (numbers) of results that genuinely match the goal.\n"
    "2. LEADS: extract any NEW angle the titles reveal — an alternate title, a new keyword, "
    "a release group, a site/database name, or a directory worth crawling — as new search "
    "strategies to try next. Skip leads that are obvious repeats of the goal. Never put a "
    "double-quote or backslash inside a query value.\n"
    'Reply with ONLY a JSON object: {"matches":[<indices>],"leads":[{"method":"...","query":"..."}]}'
)


def _clean_strategies(raw):
    """Coerce whatever the model returned into a clean list of {method,query,why}."""
    out = []
    if isinstance(raw, dict):
        raw = raw.get("strategies") or raw.get("queries") or raw.get("items") or []
    if not isinstance(raw, list):
        return out
    for s in raw:
        if isinstance(s, str):                 # model gave bare query strings
            s = {"query": s}
        if not isinstance(s, dict):
            continue
        q = s.get("query") or s.get("q") or s.get("search")
        if isinstance(q, list):
            q = " ".join(str(x) for x in q)
        q = re.sub(r"\s+", " ", str(q or "")).strip()
        if not q:
            continue
        m = str(s.get("method") or "search").strip().lower()
        if m not in ("search", "dork", "academic", "pivot"):
            m = "search"
        item = {"method": m, "query": q[:300], "why": str(s.get("why") or "")[:200]}
        try:                                       # the brain's likelihood estimate 0-1
            item["score"] = max(0.0, min(1.0, float(s.get("score"))))
        except (TypeError, ValueError):
            pass
        out.append(item)
    return out


def _salvage(txt):
    """Pull {method,query} pairs out of imperfect/truncated JSON (a small local model
    sometimes emits a stray quote or gets cut off mid-object). Order-tolerant."""
    txt = txt or ""
    out = []
    for m in re.finditer(
            r'"method"\s*:\s*"([a-zA-Z]+)"\s*,\s*"query"\s*:\s*"([^"\n]{1,300})"', txt):
        out.append({"method": m.group(1), "query": m.group(2)})
    for m in re.finditer(
            r'"query"\s*:\s*"([^"\n]{1,300})"\s*,\s*"method"\s*:\s*"([a-zA-Z]+)"', txt):
        out.append({"method": m.group(2), "query": m.group(1)})
    if not out:                                    # last resort: any query strings
        for m in re.finditer(r'"query"\s*:\s*"([^"\n]{1,300})"', txt):
            out.append({"query": m.group(1)})
    return out


def _parse_strategies(txt):
    """Strict JSON first; if that fails or is empty, salvage from the raw text."""
    if not txt:
        return []
    try:
        s = _clean_strategies(json.loads(txt))
        if s:
            return s
    except Exception:
        pass
    return _clean_strategies(_salvage(txt))


def generate(h):
    """DIVERGE: new strategies from the local LLM; deterministic stub if AI unavailable
    OR the box is too busy to spend cycles on the model."""
    if not _use_llm():
        return hunt._stub_generate(h)
    tried = [k.split("|", 1)[-1] for k in h.get("_tried_keys", [])][-_SHOW_TRIED:]
    # also fold in what's already queued so we don't re-propose it
    tried += [s.get("query", "") for s in h.get("frontier", [])][:_SHOW_TRIED]
    leads = [s.get("query", "") for s in h.get("tried_recent", [])][:_SHOW_LEADS]
    user = (
        "GOAL: %s\n"
        "CATEGORY: %s\n"
        "WHAT SUCCESS LOOKS LIKE: %s\n"
        "ALREADY TRIED (do NOT repeat or reword): %s\n"
        "RECENT ANGLES: %s\n"
        "Propose %d NEW strategies most likely to surface the target, favoring the "
        "obscure/non-surface angles. Vary the methods (%s)."
        % (h.get("goal", ""), h.get("category", "all"),
           (h.get("description") or "(not specified)")[:400],
           json.dumps(tried[-_SHOW_TRIED:], ensure_ascii=False)[:1600],
           json.dumps(leads, ensure_ascii=False)[:600],
           _N_NEW, _METHODS))
    # num_predict cap keeps a slow local model from decoding until the socket times out.
    # ~380 tokens holds several compact (method,query) strategies; the timeout is generous
    # because this is a paced BACKGROUND agent — latency doesn't matter, completing does.
    with _LLM_GATE:                     # bounded concurrency across all hunts
        txt = ai._chat(_DIVERGE_SYS, user, timeout=110, want_json=True,
                       options=dict(_LLM_OPTS, num_predict=400, temperature=0.8))
    if txt:
        _mark_llm()                     # record a REAL model response (ai._chat returns "" on failure)
    # robust parse (salvages strategies even from slightly-broken/truncated JSON); if the
    # model still gave nothing usable, keep the hunt alive with the deterministic stub.
    return _parse_strategies(txt) or hunt._stub_generate(h)


def judge(strategy, results, h):
    """CONVERGE: pick real matches + pull leads. Falls back to accept-all (stub)."""
    results = list(results or [])
    if not results:
        return [], []
    if not _use_llm():
        return hunt._stub_judge(strategy, results, h)
    shown = results[:_SHOW_RESULTS]
    listing = "\n".join("%d. %s" % (i, (r.get("title") or "")[:160])
                        for i, r in enumerate(shown))
    user = ("GOAL: %s\nCATEGORY: %s\nSTRATEGY THAT FOUND THESE: %s\n\nRESULTS:\n%s"
            % (h.get("goal", ""), h.get("category", "all"),
               strategy.get("query", ""), listing))
    with _LLM_GATE:                     # bounded concurrency across all hunts
        txt = ai._chat(_CONVERGE_SYS, user, timeout=100, want_json=True,
                       options=dict(_LLM_OPTS, num_predict=384))
    if txt:
        _mark_llm()                     # record a REAL model response (ai._chat returns "" on failure)
    if not txt:
        return hunt._stub_judge(strategy, results, h)
    # robust parse: strict JSON (an object, OR a bare [0,2,5] index array — Ollama json mode
    # permits either), else salvage indices + leads from the raw text.
    idxs, leads_raw, parsed_ok = [], [], False
    try:
        j = json.loads(txt)
        parsed_ok = True
        if isinstance(j, list):
            idxs = j
        elif isinstance(j, dict):
            idxs = j.get("matches", [])
            leads_raw = j.get("leads", [])
    except Exception:
        mm = re.search(r'"matches"\s*:\s*\[([\d,\s]*)\]', txt)
        if mm:
            parsed_ok = True
            idxs = [int(n) for n in re.findall(r"\d+", mm.group(1))]
        leads_raw = _salvage(txt)
    if not isinstance(idxs, list):
        idxs = []
    matches = []
    seen = set()
    for x in idxs:
        try:
            i = int(x)
        except (TypeError, ValueError):
            continue
        if 0 <= i < len(shown) and i not in seen:      # indices map into SHOWN, never unseen rows
            seen.add(i)
            matches.append(shown[i])
    leads = _clean_strategies(leads_raw)
    # If we UNDERSTOOD the model, honour its verdict: an explicit "none match" records nothing
    # rather than resurrecting the whole (partly-unseen) list. Only a TRUE parse failure falls
    # back — and then to the deterministic relevance gate over what the model actually SAW.
    if matches or parsed_ok:
        return matches, leads
    fb, _ = hunt._stub_judge(strategy, shown, h)
    return fb, leads


if __name__ == "__main__":
    # Offline smoke test of the parser + fallback WITHOUT a live model.
    fake = {"strategies": [
        {"method": "dork", "query": 'intitle:"index of" target flac', "why": "open dirs"},
        {"method": "SEARCH", "query": ["target", "remastered"], "why": "list query"},
        {"query": "target alternate title"}, "bare string query", {"nope": 1}]}
    got = _clean_strategies(fake)
    assert len(got) == 4, got
    assert all(g["method"] in ("search", "dork", "academic", "pivot") for g in got)
    assert got[1]["query"] == "target remastered", got[1]
    # judge index-mapping + accept-all fallback (AI off path via stub)
    print("parser OK:", [g["method"] + ":" + g["query"] for g in got])
    print("BRAIN PARSER SELF-TEST PASSED")
