"""L3 — the PLANNER (diverge v2): invent the next strategies.

Input is everything the hunt knows: the TARGET PROFILE (aliases, creators, identifiers,
formats, near-misses), the SOURCE CATALOG with this hunt's per-source yield, the JOURNAL
(facts learned, dead ends, promising hosts, hypotheses), a compact summary of what was
already tried GROUPED BY SOURCE (not a truncated raw list), and the leads still queued.
Output: N strategies, each aimed at a source with a query mode, a reason and a score.
Near-duplicates of anything tried/queued are dropped (token-set similarity), not just
exact repeats.
"""
import re
import json

import hunt
from brain import llm, manifest, profile as prof

N_NEW = 6
SCHEMA = {
    "type": "object",
    "properties": {"strategies": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "source": {"type": "string", "enum": manifest.NAMES},
            "mode": {"type": "string", "enum": manifest.MODES},
            "query": {"type": "string"},
            "why": {"type": "string"},
            "score": {"type": "number"}},
        "required": ["source", "mode", "query", "why", "score"]}}},
    "required": ["strategies"],
}

SYSTEM = (
    "You are the strategy engine of a relentless file-hunting agent. Your job: propose NEW "
    "search strategies that have NOT been tried, each aimed at ONE source from the catalog, "
    "as {source, mode, query, why, score}.\n"
    "How to think:\n"
    "- Use the PROFILE: aliases and original-language titles, creators/labels, identifiers "
    "(ISBN/DOI/catalog#/version), scene-style naming (Title.Year.1080p.Group), typical file "
    "extensions. Vary spelling/transliteration. Pivot through the creator's other works, the "
    "label/publisher catalog, the series/era, collectors' forums, mirrors of official sites.\n"
    "- Match the query to the source's MODE: trackers want short release-style keywords; "
    "archive/openalex/ietf take titles or ids; opendir wants 2-4 distinctive words plus a "
    "file extension (the executor adds the index-of operators); crawl wants a URL you already "
    "know; wayback/commoncrawl want a hostname.\n"
    "- Read the JOURNAL and the per-source YIELDS: do not re-propose dead ends; prefer sources "
    "that produced finds for THIS hunt, but keep 1-2 genuinely new angles every round.\n"
    "- Never repeat or trivially reword anything in ALREADY TRIED. Keep queries under 10 words; "
    "no double quotes or backslashes inside a query.\n"
    "- score 0-1 = how likely THIS strategy at THIS source surfaces the target. Be "
    "discriminating (an academic DB for a film is ~0.05).\n"
    "why = one short sentence a human can read in the activity log."
)


def _norm_tokens(q):
    return set(re.findall(r"[^\W_]+", (q or "").lower()))


def _near_dup(q, seen_sets, thresh=0.8):
    a = _norm_tokens(q)
    if not a:
        return True
    for b in seen_sets:
        if not b:
            continue
        j = len(a & b) / float(len(a | b))
        if j >= thresh:
            return True
    return False


def _tried_summary(h, max_chars=1500):
    """Tried strategies grouped by source with counts and the last few queries each."""
    groups = {}
    for ev in (h.get("events") or []):
        if ev.get("kind") != "cycle":
            continue
        s = ev.get("source") or ev.get("method") or "?"
        g = groups.setdefault(s, {"n": 0, "found": 0, "q": []})
        g["n"] += 1
        g["found"] += int(ev.get("new", 0) or 0)
        g["q"].append(ev.get("query", "")[:60])
    if not groups:                      # no event log yet (older hunt) -> raw keys
        keys = [k.split("|")[-1] for k in h.get("_tried_keys", [])][-25:]
        return "; ".join(keys)[:max_chars]
    parts = []
    for s, g in sorted(groups.items(), key=lambda kv: -kv[1]["n"]):
        parts.append("%s (%d tried, %d finds): %s" % (s, g["n"], g["found"], " | ".join(g["q"][-5:])))
    return "\n".join(parts)[:max_chars]


def _method_for(source, mode):
    r = manifest.route(source)
    if r[0] == "dork":
        return "dork"
    if r[0] == "crawl":
        return "pivot"
    if r[0] == "adapter":
        return "adapter"
    return "search"


def plan(h, p, journal_text="", n=N_NEW):
    """New strategies for hunt `h` given profile `p`; [] if the model gave nothing usable."""
    queued = [s.get("query", "") for s in h.get("frontier", [])][:20]
    user = (
        "TARGET PROFILE:\n%s\n\nSOURCE CATALOG (name — what it is; modes; delivers; yield this hunt):\n%s\n\n"
        "JOURNAL:\n%s\n\nALREADY TRIED (by source):\n%s\n\nQUEUED (do not repeat): %s\n\n"
        "Propose %d NEW strategies. Spread them across at least 3 different sources."
        % (prof.render(p, 1200), manifest.describe(h), journal_text or "(nothing yet)",
           _tried_summary(h), json.dumps(queued, ensure_ascii=False)[:700], n))
    j = llm.call("plan", SYSTEM, user, SCHEMA)
    if not isinstance(j, dict):
        return []
    seen = [_norm_tokens(k.split("|")[-1]) for k in h.get("_tried_keys", [])[-400:]]
    seen += [_norm_tokens(s.get("query", "")) for s in h.get("frontier", [])]
    out = []
    for s in j.get("strategies") or []:
        if not isinstance(s, dict):
            continue
        q = re.sub(r"\s+", " ", str(s.get("query") or "")).strip().replace('"', "").replace("\\", "")
        if not q or _near_dup(q, seen):
            continue
        src = str(s.get("source") or "all").lower()
        if src not in manifest.SOURCES and src != "all":
            src = "all"
        mode = str(s.get("mode") or "keyword").lower()
        if mode == "url" and not q.startswith(("http://", "https://", "ftp://")):
            continue                        # a crawl needs a real URL
        try:
            sc = max(0.0, min(1.0, float(s.get("score"))))
        except (TypeError, ValueError):
            sc = 0.5
        out.append({"method": _method_for(src, mode), "source": src, "mode": mode,
                    "query": q[:200], "why": str(s.get("why") or "")[:160], "score": sc})
        seen.append(_norm_tokens(q))
    return out
