"""L6/L7 — the JOURNAL and the REFLECT step: the hunt's memory.

A weeks-long hunt used to carry no memory beyond a truncated list of tried queries. The
journal is a compact, model-maintained note: facts learned about the target (an alternate
title seen in a release, a catalog number, the label), dead ends (sources/angles that keep
yielding nothing), promising hosts/directories, and open hypotheses. Every REFLECT_EVERY
cycles the model reads the recent activity and finds, updates the journal, may patch the
profile (new aliases / creators / near-misses) and says whether to continue, broaden or
narrow. The planner reads the journal on every call.
"""
import time

from brain import llm, profile as prof

REFLECT_EVERY = 6
_KEEP = {"facts": 24, "dead_ends": 16, "hosts": 16, "hypotheses": 8}

SCHEMA = {
    "type": "object",
    "properties": {
        "facts_add": {"type": "array", "items": {"type": "string"}},
        "dead_ends_add": {"type": "array", "items": {"type": "string"}},
        "hosts_add": {"type": "array", "items": {"type": "string"}},
        "hypotheses": {"type": "array", "items": {"type": "string"}},
        "aliases_add": {"type": "array", "items": {"type": "string"}},
        "creators_add": {"type": "array", "items": {"type": "string"}},
        "near_misses_add": {"type": "array", "items": {"type": "string"}},
        "direction": {"type": "string", "enum": ["continue", "broaden", "narrow", "exhausted"]},
        "note": {"type": "string"},
    },
    "required": ["facts_add", "dead_ends_add", "hosts_add", "hypotheses", "aliases_add",
                 "creators_add", "near_misses_add", "direction", "note"],
}

SYSTEM = (
    "You are the reflective memory of a file-hunting agent. You get the target profile, the "
    "current journal, the recent activity (strategies tried with how much each found) and the "
    "titles of the finds so far. Update the journal:\n"
    "- facts_add: concrete things the finds/activity reveal about the target (alternate titles "
    "seen, release groups, catalog numbers, labels, years, formats that exist).\n"
    "- dead_ends_add: sources or angles that repeatedly yield nothing (be specific).\n"
    "- hosts_add: sites/directories/hosts that look promising to dig into.\n"
    "- hypotheses: 1-4 open ideas about where else it could be or why it isn't found.\n"
    "- aliases_add / creators_add / near_misses_add: profile corrections from evidence.\n"
    "- direction: continue (working), broaden (too narrow, try other angles/sources), narrow "
    "(too much junk, tighten), exhausted (nothing sensible left).\n"
    "- note: one sentence for the human watching the hunt.\n"
    "Only record what the evidence supports; never invent titles or hosts."
)


def new():
    return {"facts": [], "dead_ends": [], "hosts": [], "hypotheses": [], "direction": "continue",
            "note": "", "updated": 0, "reflections": 0}


def render(j, max_chars=1100):
    j = j or {}
    parts = []
    if j.get("facts"):
        parts.append("FACTS: " + " | ".join(j["facts"][-10:]))
    if j.get("dead_ends"):
        parts.append("DEAD ENDS: " + " | ".join(j["dead_ends"][-8:]))
    if j.get("hosts"):
        parts.append("PROMISING HOSTS: " + " | ".join(j["hosts"][-8:]))
    if j.get("hypotheses"):
        parts.append("HYPOTHESES: " + " | ".join(j["hypotheses"][-4:]))
    if j.get("direction") and j.get("direction") != "continue":
        parts.append("DIRECTION: " + j["direction"] + (" — " + j["note"] if j.get("note") else ""))
    return "\n".join(parts)[:max_chars]


def _extend(lst, items, cap):
    seen = {x.lower() for x in lst}
    for x in items or []:
        x = str(x).strip()[:160]
        if x and x.lower() not in seen:
            lst.append(x)
            seen.add(x.lower())
    del lst[:-cap]


def due(h):
    st = (h or {}).get("stats", {})
    c = int(st.get("cycles", 0))
    j = h.get("journal") or {}
    return c > 0 and c % REFLECT_EVERY == 0 and j.get("last_cycle") != c


def reflect(h, p):
    """Run the reflect step; mutates h["journal"] and h["profile"]. Returns the parsed
    reflection or None (model unavailable) — the caller logs either way."""
    j = h.get("journal") or new()
    events = [e for e in (h.get("events") or []) if e.get("kind") == "cycle"][-12:]
    act = "\n".join("- [%s%s] %s -> %d results, %d kept, %d new"
                    % (e.get("method", ""), ("/" + e["source"]) if e.get("source") else "",
                       e.get("query", "")[:70], e.get("results", 0), e.get("kept", 0), e.get("new", 0))
                    for e in events) or "(no activity yet)"
    finds = [r.get("title", "")[:90] for r in (h.get("results") or [])[-15:]]
    user = ("TARGET PROFILE:\n%s\n\nJOURNAL SO FAR:\n%s\n\nRECENT ACTIVITY:\n%s\n\nRECENT FINDS (%d total):\n%s"
            % (prof.render(p, 1000), render(j) or "(empty)", act, len(h.get("results") or []),
               "\n".join("- " + t for t in finds) or "(none yet)"))
    out = llm.call("reflect", SYSTEM, user, SCHEMA)
    if not isinstance(out, dict):
        return None
    _extend(j.setdefault("facts", []), out.get("facts_add"), _KEEP["facts"])
    _extend(j.setdefault("dead_ends", []), out.get("dead_ends_add"), _KEEP["dead_ends"])
    _extend(j.setdefault("hosts", []), out.get("hosts_add"), _KEEP["hosts"])
    hyp = [str(x).strip()[:160] for x in (out.get("hypotheses") or []) if str(x).strip()]
    if hyp:
        j["hypotheses"] = hyp[:_KEEP["hypotheses"]]
    j["direction"] = out.get("direction") if out.get("direction") in ("continue", "broaden", "narrow", "exhausted") else "continue"
    j["note"] = str(out.get("note") or "")[:200]
    j["updated"] = int(time.time())
    j["reflections"] = int(j.get("reflections", 0)) + 1
    j["last_cycle"] = int((h.get("stats") or {}).get("cycles", 0))
    h["journal"] = j
    if isinstance(p, dict):
        for key, field in (("aliases_add", "aliases"), ("creators_add", "creators"),
                           ("near_misses_add", "near_misses_to_reject")):
            lst = p.setdefault(field, [])
            _extend(lst, out.get(key), 16)
    return out
