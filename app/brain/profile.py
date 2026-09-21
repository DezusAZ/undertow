"""L1 — the TARGET PROFILE: what the thing actually is.

Built once per hunt (in the worker, never on the HTTP request — the model can take 30 s
cold) and revised later by the reflect step. Every planner/judge prompt is anchored on it
instead of a 300-character goal string. The user's own description of "found" is copied
in VERBATIM and marked authoritative: in testing, a model-built profile that lost the
user's criterion ("the original albums count too") halved judge recall.
"""
import re
import unicodedata

from brain import llm

SCHEMA = {
    "type": "object",
    "properties": {
        "canonical_title": {"type": "string"},
        "kind": {"type": "string"},
        "aliases": {"type": "array", "items": {"type": "string"}},
        "creators": {"type": "array", "items": {"type": "string"}},
        "year_or_era": {"type": "string"},
        "identifiers": {"type": "array", "items": {"type": "string"}},
        "expected_formats": {"type": "array", "items": {"type": "string"}},
        "expected_size_hint": {"type": "string"},
        "expected_length": {"type": "string"},
        "likely_sources": {"type": "array", "items": {"type": "string"}},
        "near_misses_to_reject": {"type": "array", "items": {"type": "string"}},
        "must_have": {"type": "array", "items": {"type": "string"}},
        "prefer": {"type": "array", "items": {"type": "string"}},
        "also_counts": {"type": "array", "items": {"type": "string"}},
        "success_criteria": {"type": "string"},
        "knowledge_confidence": {"type": "number"},
        "notes": {"type": "string"},
    },
    "required": ["canonical_title", "kind", "aliases", "creators", "year_or_era",
                 "identifiers", "expected_formats", "near_misses_to_reject",
                 "must_have", "prefer", "also_counts",
                 "success_criteria", "knowledge_confidence"],
}

SYSTEM = (
    "You are the research analyst of a file-hunting agent. Given a target the user wants to "
    "find, write a precise TARGET PROFILE from your own knowledge so that a downstream judge "
    "can tell a true find from a near-miss and a planner can invent good searches.\n"
    "- canonical_title: the proper name. kind: what it is (film, album, book, dataset, ISO…).\n"
    "- aliases: alternate / original / foreign-language titles, transliterations, working "
    "titles, common misspellings, scene-release naming (e.g. 'Kankyō Ongaku' vs 'Kankyo Ongaku').\n"
    "- creators: artists, authors, directors, labels, publishers, studios — the names that "
    "appear in release titles. identifiers: ISBN/DOI/catalog numbers/IMDb ids/version numbers.\n"
    "- expected_formats: file types and typical qualities; expected_size_hint: rough size; "
    "expected_length: runtime / track count / page count (e.g. '15-minute short film', '38 "
    "tracks ~2 h', '~240 pages') — the judge uses this so it never guesses what 'full' means.\n"
    "- likely_sources: where such a thing tends to live (torrent trackers, Internet Archive, "
    "academic repositories, open directories, official mirrors, Usenet…).\n"
    "- near_misses_to_reject: things that LOOK like the target but are not — related artists, "
    "other editions, samplers, single tracks, remakes, same-title different works.\n"
    "- must_have: HARD requirements from the user's own words only (e.g. 'i386 install ISO', "
    "'complete album', 'the 1968 original not the remake'). If the user did not demand it, it "
    "is NOT a must_have.\n"
    "- prefer: nice-to-haves the user mentioned as preferences (4K, FLAC, 24-bit, surround, "
    "'preferred', 'ideally', 'or highest quality'). A copy without them still counts as found.\n"
    "- also_counts: OTHER works that the user said count as found too (e.g. 'any complete "
    "original 1980s album by these artists', 'the official multitrack release'). Empty if none.\n"
    "- success_criteria: one paragraph stating exactly what counts as FOUND. It MUST honour "
    "the user's own description (given below) — restate it, never narrow it.\n"
    "- knowledge_confidence 0-1: how sure you are about the facts above.\n"
    "HONESTY RULE: names you are not certain of do NOT go into aliases/creators/identifiers — "
    "an invented first name or label poisons every later judgement. Put guesses in notes "
    "prefixed 'unsure:'. Names the user wrote are facts; copy them exactly as written."
)


def build(goal, category, description):
    """Profile from the model, or None if the model is unavailable/unusable."""
    user = ("TARGET: %s\nCATEGORY: %s\nUSER'S OWN DESCRIPTION OF WHAT COUNTS AS FOUND: %s"
            % (goal, category or "any", description or "(none given — the target itself)"))
    j = llm.call("profile", SYSTEM, user, SCHEMA)
    if not isinstance(j, dict) or not j.get("canonical_title"):
        return None
    p = {k: j.get(k) for k in SCHEMA["properties"]}
    for k in ("aliases", "creators", "identifiers", "expected_formats", "likely_sources",
              "near_misses_to_reject", "must_have", "prefer", "also_counts"):
        v = p.get(k) or []
        p[k] = [str(x).strip()[:120] for x in v if str(x).strip()][:16]
    for k in ("canonical_title", "kind", "year_or_era", "expected_size_hint", "expected_length",
              "success_criteria", "notes"):
        p[k] = str(p.get(k) or "")[:600]
    try:
        p["knowledge_confidence"] = max(0.0, min(1.0, float(p.get("knowledge_confidence"))))
    except (TypeError, ValueError):
        p["knowledge_confidence"] = 0.5
    p["user_description"] = (description or "")[:500]      # verbatim, authoritative
    p["goal"] = goal
    p["category"] = category or "all"
    p["built_by"] = "llm"
    return p


def minimal(goal, category, description):
    """The no-model profile: just the user's words. Used until build() succeeds (and forever
    when AI is off) so every prompt/renderer can rely on the same shape."""
    return {"canonical_title": goal, "kind": category or "", "aliases": [], "creators": [],
            "year_or_era": "", "identifiers": [], "expected_formats": [],
            "expected_size_hint": "", "expected_length": "", "likely_sources": [],
            "near_misses_to_reject": [], "must_have": [], "prefer": [], "also_counts": [],
            "success_criteria": description or goal, "knowledge_confidence": 0.0,
            "notes": "", "user_description": (description or "")[:500], "goal": goal,
            "category": category or "all", "built_by": "none"}


def _fold(s):
    s = unicodedata.normalize("NFKD", s or "")
    return "".join(c for c in s if not unicodedata.combining(c)).lower()


_STOP = set("the a an of and or to in on for with at by from feat ft vs".split())


def terms(profile):
    """Distinctive words from the profile for the cheap lexical pre-filter: goal words, the
    user's own description (the names THEY typed are the most reliable terms we have) plus
    every alias/creator word, so an alternate-title release survives the pre-filter."""
    out = []
    for s in [profile.get("goal", ""), profile.get("canonical_title", ""),
              profile.get("user_description", "")] \
            + list(profile.get("aliases", [])) + list(profile.get("creators", [])):
        for t in re.findall(r"[^\W_]+", _fold(s)):
            if len(t) >= 3 and t not in _STOP:
                out.append(t)
    return list(dict.fromkeys(out))


def render(profile, max_chars=1400):
    """Compact, prompt-ready text of a profile (the judge/planner read this every call)."""
    p = profile or {}
    lines = ["TITLE: %s (%s, %s)" % (p.get("canonical_title", ""), p.get("kind", ""),
                                     p.get("year_or_era", ""))]
    if p.get("aliases"):
        lines.append("ALIASES: " + "; ".join(p["aliases"][:10]))
    if p.get("creators"):
        lines.append("CREATORS: " + "; ".join(p["creators"][:10]))
    if p.get("identifiers"):
        lines.append("IDS: " + "; ".join(p["identifiers"][:8]))
    if p.get("expected_formats"):
        lines.append("FORMATS: " + ", ".join(p["expected_formats"][:8])
                     + ((" (~" + p["expected_size_hint"] + ")") if p.get("expected_size_hint") else ""))
    if p.get("expected_length"):
        lines.append("LENGTH: " + p["expected_length"])
    if p.get("near_misses_to_reject"):
        lines.append("NOT THE TARGET: " + "; ".join(p["near_misses_to_reject"][:8]))
    lines.append("MUST HAVE (hard requirements): " + ("; ".join(p["must_have"][:6]) if p.get("must_have") else "none"))
    lines.append("PREFER (nice-to-have, a copy without these still counts): "
                 + ("; ".join(p["prefer"][:6]) if p.get("prefer") else "none"))
    if p.get("also_counts"):
        lines.append("ALSO COUNTS AS FOUND: " + "; ".join(p["also_counts"][:6]))
    lines.append("COUNTS AS FOUND: " + (p.get("success_criteria") or p.get("goal", "")))
    if p.get("user_description"):
        lines.append("USER'S OWN WORDS (authoritative): " + p["user_description"])
    txt = "\n".join(lines)
    return txt[:max_chars]
