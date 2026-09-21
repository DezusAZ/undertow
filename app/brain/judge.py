"""L5 — the JUDGE: per-row verdicts with confidence and a reason.

The old judge saw a numbered list of bare titles and returned "matches: [0, 4]". This one
sees structured rows (title, source, kind, size, seeders, date, host) next to the TARGET
PROFILE, and returns a verdict for every row:

  exact    the target itself (any acceptable edition/format)        -> counts as found
  variant  the target's content under another title/edition/language -> counts as found
  related  same creator/series/label but NOT the target               -> not found
  no       unrelated, or one of the profile's near-misses             -> not found

plus LEADS: new queries the rows suggest (a label, a catalog number, an alternate title).
The verdict, confidence and one-line reason are stored on the result so the UI can show
"why this result". A cheap lexical pre-filter keeps each call to ROW_LIMIT rows, and the
deterministic gate (hunt._stub_judge) remains the fallback when the model is off.
"""
import math
import urllib.parse

import hunt
from brain import llm, profile as prof

ROW_LIMIT = 25          # rows per LLM call (fits 8K ctx with the profile + system prompt)
MAX_BATCHES = 2         # at most 50 rows judged per strategy; the rest are pre-filter rejects
MIN_CONF = 0.5

SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {"type": "array", "items": {"type": "object", "properties": {
            "i": {"type": "integer"},
            "verdict": {"type": "string", "enum": ["exact", "variant", "related", "no"]},
            "confidence": {"type": "number"},
            "reason": {"type": "string"},
            "contradiction": {"type": "string"}},
            "required": ["i", "verdict", "confidence", "reason", "contradiction"]}},
        "leads": {"type": "array", "items": {"type": "object", "properties": {
            "query": {"type": "string"}, "why": {"type": "string"}},
            "required": ["query", "why"]}},
    },
    "required": ["verdicts", "leads"],
}

SYSTEM = (
    "You are the verification judge of a file-hunting agent. You get a TARGET PROFILE and a "
    "list of candidate rows found by one search. For EVERY row give a verdict:\n"
    "  exact   = this IS the target work (any acceptable edition/format/quality)\n"
    "  variant = the target's content under another title/edition/language/quality (counts as found)\n"
    "  related = same creator/series/label but a DIFFERENT work (does not count)\n"
    "  no      = unrelated, or a trailer/sample/making-of/review ABOUT the target, or a near-miss\n"
    "CALIBRATION — read carefully:\n"
    "- If a row's title names the target (its title or an alias) and nothing in the row "
    "contradicts the profile, the verdict is exact (or variant), NOT 'no'. Rejecting requires a "
    "CONCRETE contradiction visible in the row: a different work, an explicit 'trailer'/'making "
    "of'/'sample'/'remix', a different artist, an edition the user excluded. Write that "
    "contradiction in the contradiction field; leave it empty for exact/variant.\n"
    "- Do NOT invent facts the profile does not state (runtimes, sequels, 'third film', track "
    "counts, what a 'normal' size is). A 15-minute short film is 15 minutes; a compilation is "
    "'Various Artists' by nature; an album can be 300 MB or 3 GB.\n"
    "- The verdict depends ONLY on identity (is it the work, or something in ALSO COUNTS?) and "
    "the MUST HAVE list. Everything under PREFER (4K, FLAC, 24-bit, surround…) changes the "
    "confidence, never the verdict: a 1080p or mp3 copy of the target is 'variant' at 0.6-0.8. "
    "Streaming pages that name the work are 'variant' too. Never write a quality/format/"
    "resolution/language/hosting difference into contradiction — those are not contradictions.\n"
    "- A row matching an ALSO COUNTS entry (e.g. an album by one of the named creators when the "
    "user said such albums count) is 'variant' with high confidence.\n"
    "- Row kinds: 'torrent'/'usenet'/'file' are downloadable; 'page' is a web page that may "
    "host the file (judge by title, keep it if it names the target); 'dir' is a folder listing.\n"
    "- The USER'S OWN WORDS in the profile are authoritative about what counts as found.\n"
    "confidence is 0-1. reason is one short sentence.\n"
    "Then list up to 3 LEADS: NEW search queries these rows suggest (an alternate title, a "
    "release group, a catalog number, a label, a site worth searching) with why. No leads "
    "that merely repeat the target's name."
)


def _kind(r):
    if r.get("nzb_id"):
        return "usenet"
    if r.get("magnet") or r.get("torrent_url"):
        return "torrent"
    t = r.get("title") or ""
    if t.endswith("[open dir]"):
        return "dir"
    src = (r.get("source") or "")
    if src.startswith("Open dir"):
        return "file"
    return "page" if r.get("url") else "?"


def _human(n):
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%.0f%s" % (n, unit) if unit != "B" else "%dB" % n
        n /= 1024.0
    return "%.0fPB" % n


def _host(r):
    u = r.get("url") or r.get("torrent_url") or ""
    try:
        return urllib.parse.urlsplit(u).hostname or ""
    except Exception:
        return ""


def _row(i, r):
    seeds = r.get("seeders")
    return {"i": i, "title": (r.get("title") or "")[:140], "src": (r.get("source") or "")[:24],
            "kind": _kind(r), "size": _human(r.get("size")),
            "seeds": ("?" if seeds is None else int(seeds)), "date": (r.get("date") or "")[:10],
            "host": _host(r)[:40], "q": (r.get("quality") or "")[:12]}


import re as _re

_PREF_ONLY = _re.compile(
    r"(resolution|2160|4k|uhd|1080|720|818p|\bhd\b|quality|format|bitrate|flac|mp3|lossless|"
    r"24.?bit|stream|hosting|source is|language|french|subtitl|codec|x265|x264|surround|atmos|"
    r"size|mb\b|gb\b)", _re.I)


# A `reason` that itself states a contradiction (the model skipped the dedicated field).
_CONTRA_WORDS = _re.compile(
    r"\b(not (the|by|a|an|part|from|related|this|what)|isn.t|is not|does not|doesn.t|different|unrelated|"
    r"incorrect|wrong|mismatch|fails|excluded|other (artist|work|film|album)|remake|trailer|"
    r"making.of|sample|single track|review|documentary about)\b", _re.I)

_HARD_WORDS = _re.compile(r"\b(only|must|need|needs|required?|requirement|no less than|at least|minimum|"
                          r"not lower|nothing lower|strictly)\b", _re.I)


def _mentions_must(text, p):
    """Does the stated contradiction touch a GENUINE hard requirement? The model-built
    must_have list is not trusted for quality terms: '4K (2160p) master' lands in must_have
    whenever the user merely mentioned 4K. A quality/format item counts as hard only when the
    user's own words contain a hard-requirement marker (only / must / at least …)."""
    t = prof._fold(text)
    hard_user = bool(_HARD_WORDS.search(p.get("user_description") or ""))
    for m in p.get("must_have") or []:
        if _PREF_ONLY.search(m) and not hard_user:
            continue                        # a preference wearing a must_have badge
        for tok in prof._fold(m).split():
            if len(tok) >= 4 and tok in t:
                return True
    return False


_NAME_STOP = {"the", "a", "an", "of", "and", "or", "in", "on", "by", "for", "to", "open", "movie",
              "film", "album", "edition", "version", "release", "original", "official"}


def _name_tokens(s):
    """Distinctive words of a name: parentheticals, years and generic words dropped."""
    s = _re.sub(r"\([^)]*\)|\[[^\]]*\]", " ", s or "")
    toks = [x for x in _re.findall(r"[^\W_]+", prof._fold(s)) if len(x) >= 3]
    return [x for x in toks if x not in _NAME_STOP and not _re.fullmatch(r"(19|20)\d\d", x)]


def _names_target(title, p):
    """Does the title carry the target's name — the canonical title, an alias, or the goal's
    own distinctive words (≥75 % of them)? Used to catch verdicts that reject the very thing
    the user asked for."""
    t = prof._fold(title)
    tw = set(_re.findall(r"[^\W_]+", t))
    for n in [p.get("canonical_title", "")] + list(p.get("aliases", []) or []):
        toks = _name_tokens(n)
        if toks and all(x in tw or x in t for x in toks):
            return True
    g = _name_tokens(p.get("goal", ""))
    if g:
        hit = sum(1 for x in g if x in tw or x in t)
        if hit / float(len(g)) >= 0.75:
            return True
    return False


def prefilter(results, p, h):
    """Rows worth the model's time, best first: anything sharing a goal/alias/creator term
    or a crawl match score. If nothing shares a term (a foreign-title release the profile
    didn't anticipate) keep the first few so the model still gets a look."""
    gterms = hunt._goal_terms(h)
    pterms = prof.terms(p)
    scored = []
    for r in results:
        if not isinstance(r, dict):
            continue
        title = r.get("title") or ""
        rel = max(hunt._title_rel(title, gterms), hunt._title_rel(title, pterms) if pterms else 0.0)
        m = float(r.get("_match") or 0)
        if rel > 0 or m > 0:
            scored.append((rel + 0.5 * m, 1 if hunt._downloadable(r) else 0,
                           math.log10((r.get("seeders") or 0) + 1), r))
    scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
    keep = [x[3] for x in scored[:ROW_LIMIT * MAX_BATCHES]]
    if not keep:
        keep = [r for r in results if isinstance(r, dict)][:10]
    return keep


# The last call's rows + verdicts (all of them, rejects included) — for the eval harness's
# --debug view and for a future "why was this rejected" UI. Overwritten every call.
LAST = {}


def judge(strategy, results, h, p):
    """(matches, leads) or None if the model gave nothing usable (caller falls back)."""
    rows = prefilter(results, p, h)
    LAST.clear()
    LAST.update({"query": strategy.get("query", ""), "rows": len(rows), "verdicts": []})
    if not rows:
        return [], []
    matches, leads, any_ok = [], [], False
    for b in range(0, len(rows), ROW_LIMIT):
        batch = rows[b:b + ROW_LIMIT]
        listing = [_row(i, r) for i, r in enumerate(batch)]
        user = ("TARGET PROFILE:\n%s\n\nFOUND BY: %s (%s)\n\nCANDIDATE ROWS (JSON, one per line):\n%s"
                % (prof.render(p), strategy.get("query", "")[:120], strategy.get("method", ""),
                   "\n".join(__import__("json").dumps(x, ensure_ascii=False) for x in listing)))
        j = llm.call("judge", SYSTEM, user, SCHEMA)
        if not isinstance(j, dict):
            continue
        any_ok = True
        seen = set()
        for v in j.get("verdicts") or []:
            try:
                i = int(v.get("i"))
                conf = max(0.0, min(1.0, float(v.get("confidence", 0))))
            except (TypeError, ValueError):
                continue
            if i in seen or not (0 <= i < len(batch)):
                continue
            seen.add(i)
            verdict = str(v.get("verdict") or "no")
            contra = str(v.get("contradiction") or "").strip()
            reason = str(v.get("reason") or "").strip()
            if not contra and _CONTRA_WORDS.search(reason):
                contra = reason                 # the model put its contradiction in `reason`
            # Small-model false negatives on rows that carry the target's own title/alias:
            # (a) no contradiction stated ("this 'Third Open Movie' is not Sintel"), or
            # (b) a contradiction that is really a PREFERENCE (resolution, format, bitrate,
            #     language, "streaming page") — the user did not require it. Downgrade to a
            # low-confidence variant instead of losing the find; the results view ranks by
            # confidence so it sits below solid matches. A must_have contradiction stands.
            if verdict == "no" and _names_target(batch[i].get("title") or "", p) and (
                    not contra or (_PREF_ONLY.search(contra) and not _mentions_must(contra, p))):
                verdict, conf = "variant", min(conf, 0.5)
            LAST["verdicts"].append({"title": (batch[i].get("title") or "")[:120], "verdict": verdict,
                                     "confidence": round(conf, 2), "reason": str(v.get("reason") or "")[:160],
                                     "contradiction": contra[:120]})
            if verdict in ("exact", "variant") and conf >= MIN_CONF:
                r = dict(batch[i])
                r["_verdict"] = verdict
                r["_conf"] = round(conf, 2)
                r["_why"] = str(v.get("reason") or "")[:200]
                # relevance for the results-view ranking: the model's confidence, not the
                # lexical overlap (a variant title has little overlap and full confidence)
                r["_match"] = round(0.6 + 0.4 * conf if verdict == "exact" else 0.5 + 0.3 * conf, 3)
                matches.append(r)
        # Leads are cheap hints, not plans: cap them and score them BELOW planned strategies so
        # a stream of leads can't crowd the planner's source-aimed work out of the frontier.
        # Rows the model silently skipped (small models drop a row or two from a long list):
        # keep the ones that carry the target's own title as low-confidence variants rather
        # than losing them; anything else it skipped is treated as rejected.
        for i, r in enumerate(batch):
            if i in seen:
                continue
            if _names_target(r.get("title") or "", p):
                r = dict(r)
                r["_verdict"], r["_conf"] = "variant", 0.5
                r["_why"] = "no verdict returned for this row; kept because the title names the target"
                r["_match"] = 0.65
                matches.append(r)
                LAST["verdicts"].append({"title": (r.get("title") or "")[:120], "verdict": "variant",
                                         "confidence": 0.5, "reason": r["_why"], "contradiction": ""})
        for l in (j.get("leads") or [])[:2]:
            q = str((l or {}).get("query") or "").strip()
            if q:
                leads.append({"method": "search", "query": q[:200],
                              "why": "lead: " + str(l.get("why") or "")[:150], "score": 0.45})
    if not any_ok:
        return None
    return matches, leads
