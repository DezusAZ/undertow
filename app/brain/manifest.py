"""L2 — the SOURCE MANIFEST: what each source can do, and how it is doing.

The old brain could only say "search / dork / academic / pivot"; every strategy then
fanned out to whatever the hunt's category happened to allow (an "all" hunt reached six
adapters). Here every source declares its kind, query modes, what it delivers and a
one-line note the planner reads — so the planner can aim a strategy ("look up this DOI on
openalex", "host-scope wayback on host X", "github for the source tarball"), and the router
can run exactly that. Live health (registry breaker) and this hunt's yield per source are
folded into the catalog text the planner sees.

`route(source)` -> how the executor should run it:
  ("meta", category)   the full meta-search (Jackett + adapters + DHT + Usenet), scoped
  ("adapter", module)  one adapter directly (bypasses the hunt-category gating)
  ("dork",)            open-directory dorking via the discovery transports
  ("crawl",)           deep-crawl a directory/site tree (query must be a URL)
"""
# name -> declaration. `modes`: keyword | title | id | host | url. `delivers`: what a hit is.
SOURCES = {
    "trackers":  {"kind": "torrent", "route": ("meta", None), "modes": ["keyword", "title"],
                  "delivers": "magnet/torrent", "cats": "all",
                  "note": "100+ public torrent indexers via Jackett + Usenet + our DHT crawler; "
                          "scene-style titles (Group, year, quality tags) match best"},
    "usenet":    {"kind": "usenet", "route": ("meta", None), "modes": ["keyword", "title"],
                  "delivers": "nzb", "cats": "all",
                  "note": "Newznab Usenet indexer (part of the meta-search); good for recent "
                          "releases, weak for anything older than ~a decade"},
    "dht":       {"kind": "torrent", "route": ("adapter", "bitmagnet"), "modes": ["keyword"],
                  "delivers": "magnet", "cats": "all",
                  "note": "our own DHT crawl of live swarms — finds torrents on NO website; "
                          "short exact-ish keywords only"},
    "bt4g":      {"kind": "torrent", "route": ("adapter", "bt4g"), "modes": ["keyword"],
                  "delivers": "magnet", "cats": "all", "note": "BT4G torrent meta-index (no seed counts)"},
    "archive":   {"kind": "archive", "route": ("adapter", "internetarchive"), "modes": ["keyword", "title", "id"],
                  "delivers": "file/torrent", "cats": "all",
                  "note": "Internet Archive: public-domain/CC media, old software, live music, "
                          "scanned books; excellent for anything historical or out-of-print"},
    "annas":     {"kind": "books", "route": ("adapter", "annas"), "modes": ["title", "id"],
                  "delivers": "landing", "cats": "documents",
                  "note": "shadow-library book/paper meta-search by title/ISBN/DOI"},
    "openlib":   {"kind": "books", "route": ("adapter", "openlibrary"), "modes": ["title", "id"],
                  "delivers": "landing", "cats": "documents", "note": "Open Library editions (ISBN, scans on archive.org)"},
    "arxiv":     {"kind": "academic", "route": ("adapter", "arxiv"), "modes": ["keyword", "id"],
                  "delivers": "file", "cats": "documents", "note": "arXiv preprints (physics/CS/math); may be blocked from this exit"},
    "openalex":  {"kind": "academic", "route": ("adapter", "openalex"), "modes": ["title", "id"],
                  "delivers": "file", "cats": "documents", "note": "OpenAlex scholarly index with open-access PDF links; DOI/title lookups"},
    "pubmed":    {"kind": "academic", "route": ("adapter", "pubmed"), "modes": ["keyword"],
                  "delivers": "landing", "cats": "documents", "note": "biomedical literature"},
    "semsch":    {"kind": "academic", "route": ("adapter", "semanticscholar"), "modes": ["title"],
                  "delivers": "landing", "cats": "documents", "note": "Semantic Scholar (rate-limited)"},
    "doaj":      {"kind": "academic", "route": ("adapter", "doaj"), "modes": ["keyword"],
                  "delivers": "file", "cats": "documents", "note": "open-access journals"},
    "doab":      {"kind": "books", "route": ("adapter", "doab"), "modes": ["title"],
                  "delivers": "landing", "cats": "documents", "note": "open-access academic books"},
    "courts":    {"kind": "legal", "route": ("adapter", "courtlistener"), "modes": ["keyword"],
                  "delivers": "landing", "cats": "documents", "note": "US court opinions"},
    "ietf":      {"kind": "standards", "route": ("adapter", "ietf"), "modes": ["title", "id"],
                  "delivers": "file", "cats": "documents", "note": "RFCs / internet drafts by number or short title"},
    "sec":       {"kind": "filings", "route": ("adapter", "secedgar"), "modes": ["keyword"],
                  "delivers": "file", "cats": "documents", "note": "SEC EDGAR filings (company names)"},
    "ckan":      {"kind": "data", "route": ("adapter", "ckan"), "modes": ["keyword"],
                  "delivers": "file", "cats": "other", "note": "open-data portals (datasets)"},
    "github":    {"kind": "code", "route": ("adapter", "github"), "modes": ["keyword", "title"],
                  "delivers": "landing", "cats": "software", "note": "GitHub repositories (source, releases, mirrors of old software)"},
    "swh":       {"kind": "code", "route": ("adapter", "softwareheritage"), "modes": ["keyword", "url"],
                  "delivers": "landing", "cats": "software", "note": "Software Heritage archive of source code"},
    "hf":        {"kind": "data", "route": ("adapter", "huggingface"), "modes": ["keyword"],
                  "delivers": "landing", "cats": "software", "note": "Hugging Face models/datasets (single-word repo ids work best)"},
    "openrepos": {"kind": "data", "route": ("adapter", "openrepos"), "modes": ["keyword"],
                  "delivers": "file", "cats": "all", "note": "Zenodo / Wikimedia Commons / Openverse / Gutenberg / open repositories"},
    "nasa":      {"kind": "media", "route": ("adapter", "nasa"), "modes": ["keyword"],
                  "delivers": "file", "cats": "other", "note": "NASA image/video/audio library"},
    "peertube":  {"kind": "video", "route": ("adapter", "peertube"), "modes": ["keyword"],
                  "delivers": "landing", "cats": "movies", "note": "federated PeerTube video search"},
    "ccmixter":  {"kind": "music", "route": ("adapter", "ccmixter"), "modes": ["keyword"],
                  "delivers": "file", "cats": "music", "note": "Creative-Commons music (ccMixter)"},
    "opendir":   {"kind": "web", "route": ("dork",), "modes": ["keyword"],
                  "delivers": "dir", "cats": "all",
                  "note": "open-directory dorking (intitle:\"index of\" …) through the search "
                          "transports; finds autoindex folders to crawl — use distinctive 2-4 words"},
    "crawl":     {"kind": "web", "route": ("crawl",), "modes": ["url"],
                  "delivers": "file", "cats": "all",
                  "note": "deep-crawl a known open directory / site tree (query MUST be a URL)"},
    "wayback":   {"kind": "archive", "route": ("adapter", "wayback"), "modes": ["host"],
                  "delivers": "file", "cats": "all",
                  "note": "Wayback Machine CDX — lists archived FILES under a host (query = a hostname)"},
    "commoncrawl": {"kind": "archive", "route": ("adapter", "commoncrawl"), "modes": ["host"],
                    "delivers": "file", "cats": "all",
                    "note": "Common Crawl index — files under a host/domain (query = hostname or domain)"},
}

# The planner picks from these names; "all" = the meta-search with the hunt's category.
NAMES = ["all"] + sorted(SOURCES)
MODES = ["keyword", "title", "id", "host", "url"]


def route(source):
    d = SOURCES.get((source or "").lower())
    if not d:
        return ("meta", None)
    return d["route"]


def _health_map():
    try:
        import sources
        return {h["name"]: h for h in sources.health_report()}
    except Exception:
        return {}


def _adapter_name(module):
    try:
        import sources
        for a in sources.adapter_info():
            if a["module"] == module:
                return a["name"]
    except Exception:
        pass
    return module


def describe(h, max_chars=2600):
    """Prompt-ready catalog: one line per source with kind, modes, what it delivers, live
    health and THIS hunt's yield (tries→finds). Sources in cooldown are marked so the
    planner stops proposing them until they recover."""
    health = _health_map()
    ss = (h or {}).get("source_stats", {}) or {}
    lines = ["all — the full meta-search (trackers+usenet+dht+adapters) scoped to the hunt's "
             "category; modes: keyword/title"]
    for name, d in SOURCES.items():
        state = ""
        if d["route"][0] == "adapter":
            hh = health.get(_adapter_name(d["route"][1]))
            if hh and hh.get("state") == "cooldown":
                state = " [DOWN — skip]"
            elif hh and hh.get("state") == "degraded":
                state = " [flaky]"
        y = ss.get(name)
        yld = (" yield %d/%d" % (y.get("found", 0), y.get("tries", 0))) if y else ""
        lines.append("%s — %s; modes: %s; delivers: %s%s%s"
                     % (name, d["note"], "/".join(d["modes"]), d["delivers"], yld, state))
    return "\n".join(lines)[:max_chars]
