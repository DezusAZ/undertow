"""Optional local-AI features, powered by a local Ollama server.

OFF BY DEFAULT and fully degradable — Undertow works normally without it, so the
standalone app runs fine for anyone without a GPU. When ON, it adds:
  • Smart search — turn a natural-language request into optimized query + category.
  • Explain — a plain-English summary of any result.

Config lives in /config/ai.json (persisted, toggled from the UI):
  {"enabled": bool, "url": "http://<ollama-host>:11434", "model": "<model>"}

The app is VPN-locked; it reaches Ollama on the LAN (a private range the kill-switch
allows). Every call TIMES OUT and NEVER raises, so AI being slow or down can't break
or hang the app. stdlib only.
"""
import os
import json
import threading
import time
import urllib.request

AI_CONFIG_FILE = os.environ.get("AI_CONFIG_FILE", "/config/ai.json")
# On-demand GPU: the local AI is OFF (container stopped, 0 VRAM) between uses. Touching this
# file signals the watchdog (undertow-heal.sh) to spin ollama up; it's refreshed on every AI
# call and goes stale after WAKE_TTL, at which point the watchdog stops ollama again. So the
# GPU only runs while AI is actually being used — never idling in the background.
AI_WAKE_FILE = os.environ.get("AI_WAKE_FILE", "/config/.ai_wake")
AI_WAKE_TTL = int(os.environ.get("AI_WAKE_TTL", "900"))     # 15 min idle -> ollama auto-stops
_CATS = {"movies", "tv", "music", "documents", "software", "other"}
_lock = threading.Lock()
_cache = None
_cache_mtime = -1

_DEFAULTS = {
    "enabled": False,
    # No default server: local AI is opt-in, and a hardcoded LAN address would both be
    # wrong on someone else's network and disclose the packager's topology.
    "url": os.environ.get("OLLAMA_URL", ""),
    "model": os.environ.get("AI_MODEL", "mistral-7b:latest"),
}


def get_config():
    global _cache, _cache_mtime
    try:
        m = os.path.getmtime(AI_CONFIG_FILE)
    except OSError:
        m = 0
    with _lock:
        if _cache is not None and m == _cache_mtime:
            return dict(_cache)
    cfg = dict(_DEFAULTS)
    try:
        loaded = json.load(open(AI_CONFIG_FILE))
        if isinstance(loaded, dict):
            cfg.update({k: loaded[k] for k in ("enabled", "url", "model") if k in loaded})
    except Exception:
        pass
    with _lock:
        _cache, _cache_mtime = cfg, m
    return dict(cfg)


def set_config(patch):
    cfg = get_config()
    if "enabled" in patch:
        cfg["enabled"] = bool(patch["enabled"])
    for k in ("url", "model"):
        if patch.get(k):
            cfg[k] = str(patch[k]).strip()
    try:
        tmp = AI_CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, AI_CONFIG_FILE)
    except Exception:
        pass
    global _cache
    with _lock:
        _cache = None                 # force a reload next read
    return get_config()


def is_enabled():
    return bool(get_config().get("enabled"))


_warming = threading.Event()   # set while a background warm-up is loading the model into VRAM


def _reachable(cfg, t=3):
    try:
        urllib.request.urlopen(cfg["url"].rstrip("/") + "/api/tags", timeout=t)
        return True
    except Exception:
        return False


def is_loaded():
    """True when the configured model is actually resident in VRAM (ollama /api/ps) — the real
    'ready to answer instantly' signal. 'reachable' only means the container answers; the first
    query still pays the model-load cost (~60-90s from cold on the HDD), which is exactly what
    the warm-up below absorbs so the user's actual search is fast."""
    cfg = get_config()
    try:
        d = json.load(urllib.request.urlopen(cfg["url"].rstrip("/") + "/api/ps", timeout=3))
        want = cfg.get("model")
        return any(m.get("name") == want or m.get("model") == want
                   for m in d.get("models", []))
    except Exception:
        return False


def _warm_worker():
    """Load the model into VRAM with a throwaway 1-token generate. Runs server-side with a long
    timeout so the load COMPLETES even though the browser polls/reloads — a short client-side
    request would cancel the load mid-way and it'd never finish."""
    try:
        cfg = get_config()
        for _ in range(45):                 # wait up to ~90s for the watchdog to start ollama
            if _reachable(cfg):
                break
            time.sleep(2)
        else:
            return
        body = json.dumps({"model": cfg["model"], "prompt": " ", "stream": False,
                           "keep_alive": "30m", "options": {"num_predict": 1}}).encode()
        req = urllib.request.Request(cfg["url"].rstrip("/") + "/api/generate", body,
                                     {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=240)
    except Exception:
        pass
    finally:
        _warming.clear()


def wake():
    """Bring the local AI up on demand: touch the watchdog's wake file (so it starts/keeps
    ollama) and kick a one-shot background warm-up that loads the model into VRAM. Refreshed on
    every AI request; goes stale after WAKE_TTL -> watchdog stops ollama. Cheap, never raises."""
    try:
        with open(AI_WAKE_FILE, "w") as f:
            f.write(str(int(time.time())))
    except OSError:
        pass
    if is_enabled() and not _warming.is_set() and not is_loaded():
        _warming.set()
        threading.Thread(target=_warm_worker, daemon=True).start()


def wake_fresh():
    """True if AI was used within WAKE_TTL — mirrors the watchdog's own staleness check so the
    UI can tell 'starting on demand' from 'idle/asleep'."""
    try:
        return (time.time() - os.path.getmtime(AI_WAKE_FILE)) < AI_WAKE_TTL
    except OSError:
        return False


def status():
    """UI status: whether AI is on, the endpoint/model, whether Ollama answers, and a coarse
    lifecycle `state` for the on-demand GPU: off | ready | starting | idle.
    `ready` means the model is loaded in VRAM (answers instantly), NOT merely that the container
    is up — so the UI keeps showing 'warming up' through the model load, then flips to ready."""
    cfg = get_config()
    reachable, models, loaded = False, [], False
    try:
        d = json.load(urllib.request.urlopen(
            cfg["url"].rstrip("/") + "/api/tags", timeout=4))
        models = sorted(m.get("name", "") for m in d.get("models", []))
        reachable = True
    except Exception:
        pass
    if reachable:
        loaded = is_loaded()
    if not cfg.get("enabled"):
        state = "off"                       # feature disabled in the UI
    elif loaded:
        state = "ready"                     # model resident in VRAM -> answers instantly
    elif reachable or wake_fresh() or _warming.is_set():
        state = "starting"                  # container up / woken; model loading into VRAM
    else:
        state = "idle"                      # asleep; will auto-start on next AI use
    return {"enabled": bool(cfg.get("enabled")), "url": cfg.get("url"),
            "model": cfg.get("model"), "reachable": reachable, "loaded": loaded,
            "models": models, "state": state}


def _chat(system, user, timeout=45, want_json=False, options=None):
    """One-shot chat to Ollama; returns the text ("" on any error). Never raises.

    `options` passes Ollama sampling params (e.g. {"num_predict": 512}). A num_predict
    cap is IMPORTANT for open-ended generations — without it the model can decode until
    the socket times out and returns nothing usable."""
    cfg = get_config()
    if not cfg.get("enabled"):
        return ""
    wake()                       # refresh the keep-alive so ollama stays up while AI is in use
    body = {"model": cfg["model"], "stream": False, "keep_alive": "30m",
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]}
    if options:
        body["options"] = options
    if want_json:
        body["format"] = "json"
    try:
        req = urllib.request.Request(
            cfg["url"].rstrip("/") + "/api/chat",
            json.dumps(body).encode(), {"Content-Type": "application/json"})
        d = json.load(urllib.request.urlopen(req, timeout=timeout))
        return (d.get("message") or {}).get("content", "") or ""
    except Exception:
        return ""


def smart_query(text):
    """Natural language -> {query, category, ai}. Falls back to the raw text (ai=False)
    if AI is off or unavailable, so search always still runs."""
    text = (text or "").strip()
    if not text or not is_enabled():
        return {"query": text, "category": "all", "ai": False}
    system = (
        "You convert a natural-language request to FIND media or files into a compact "
        "JSON object with two keys:\n"
        "- \"query\": a single string of the best 2-5 search keywords (a plain string, "
        "NOT a list; drop filler words like 'find me', 'obscure', 'around').\n"
        "- \"category\": exactly one of movies, tv, music, documents, software, other. "
        "Use these meanings: movies = any film INCLUDING documentaries; tv = series/"
        "episodes; music = songs/albums/audio; documents = text files, papers, books, "
        "PDFs; software = apps/code/datasets. Reply with ONLY the JSON object.")
    out = _chat(system, text, timeout=45, want_json=True)
    try:
        j = json.loads(out)
        q = j.get("query") or text
        if isinstance(q, list):                # some models return keywords as a list
            q = " ".join(str(x) for x in q)
        q = str(q).strip()
        c = str(j.get("category") or "all").strip().lower()
        return {"query": q or text, "category": (c if c in _CATS else "all"), "ai": True}
    except Exception:
        return {"query": text, "category": "all", "ai": False}


def explain(title, context=""):
    """A short plain-English explanation of a result ("" if AI off/unavailable)."""
    if not is_enabled() or not (title or context):
        return ""
    system = ("You are a concise librarian. In 2-3 sentences of plain English, say what "
              "this item is and why someone might want it. No preamble, no markdown.")
    return _chat(system, ("Title: " + str(title) + "\n" + str(context)).strip(),
                 timeout=60).strip()
