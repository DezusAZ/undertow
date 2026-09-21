"""Optional local-AI features, powered by a local Ollama server.

OFF BY DEFAULT and fully degradable — Undertow works normally without it, so the
standalone app runs fine for anyone without a GPU. When ON, it adds:
  • Smart search — turn a natural-language request into optimized query + category.
  • Explain — a plain-English summary of any result.
  • The Deep Hunt brain (hunt_brain / brain package) — built on _chat / chat_json below.

Config lives in /config/ai.json (persisted, toggled from the UI):
  {"enabled": bool, "url": "http://<ollama-host>:11434", "model": "<model>"}

The app is VPN-locked; the kill-switch exempts EXACTLY ONE LAN host from the tunnel: the
Ollama server, as a /32, and only if it is a private address (see entrypoint.sh ai_host()
and _ensure_route() here). Every call TIMES OUT and NEVER raises, so AI being slow or down
can't break or hang the app. Every call is COUNTED (stats()) so the UI can tell "the model
answered" from "silently fell back". stdlib only.
"""
import os
import re
import json
import ipaddress
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

AI_CONFIG_FILE = os.environ.get("AI_CONFIG_FILE", "/config/ai.json")
# On-demand GPU: the local AI is OFF (container stopped, 0 VRAM) between uses. Touching this
# file signals the watchdog (undertow-heal.sh) to spin ollama up; it's refreshed on every AI
# call and goes stale after WAKE_TTL, at which point the watchdog stops ollama again. So the
# GPU only runs while AI is actually being used — never idling in the background.
AI_WAKE_FILE = os.environ.get("AI_WAKE_FILE", "/config/.ai_wake")
AI_WAKE_TTL = int(os.environ.get("AI_WAKE_TTL", "900"))     # 15 min idle -> ollama auto-stops
# Context window for every call. Ollama's per-model default is small (2-4K) and it truncates
# the FRONT of an over-long prompt — i.e. the system prompt — silently. 8K holds the hunt
# brain's biggest prompt (profile + journal + 25 structured rows) with room to spare.
NUM_CTX = int(os.environ.get("AI_NUM_CTX", "8192"))
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

# Model families that emit a "thinking" phase. For those we pass think=false on the hot
# path (judging, planning) — reasoning tokens would otherwise eat the num_predict budget
# and, on older Ollama builds, break schema-constrained output entirely.
_THINKING_FAMILIES = ("qwen3", "deepseek-r1", "gemma4", "gpt-oss", "magistral", "qwq")


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


def _private_v4(url):
    """The IPv4 of `url`'s host if it is a PRIVATE (RFC1918 / CGNAT) address, else None.
    A public Ollama host is never exempted from the tunnel (that would leak the real IP)."""
    try:
        h = urllib.parse.urlsplit(url).hostname or ""
        ip = ipaddress.ip_address(socket.gethostbyname(h))
        if ip.version == 4 and not ip.is_loopback and (
                ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10")):
            return str(ip)
    except Exception:
        pass
    return None


def _ensure_route(url):
    """Mirror of entrypoint.sh ai_host(): when the Ollama URL is changed from the UI, point
    the kill-switch's single /32 routing exception at the new host (priority 990, below
    wg-quick's 999 catch-all). Old exceptions at that priority are dropped first so exactly
    one host is ever exempt. No-op outside the container / without NET_ADMIN. Never raises."""
    ip = _private_v4(url or "")
    try:
        # drop whatever was exempt before (loop: `ip rule del` removes one rule per call)
        for _ in range(8):
            r = subprocess.run(["ip", "rule", "del", "priority", "990"],
                               capture_output=True, timeout=5)
            if r.returncode != 0:
                break
        if ip:
            subprocess.run(["ip", "rule", "add", "to", ip + "/32", "lookup", "main",
                            "priority", "990"], capture_output=True, timeout=5)
    except Exception:
        pass


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
    if patch.get("url"):
        _ensure_route(cfg["url"])
    return get_config()


def is_enabled():
    return bool(get_config().get("enabled"))


def model_thinks(name=None):
    """True if the (configured) model belongs to a family with a thinking phase."""
    n = (name or get_config().get("model") or "").lower()
    return any(f in n for f in _THINKING_FAMILIES)


# ---------------------------------------------------------------------------- call stats
# Proof of life for the UI: how many calls actually got a model answer vs failed, the last
# error text, and latency. brain_status() reads this so "AI active" can't be claimed while
# every call is silently timing out (the failure mode that hid a 32-day outage).
_stats_lock = threading.Lock()
_stats = {"calls": 0, "ok": 0, "fail": 0, "last_error": "", "last_latency_s": None,
          "last_ok_ts": 0, "last_fail_ts": 0, "tokens_in": 0, "tokens_out": 0}


def _note(ok, latency=None, err="", tok_in=0, tok_out=0):
    with _stats_lock:
        _stats["calls"] += 1
        if ok:
            _stats["ok"] += 1
            _stats["last_ok_ts"] = int(time.time())
            _stats["last_error"] = ""
        else:
            _stats["fail"] += 1
            _stats["last_fail_ts"] = int(time.time())
            _stats["last_error"] = (err or "")[:200]
        if latency is not None:
            _stats["last_latency_s"] = round(latency, 1)
        _stats["tokens_in"] += int(tok_in or 0)
        _stats["tokens_out"] += int(tok_out or 0)


def stats():
    with _stats_lock:
        return dict(_stats)


_warming = threading.Event()   # set while a background warm-up is loading the model into VRAM


def _wait_reachable(cfg, seconds):
    """Block until the on-demand AI answers, or `seconds` elapse. Returns True if up."""
    deadline = time.time() + max(0, seconds)
    while time.time() < deadline:
        if _reachable(cfg):
            return True
        time.sleep(3)
    return False


_reach_cache = {"ts": 0.0, "ok": False, "url": ""}


def _reachable(cfg, t=3):
    try:
        urllib.request.urlopen(cfg["url"].rstrip("/") + "/api/tags", timeout=t)
        return True
    except Exception:
        return False


def reachable_cached(ttl=15):
    """Reachability with a short cache, for UI polls (a 4 s poll must not probe every time)."""
    cfg = get_config()
    now = time.time()
    if (_reach_cache["url"] == cfg.get("url") and now - _reach_cache["ts"] < ttl):
        return _reach_cache["ok"]
    ok = bool(cfg.get("url")) and _reachable(cfg, 2)
    _reach_cache.update(ts=now, ok=ok, url=cfg.get("url"))
    return ok


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
    reachable, models, loaded, version = False, [], False, ""
    try:
        d = json.load(urllib.request.urlopen(
            cfg["url"].rstrip("/") + "/api/tags", timeout=4))
        models = sorted(m.get("name", "") for m in d.get("models", []))
        reachable = True
    except Exception:
        pass
    if reachable:
        loaded = is_loaded()
        try:
            version = json.load(urllib.request.urlopen(
                cfg["url"].rstrip("/") + "/api/version", timeout=3)).get("version", "")
        except Exception:
            pass
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
            "models": models, "state": state, "version": version,
            "model_installed": (cfg.get("model") in models) if reachable else None,
            "thinking_model": model_thinks(cfg.get("model")), "num_ctx": NUM_CTX,
            "stats": stats()}


def _chat(system, user, timeout=45, want_json=False, options=None, schema=None, think=None,
          messages=None):
    """One-shot chat to Ollama; returns the text ("" on any error). Never raises.

    `options` passes Ollama sampling params (e.g. {"num_predict": 512}). A num_predict
    cap is IMPORTANT for open-ended generations — without it the model can decode until
    the socket times out and returns nothing usable.
    `schema`   — a JSON schema dict: the server constrains the output to it (Ollama >= 0.5).
    `think`    — False/True for thinking-family models (ignored by others; if the server
                 rejects the field the call is retried once without it).
    `messages` — a full message list (multi-turn) instead of system+user."""
    cfg = get_config()
    if not cfg.get("enabled"):
        return ""
    wake()                       # refresh the keep-alive so ollama stays up while AI is in use
    opts = {"num_ctx": NUM_CTX}
    if options:
        opts.update(options)
    body = {"model": cfg["model"], "stream": False, "keep_alive": "30m", "options": opts,
            "messages": messages or [{"role": "system", "content": system},
                                     {"role": "user", "content": user}]}
    if schema is not None:
        body["format"] = schema
    elif want_json:
        body["format"] = "json"
    if think is not None:
        body["think"] = bool(think)

    def _try(t):
        req = urllib.request.Request(
            cfg["url"].rstrip("/") + "/api/chat",
            json.dumps(body).encode(), {"Content-Type": "application/json"})
        t0 = time.time()
        d = json.load(urllib.request.urlopen(req, timeout=t))
        txt = (d.get("message") or {}).get("content", "") or ""
        _note(True, time.time() - t0, tok_in=d.get("prompt_eval_count"),
              tok_out=d.get("eval_count"))
        return txt

    def _http_err_text(e):
        try:
            return (e.read() or b"")[:200].decode("utf-8", "replace")
        except Exception:
            return ""

    try:
        return _try(timeout)
    except urllib.error.HTTPError as e:
        msg = _http_err_text(e)
        # An Ollama build (or model) without thinking support rejects the field -> retry bare.
        if "think" in body and "think" in msg.lower():
            body.pop("think", None)
            try:
                return _try(timeout)
            except Exception as e2:
                _note(False, err="HTTP retry: %s" % (str(e2)[:120]))
                return ""
        _note(False, err="HTTP %s: %s" % (e.code, msg))
        return ""                # the server answered — waiting for it would not help
    except Exception as e:
        first = str(e)[:120] or type(e).__name__
    # The local AI is started ON DEMAND: it shuts down after ~15 min idle to keep the GPU
    # cold, and the watchdog only notices the wake() above on its next ~15s cycle. So the
    # FIRST request after an idle period always hit a dead server and returned "" — which
    # the UI rendered as nothing happening at all. Wait for it to come up, then retry once.
    # (Only when it is genuinely unreachable: a reachable server that timed out is retried
    # immediately — its model is now loaded, which was usually the slow part.)
    if not _reachable(cfg) and not _wait_reachable(cfg, 75):
        _note(False, err="unreachable: " + first)
        return ""
    try:
        return _try(timeout)
    except Exception as e:
        _note(False, err=str(e)[:160] or type(e).__name__)
        return ""


def chat_json(system, user, schema, timeout=90, options=None, think=None, messages=None):
    """Schema-constrained call parsed to a dict/list; None if the model gave nothing usable.
    Falls back to the first {...} block in the text when the server ignored the schema."""
    txt = _chat(system, user, timeout=timeout, options=options, schema=schema, think=think,
                messages=messages)
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        pass
    m = re.search(r"\{.*\}", txt, re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


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
    schema = {"type": "object",
              "properties": {"query": {"type": "string"},
                             "category": {"type": "string", "enum": sorted(_CATS)}},
              "required": ["query", "category"]}
    # cold start: the model may still be loading (60-90 s from disk) -> a generous timeout
    j = chat_json(system, text, schema, timeout=120, options={"num_predict": 80},
                  think=False if model_thinks() else None)
    try:
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
                 timeout=120, options={"num_predict": 160},
                 think=False if model_thinks() else None).strip()
