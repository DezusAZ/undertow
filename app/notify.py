"""notify.py — outbound notifications when a Deep Hunt surfaces new results (or a test ping).

The whole value of a background hunt is that it runs while you're away — so it has to be able
to REACH you when it finds a hard-to-find file. Sends via ntfy / a generic webhook / Telegram,
over the VPN egress, to PUBLIC hosts only (reuses discover.py's pinned SSRF-safe opener, so a
notification target can never be used to poke the LAN / loopback / cloud metadata). Config lives
in /config/notify.json. Per-hunt debounced so a hunt that trickles finds can't spam you.

stdlib only; never raises out of the public helpers.
"""
import os
import json
import time
import threading
import urllib.parse
import urllib.request

import discover

CONFIG_PATH = os.environ.get("NOTIFY_CONFIG", "/config/notify.json")
_MIN_INTERVAL = int(os.environ.get("NOTIFY_MIN_INTERVAL", "120"))   # per-hunt debounce (seconds)
_lock = threading.Lock()
_state = {}                                                          # hunt_id -> {last, pending, shown}


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            c = json.load(f)
        return c if isinstance(c, dict) else {}
    except Exception:
        return {}


def save_config(cfg):
    """Persist config (merging over what's there so a UI save can't wipe the token by omission)."""
    cur = load_config()
    cur.update({k: v for k, v in (cfg or {}).items() if v is not None})
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cur, f)
    os.replace(tmp, CONFIG_PATH)
    return public_config()


def public_config():
    """Config shaped for the UI — secrets are never sent to the browser, only whether they're set."""
    c = load_config()
    return {"enabled": bool(c.get("enabled")), "kind": (c.get("kind") or "ntfy"),
            "ntfy_url": c.get("ntfy_url", ""), "webhook_url": c.get("webhook_url", ""),
            "telegram_chat": c.get("telegram_chat", ""),
            "has_telegram_token": bool(c.get("telegram_token"))}


def _post(url, data=None, headers=None, timeout=12):
    """SSRF-safe POST via the pinned opener (public host, IP-pinned, redirects re-validated).
    HTTP(S) only — reject file://, ftp://, data:// etc. which would bypass the IP-pin and could
    read a local file or reach a LAN service."""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("unsupported url scheme (http/https only)")
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    with discover._SAFE_OPENER.open(req, timeout=timeout) as resp:
        return 200 <= getattr(resp, "status", 200) < 300


def send(title, message, cfg=None):
    """Send ONE notification via the configured channel. Returns (ok: bool, detail: str)."""
    cfg = cfg or load_config()
    kind = (cfg.get("kind") or "ntfy").lower()
    try:
        if kind == "ntfy":
            url = (cfg.get("ntfy_url") or "").strip()
            if not url:
                return False, "no ntfy topic/url set"
            if "://" not in url:
                url = "https://ntfy.sh/" + url.lstrip("/")     # bare topic -> ntfy.sh
            _post(url, data=message.encode("utf-8"),
                  headers={"Title": title, "Content-Type": "text/plain; charset=utf-8"})
            return True, "sent"
        if kind == "webhook":
            url = (cfg.get("webhook_url") or "").strip()
            if not url:
                return False, "no webhook url set"
            _post(url, data=json.dumps({"title": title, "message": message}).encode(),
                  headers={"Content-Type": "application/json"})
            return True, "sent"
        if kind == "telegram":
            tok = (cfg.get("telegram_token") or "").strip()
            chat = (cfg.get("telegram_chat") or "").strip()
            if not tok or not chat:
                return False, "telegram token/chat not set"
            _post("https://api.telegram.org/bot%s/sendMessage" % urllib.parse.quote(tok),
                  data=urllib.parse.urlencode({"chat_id": chat, "text": title + "\n" + message}).encode(),
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
            return True, "sent"
        return False, "unknown channel '%s'" % kind
    except Exception as e:
        return False, str(e)[:200]


def send_test():
    cfg = load_config()
    if not cfg.get("kind"):
        return False, "pick a channel first"
    return send("🔔 Undertow test", "If you can read this, hunt notifications are working.", cfg)


def _compose(goal, pending, shown):
    plural = "" if pending == 1 else "s"
    title = "🎯 Undertow: %d new find%s" % (pending, plural)
    msg = "Hunt “%s” found %d new result%s.%s" % (
        goal, pending, plural,
        ("\n• " + "\n• ".join((t or "")[:90] for t in shown)) if shown else "")
    return title, msg


def _flush(hid):
    """Trailing-edge send: fire the accumulated finds even if NO later find arrives (otherwise
    the last batch before a hunt goes quiet would sit in 'pending' forever). Never raises."""
    try:
        cfg = load_config()
        with _lock:
            st = _state.get(hid)
            if not st:
                return
            st["timer"] = None
            pending, shown, goal = st["pending"], st["shown"][:3], st.get("goal", "your hunt")
            st["last"], st["pending"], st["shown"] = time.time(), 0, []
        if cfg.get("enabled") and pending > 0:
            title, msg = _compose(goal, pending, shown)
            send(title, msg, cfg)
    except Exception:
        pass


def notify_hunt(h, new_count, titles):
    """Called by the hunt worker when new results were recorded. Debounced per hunt so a hunt
    that trickles finds doesn't spam — the FIRST find pings immediately, further finds inside the
    window accumulate and go out as one summary (via a trailing flush timer, so they're never
    stranded). Never raises."""
    try:
        cfg = load_config()
        if not cfg.get("enabled") or not new_count or new_count <= 0:
            return
        hid = (h.get("id") if isinstance(h, dict) else str(h)) or "?"
        goal = ((h.get("goal") if isinstance(h, dict) else "") or "your hunt")[:80]
        now = time.time()
        do_send = False
        with _lock:
            st = _state.setdefault(hid, {"last": 0.0, "pending": 0, "shown": [],
                                         "timer": None, "goal": goal})
            st["goal"] = goal
            st["pending"] += int(new_count)
            for t in (titles or []):
                if t and t not in st["shown"] and len(st["shown"]) < 3:
                    st["shown"].append(t)
            if now - st["last"] < _MIN_INTERVAL:
                if not st.get("timer"):                         # arm a one-shot trailing flush
                    tm = threading.Timer(max(1.0, _MIN_INTERVAL - (now - st["last"])),
                                         _flush, args=(hid,))
                    tm.daemon = True
                    st["timer"] = tm
                    tm.start()
                return
            pending, shown = st["pending"], st["shown"][:3]     # window elapsed -> send now
            st["last"], st["pending"], st["shown"] = now, 0, []
            if st.get("timer"):
                try: st["timer"].cancel()
                except Exception: pass
                st["timer"] = None
            do_send = True
        if do_send:
            title, msg = _compose(goal, pending, shown)
            send(title, msg, cfg)
    except Exception:
        pass
