"""Debrid integration — Real-Debrid / TorBox.

A debrid service keeps a huge library of already-downloaded torrents on its own
high-speed servers. When you "grab" a magnet and debrid is enabled, we hand the magnet
to the service instead of joining the swarm ourselves:
  * cached      -> it becomes an instant high-speed HTTPS download,
  * not cached  -> the service fetches it on THEIR servers and gives us a direct link
                   when ready.
Either way WE only ever pull a finished file over HTTP (through fetcher.py). We never
join the BitTorrent swarm and never seed — which is strictly more download-only than our
own libtorrent path. The debrid CDN is a public host, so fetcher's public-host SSRF guard
passes and the pull exits through the Proton tunnel like every other request.

SECURITY
  * The API key is a SECRET. It lives server-side in /config/debrid.json and is NEVER sent
    to the browser: get_config() returns only whether a key is set + its last 4 chars.
  * Every provider call goes out through the VPN-locked container (so through the tunnel).
  * Dormant until a key is saved in Settings; active() is False with no key.

stdlib only. Nothing here ever runs a downloaded file; it only resolves direct links and
hands the URL to the direct-download engine (which has its own size/space/host guards).
"""
import os
import json
import time
import threading
import urllib.parse
import urllib.request
import urllib.error

CFG_FILE = os.environ.get("DEBRID_CONFIG_FILE", "/config/debrid.json")
_UA = "vpntorrent"

# provider ids
RD = "realdebrid"
TB = "torbox"
PROVIDERS = (RD, TB)

_DEFAULTS = {
    "enabled": False,     # master switch
    "provider": "",       # "" | realdebrid | torbox
    "key": "",            # API token (secret; never leaves the server)
    "auto": True,         # when active, magnet grabs route through debrid (fallback to libtorrent)
}

_lock = threading.Lock()
_cache = None
_cache_mtime = 0
_fetch_add = None         # injected hook: fetcher.add(url, cat, name) -> job id
_vpn_ok = lambda: True    # injected hook: the live VPN gate


# ---- config (secret-safe) --------------------------------------------------------------
def _read():
    cfg = dict(_DEFAULTS)
    try:
        loaded = json.load(open(CFG_FILE))
        if isinstance(loaded, dict):
            for k in _DEFAULTS:
                if k in loaded:
                    cfg[k] = loaded[k]
    except Exception:
        pass
    # normalise
    cfg["enabled"] = bool(cfg.get("enabled"))
    cfg["auto"] = bool(cfg.get("auto", True))
    cfg["provider"] = cfg["provider"] if cfg.get("provider") in PROVIDERS else ""
    cfg["key"] = str(cfg.get("key") or "").strip()
    return cfg


def _load():
    """Full config INCLUDING the raw key — server-side use only. Cached by mtime."""
    global _cache, _cache_mtime
    try:
        m = os.path.getmtime(CFG_FILE)
    except OSError:
        m = 0
    with _lock:
        if _cache is not None and m == _cache_mtime:
            return dict(_cache)
    cfg = _read()
    with _lock:
        _cache, _cache_mtime = cfg, m
    return dict(cfg)


def active():
    """True when debrid is enabled AND has a provider+key — i.e. grabs should route to it."""
    c = _load()
    return bool(c["enabled"] and c["provider"] and c["key"])


def auto_on():
    c = _load()
    return bool(c["enabled"] and c["provider"] and c["key"] and c["auto"])


def get_config():
    """UI-safe view: the key itself is NEVER returned — only whether one is set + last 4."""
    c = _load()
    key = c["key"]
    return {
        "enabled": c["enabled"],
        "provider": c["provider"],
        "auto": c["auto"],
        "has_key": bool(key),
        "key_hint": ("…" + key[-4:]) if len(key) >= 4 else ("set" if key else ""),
        "active": active(),
        "providers": [{"id": RD, "name": "Real-Debrid"}, {"id": TB, "name": "TorBox"}],
    }


def set_config(patch):
    """Apply a settings patch and persist atomically. A blank 'key' leaves the stored key
    untouched (the UI never receives it, so it can't echo it back); send key='' with
    clear_key=True to actually remove it."""
    cfg = _load()
    if "enabled" in patch:
        cfg["enabled"] = bool(patch["enabled"])
    if "auto" in patch:
        cfg["auto"] = bool(patch["auto"])
    if patch.get("provider") in PROVIDERS:
        cfg["provider"] = patch["provider"]
    elif patch.get("provider") == "":
        cfg["provider"] = ""
    if patch.get("clear_key"):
        cfg["key"] = ""
    elif str(patch.get("key") or "").strip():
        cfg["key"] = str(patch["key"]).strip()
    try:
        tmp = CFG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CFG_FILE)
        try:
            os.chmod(CFG_FILE, 0o600)        # it holds a token — keep it tight
        except OSError:
            pass
    except Exception:
        pass
    global _cache
    with _lock:
        _cache = None
    return get_config()


# ---- HTTP helpers ----------------------------------------------------------------------
def _req(method, url, key, data=None, form=None, timeout=20):
    headers = {"User-Agent": _UA, "Authorization": "Bearer " + key}
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        body = data
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(2 * 1024 * 1024)
    try:
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _infohash(magnet):
    """btih (lowercase hex) from a magnet URI, or ''."""
    try:
        for xt in urllib.parse.parse_qs(urllib.parse.urlsplit(magnet).query).get("xt", []):
            if xt.lower().startswith("urn:btih:"):
                h = xt.split(":")[-1].strip().lower()
                if len(h) == 40:
                    return h
                # base32 (32 chars) -> leave as-is; providers accept the full magnet anyway
                return h
    except Exception:
        pass
    return ""


# ---- Real-Debrid -----------------------------------------------------------------------
_RD = "https://api.real-debrid.com/rest/1.0"


def _rd_submit(magnet, key):
    """Add magnet, select all files, return the RD torrent id."""
    r = _req("POST", _RD + "/torrents/addMagnet", key, form={"magnet": magnet}, timeout=20)
    tid = r.get("id")
    if not tid:
        raise RuntimeError("real-debrid did not accept the magnet")
    try:
        _req("POST", _RD + "/torrents/selectFiles/" + str(tid), key,
             form={"files": "all"}, timeout=20)
    except Exception:
        pass            # already selected / some files unavailable — info() still progresses
    return str(tid)


def _rd_links_when_ready(tid, key, deadline):
    """Poll RD torrent info; when downloaded, unrestrict each link to a direct URL.
    Returns [(direct_url, filename, size_bytes), ...]."""
    while time.time() < deadline:
        info = _req("GET", _RD + "/torrents/info/" + tid, key, timeout=20)
        status = (info.get("status") or "").lower()
        if status == "downloaded":
            out = []
            for link in (info.get("links") or []):
                try:
                    u = _req("POST", _RD + "/unrestrict/link", key,
                             form={"link": link}, timeout=25)
                    dl = u.get("download")
                    if dl:
                        out.append((dl, u.get("filename") or "", int(u.get("filesize") or 0)))
                except Exception:
                    pass
            return out
        if status in ("error", "magnet_error", "virus", "dead"):
            raise RuntimeError("real-debrid status: " + status)
        time.sleep(4)
    raise RuntimeError("real-debrid timed out before the torrent was ready")


def _rd_cached(hashes, key):
    """Best effort. RD deprecated /torrents/instantAvailability (now returns nothing useful),
    so we honestly report 'unknown' rather than promise a badge we can't back."""
    return {h: None for h in hashes}


# ---- TorBox ----------------------------------------------------------------------------
_TB = "https://api.torbox.app/v1/api"


def _tb_submit(magnet, key):
    # seed="3" = NEVER seed. Undertow is strictly download-only; we must not let the debrid
    # side seed on the user's behalf either (seed="1" is auto, which can seed). allow_zip off
    # so we get individual file links to hand to the fetcher, not a bundled zip.
    r = _req("POST", _TB + "/torrents/createtorrent", key,
             form={"magnet": magnet, "seed": "3", "allow_zip": "false"}, timeout=25)
    if not r.get("success") and r.get("error"):
        raise RuntimeError("torbox: " + str(r.get("detail") or r.get("error")))
    d = r.get("data") or {}
    tid = d.get("torrent_id") or d.get("id")
    if tid is None:
        raise RuntimeError("torbox did not return a torrent id")
    return str(tid)


def _tb_links_when_ready(tid, key, deadline):
    while time.time() < deadline:
        r = _req("GET", _TB + "/torrents/mylist?id=" + tid + "&bypass_cache=true", key, timeout=20)
        d = r.get("data")
        if isinstance(d, list):
            d = d[0] if d else {}
        d = d or {}
        ready = bool(d.get("download_present")) or (d.get("download_state") in ("completed", "uploading", "cached"))
        files = d.get("files") or []
        if ready and files:
            out = []
            for f in files:
                fid = f.get("id")
                if fid is None:
                    continue
                try:
                    rr = _req("GET", _TB + "/torrents/requestdl?token=" + urllib.parse.quote(key)
                              + "&torrent_id=" + tid + "&file_id=" + str(fid) + "&redirect=false",
                              key, timeout=20)
                    rd = rr.get("data")
                    dl = rd if isinstance(rd, str) else (rd.get("url") if isinstance(rd, dict) else None)
                    if dl:
                        out.append((dl, f.get("short_name") or f.get("name") or "",
                                    int(f.get("size") or 0)))
                except Exception:
                    pass
            if out:
                return out
        if d.get("download_state") in ("error", "failed"):
            raise RuntimeError("torbox download failed")
        time.sleep(4)
    raise RuntimeError("torbox timed out before the torrent was ready")


def _tb_cached(hashes, key):
    out = {h: None for h in hashes}
    if not hashes:
        return out
    try:
        q = "&".join("hash=" + h for h in hashes)
        r = _req("GET", _TB + "/torrents/checkcached?" + q + "&format=object&list_files=false",
                 key, timeout=12)
        data = r.get("data") or {}
        if isinstance(data, dict):
            for h in hashes:
                out[h] = bool(data.get(h))
    except Exception:
        pass
    return out


# ---- public API ------------------------------------------------------------------------
def start(fetch_add=None, vpn_check=None):
    """Inject the fetcher hand-off + VPN gate. Call once at startup."""
    global _fetch_add, _vpn_ok
    if fetch_add is not None:
        _fetch_add = fetch_add
    if vpn_check is not None:
        _vpn_ok = vpn_check


def check_cached(magnets):
    """Map {magnet -> True/False/None} for result badging. None = unknown (no badge).
    Only TorBox supports a reliable cached check; RD returns unknown by design."""
    c = _load()
    if not active():
        return {m: None for m in magnets}
    by_hash = {}
    for m in magnets:
        h = _infohash(m)
        if h and len(h) == 40:
            by_hash.setdefault(h, []).append(m)
    hashes = list(by_hash)
    if c["provider"] == TB:
        res = _tb_cached(hashes, c["key"])
    else:
        res = _rd_cached(hashes, c["key"])
    out = {m: None for m in magnets}
    for h, ms in by_hash.items():
        for m in ms:
            out[m] = res.get(h)
    return out


# active debrid submissions, surfaced to the UI as a lightweight status line
_pending = {}
_plock = threading.Lock()
_PENDING_KEEP = 30


def _set_pending(pid, **kw):
    with _plock:
        j = _pending.setdefault(pid, {"id": pid, "added": time.time()})
        j.update(kw)
        # trim finished
        done = [k for k, v in _pending.items() if v.get("state") in ("done", "failed")]
        while len(done) > _PENDING_KEEP:
            _pending.pop(done.pop(0), None)


def pending():
    with _plock:
        return sorted(_pending.values(), key=lambda j: j.get("added", 0), reverse=True)


def submit(magnet, cat="other", name=None, max_wait=600):
    """Hand a magnet to the active debrid provider. Returns immediately with a status dict;
    the (possibly slow) resolve+handoff runs in the background and lands in the normal
    download list via fetcher once the provider has the file. Raises if debrid isn't active
    or the initial add is rejected."""
    c = _load()
    if not active():
        raise RuntimeError("debrid not configured")
    if _fetch_add is None:
        raise RuntimeError("download engine unavailable")
    provider, key = c["provider"], c["key"]
    # Cap concurrent in-flight resolves: each spawns a thread that polls for up to max_wait.
    # Without a cap, an authenticated user spamming grabs could pile up polling threads
    # (self-DoS on their own box). This bounds it cheaply.
    with _plock:
        inflight = sum(1 for v in _pending.values()
                       if v.get("state") in ("submitting", "caching"))
    if inflight >= 20:
        raise RuntimeError("too many debrid transfers resolving at once — wait a moment")
    pid = "db-%x-%s" % (int(time.time() * 1000), os.urandom(2).hex())
    _set_pending(pid, provider=provider, name=(name or magnet[:60]), cat=cat,
                 state="submitting")
    # The initial add is quick; do it inline so a rejected magnet errors to the user now.
    if provider == RD:
        tid = _rd_submit(magnet, key)
    else:
        tid = _tb_submit(magnet, key)
    _set_pending(pid, state="caching", tid=tid)

    def _bg():
        # This thread polls the provider API and then hands links to the fetcher. It runs
        # inside the kill-switched container (OUTPUT DROP except via wg), so even if the VPN
        # drops mid-resolve these API calls can only go through the tunnel or time out — they
        # cannot leak via a non-tunnel path. The actual file pull is additionally VPN-gated by
        # the fetcher worker (it parks as vpn_wait when the tunnel is down).
        try:
            deadline = time.time() + max_wait
            if provider == RD:
                links = _rd_links_when_ready(tid, key, deadline)
            else:
                links = _tb_links_when_ready(tid, key, deadline)
            if not links:
                _set_pending(pid, state="failed", error="no download links")
                return
            n = 0
            for url, fname, _size in links:
                try:
                    _fetch_add(url, cat, fname or name)
                    n += 1
                except Exception:
                    pass
            _set_pending(pid, state="done" if n else "failed",
                         error="" if n else "could not queue links", files=n)
        except Exception as e:
            _set_pending(pid, state="failed", error=str(e)[:160])

    threading.Thread(target=_bg, name="debrid-" + pid, daemon=True).start()
    return {"ok": True, "id": pid, "provider": provider, "state": "caching"}


_VIDEO_EXT = (".mkv", ".mp4", ".m4v", ".avi", ".mov", ".wmv", ".ts", ".m2ts", ".webm", ".flv", ".mpg", ".mpeg")


def _best_video(links):
    """From [(url, filename, size), ...] pick the main video file: the largest file with a
    video extension, else the largest file overall, else the first. links is non-empty."""
    vids = [l for l in links if (l[1] or "").lower().endswith(_VIDEO_EXT)]
    pool = vids or links
    return max(pool, key=lambda l: l[2] or 0)


def resolve_for_stream(magnet, max_wait=120):
    """Resolve a magnet to a single direct URL for its main video file, for STREAMING.
    Blocks (streaming waits on it): fast when the provider has it cached, up to max_wait
    otherwise. Returns {url, filename, size}. Raises if debrid isn't active or it can't be
    made ready in time (caller should suggest Download instead)."""
    c = _load()
    if not active():
        raise RuntimeError("debrid not configured")
    provider, key = c["provider"], c["key"]
    deadline = time.time() + max_wait
    if provider == RD:
        tid = _rd_submit(magnet, key)
        links = _rd_links_when_ready(tid, key, deadline)
    else:
        tid = _tb_submit(magnet, key)
        links = _tb_links_when_ready(tid, key, deadline)
    if not links:
        raise RuntimeError("no streamable file in that torrent")
    url, fname, size = _best_video(links)
    if not url:
        raise RuntimeError("could not resolve a direct link")
    return {"url": url, "filename": fname or "video", "size": int(size or 0)}


def test(provider=None, key=None):
    """Validate a key against the provider (used by the Settings 'Test' button). Returns
    {ok, user} or {ok:false, error}. Uses the saved key when none is passed."""
    c = _load()
    provider = provider if provider in PROVIDERS else c["provider"]
    key = (key or "").strip() or c["key"]
    if not provider or not key:
        return {"ok": False, "error": "pick a provider and enter a key"}
    try:
        if provider == RD:
            u = _req("GET", _RD + "/user", key, timeout=15)
            return {"ok": True, "user": u.get("username") or u.get("email") or "ok",
                    "premium": bool(u.get("premium"))}
        else:
            u = _req("GET", _TB + "/user/me", key, timeout=15)
            d = u.get("data") or {}
            return {"ok": True, "user": d.get("email") or d.get("username") or "ok",
                    "premium": bool(d.get("plan"))}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": "auth failed (HTTP %s)" % e.code if e.code in (401, 403)
                else "provider error (HTTP %s)" % e.code}
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}
