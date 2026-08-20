#!/usr/bin/env python3
"""vpntorrent - minimal download-only torrent client, hard-locked to the VPN.

Rules enforced here:
  * Nothing downloads unless the VPN is up. No VPN at start -> downloads disabled.
    VPN drops mid-download -> everything pauses until it's back.
  * Download only. Torrents stop the instant they finish — never seed, never
    share completed files.
  * Files are saved into category folders (movies/tv/music/...).

Pure stdlib HTTP server + libtorrent engine. Traffic is bound to the VPN IP, so
even if the killswitch ever failed, the engine has no non-VPN address to use.
"""
import os
import re
import json
import math
import time
import unicodedata
import hmac
import signal
import secrets
import threading
import subprocess
import faulthandler
try:                                    # DEBUG: `kill -USR1 <pid>` dumps all thread stacks
    faulthandler.register(signal.SIGUSR1)
except Exception:
    pass
try:
    # Dump a Python traceback on SIGSEGV/SIGABRT/SIGBUS/SIGFPE. libtorrent is a C++
    # extension: when it faults, the process dies with NO Python traceback at all, which
    # made a real crash look like a silent exit. This turns that into a stack we can read
    # (it only costs a signal handler; it does not slow anything down).
    faulthandler.enable(all_threads=True)
except Exception:
    pass
import http.cookiejar
import urllib.request
import urllib.error
import concurrent.futures
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote, urlencode

import libtorrent as lt
import library  # local module: media library index + in-browser streaming
try:
    import sources  # local package: external media-source adapters (IA, DHT, books…)
except Exception:
    sources = None
try:
    import discover  # local module: "Sources mode" open-directory / file-server finder
except Exception:
    discover = None
try:
    import verify  # local module: liveness verification (probe results are actually retrievable)
except Exception:
    verify = None
try:
    import notify  # local module: outbound notifications when a hunt finds new results
except Exception:
    notify = None
try:
    import ai  # local module: optional local-AI (Ollama) features — off by default
except Exception:
    ai = None
try:
    import hunt  # local module: Deep Hunt persistent background search agent
except Exception:
    hunt = None
try:
    import hunt_brain  # local module: Deep Hunt LLM brain (diverge/converge, offline)
except Exception:
    hunt_brain = None
try:
    import hunt_exec  # local module: Deep Hunt executor (strategy -> real search infra)
except Exception:
    hunt_exec = None

SAVE = os.environ.get("SAVE_PATH", "/downloads")
VPN_IP = os.environ.get("VPN_IP", "").strip()
PORT = int(os.environ.get("PORT", "8722"))
PROTECTED = VPN_IP not in ("", "0.0.0.0")
START = time.time()
TMDB_API_KEY = os.environ.get("TMDB_API_KEY", "").strip()   # optional: poster art + descriptions
FLARESOLVERR = "http://127.0.0.1:8191"   # Cloudflare solver (shares the VPN namespace)
# Locked-down decoder sandbox (separate container, no internet, static IP on an
# internal docker net). We proxy /play to it so ffmpeg never runs in THIS
# privileged/VPN container — a malicious media file can't escape the sandbox.
TRANSCODER = os.environ.get("TRANSCODER_URL", "http://172.24.9.2:8723")

# --- web login -------------------------------------------------------------
# Priority: VT_PASSWORD env (set in docker-compose.yml) -> config/password.txt ->
# auto-generated. So you can change the login by editing one line in the compose
# file (which you own) and restarting.
PW_FILE = os.environ.get("PASSWORD_FILE", "/config/password.txt")
PASSWORD = os.environ.get("VT_PASSWORD", "").strip()
if not PASSWORD:
    try:
        PASSWORD = open(PW_FILE).read().strip()
    except Exception:
        PASSWORD = ""
if not PASSWORD:                       # no password set -> make one so we're never open
    PASSWORD = secrets.token_urlsafe(9)
    try:
        with open(PW_FILE, "w") as f:
            f.write(PASSWORD + "\n")
        os.chmod(PW_FILE, 0o600)
    except Exception:
        pass
    print(f"[vpntorrent] generated web password: {PASSWORD}  (change it in {PW_FILE})",
          flush=True)
_sessions = {}                         # token -> expiry epoch (in-memory)
_SESSION_TTL = 604800                  # 7 days, matches the cookie Max-Age

# --- login brute-force throttle ---------------------------------------------
# Per-client-IP failure counter. This is the real brute-force defence: the server is
# threaded, so a per-request sleep runs in parallel across connections and throttles
# nothing. Deliberately NOT a global concurrency cap — the same handler serves
# long-lived media streams, and a global cap would let one movie stall the whole UI.
# Extra origins the operator trusts (a reverse proxy / front door), comma-separated,
# e.g. TRUSTED_ORIGINS=https://box.tailnet.ts.net:8723,http://192.168.1.10:8722
TRUSTED_ORIGINS = set()
for _o in (os.environ.get("TRUSTED_ORIGINS", "") or "").split(","):
    _o = _o.strip().lower().rstrip("/")
    if _o:
        TRUSTED_ORIGINS.add(_o)
        # also accept the bare host:port form so either spelling works
        try:
            _p = urlparse(_o)
            if _p.netloc:
                TRUSTED_ORIGINS.add(_p.netloc)
        except Exception:
            pass
_csrf_seen = set()                     # distinct rejected origins already logged

_LOGIN_FAILS = {}                      # ip -> [fail_count, window_start_epoch]
_LOGIN_MAX = 5                         # failures allowed per window
_LOGIN_WINDOW = 900                    # 15 minutes
_login_lock = threading.Lock()


def _login_blocked(ip):
    with _login_lock:
        rec = _LOGIN_FAILS.get(ip)
        if not rec:
            return False
        count, start = rec
        if time.time() - start > _LOGIN_WINDOW:
            _LOGIN_FAILS.pop(ip, None)   # window elapsed -> forgiven
            return False
        return count >= _LOGIN_MAX


def _login_fail(ip):
    now = time.time()
    with _login_lock:
        count, start = _LOGIN_FAILS.get(ip, (0, now))
        if now - start > _LOGIN_WINDOW:
            count, start = 0, now
        _LOGIN_FAILS[ip] = (count + 1, start)
        if len(_LOGIN_FAILS) > 4096:     # bound memory against spoofed-source floods
            for k in [k for k, v in _LOGIN_FAILS.items()
                      if now - v[1] > _LOGIN_WINDOW][:2048]:
                _LOGIN_FAILS.pop(k, None)


def _login_ok(ip):
    with _login_lock:
        _LOGIN_FAILS.pop(ip, None)

# --- stream tokens ---------------------------------------------------------
# Let an external player (VLC on your phone/laptop/TV) fetch a file over Tailscale
# WITHOUT the login cookie. The logged-in UI mints a short-lived HMAC token bound
# to one specific file; that token is the only credential in the handed-off URL,
# so it can't be reused for anything else and it expires on its own.
SECRET_FILE = os.environ.get("SECRET_FILE", "/config/secret")
try:
    SECRET = open(SECRET_FILE, "rb").read().strip()
    if not SECRET:
        raise ValueError
except Exception:
    SECRET = secrets.token_bytes(32)
    try:
        with open(SECRET_FILE, "wb") as f:
            f.write(SECRET)
        os.chmod(SECRET_FILE, 0o600)
    except Exception:
        pass
TOKEN_TTL = 6 * 3600                    # a handed-off stream URL is valid 6h (any film)


def make_token(item_id, f):
    exp = int(time.time()) + TOKEN_TTL
    sig = hmac.new(SECRET, f"{item_id}:{f}:{exp}".encode(), "sha256").hexdigest()[:32]
    return f"{exp}.{sig}"


def check_token(item_id, f, tok):
    try:
        exp_s, sig = tok.split(".", 1)
        exp = int(exp_s)
    except Exception:
        return False
    if time.time() > exp:
        return False
    good = hmac.new(SECRET, f"{item_id}:{f}:{exp}".encode(), "sha256").hexdigest()[:32]
    return hmac.compare_digest(sig, good)

# (label shown in UI, subfolder on disk)
CATEGORIES = [
    ("All types", "all"),      # default: broad search scope + downloads to "other"
    ("Movies", "movies"),
    ("TV", "tv"),
    ("Music", "music"),
    ("Documents", "documents"),
    ("Software", "software"),
    ("Other", "other"),
]
# "all" is a search SCOPE, not a real download folder — exclude it so downloads
# made under "All types" land in "other".
FOLDERS = {sub for _, sub in CATEGORIES if sub != "all"}

_lock = threading.Lock()
_torrents = {}          # info_hash -> {"h": handle, "cat": subfolder}
vpn_ok = PROTECTED      # live VPN health flag

# Fast-resume persistence: torrents (and their progress) survive a container
# restart, so the Downloads tab isn't wiped every time the stack comes back up.
RESUME_DIR = "/config/resume"          # one libtorrent .resume blob per torrent
STATE_FILE = "/config/torrents.json"   # our sidecar: category + user-paused flag


def _storage_alert_mask():
    """Alert category that includes save_resume_data_alert (name varies by build)."""
    for getter in (lambda: lt.alert.category_t.storage_notification,
                   lambda: lt.alert_category.storage):
        try:
            return int(getter())
        except Exception:
            pass
    return 0x7fffffff


def _resume_flags():
    """Ask save_resume_data to embed the info-dict, so a torrent restores after a
    restart WITHOUT re-fetching metadata from the swarm (works for dead swarms)."""
    for getter in (lambda: lt.torrent_handle.save_info_dict,
                   lambda: lt.save_resume_flags_t.save_info_dict):
        try:
            return getter()
        except Exception:
            pass
    return 0


_RESUME_FLAGS = _resume_flags()


def _save_resume(h):
    """Request resume data for a handle, but ONLY once it has metadata.

    _RESUME_FLAGS asks libtorrent to embed the info-dict in the blob. On a magnet that
    has not yet fetched metadata there IS no info-dict, and asking for one in
    libtorrent 2.0.x can fault inside the C++ layer — observed as a silent
    `python3 segfault ... in libstdc++` with no Python traceback, which killed the whole
    app right after an /add. There is also nothing worth saving before metadata arrives,
    so skipping is free. Never raises."""
    try:
        if not h.is_valid():
            return False
        st = h.status()
        if not getattr(st, "has_metadata", False):
            return False
        h.save_resume_data(_RESUME_FLAGS)
        return True
    except Exception:
        return False

ses = None
if PROTECTED:
    _s = {
        "listen_interfaces": f"{VPN_IP}:6881",
        "outgoing_interfaces": VPN_IP,   # only ever originate from the tunnel
        "alert_mask": _storage_alert_mask(),   # need save_resume_data alerts
        "enable_lsd": False,             # don't advertise on the local network
        "enable_natpmp": False,
        "enable_upnp": False,
        "seed_time_limit": 0,            # never seed
        "share_ratio_limit": 0,
    }
    ses = lt.session(_s)


# ----------------------------------------------------------------------------- VPN health
def vpn_healthy():
    """True only if the wg interface is up with its IP and a fresh handshake."""
    if not PROTECTED:
        return False
    try:
        addr = subprocess.run(["ip", "-4", "addr", "show", "wg"],
                              capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return False
    if VPN_IP not in addr:
        return False
    try:
        hs = subprocess.run(["wg", "show", "wg", "latest-handshakes"],
                            capture_output=True, text=True, timeout=5).stdout
        ts = max([int(p[1]) for p in (l.split("\t") for l in hs.splitlines())
                  if len(p) > 1] or [0])
    except Exception:
        ts = 0
    if ts == 0:                       # no handshake yet — allow a startup grace window
        return (time.time() - START) < 90
    return (time.time() - ts) < 180


def monitor():
    """Pause everything if the VPN drops; pause torrents the moment they finish."""
    global vpn_ok
    was_ok = None
    while True:
        ok = vpn_healthy()
        if ok and was_ok is False:
            # VPN just came back after a drop. During a failover the entrypoint tears
            # down and rebuilds the wg interface; libtorrent's listen sockets were bound
            # to the old interface and are now wedged (they stay bound but send nothing,
            # so torrents get 0 peers even after resume()). Rebind them to the fresh
            # interface so downloads actually recover instead of silently hanging.
            try:
                ses.reopen_network_sockets()
                print("[vpntorrent] VPN recovered — reopened libtorrent sockets", flush=True)
            except Exception as e:
                print(f"[vpntorrent] socket reopen failed: {e}", flush=True)
        was_ok = ok
        vpn_ok = ok
        with _lock:
            items = list(_torrents.items())
        for ih, t in items:
            try:                          # a torn-down/invalid handle must not kill the loop
                h = t["h"]
                if not h.is_valid():
                    continue
                s = h.status()
                if not ok:
                    if not s.paused:
                        h.pause()         # VPN down -> pause (not a user pause)
                    continue
                if s.is_finished:        # download-only: stop dead on completion
                    if not t.get("finished"):
                        t["finished"] = True      # remember across restarts (no seeding)
                        _save_state()
                    if not s.paused:
                        h.pause()
                        _save_resume(h)          # persist completed state (guarded)
                elif s.paused and not t["user_paused"] and not t.get("finished"):
                    # `finished` is checked as well as is_finished: right after a restart
                    # libtorrent may still report is_finished False for a complete torrent,
                    # and resuming it — even for one 5s cycle — would announce us as a
                    # seeder. The persisted flag is authoritative until proven otherwise.
                    h.resume()           # VPN back & user didn't pause it -> resume
            except Exception:
                continue
        time.sleep(5)


# ----------------------------------------------------------------------------- engine ops
def add_magnet(magnet, cat):
    if cat not in FOLDERS:
        cat = "other"
    path = os.path.join(SAVE, cat)
    os.makedirs(path, exist_ok=True)
    p = lt.parse_magnet_uri(magnet)
    p.save_path = path
    # We manage start/stop ourselves. Auto-management lets libtorrent override our
    # pause() (and would auto-seed completed torrents), so turn it off. But we must
    # ALSO clear the default `paused` flag: libtorrent's add_torrent_params default is
    # auto_managed|paused, and the auto-manager is what normally unpauses a new torrent.
    # Clearing auto_managed WITHOUT clearing paused adds the torrent paused forever — it
    # never announces to trackers, so it sits at 0 peers / "Fetching info…" indefinitely.
    p.flags &= ~(lt.torrent_flags.auto_managed | lt.torrent_flags.paused)
    h = ses.add_torrent(p)
    ih = str(h.info_hash())
    with _lock:
        _torrents[ih] = {"h": h, "cat": cat, "user_paused": False, "finished": False}
    _save_state()
    _save_resume(h)      # no-op until metadata arrives (see _save_resume)
    return ih


# Some sources (Internet Archive) publish a .torrent FILE rather than a magnet.
# We fetch it (through the VPN) and hand the bytes to libtorrent. To avoid an
# SSRF into the LAN/localhost, only these hosts may be fetched, over http(s) only,
# with a small size cap (a .torrent is tiny).
TORRENT_URL_HOSTS = ("archive.org",)
TORRENT_FILE_CAP = 12 * 1024 * 1024


def _torrent_host_ok(host):
    host = (host or "").lower()
    return any(host == h or host.endswith("." + h) for h in TORRENT_URL_HOSTS)


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    """Re-validate EVERY redirect hop against the allowlist so an open-redirect on
    an allowlisted host can't bounce the fetch to Jackett/localhost/the LAN."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not (newurl.startswith("http://") or newurl.startswith("https://")) \
                or not _torrent_host_ok(urlparse(newurl).hostname):
            raise urllib.error.HTTPError(req.full_url, code,
                                         "redirect target not allowed", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_TORRENT_OPENER = urllib.request.build_opener(_AllowlistRedirect())


def add_torrent_url(url, cat):
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("bad scheme")
    if not _torrent_host_ok(urlparse(url).hostname):
        raise ValueError("host not allowed")
    if cat not in FOLDERS:
        cat = "other"
    path = os.path.join(SAVE, cat)
    os.makedirs(path, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "vpntorrent"})
    data = _TORRENT_OPENER.open(req, timeout=30).read(TORRENT_FILE_CAP)
    try:                                   # libtorrent 2.0 preferred loader
        p = lt.load_torrent_buffer(data)
    except Exception:                      # fallback for older bindings
        p = lt.add_torrent_params()
        p.ti = lt.torrent_info(lt.bdecode(data))
    p.save_path = path
    # never auto-seed (download-only) AND never add paused (see add_magnet) — else it
    # would stall at 0 peers instead of downloading.
    p.flags &= ~(lt.torrent_flags.auto_managed | lt.torrent_flags.paused)
    h = ses.add_torrent(p)
    ih = str(h.info_hash())
    with _lock:
        _torrents[ih] = {"h": h, "cat": cat, "user_paused": False, "finished": False}
    _save_state()
    _save_resume(h)
    return ih


# --- Usenet: hand an NZB to SABnzbd, which downloads it from the provider ------
SAB_URL = os.environ.get("SAB_URL", "http://127.0.0.1:8085").rstrip("/")
SAB_APIKEY = os.environ.get("SAB_APIKEY", "")
NEWZNAB_URL = os.environ.get("NEWZNAB_URL", "").rstrip("/")
NZBGEEK_APIKEY = os.environ.get("NZBGEEK_APIKEY", "")


def usenet_ready():
    return bool(SAB_APIKEY and NEWZNAB_URL and NZBGEEK_APIKEY)


def add_nzb(nzb_id, cat):
    """Build the authenticated indexer get-URL SERVER-SIDE (the indexer API key is
    never exposed to the browser) and tell SABnzbd to fetch it. SABnzbd downloads
    from the Usenet provider through the VPN and drops the file in /downloads/<cat>."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{4,128}", nzb_id or ""):
        raise ValueError("bad nzb id")
    if not usenet_ready():
        raise ValueError("usenet not configured")
    if cat not in FOLDERS:
        cat = "other"
    nzb_url = f"{NEWZNAB_URL}/api?t=get&id={quote(nzb_id)}&apikey={NZBGEEK_APIKEY}"
    params = urlencode({"mode": "addurl", "name": nzb_url, "cat": cat,
                        "apikey": SAB_APIKEY, "output": "json"})
    resp = json.load(urllib.request.urlopen(f"{SAB_URL}/api?{params}", timeout=30))
    if not resp.get("status", False):
        raise ValueError("SABnzbd rejected the NZB")
    return True


def _sab_api(mode, extra=None, timeout=12):
    """Call SABnzbd's JSON API. Returns {} on any failure (never raises)."""
    if not SAB_APIKEY:
        return {}
    q = {"mode": mode, "output": "json", "apikey": SAB_APIKEY}
    q.update(extra or {})
    try:
        return json.load(urllib.request.urlopen(
            SAB_URL + "/api?" + urlencode(q), timeout=timeout)) or {}
    except Exception:
        return {}


def usenet_snapshot():
    """Usenet transfers, shaped like the torrent rows the Downloads tab already draws.

    Without this, an NZB handed to SABnzbd was completely invisible: /add returned
    "added" and then nothing ever appeared, with no way to see progress or cancel it.
    Includes items still being unpacked/repaired after the download finishes, because
    that stage can take minutes and the file is not usable yet.
    """
    out = []
    if not SAB_APIKEY:
        return out
    q = _sab_api("queue").get("queue", {}) or {}
    for s in (q.get("slots") or []):
        try:
            pct = float(s.get("percentage") or 0)
        except (TypeError, ValueError):
            pct = 0.0
        paused = str(s.get("status", "")).lower() == "paused"
        out.append({
            "id": s.get("nzo_id", ""),
            "name": s.get("filename") or s.get("nzo_id") or "(usenet)",
            "cat": s.get("cat") or "other",
            "progress": round(pct, 1),
            "state": "Paused" if paused else "Downloading",
            "paused": paused,
            "eta": s.get("timeleft") or "",
            "size": s.get("size") or "",
            "done": False,
        })
    # History rows that are NOT finished yet are still work in progress (Extracting,
    # Repairing, Verifying...). A completed row is dropped: it is in the Library now.
    h = _sab_api("history", {"limit": 25}).get("history", {}) or {}
    for s in (h.get("slots") or []):
        st = str(s.get("status") or "")
        if st.lower() in ("completed", "failed"):
            if st.lower() == "failed":
                out.append({"id": s.get("nzo_id", ""),
                            "name": s.get("name") or "(usenet)",
                            "cat": s.get("category") or "other",
                            "progress": 0, "state": "Failed",
                            "error": (s.get("fail_message") or "")[:160],
                            "paused": False, "eta": "", "size": s.get("size") or "",
                            "done": True})
            continue
        out.append({"id": s.get("nzo_id", ""),
                    "name": s.get("name") or "(usenet)",
                    "cat": s.get("category") or "other",
                    "progress": 100, "state": st or "Processing",
                    "paused": False, "eta": "", "size": s.get("size") or "",
                    "done": False})
    return out


def usenet_remove(nzo_id, delete_files=False):
    """Cancel a usenet job. Tries the queue first, then history (post-processing)."""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", nzo_id or ""):
        return False
    d = "1" if delete_files else "0"
    r1 = _sab_api("queue", {"name": "delete", "value": nzo_id, "del_files": d})
    r2 = _sab_api("history", {"name": "delete", "value": nzo_id, "del_files": d})
    return bool(r1.get("status") or r2.get("status"))


def remove(ih, delete_files=False):
    if not re.fullmatch(r'[0-9a-fA-F]{40,64}', ih or ''):   # only real info-hashes touch the fs
        return
    with _lock:
        t = _torrents.pop(ih, None)
    if t is not None:
        ses.remove_torrent(t["h"], lt.options_t.delete_files if delete_files else 0)
    try:
        os.remove(os.path.join(RESUME_DIR, ih + ".resume"))
    except Exception:
        pass
    _save_state()


def _remove_torrent_for_rel(rel):
    """After a library item's files are deleted, drop any active torrent still pointing at
    that content (cat/name) so it can't re-download the files we just removed."""
    rel = (rel or "").replace("\\", "/").strip("/")
    if "/" not in rel:
        return
    cat, name = rel.split("/", 1)
    name = name.split("/", 1)[0]                    # the top folder/file under the category
    with _lock:
        items = list(_torrents.items())
    for ih, t in items:
        if t.get("cat") != cat:
            continue
        try:
            tname = t["h"].status().name or ""
        except Exception:
            tname = ""
        if tname and (tname == name or name == tname):
            remove(ih, delete_files=False)          # files are already gone


def pause(ih):
    with _lock:
        t = _torrents.get(ih)
    if t:
        t["user_paused"] = True
        t["h"].pause()
        _save_state()


def resume(ih):
    with _lock:
        t = _torrents.get(ih)
    if t:
        t["user_paused"] = False
        if vpn_ok and not t["h"].status().is_finished:
            t["h"].resume()
        _save_state()


def recheck(ih):
    with _lock:
        t = _torrents.get(ih)
    if t:
        t["h"].force_recheck()


# ----------------------------------------------------------------------------- persistence
def _load_state():
    try:
        return json.load(open(STATE_FILE))
    except Exception:
        return {}


def _save_state():
    """Persist each torrent's category, user-paused flag AND completion so a restart
    restores it to the right folder and state (the .resume blob holds the rest).

    `finished` matters for more than cosmetics: without it a restart cannot tell a
    torrent we paused because it COMPLETED from one the user paused, so completed
    torrents came back active and announced us to trackers/DHT as a seeder — which
    this app promises never to do."""
    try:
        with _lock:
            data = {ih: {"cat": t["cat"], "user_paused": t["user_paused"],
                         "finished": bool(t.get("finished"))}
                    for ih, t in _torrents.items()}
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())        # durable before rename — survives power loss
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass


def alert_pump():
    """Drain libtorrent alerts; write a .resume blob whenever one is produced."""
    while True:
        try:
            ses.wait_for_alert(1000)
            for a in ses.pop_alerts():
                if isinstance(a, lt.save_resume_data_alert):
                    try:
                        ih = str(a.handle.info_hash())
                        with _lock:
                            tracked = ih in _torrents
                        # A save_resume_data request queued before remove() can drain
                        # AFTER it. Don't write a blob for an untracked torrent, or
                        # restore_torrents would resurrect it on the next restart.
                        if not tracked:
                            continue
                        buf = lt.write_resume_data_buf(a.params)
                        # Atomic: write a temp file, fsync, then rename over the real
                        # one — so power loss mid-write can never truncate a .resume
                        # blob and make the torrent vanish from Downloads on next boot.
                        dst = os.path.join(RESUME_DIR, ih + ".resume")
                        tmp = dst + ".tmp"
                        with open(tmp, "wb") as f:
                            f.write(buf)
                            f.flush()
                            os.fsync(f.fileno())
                        os.replace(tmp, dst)
                    except Exception:
                        pass
        except Exception:
            time.sleep(1)


def resume_saver():
    """Periodically checkpoint every torrent's resume data + our sidecar state,
    so an unexpected restart loses as little progress as possible."""
    while True:
        time.sleep(30)
        with _lock:
            handles = [t["h"] for t in _torrents.values()]
        for h in handles:
            _save_resume(h)
        _save_state()


def restore_torrents():
    """Re-add torrents saved from a previous run (one .resume blob each), so the
    Downloads tab survives a container restart. The blob embeds the metadata, so
    completed/partial files are picked up from disk without needing the swarm."""
    state = _load_state()
    try:
        files = sorted(os.listdir(RESUME_DIR))
    except Exception:
        files = []
    for fn in files:
        if not fn.endswith(".resume"):
            continue
        try:
            with open(os.path.join(RESUME_DIR, fn), "rb") as f:
                atp = lt.read_resume_data(f.read())
            # Clear auto_managed AND paused so the torrent is startable at all (a blob
            # saved while paused otherwise comes back paused with no way out), but then
            # immediately pause it below. monitor() decides within 5s whether it should
            # actually run — that keeps COMPLETED torrents from announcing us as a seeder
            # in the seconds before the first monitor pass.
            atp.flags &= ~(lt.torrent_flags.auto_managed | lt.torrent_flags.paused)
            h = ses.add_torrent(atp)
            h.pause()
            ih = str(h.info_hash())
            st = state.get(ih) or state.get(fn[:-7]) or {}
            cat = st.get("cat")
            if not cat:                       # fall back to the save_path basename
                try:
                    cat = os.path.basename(str(atp.save_path).rstrip("/"))
                except Exception:
                    cat = "other"
            if cat not in FOLDERS:
                cat = "other"
            up = bool(st.get("user_paused", False))
            # Carry completion across the restart. libtorrent's own is_finished can read
            # False for a moment after add (the resume check hasn't run), and monitor()
            # would take that moment to "resume" a finished torrent — a brief but real
            # seeder announce. Trusting our own persisted flag closes that window.
            fin = bool(st.get("finished", False))
            with _lock:
                _torrents[ih] = {"h": h, "cat": cat, "user_paused": up, "finished": fin}
            # already paused above; monitor() starts it if it is genuinely unfinished
            print(f"[vpntorrent] restored {ih} -> {cat}"
                  f"{' (complete)' if fin else ''}", flush=True)
        except Exception as e:
            print(f"[vpntorrent] restore skip {fn} ({e})", flush=True)


def snapshot():
    out = []
    with _lock:
        items = list(_torrents.items())
    for ih, t in items:
        h = t["h"]
        if not h.is_valid():
            continue
        s = h.status()
        checking = s.state in (lt.torrent_status.checking_files,
                               lt.torrent_status.checking_resume_data)
        if not vpn_ok:
            state = "Paused — VPN down"
        elif checking:
            state = "Checking…"
        elif s.is_finished:
            state = "✓ Complete"
        elif s.paused or t["user_paused"]:
            # check paused BEFORE downloading_metadata: libtorrent still reports the
            # state as downloading_metadata while paused, so a paused torrent would
            # otherwise masquerade as "Fetching info…" and hide that it's stalled.
            state = "Paused"
        elif s.state == lt.torrent_status.downloading_metadata:
            state = "Fetching info…"
        else:
            state = "Downloading"
        out.append({
            "ih": ih,
            "name": s.name or "(fetching metadata…)",
            "cat": t["cat"],
            "progress": round(s.progress * 100, 1),
            "state": state,
            "finished": bool(s.is_finished),
            "upaused": bool(t["user_paused"]),
            "dl": s.download_rate,
            "peers": s.num_peers,
            "size": s.total_wanted,
            "done": s.total_done,
        })
    return out


# ----------------------------------------------------------------------------- search (Jackett)
# Jackett runs in the SAME VPN namespace (see compose), so its searches go out
# through Proton too. We read its auto-generated API key from a shared read-only
# mount, auto-configure a set of public indexers, and proxy searches to it.
JACKETT = "http://127.0.0.1:9117"
JKEY_FILE = os.environ.get("JACKETT_KEYFILE", "/jackett/Jackett/ServerConfig.json")
# kickasstorrents-ws dropped (KAT long dead). CF/DDoS-Guard ones (1337x, torlock,
# limetorrents, glodls, torrentgalaxy, torrentdownloads, ext, yourbittorrent) now
# work because FlareSolverr is wired in below.
# Curated set of public indexers. The search now queries each in PARALLEL with a
# short per-indexer timeout and drops any that hang/error, so a dead site never
# stalls or zeroes the batch — meaning we can cast a wide net cheaply. Jackett skips
# any ID it doesn't ship or can't configure (see jackett_setup). Meta-indexers like
# knaben/bitsearch each aggregate many sites themselves, multiplying coverage.
INDEXERS = ["thepiratebay", "1337x", "yts", "eztv", "nyaasi", "limetorrents",
            "torlock", "btdigg", "torrentgalaxy", "yourbittorrent", "glodls",
            "torrentdownloads", "ext", "bitsearch", "therarbg", "knaben",
            "solidtorrents", "anidex", "tokyotoshokan"]
TRACKERS = ["udp://tracker.opentrackr.org:1337/announce",
            "udp://open.tracker.cl:1337/announce",
            "udp://tracker.openbittorrent.com:6969/announce",
            "udp://exodus.desync.com:6969/announce"]
_jkey = None
_jlock = threading.Lock()


def _jackett_opener():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(JACKETT + "/UI/Dashboard", timeout=10)   # grab the admin session cookie
    return op


def _jackett_set_flaresolverr(op, key):
    """Point Jackett's server config at FlareSolverr (server-wide setting).

    Returns True if it actually changed the config — the caller must then restart
    Jackett, since FlareSolverr URL is only read at startup. Idempotent: once the
    URL is persisted, later runs see it already set and skip the restart.
    """
    url = f"{JACKETT}/api/v2.0/server/config?apikey={key}"
    try:
        cfg = json.load(op.open(url, timeout=20))
    except Exception as e:
        print(f"[vpntorrent] search: can't read Jackett server config ({e})", flush=True)
        return False
    # The API's field name has varied in casing across versions; match whatever
    # key the running Jackett uses (any key containing 'flaresolverr').
    changed = False
    found_url = False
    for k in list(cfg.keys()):
        lk = k.lower()
        if "flaresolverr" in lk and "url" in lk:
            found_url = True
            if cfg[k] != FLARESOLVERR:
                cfg[k] = FLARESOLVERR
                changed = True
        elif "flaresolverr" in lk and "timeout" in lk:
            if cfg[k] != 60000:           # 60s; long timeouts hold Chromium RAM
                cfg[k] = 60000
                changed = True
    if not found_url:                     # field absent -> add the common keys
        cfg["flaresolverrurl"] = FLARESOLVERR
        cfg["flaresolverr_maxtimeout"] = 60000
        changed = True
    if not changed:
        return False
    try:
        req = urllib.request.Request(url, data=json.dumps(cfg).encode(),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        op.open(req, timeout=20)
        print("[vpntorrent] search: FlareSolverr wired into Jackett", flush=True)
        return True
    except Exception as e:
        print(f"[vpntorrent] search: FlareSolverr config POST failed ({e})", flush=True)
        return False


def _jackett_restart(op, key):
    """Trigger Jackett's self-restart so a server-config change takes effect."""
    print("[vpntorrent] search: restarting Jackett to apply FlareSolverr…", flush=True)
    try:
        req = urllib.request.Request(f"{JACKETT}/api/v2.0/server/restart?apikey={key}",
                                     data=b"", method="POST")
        op.open(req, timeout=10)
    except Exception:
        pass                              # the server drops the connection as it restarts — expected


def _configure_indexer(key, ind):
    """Configure ONE indexer with its default settings (public/no-login ones just
    need the form POSTed back). Jackett's config API needs the admin session cookie,
    so each call gets its OWN opener (fresh cookiejar) — safe to run in parallel.
    Returns (id, ok)."""
    try:
        op = _jackett_opener()
        cfg = json.load(op.open(
            f"{JACKETT}/api/v2.0/indexers/{ind}/config?apikey={key}", timeout=25))
        req = urllib.request.Request(
            f"{JACKETT}/api/v2.0/indexers/{ind}/config?apikey={key}",
            data=json.dumps(cfg).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        op.open(req, timeout=30)
        return ind, True
    except Exception:
        return ind, False


def jackett_setup():
    """Wait for Jackett, then ensure the target indexers are configured (idempotent)."""
    global _jkey
    while True:
        try:
            key = json.load(open(JKEY_FILE)).get("APIKey")
        except Exception:
            key = None
        if key:
            try:
                op = _jackett_opener()
                # Wire FlareSolverr first so the CF-protected indexers configure.
                if _jackett_set_flaresolverr(op, key):
                    _jackett_restart(op, key)
                    time.sleep(8)         # give Jackett a moment to come back
                    op = _jackett_opener()   # fresh admin cookie after restart
                lst = json.load(op.open(f"{JACKETT}/api/v2.0/indexers?apikey={key}", timeout=20))
                have = {x["id"] for x in lst if x.get("configured")}
                avail = {x["id"] for x in lst}
                # Cast the WIDEST net: configure every PUBLIC (no-login) indexer Jackett
                # ships, plus the curated priority set. The parallel search drops any that
                # are dead/slow, so more indexers only ever means better coverage.
                public = {x["id"] for x in lst if x.get("type") == "public"}
                targets = (public | set(INDEXERS)) & avail
                todo = [i for i in targets if i not in have]
                added = 0
                with ThreadPoolExecutor(max_workers=10) as cex:
                    for ind, okk in cex.map(lambda i: _configure_indexer(key, i), todo):
                        if okk:
                            have.add(ind)
                            added += 1
                print(f"[vpntorrent] search: configured {len(have)} indexers "
                      f"(+{added} new; {len(public)} public available)", flush=True)
                with _jlock:
                    _jkey = key
                print(f"[vpntorrent] search: ready, {len(have)} indexers configured", flush=True)
                return
            except Exception as e:
                print(f"[vpntorrent] search: waiting for Jackett ({e})", flush=True)
        time.sleep(5)


_jindexers = []          # cached list of *configured* indexer IDs
_jindexers_ts = 0.0
PER_INDEXER_TIMEOUT = 12    # a single dead site can't cost more than this
SEARCH_DEADLINE = 22        # overall wall-clock budget for a search
SEARCH_WORKERS = 64         # query this many indexers at once (64GB box; dozens of indexers)


def _configured_indexers(key):
    """The indexer IDs Jackett has configured, cached ~1 min. Read straight from the
    read-only jackett-config mount: Jackett writes one <id>.json per configured
    indexer. (The /api/v2.0/indexers LIST endpoint needs the admin session cookie and
    400s on a plain apikey request, which used to silently fall us back to the ~19
    static IDs — so we never queried the 99 auto-configured ones. Disk is the truth.)"""
    global _jindexers, _jindexers_ts
    now = time.time()
    with _jlock:
        if _jindexers and now - _jindexers_ts < 60:
            return list(_jindexers)
    ids = []
    try:
        idx_dir = os.path.join(os.path.dirname(JKEY_FILE), "Indexers")
        for fn in os.listdir(idx_dir):
            if fn.endswith(".json"):
                ids.append(fn[:-5])
    except Exception:
        pass
    if not ids:
        ids = list(INDEXERS)               # last-resort fallback
    with _jlock:
        _jindexers, _jindexers_ts = ids, now
    return ids


def _infohash_of(magnet):
    m = re.search(r"btih:([0-9A-Za-z]+)", magnet or "")
    return m.group(1).lower() if m else ""


def _parse_torznab(raw, fallback_tracker=""):
    """Parse a torznab XML feed into normalized result dicts. Namespace-agnostic
    (matches on the local tag name) so it survives Jackett's schema quirks."""
    out = []
    try:
        root = ET.fromstring(raw)
    except Exception:
        return out
    for item in root.iter():
        if item.tag.split("}")[-1] != "item":
            continue
        title = ""; size = 0; seeders = 0; magnet = ""; ih = ""
        tracker = fallback_tracker; pub = ""; link = ""; enc = ""; cats = []
        for ch in item:
            tag = ch.tag.split("}")[-1]
            if tag == "title":
                title = (ch.text or "").strip()
            elif tag == "size":
                try: size = int((ch.text or "0").strip())
                except Exception: pass
            elif tag == "link":
                link = (ch.text or "").strip()
            elif tag == "pubDate":
                pub = (ch.text or "").strip()
            elif tag == "jackettindexer":
                tracker = (ch.text or "").strip() or tracker
            elif tag == "enclosure":
                enc = ch.get("url") or ""
            elif tag == "category":
                if (ch.text or "").strip():
                    cats.append((ch.text or "").strip())      # <category>2040</category>
            elif tag == "attr":
                name = (ch.get("name") or "").lower(); val = ch.get("value") or ""
                if name == "seeders":
                    try: seeders = int(val)
                    except Exception: pass
                elif name == "magneturl" and val.startswith("magnet:"):
                    magnet = val
                elif name == "infohash":
                    ih = val.strip()
                elif name == "category":
                    cats.append(val)                          # <torznab:attr name="category" value="2040"/>
                elif name == "size" and not size:
                    try: size = int(val)
                    except Exception: pass
        if not magnet:
            if link.startswith("magnet:"): magnet = link
            elif enc.startswith("magnet:"): magnet = enc
        if not magnet and ih:
            magnet = ("magnet:?xt=urn:btih:" + ih + "&dn=" + quote(title)
                      + "".join("&tr=" + quote(t) for t in TRACKERS))
        if not magnet:
            continue           # no usable magnet/infohash -> can't download it
        out.append({"title": title, "tracker": tracker, "seeders": seeders,
                    "size": size, "magnet": magnet, "date": pub,
                    "category": _torznab_cat(cats),          # so scoping to a type actually finds it
                    "source": tracker or fallback_tracker})
    return out


def _query_indexer(iid, q, key):
    """Query ONE indexer's torznab endpoint. Never raises — a dead/slow indexer
    just returns []. Uses the apikey (no shared cookie), so it's thread-safe."""
    url = (f"{JACKETT}/api/v2.0/indexers/{quote(iid)}/results/torznab/api"
           f"?apikey={key}&t=search&q={quote(q)}")
    try:
        raw = urllib.request.urlopen(url, timeout=PER_INDEXER_TIMEOUT).read()
    except Exception:
        return []
    return _parse_torznab(raw, iid)


def jackett_search(q):
    """Fan out to every configured indexer IN PARALLEL, gather whatever returns
    within the deadline, dedupe by infohash, rank by seeders. One dead indexer can
    no longer stall or empty the whole search. Returns None if search isn't ready."""
    with _jlock:
        key = _jkey
    if not key:
        return None
    ids = _configured_indexers(key)
    if not ids:
        return []
    results = []
    ex = ThreadPoolExecutor(max_workers=min(SEARCH_WORKERS, len(ids)))
    futs = [ex.submit(_query_indexer, iid, q, key) for iid in ids]
    try:
        for fut in as_completed(futs, timeout=SEARCH_DEADLINE):
            try:
                results.extend(fut.result())
            except Exception:
                pass
    except concurrent.futures.TimeoutError:
        pass                       # stragglers dropped; keep what we have
    ex.shutdown(wait=False)
    # Dedupe across indexers by infohash (same torrent found on many sites);
    # keep the copy reporting the most seeders.
    best = {}
    for r in results:
        k = _infohash_of(r["magnet"]) or ("t:" + r["title"].lower())
        cur = best.get(k)
        if cur is None or r["seeders"] > cur["seeders"]:
            best[k] = r
    out = list(best.values())
    out.sort(key=lambda r: r["seeders"], reverse=True)
    return out[:250]


# --- unified meta-search: Jackett trackers + external adapters, ranked ---------
_QUAL_MAP = [("2160p", "2160p"), ("uhd", "2160p"), ("4k", "2160p"),
             ("1080p", "1080p"), ("720p", "720p"), ("480p", "480p"),
             ("flac", "FLAC"), ("bluray", "BluRay"), ("web-dl", "WEB-DL"),
             ("remux", "REMUX")]


def _quality_of(title):
    t = (title or "").lower()
    for pat, label in _QUAL_MAP:
        if pat in t:
            return label
    return ""


# ---- CATEGORY normalisation ------------------------------------------------------------------
# Every source labels types differently — Jackett usually not at all, bt4g says "movie"/"book",
# others "media"/"filetype"/"dataset". Canonicalise EVERYTHING to the six dropdown categories so
# that scoping the search to a type actually shows that type (and downloads land in the right folder).
_CAT_ALIAS = {
    "movie": "movies", "movies": "movies", "film": "movies", "films": "movies", "video": "movies",
    "tv": "tv", "show": "tv", "shows": "tv", "series": "tv", "television": "tv", "hdtv": "tv",
    "music": "music", "audio": "music", "song": "music", "songs": "music", "album": "music", "flac": "music",
    "book": "documents", "books": "documents", "ebook": "documents", "ebooks": "documents",
    "document": "documents", "documents": "documents", "doc": "documents", "docs": "documents",
    "pdf": "documents", "paper": "documents", "papers": "documents", "comic": "documents", "magazine": "documents",
    "software": "software", "app": "software", "apps": "software", "application": "software",
    "game": "software", "games": "software", "pc": "software", "iso": "software",
}
# STRONG (unambiguous) signals vs WEAK (ambiguous) ones — checked strong-first so a real movie
# named "Soundtrack…2024 1080p" isn't stolen by "soundtrack", a "…Audiobook MP3" isn't stolen by
# "mp3", and disc/model tokens (2x12 vinyl, S10 Ultra) don't fake a TV episode.
_RX_TV_EP = re.compile(r"(?:^|[^a-z0-9])s\d{1,2}e\d{1,2}(?:[^a-z0-9]|$)", re.I)          # SxxExx — unambiguous
_RX_TV_PACK = re.compile(r"(?:^|[^a-z0-9])(complete series|mini[- ]?series|season[ ._-]?\d{1,2})(?:[^a-z0-9]|$)", re.I)
_RX_DOC = re.compile(r"\.(?:pdf|epub|mobi|azw3|m4b)(?![a-z0-9])|(?:^|[^a-z0-9])(?:epub|mobi|azw3|m4b|audio ?book|unabridged)(?:[^a-z0-9]|$)", re.I)
_RX_COMIC = re.compile(r"\.(?:cbr|cbz)(?![a-z0-9])", re.I)   # comic — .CBR collides w/ the MP3 'CBR' bitrate, so checked AFTER music
_RX_MUSIC_STRONG = re.compile(r"(?:^|[^a-z0-9])(flac|mp3|320 ?kbps|256 ?kbps|discography|\bwav\b|\bape\b|\bm4a\b|24 ?bit|lossless)(?:[^a-z0-9]|$)", re.I)
_RX_MUSIC_WEAK = re.compile(r"(?:^|[^a-z0-9])(\balbum\b|soundtrack|\bost\b|vinyl)(?:[^a-z0-9]|$)", re.I)
_RX_MOVIE = re.compile(r"(19|20)\d\d\D{0,40}(1080p|720p|2160p|4k|blu-?ray|x264|x265|h ?264|h ?265|hevc|web-?rip|web-?dl|hdrip|dvdrip|bdrip|brrip|\bcam\b|hdcam|telesync)", re.I)
# STRONG = tokens that NEVER appear in a real movie/TV title (win/x64/keygen); MED = English words
# that DO appear in film titles ('Crack','Activate') or ambiguous images (.iso), so checked after MOVIE.
_RX_SOFT_STRONG = re.compile(r"(?:^|[^a-z0-9])(keygen|setup\.exe|x64|x86|win(?:dows)?[ ._-]?(?:xp|7|8|10|11)|mac ?os|\bosx\b)(?:[^a-z0-9]|$)", re.I)
_RX_SOFT_MED = re.compile(r"\.iso(?![a-z0-9])|(?:^|[^a-z0-9])(cracked|\bcrack\b|activat(?:or|ed|ion|e)|keygen)(?:[^a-z0-9]|$)", re.I)
_RX_SOFT_WEAK = re.compile(r"(?:^|[^a-z0-9])(multilingual|portable|repack)(?:[^a-z0-9]|$)", re.I)


def _infer_category(title):
    """Best-effort type from release-naming when the source gave no usable label. A VIDEO signature
    (SxxExx, or a year next to a video-quality token) is the strongest, most reliable signal and wins
    FIRST — so a movie/TV release whose title happens to contain 'mp3'/'flac'/'crack' is not stolen by
    those; then the unmistakable doc/software/audio tokens; then the weak/ambiguous words last."""
    t = title or ""
    # Precedence resolves every overlap seen in review: SxxExx (tv) -> book extension/word (doc, so a
    # 'Complete Series Audiobook'/'Season 5 EPUB' is a book) -> STRONG software (x64/keygen/win, so a
    # 'Season 4 ... x64' game is software) -> TV pack incl. bare 'season N' & complete/mini-series (tv even
    # with a year, so a dated 1080p pack isn't a movie) -> year+quality (movies, so 'Cracked 2022 1080p' is
    # a film) -> MED software (crack/activate/.iso — words that ALSO appear in film titles) -> flac/mp3
    # (music) -> .cbr/.cbz comic (after music, so an MP3 'CBR' bitrate stays music) -> weak words last.
    if _RX_TV_EP.search(t): return "tv"
    if _RX_DOC.search(t): return "documents"
    if _RX_SOFT_STRONG.search(t): return "software"
    if _RX_TV_PACK.search(t): return "tv"
    if _RX_MOVIE.search(t): return "movies"
    if _RX_SOFT_MED.search(t): return "software"
    if _RX_MUSIC_STRONG.search(t): return "music"
    if _RX_COMIC.search(t): return "documents"
    if _RX_MUSIC_WEAK.search(t): return "music"
    if _RX_SOFT_WEAK.search(t): return "software"
    return ""


def _canon_category(cat, title=""):
    """Return (type, confident): the six dropdown types (or "xxx"/"" ), and whether the type came from a
    source LABEL / torznab id (trustworthy) vs. GUESSED from the title. NOTE: a source label of "other"
    is NOT trusted as a type — many adapters use it as a catch-all for content they DO serve, and hard-
    dropping it from a scope loses real results — so it's treated as unknown (read the title, else "")."""
    c = (cat or "").strip().lower()
    if c in _CAT_ALIAS:
        return _CAT_ALIAS[c], True
    if c in ("movies", "tv", "music", "documents", "software", "xxx"):
        return c, True
    inf = _infer_category(title)         # "other" / junk label / "" -> read the release title (a guess)
    return (inf, False) if inf else ("", False)


def _torznab_cat(cats):
    """Newznab/torznab numeric category id -> our type. Resolved by a FIXED PRECEDENCE over the WHOLE
    id set (never by the indexer's list order), so a cross-tagged release (e.g. a concert film tagged
    Movies+Audio, or an audiobook tagged Audio-parent+Books) always lands in the same, most-sensible
    scope. XXX wins over everything; a specific subcategory (audiobook 3030) beats its generic parent."""
    ids = []
    for v in cats:
        try:
            ids.append(int(str(v).strip()))
        except (TypeError, ValueError):
            continue
    has = lambda lo, hi: any(lo <= n < hi for n in ids)
    if has(6000, 7000): return "xxx"                # adult content is authoritative — never a normal scope
    if 3030 in ids: return "documents"              # Audiobook subcategory -> documents (its canonical home)
    if 5070 in ids and not any(5000 <= n < 6000 and n != 5070 for n in ids):
        return ""                                   # PURE anime tag: film-vs-series ambiguous -> title decides;
                                                    # but a co-tagged TV sibling (5030/5000) makes it clearly TV
    # fixed precedence for a multi-range cross-tag: video (movies>tv) > books > audio > software > misc.
    if has(2000, 3000): return "movies"
    if has(5000, 6000): return "tv"
    if has(7000, 8000): return "documents"
    if has(3000, 4000): return "music"
    if has(4000, 5000) or has(1000, 2000): return "software"   # apps + console games
    if has(8000, 9000): return ""                   # misc/other bucket -> unknown, let the title decide
    return ""


# Only TRUE function words — NOT content words like music/album/video, which are often the
# discriminating term (stripping them mis-ranked "The Sound of Music" / "Full Album").
_STOP_Q = set("the a an of and or to in on for with at by from feat ft vs".split())


def _fold(s):
    """Lowercase + strip diacritics so an ASCII query ('beyonce', 'motorhead') matches the
    accented release title ('Beyoncé', 'Motörhead') and vice-versa. Non-Latin scripts
    (Cyrillic/CJK/Greek) survive casefold intact, so those queries still match too."""
    s = unicodedata.normalize("NFKD", s or "")
    return "".join(c for c in s if not unicodedata.combining(c)).casefold()


def _query_terms(q):
    """Meaningful, deduped words of the query, for relevance. Unicode-aware. If the query is
    ALL stopwords (e.g. the band 'The The'), fall back to the raw words rather than []—an
    empty term list would make _relevance treat EVERY result as a match and disable ranking."""
    toks = re.findall(r"[^\W_]+", _fold(q))
    terms = [t for t in toks if len(t) >= 2 and t not in _STOP_Q]
    terms = terms or [t for t in toks if len(t) >= 2] or toks
    return list(dict.fromkeys(terms))                 # dedupe, keep order


def _relevance(title, qterms):
    """0..1 — fraction of query terms present in the title; this is what keeps the thing you
    actually searched for above a high-seed WRONG hit. A term must appear at a WORD BOUNDARY
    (so 'ac'/'dc' from AC/DC don't spuriously match 'soundtrack', and 'cream' doesn't match
    'scream'), but as a prefix so stems/scene-concatenation still match ('radiohead' hits
    'radioheads', 'Radiohead-OKComputer')."""
    if not qterms:
        return 1.0
    t = _fold(title)
    hit = sum(1 for term in qterms
              if re.search(r"(?<![^\W_])" + re.escape(term), t))
    return hit / len(qterms)


def _score(r, qterms=None):
    """Rank so the RIGHT result (matches your query) leads, and among those the ones you can
    actually DOWNLOAD float up. Relevance dominates; then downloadability (seeders for
    torrents — a zero-seed torrent is undownloadable and sinks; Usenet/direct sources are
    downloadable regardless of 'seeders'); then quality + a little recency."""
    rel = _relevance(r.get("title", ""), qterms or [])
    s = max(0, int(r.get("seeders") or 0))     # clamp: a stray -1 ('unknown') must not crash log10
    known = r.get("_seed_known", True)          # False = source didn't report a swarm count
    is_torrent = bool(r.get("magnet") or r.get("torrent_url"))
    if is_torrent:
        dl = math.log10(s + 1) * 220           # 0 at 0 seeders, ~880 at 10k
        if s == 0:
            if not known:
                dl += 80                        # swarm size UNKNOWN (DHT/RSS not scraped) — neutral
            elif r.get("nzb_id"):
                dl = 500                        # also has a Usenet path
            elif r.get("url"):
                dl = 350                        # also has a direct-HTTP path (e.g. verified IA)
            else:
                dl -= 1200                      # genuinely dead: 0 seeders, magnet-only -> bottom
    elif r.get("nzb_id"):
        dl = 500                                # Usenet: downloadable + reliable
    elif r.get("url"):
        dl = 350                                # direct source (Internet Archive / open dir)
    else:
        dl = 0
    q = (r.get("quality") or _quality_of(r.get("title", ""))).lower()
    dl += {"2160p": 45, "1080p": 30, "720p": 15, "480p": 5,
           "flac": 25, "remux": 20, "bluray": 12, "web-dl": 8}.get(q, 0)
    yr = re.search(r"(19|20)\d\d", str(r.get("date", "")) + " " + r.get("title", ""))
    if yr and 2018 <= int(yr.group(0)) <= 2030:
        dl += (int(yr.group(0)) - 2018) * 1.2   # gentle recency nudge
    # relevance dominates (right result first); downloadability orders within it.
    return rel * 4000 + dl


def _norm(r):
    """Force any result (Jackett row or adapter row) into the full common shape."""
    # Distinguish a REPORTED seeder count from an UNKNOWN one: adapters that can't scrape a
    # swarm (DHT/RSS) send seeders=None, and some indexers send -1 for 'unknown'. Either way
    # the count is unknown (not a real 0), so _score must not slap the dead-torrent penalty
    # on it. A clamped non-negative int is still exposed as "seeders" for display/dedup.
    raw = r.get("seeders")
    try:
        si = int(raw)
        known = raw is not None and si >= 0
    except (TypeError, ValueError):
        si, known = 0, False
    cat, cat_conf = _canon_category(r.get("category", ""), r.get("title", ""))
    return {
        "title": r.get("title", ""),
        "source": r.get("source") or r.get("tracker", ""),
        "tracker": r.get("tracker") or r.get("source", ""),
        "seeders": max(0, si),
        "_seed_known": known,
        "size": int(r.get("size") or 0),
        "magnet": r.get("magnet", "") or "",
        "torrent_url": r.get("torrent_url", "") or "",
        "url": r.get("url", "") or "",
        "nzb_id": r.get("nzb_id", "") or "",
        "date": r.get("date", "") or "",
        "category": cat,
        "_cat_conf": cat_conf,
        "quality": r.get("quality") or _quality_of(r.get("title", "")),
    }


def meta_search(q, category=""):
    """Query Jackett trackers AND every external adapter concurrently, merge,
    dedupe, and rank. Returns {"ready": bool, "results": [...]}. 'ready' is False
    only when nothing at all is available yet (Jackett still warming, no adapters)."""
    jk, ext = None, []
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_jk = ex.submit(jackett_search, q)
        f_ext = ex.submit(sources.search_all, q, category, 12) if sources else None
        try:
            jk = f_jk.result(timeout=SEARCH_DEADLINE + 6)
        except Exception:
            jk = None
        if f_ext is not None:
            try:
                ext = f_ext.result(timeout=SEARCH_DEADLINE + 6) or []
            except Exception:
                ext = []
    qterms = _query_terms(q)
    rows = [_norm(r) for r in (jk or [])] + [_norm(r) for r in ext]
    best = {}
    for r in rows:
        k = (_infohash_of(r["magnet"]) or r["torrent_url"]
             or (("nzb:" + r["nzb_id"]) if r["nzb_id"] else "")
             or r["url"] or ("t:" + r["title"].lower()))
        cur = best.get(k)
        if cur is not None:
            # Same file from two sources (e.g. a DHT adapter with a clean title but no swarm
            # count + a tracker with the real seeders): MERGE the swarm size and every download
            # path onto BOTH before picking a winner, so the survivor is never mislabeled as
            # 0-seed/undownloadable just because the higher-relevance copy came from the source
            # that didn't report seeders.
            smax = max(r["seeders"], cur["seeders"])
            r["seeders"] = cur["seeders"] = smax
            if smax > 0 or r.get("_seed_known") or cur.get("_seed_known"):
                r["_seed_known"] = cur["_seed_known"] = True
            for fld in ("magnet", "torrent_url", "url", "nzb_id"):
                v = r.get(fld) or cur.get(fld)
                r[fld] = cur[fld] = v
            # Keep the TRUSTWORTHY (source-labelled) category if either copy has one, so a
            # guessed-wrong duplicate can't erase a real label and drop the row from its scope.
            if r.get("_cat_conf") and not cur.get("_cat_conf"):
                cur["category"], cur["_cat_conf"] = r["category"], True
            elif cur.get("_cat_conf") and not r.get("_cat_conf"):
                r["category"], r["_cat_conf"] = cur["category"], True
        if cur is None or _score(r, qterms) > _score(cur, qterms):
            best[k] = r
    scope = (category or "").strip().lower()
    # "xxx" is an internal exclusion label (adult content), not a reachable dropdown scope — drop it
    # ALWAYS, since the type filter below runs only for the 5 explicit scopes (not "all"/"other").
    rows = [r for r in best.values() if r.get("category") != "xxx"]
    scoped = False
    if scope and scope not in ("all", "other"):
        # Scoping to a type SHOWS that type: keep results OF that category, plus genuinely-unknown
        # ("") ones (never drop a possible match a source just didn't label). Everything of a
        # DIFFERENT known type (a music track under a Movies search) is dropped. Then rank the
        # survivors by the SAME relevance+downloadability order used for "All". If categorisation
        # somehow leaves nothing, fall back to all rows (scoped=False) so the search is never empty.
        cand = [r for r in rows if r.get("category") in (scope, "")]
        if cand:
            rows, scoped = cand, True
    out = sorted(rows, key=lambda r: _score(r, qterms), reverse=True)[:300]
    ready = (jk is not None) or bool(out)
    return {"ready": ready, "results": out, "scoped": scoped}


def _engine_status():
    """Health of every backend engine, so the ONE web UI shows the whole stack.
    The 8 containers are one app — this is the umbrella view over them."""
    def _up(url, t=4):
        try:
            urllib.request.urlopen(url, timeout=t)
            return True
        except urllib.error.HTTPError:
            return True                    # any HTTP response means it's alive
        except Exception:
            return False
    vdetail = ("connected · " + str(VPN_IP)) if vpn_ok else "DOWN — downloads disabled"
    try:                                          # show failover pool status if configured
        with open("/config/.vpn_pool") as _f:
            _p = json.load(_f)
        _tot = int(_p.get("total") or 1)
        if _tot > 1 and vpn_ok:
            vdetail += " · failover: server %s of %s" % (_p.get("active"), _tot)
    except Exception:
        pass
    out = [{"name": "VPN · Proton", "ok": bool(vpn_ok), "detail": vdetail}]
    try:
        n = len(_configured_indexers(_jkey)) if _jkey else 0
    except Exception:
        n = 0
    out.append({"name": "Torrent indexers · Jackett", "ok": n > 0, "detail": f"{n} indexers"})
    out.append({"name": "Deep search · SearXNG", "ok": _up("http://127.0.0.1:8080/healthz"),
                "detail": "metasearch / dork transport"})
    out.append({"name": "DHT crawler · bitmagnet", "ok": _up("http://127.0.0.1:3333/torznab/api?t=caps"),
                "detail": "harvesting the swarm"})
    out.append({"name": "Cloudflare solver · FlareSolverr", "ok": _up("http://127.0.0.1:8191/"),
                "detail": "unlocks protected indexers"})
    if usenet_ready():
        out.append({"name": "Usenet client · SABnzbd",
                    "ok": _up(SAB_URL + "/api?mode=version&apikey=" + SAB_APIKEY),
                    "detail": "Usenet download pipe (Newshosting)"})
    out.append({"name": "Malware scanner · ClamAV", "ok": os.path.exists("/config/clamav/results.json"),
                "detail": "flag-and-keep"})
    out.append({"name": "Media sandbox · transcoder", "ok": _up(TRANSCODER + "/", 3),
                "detail": "isolated no-network decoder"})
    try:
        srcn = len(sources.adapter_names()) if sources else 0
        rep = sources.health_report() if sources else []
    except Exception:
        srcn, rep = 0, []
    cooling = [r["name"] for r in rep if r["state"] == "cooldown"]
    degraded = [r["name"] for r in rep if r["state"] == "degraded"]
    detail = f"{srcn} sources"
    if cooling:
        detail += " · %d auto-paused: %s" % (len(cooling), ", ".join(cooling[:4]))
    elif degraded:
        detail += " · %d flaky: %s" % (len(degraded), ", ".join(degraded[:4]))
    else:
        detail += " · all healthy"
    out.append({"name": "File-source adapters", "ok": srcn > 0, "detail": detail})
    return out


# ----------------------------------------------------------------------------- web UI
OPTS = "".join(f'<option value="{sub}">{label}</option>' for label, sub in CATEGORIES)

LOGIN_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Undertow — login</title><style>
:root{--green:#34dd7d;--green-b:#68f0a6;--font:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",system-ui,sans-serif}
*{box-sizing:border-box}
body{font:15px/1.5 var(--font);margin:0;color:#e8f2ec;-webkit-font-smoothing:antialiased;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:20px;background:radial-gradient(900px 500px at 50% -140px,#0d2a1c,#06110c 62%) fixed,#06110c}
.box{background:linear-gradient(180deg,#0b1913,rgba(11,25,19,.6));border:1px solid rgba(120,220,160,.14);border-radius:20px;padding:34px 30px;width:328px;text-align:center;box-shadow:0 24px 60px rgba(0,0,0,.5)}
.lmark{width:56px;height:56px;border-radius:16px;margin:0 auto 16px;display:grid;place-items:center;background:linear-gradient(155deg,#1a5c3b,#0a2b1c);border:1px solid rgba(120,220,160,.22);box-shadow:0 8px 22px rgba(0,0,0,.4),0 0 30px -8px rgba(52,221,125,.3)}
.lmark svg{width:30px;height:30px}
h1{font-size:21px;font-weight:650;letter-spacing:-.02em;margin:0 0 4px}
.s{color:#8aa89a;font-size:13px;margin-bottom:20px}
input{width:100%;font:inherit;padding:12px 14px;border-radius:11px;border:1px solid rgba(120,220,160,.14);background:#06110c;color:#e8f2ec;margin-bottom:12px;outline:none;transition:.18s}
input:focus{border-color:rgba(52,221,125,.45);box-shadow:0 0 0 3px rgba(52,221,125,.14)}
input::placeholder{color:#5f7568}
button{width:100%;font:600 15px var(--font);padding:12px;border:0;border-radius:11px;background:linear-gradient(180deg,var(--green-b),var(--green));color:#04140b;cursor:pointer;box-shadow:inset 0 1px 0 rgba(255,255,255,.35);transition:.16s}
button:hover{filter:brightness(1.06)}button:active{transform:scale(.98)}
.err{color:#ff8f8f;font-size:13px;margin-bottom:12px}
</style></head><body><form class=box method=post action=/login>
<div class=lmark><svg viewBox="0 0 24 24" fill="none"><path d="M12 2.6 20 6v6.2c0 5-3.4 8.3-8 9.8-4.6-1.5-8-4.8-8-9.8V6l8-3.4Z" fill="rgba(52,221,125,.14)" stroke="#68f0a6" stroke-width="1.5" stroke-linejoin="round"/><path d="M12 8.4v6.4M8.7 11.6 12 14.9l3.3-3.3" stroke="#68f0a6" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
<h1>Undertow</h1><div class=s>Enter your password to continue</div>
__ERR__
<input type=password name=pw placeholder=Password autofocus>
<button>Log in</button></form></body></html>"""

PAGE = r"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Undertow</title><style>
:root{
--canvas:#06110c;--glow:#0d2a1c;--surface:#0b1913;--surface-2:#0f2318;--surface-3:#122a1d;
--hair:rgba(120,220,160,.12);--hair2:rgba(120,220,160,.22);
--text:#e8f2ec;--muted:#8aa89a;--faint:#5f7568;
--green:#34dd7d;--green-b:#68f0a6;--green-d:#0f3826;--glowc:rgba(52,221,125,.28);
--blue:#57b6ff;--violet:#b98bff;--amber:#f2b83f;--red:#ff6f6f;
--r:16px;--rs:11px;--pill:999px;
--font:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI",system-ui,sans-serif;
--mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,monospace;
--ease:cubic-bezier(.4,0,.2,1);--sh:0 12px 34px rgba(0,0,0,.5)}
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 var(--font);color:var(--text);-webkit-font-smoothing:antialiased;
background:radial-gradient(1100px 560px at 50% -160px,var(--glow),var(--canvas) 62%) fixed,var(--canvas);min-height:100vh}
.wrap{max-width:860px;margin:0 auto;padding:26px 18px 64px}
.top{display:flex;align-items:center;gap:13px;margin-bottom:4px}
.mark{width:42px;height:42px;border-radius:12px;flex:0 0 auto;display:grid;place-items:center;
background:linear-gradient(155deg,#1a5c3b,#0a2b1c);border:1px solid var(--hair2);
box-shadow:0 6px 18px rgba(0,0,0,.4),0 0 24px -8px var(--glowc),inset 0 1px 0 rgba(255,255,255,.06)}
.mark svg{width:23px;height:23px}
.brand{display:flex;flex-direction:column;gap:1px;line-height:1.12}
h1{font-size:19px;font-weight:650;letter-spacing:-.015em;margin:0}
.brandsub{font-size:11.5px;color:var(--muted);letter-spacing:.02em}
.grow{flex:1}
a.lo{color:var(--faint);font-size:12.5px;text-decoration:none;padding:7px 12px;border-radius:var(--pill);border:1px solid transparent;transition:.18s var(--ease)}
a.lo:hover{color:var(--text);border-color:var(--hair);background:var(--surface)}
.sub{color:var(--muted);font-size:12.5px;margin:4px 0 18px 55px}
.sub code{font-family:var(--mono);font-size:12px;color:#bfe1cf;background:rgba(52,221,125,.08);padding:1px 6px;border-radius:5px}
.vpn{display:flex;align-items:center;gap:10px;padding:12px 16px;border-radius:var(--rs);font-size:13.5px;font-weight:550;margin-bottom:20px;border:1px solid var(--hair)}
.vpn::before{content:"";width:9px;height:9px;border-radius:50%;flex:0 0 auto;background:var(--faint)}
.ok{background:linear-gradient(180deg,rgba(52,221,125,.10),rgba(52,221,125,.03));color:#a7ecc6;border-color:rgba(52,221,125,.28)}
.ok::before{background:var(--green);box-shadow:0 0 0 4px rgba(52,221,125,.16),0 0 12px var(--green)}
.bad{background:rgba(255,111,111,.08);color:#ffc2c2;border-color:rgba(255,111,111,.3)}
.bad::before{background:var(--red)}
form.add,form.search{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}
input[type=text],select{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--hair);border-radius:var(--rs);padding:12px 14px;outline:none;transition:.18s var(--ease)}
input[type=text]{flex:1;min-width:220px}
input[type=text]:focus,select:focus,.lib-search:focus{border-color:rgba(52,221,125,.45);box-shadow:0 0 0 3px rgba(52,221,125,.14)}
input::placeholder{color:var(--faint)}
#q,#sq{padding-left:42px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%235f7568' stroke-width='1.8' stroke-linecap='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m20 20-3.2-3.2'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:left 13px center;background-size:18px}
select{cursor:pointer;padding-right:34px;appearance:none;-webkit-appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12' fill='none' stroke='%238aa89a' stroke-width='1.6' stroke-linecap='round'%3E%3Cpath d='M3 4.5 6 7.5 9 4.5'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 13px center}
button{font:600 14px var(--font);color:#04140b;background:linear-gradient(180deg,var(--green-b),var(--green));border:0;border-radius:var(--rs);padding:12px 18px;cursor:pointer;transition:.16s var(--ease);box-shadow:0 6px 18px -4px var(--glowc),inset 0 1px 0 rgba(255,255,255,.35)}
button:hover{filter:brightness(1.06)}button:active{transform:scale(.975)}
button:disabled{background:var(--surface-2);color:var(--faint);box-shadow:none;cursor:not-allowed;filter:none}
button.sec{font-size:12.5px;font-weight:600;color:var(--green-b);background:rgba(52,221,125,.08);border:1px solid rgba(52,221,125,.24);padding:6px 12px;box-shadow:none}
button.sec:hover{background:rgba(52,221,125,.15);filter:none}
details{margin:6px 0 14px}summary{cursor:pointer;color:var(--muted);font-size:13px}summary:hover{color:var(--text)}
h3{font-size:13.5px;color:var(--muted);margin:20px 0 12px 2px;font-weight:600}
.tabs{display:inline-flex;gap:3px;padding:4px;margin-bottom:24px;border-radius:var(--pill);background:var(--surface);border:1px solid var(--hair);max-width:100%;overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tabbtn{border:0;background:transparent;color:var(--muted);font:600 13px var(--font);cursor:pointer;padding:8px 15px;border-radius:var(--pill);white-space:nowrap;display:inline-flex;align-items:center;gap:7px;transition:.18s var(--ease)}
.tabbtn svg{width:15px;height:15px;opacity:.85}
.tabbtn:hover{color:var(--text)}
.tabbtn.active{color:#04140b;background:linear-gradient(180deg,var(--green-b),var(--green));box-shadow:0 4px 14px rgba(0,0,0,.35),0 0 22px -6px var(--glowc),inset 0 1px 0 rgba(255,255,255,.35)}
.tabbtn.active svg{opacity:1}
.tab-panel[hidden]{display:none}
.aibtn{font:600 14px var(--font);color:#fff;background:linear-gradient(180deg,#c297ff,#8957e5);border:0;border-radius:var(--rs);padding:12px 16px;cursor:pointer;box-shadow:0 6px 18px -4px rgba(185,139,255,.4),inset 0 1px 0 rgba(255,255,255,.35)}
.aibtn:hover{filter:brightness(1.07)}.aibtn[hidden]{display:none}
.ainote{margin:0 0 12px 2px;font-size:12.5px;color:#cbb0ff;background:rgba(185,139,255,.1);border:1px solid rgba(185,139,255,.25);border-radius:9px;padding:8px 12px;line-height:1.5}
.ainote[hidden]{display:none}
.aiexplain{background:rgba(185,139,255,.1);border:1px solid rgba(185,139,255,.3);color:#cbb0ff;border-radius:9px;padding:6px 11px;font:600 12px var(--font);cursor:pointer}
.aiexplain:hover{background:rgba(185,139,255,.18)}
.aibox{margin-top:9px;font-size:12.5px;color:#c9dccf;background:rgba(185,139,255,.07);border:1px solid rgba(185,139,255,.22);border-radius:9px;padding:9px 12px;line-height:1.55}
.aiset{background:linear-gradient(180deg,var(--surface),rgba(11,25,19,.4));border:1px solid rgba(185,139,255,.22);border-radius:var(--r);padding:14px 16px;margin-bottom:16px}
.aiset h4{margin:0 0 4px;font-size:14px;font-weight:650}
.aiset .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
.aiset input[type=text]{min-width:180px}
.switch{position:relative;display:inline-block;width:44px;height:24px;flex:0 0 auto}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:var(--surface-3);border:1px solid var(--hair);border-radius:24px;cursor:pointer;transition:.2s}
.slider:before{content:"";position:absolute;height:18px;width:18px;left:2px;top:2px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:linear-gradient(180deg,#c297ff,#8957e5);border-color:transparent}
.switch input:checked+.slider:before{transform:translateX(20px)}
#tab-library{padding:0}
.t{background:linear-gradient(180deg,var(--surface),rgba(11,25,19,.55));border:1px solid var(--hair);border-radius:var(--r);padding:14px 16px;margin:11px 0;transition:.18s var(--ease)}
.t:hover{border-color:var(--hair2);transform:translateY(-1px);box-shadow:var(--sh)}
.tn{font-weight:600;font-size:15px;letter-spacing:-.01em;line-height:1.35;word-break:break-word}
.bar{height:6px;background:var(--surface-3);border-radius:99px;margin:9px 0;overflow:hidden}
.fill{height:100%;background:linear-gradient(90deg,var(--green-d),var(--green));transition:width .4s}
.meta{color:var(--muted);font-size:12px;display:flex;gap:11px;flex-wrap:wrap;align-items:center;margin-top:9px;font-variant-numeric:tabular-nums}
.acts{display:flex;gap:8px;margin-top:11px;flex-wrap:wrap}
.tag{background:var(--surface-2);border:1px solid var(--hair);border-radius:var(--pill);padding:2px 9px;font-size:11px;color:var(--text);text-transform:capitalize}
.qual{background:rgba(87,182,255,.12);color:#9ed0ff;border:1px solid rgba(87,182,255,.25);border-radius:var(--pill);padding:2px 9px;font-size:11px;font-weight:600}
.typ{background:rgba(185,139,255,.12);color:#cbb0ff;border:1px solid rgba(185,139,255,.25);border-radius:var(--pill);padding:2px 9px;font-size:11px;text-transform:capitalize}
.viacrawl{background:rgba(185,139,255,.14);color:#cbb0ff;border:1px solid rgba(185,139,255,.3);border-radius:var(--pill);padding:2px 9px;font-size:11px;font-weight:600}
.viasearch{background:var(--surface-2);color:var(--muted);border:1px solid var(--hair);border-radius:var(--pill);padding:2px 9px;font-size:11px}
.srcintro{background:linear-gradient(180deg,var(--surface),rgba(11,25,19,.4));border:1px solid var(--hair);border-radius:var(--r);padding:13px 15px;margin-bottom:14px;font-size:13px;color:#adc4b7;line-height:1.55}
.srcintro b{color:var(--text)}
.empty{color:var(--faint);text-align:center;padding:34px 0}
form.huntform{display:flex;gap:10px;margin:14px 0 8px;flex-wrap:wrap}
.hdesc{width:100%;margin:0 0 4px}
.hunt{background:linear-gradient(180deg,var(--surface),rgba(11,25,19,.55));border:1px solid var(--hair);border-radius:var(--r);padding:15px 17px;margin:12px 0;transition:.18s var(--ease)}
.hunt:hover{border-color:rgba(52,221,125,.28)}
.hunttop{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.huntgoal{font-weight:650;font-size:15px;color:var(--text);display:flex;align-items:center;gap:9px;line-height:1.35}
.huntdot{width:9px;height:9px;border-radius:50%;flex:0 0 auto;box-shadow:0 0 8px -1px currentColor}
.huntstatus{font-size:11.5px;color:var(--muted);text-transform:capitalize;white-space:nowrap;font-variant-numeric:tabular-nums}
.huntrecent{font-size:12px;color:var(--faint);margin-top:8px;font-style:italic;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.huntbrain{font-size:12.5px;margin:2px 0 12px;padding:8px 12px;border-radius:10px;border:1px solid var(--hair);background:rgba(6,17,12,.4);line-height:1.5}
.huntbrain:empty{display:none}
.huntrecent:empty{display:none}
.huntres{margin-top:12px;border-top:1px solid var(--hair);padding-top:6px}
.huntres .t{background:rgba(11,25,19,.4);padding:11px 13px;margin:8px 0}
.lib-toolbar{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.lib-search{flex:1 1 240px;min-width:0;background:var(--surface);border:1px solid var(--hair);border-radius:var(--rs);color:var(--text);font:inherit;font-size:15px;padding:12px 14px;outline:none}
.lib-search::placeholder{color:var(--faint)}
.lib-btn{background:var(--surface);border:1px solid var(--hair);border-radius:var(--rs);color:var(--text);font:inherit;font-size:14px;cursor:pointer;padding:11px 14px;white-space:nowrap;transition:.16s var(--ease)}
.lib-btn:hover{background:var(--surface-2);border-color:var(--hair2)}
.lib-count{color:var(--muted);font-size:13px;margin:0 0 14px 2px}
.lib-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:16px}
.lib-tile{background:var(--surface);border:1px solid var(--hair);border-radius:14px;overflow:hidden;cursor:pointer;position:relative;transition:transform .18s var(--ease),box-shadow .18s var(--ease),border-color .18s var(--ease)}
.lib-tile:hover{transform:translateY(-3px);box-shadow:var(--sh);border-color:var(--hair2);z-index:2}
.lib-poster{width:100%;aspect-ratio:2/3;object-fit:cover;display:block;background:var(--canvas)}
.lib-meta{padding:9px 11px 11px}
.lib-title{font-size:13.5px;font-weight:600;color:var(--text);line-height:1.3;margin:0 0 5px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.lib-sub{display:flex;align-items:center;gap:6px}
.lib-year{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.lib-badge{font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 7px;border-radius:var(--pill);color:var(--text);background:var(--surface-2);border:1px solid var(--hair)}
.lib-badge.t-movie{background:rgba(52,221,125,.15);border-color:rgba(52,221,125,.35);color:var(--green-b)}
.lib-badge.t-tv{background:rgba(87,182,255,.15);border-color:rgba(87,182,255,.35);color:#9ed0ff}
.lib-badge.t-album{background:rgba(185,139,255,.15);border-color:rgba(185,139,255,.35);color:#cbb0ff}
.lib-badge.t-doc{background:rgba(242,184,63,.15);border-color:rgba(242,184,63,.35);color:#f3cd78}
.lib-badge.t-other{background:var(--surface-2);border-color:var(--hair);color:var(--muted)}
.lib-empty{color:var(--muted);text-align:center;padding:60px 20px;font-size:15px;border:1px dashed var(--hair);border-radius:14px}
.lib-modal{position:fixed;inset:0;z-index:1000;background:rgba(2,8,5,.8);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:flex;align-items:flex-start;justify-content:center;padding:28px 16px;overflow-y:auto}
.lib-modal[hidden]{display:none}
.lib-dialog{background:var(--surface);border:1px solid var(--hair2);border-radius:18px;width:100%;max-width:820px;box-shadow:0 30px 70px rgba(0,0,0,.7);position:relative;overflow:hidden}
.lib-close{position:absolute;top:12px;right:12px;z-index:3;width:34px;height:34px;border-radius:50%;background:rgba(6,17,12,.8);border:1px solid var(--hair);color:var(--text);font-size:18px;line-height:1;cursor:pointer}
.lib-close:hover{background:var(--red);border-color:var(--red);color:#fff}
.lib-dhead{display:flex;gap:18px;padding:20px}
.lib-dposter{width:150px;flex:0 0 150px;aspect-ratio:2/3;object-fit:cover;border-radius:10px;background:var(--canvas)}
.lib-dinfo{min-width:0;flex:1}
.lib-dtitle{font-size:22px;font-weight:700;letter-spacing:-.02em;margin:4px 0 8px;color:var(--text)}
.lib-drow{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.lib-dsize{color:var(--muted);font-size:13px;font-variant-numeric:tabular-nums}
.lib-overview{color:#c3d6cb;font-size:14px;line-height:1.55;margin:8px 0 0}
.lib-player{padding:0 20px}
.lib-player video,.lib-player audio{width:100%;border-radius:10px;background:#000;display:block}
.lib-player audio{background:var(--canvas)}
.lib-transnote{color:var(--amber);font-size:12px;margin:8px 0 0}
.lib-prep{margin:14px 20px;padding:16px;border:1px solid var(--hair);border-radius:12px;background:rgba(11,25,19,.5);color:#adc4b7;font-size:14px;text-align:center;line-height:1.6}
.lib-prep small{color:var(--faint);font-size:12px}
.lib-prep-err{color:#f8827b;border-color:rgba(248,81,73,.4)}
.lib-spin{display:inline-block;width:13px;height:13px;border:2px solid rgba(52,221,125,.3);border-top-color:var(--green);border-radius:50%;vertical-align:-2px;margin-right:6px;animation:libspin .8s linear infinite}
@keyframes libspin{to{transform:rotate(360deg)}}
.lib-files{padding:16px 20px 22px}
.lib-files h4{margin:0 0 10px;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.lib-file{display:flex;align-items:center;gap:10px;padding:10px 11px;border:1px solid var(--hair);border-radius:10px;margin-bottom:8px;background:var(--surface-2)}
.lib-fname{flex:1;min-width:0;font-size:13.5px;color:var(--text);word-break:break-word}
.lib-fsize{font-size:12px;color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}
.lib-play,.lib-dl{font:inherit;font-size:12.5px;text-decoration:none;white-space:nowrap;padding:7px 12px;border-radius:9px;cursor:pointer;font-weight:600}
.lib-play{background:linear-gradient(180deg,var(--green-b),var(--green));border:0;color:#04140b}
.lib-play:hover{filter:brightness(1.06)}
.lib-dl{background:rgba(52,221,125,.08);border:1px solid rgba(52,221,125,.24);color:var(--green-b)}
.lib-dl:hover{background:rgba(52,221,125,.15)}
.lib-vlc{font:inherit;font-size:12.5px;white-space:nowrap;padding:7px 12px;border-radius:9px;cursor:pointer;background:rgba(242,184,63,.14);border:1px solid rgba(242,184,63,.4);color:#f3cd78;font-weight:600}
.lib-vlc:hover{background:rgba(242,184,63,.22)}
.lib-actions{margin-top:12px}
.lib-del{font:inherit;font-size:12.5px;font-weight:600;white-space:nowrap;padding:7px 13px;border-radius:9px;cursor:pointer;background:rgba(248,81,73,.12);border:1px solid rgba(248,81,73,.4);color:#f8827b}
.lib-del:hover{background:rgba(248,81,73,.2)}
.lib-ext{padding:0 20px}
.lib-extbox{background:var(--surface-2);border:1px solid var(--hair);border-radius:10px;padding:12px 14px;margin-top:4px}
.lib-exttitle{font-size:13px;font-weight:600;color:var(--text);margin-bottom:8px}
.lib-extrow{display:flex;gap:8px;margin-bottom:8px}
.lib-exturl{flex:1;min-width:0;font-family:var(--mono);font-size:12px;background:var(--canvas);border:1px solid var(--hair);border-radius:8px;color:var(--muted);padding:8px 10px}
.lib-extbtns{display:flex;gap:8px;flex-wrap:wrap}
.lib-extlink{font:inherit;font-size:12.5px;text-decoration:none;white-space:nowrap;padding:8px 12px;border-radius:9px;cursor:pointer;background:rgba(52,221,125,.08);border:1px solid rgba(52,221,125,.24);color:var(--green-b)}
.lib-extlink:hover{background:rgba(52,221,125,.15)}
.lib-exthint{color:var(--muted);font-size:11.5px;margin-top:9px;line-height:1.5}
.lib-shield{position:absolute;top:7px;left:7px;background:rgba(255,111,111,.92);color:#fff;border-radius:7px;font-size:10px;font-weight:700;padding:2px 7px;z-index:1}
.lib-secbanner{background:rgba(255,111,111,.1);border:1px solid rgba(255,111,111,.3);color:#ffc2c2;border-radius:var(--rs);padding:11px 13px;margin-bottom:12px;font-size:13px;line-height:1.5}
.lib-sec{border-radius:var(--rs);padding:10px 13px;margin:0 20px 4px;font-size:13px;line-height:1.5}
.lib-sec-ok{background:rgba(52,221,125,.09);border:1px solid rgba(52,221,125,.24);color:#a7ecc6}
.lib-sec-bad{background:rgba(255,111,111,.1);border:1px solid rgba(255,111,111,.3);color:#ffc2c2}
.lib-sec-pending{background:var(--surface-2);border:1px solid var(--hair);color:var(--muted)}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
@media (max-width:520px){.lib-dhead{flex-direction:column;align-items:center;text-align:center}.lib-dposter{width:130px;flex-basis:auto}.lib-dtitle{font-size:19px}.lib-grid{grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:12px}.sub{margin-left:2px}}
</style></head><body><div class=wrap>
<div class=top>
<div class=mark><svg viewBox="0 0 24 24" fill="none"><path d="M12 2.6 20 6v6.2c0 5-3.4 8.3-8 9.8-4.6-1.5-8-4.8-8-9.8V6l8-3.4Z" fill="rgba(52,221,125,.14)" stroke="#68f0a6" stroke-width="1.5" stroke-linejoin="round"/><path d="M12 8.4v6.4M8.7 11.6 12 14.9l3.3-3.3" stroke="#68f0a6" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
<div class=brand><h1>Undertow</h1><span class=brandsub>Beneath the surface · VPN-locked</span></div>
<div class=grow></div>
<a class=lo href=# onclick="lo()">Log out</a></div>
<div class=sub>download-only · never seeds · saving to <code>__SAVE__</code></div>
<div id=vpn class=vpn>checking VPN…</div>
<div class=tabs>
<button class="tabbtn active" data-tab=search onclick="showTab('search')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg>Search</button>
<button class="tabbtn" data-tab=sources onclick="showTab('sources')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"/></svg>Sources</button>
<button class="tabbtn" data-tab=hunt onclick="showTab('hunt')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12 18.5 5.5"/></svg>Deep Hunt</button>
<button class="tabbtn" data-tab=downloads onclick="showTab('downloads')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12m0 0 4.5-4.5M12 15l-4.5-4.5M4 19h16"/></svg>Downloads <span id=dlcount></span></button>
<button class="tabbtn" data-tab=library onclick="showTab('library')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="3"/><path d="m10 9 5 3-5 3Z"/></svg>Library</button>
<button class="tabbtn" data-tab=engines onclick="showTab('engines')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="3.2"/><path d="M12 3.5v2.2M12 18.3v2.2M20.5 12h-2.2M5.7 12H3.5M18 6l-1.6 1.6M7.6 16.4 6 18M18 18l-1.6-1.6M7.6 7.6 6 6"/></svg>Engines</button>
</div>
<div id=tab-search class=tab-panel>
<form class=search onsubmit="search(event)">
<input type=text id=q placeholder="search for movies, shows, music, anything…" autocomplete=off>
<select id=cat>__OPTS__</select>
<button type=button id=aibtn class=aibtn hidden onclick="smartSearch()" title="Ask in plain English — the local AI picks the keywords + category">✨ AI</button>
<button id=go>Search</button></form>
<div id=ainote class=ainote hidden></div>
<details><summary>…or paste a magnet link directly</summary>
<form class=add onsubmit="add(event)">
<input type=text id=m placeholder="magnet: link" autocomplete=off>
<button>Download</button></form>
<button class=sec onclick="reg()">↪ Make magnet links open here</button></details>
<div id=results></div>
</div>
<div id=tab-sources class=tab-panel hidden>
<div class=srcintro>🛰 <b>Sources mode</b> — instead of files, this finds the <b>open directories & file servers</b> where files live, so you can browse them yourself. Search a topic and (optionally) a file type; every result below is a confirmed, browsable open directory.</div>
<form class=search onsubmit="findSources(event)">
<input type=text id=sq placeholder="topic — e.g. jazz, apollo, linux, synthwave…" autocomplete=off>
<input type=text id=sext placeholder="type (optional): pdf, flac, mp4…" autocomplete=off style="max-width:150px">
<button id=sgo>Find servers</button></form>
<div id=srcresults></div>
</div>
<div id=tab-hunt class=tab-panel hidden>
<div class=srcintro>🔦 <b>Deep Hunt</b> — for when a normal search comes up empty. Give it a target and it grinds in the <b>background for as long as it takes</b> — days, weeks — inventing new angles (rephrasings, translations, open-directory dorks, source pivots) with the local AI, going deeper into anything promising, and piling up <b>every</b> result until you stop it. Keeps running across reboots. Optional: works without AI too, just less clever.</div>
<form class=huntform onsubmit="createHunt(event)">
<input type=text id=hgoal placeholder="what to hunt for — e.g. obscure 1970s japanese ambient records" autocomplete=off>
<select id=hcat>__OPTS__</select>
<select id=hpace title="how hard to grind"><option value=gentle>Gentle</option><option value=normal selected>Normal</option><option value=aggressive>Aggressive</option></select>
<label class=huntwatch title="Keep watching: once it runs out of ideas, re-sweep on a schedule so files uploaded LATER are still caught. Pairs with notifications."><input type=checkbox id=hwatch onchange="document.getElementById('hsweep').disabled=!this.checked"> 👁 Keep watching</label>
<select id=hsweep disabled title="how often to re-sweep for new uploads"><option value=6h>every 6h</option><option value=daily selected>daily</option><option value=weekly>weekly</option></select>
<button id=hgo>🔦 Start hunt</button></form>
<input type=text id=hdesc class=hdesc placeholder="optional — what a good match looks like (helps the AI judge results)" autocomplete=off>
<div id=huntbrain class=huntbrain></div>
<div id=hunts></div>
</div>
<div id=tab-engines class=tab-panel hidden>
<div class=srcintro>⚙ <b>Engines</b> — this app is one umbrella over its backend services. Everything below runs from the single dashboard card; you only ever use this one interface.</div>
<div id=aisettings></div>
<div id=notifysettings></div>
<div id=engines></div>
</div>
<div id=tab-downloads class=tab-panel hidden>
<div id=list></div>
<div id=dlempty class=empty>No downloads yet — find something in Search.</div>
</div>
<div id="tab-library" class="tab-panel" hidden>
  <div class="lib-toolbar">
    <input id="lq" class="lib-search" type="search" placeholder="Search your library…" oninput="libFilter()" autocomplete="off">
    <button class="lib-btn" onclick="loadLibrary()">↻ Refresh</button>
  </div>
  <div id="libSecBanner"></div>
  <p id="libCount" class="lib-count"></p>
  <div id="libGrid" class="lib-grid"></div>
  <div id="libModal" class="lib-modal" hidden onclick="libModalBgClose(event)">
    <div class="lib-dialog" role="dialog" aria-modal="true">
      <button class="lib-close" onclick="libCloseModal()" aria-label="Close">✕</button>
      <div id="libModalBody"></div>
    </div>
  </div>
</div>
</div><script>
function fmt(b){if(b<1024)return b+' B';let u=['KB','MB','GB','TB'],i=-1;do{b/=1024;i++}while(b>=1024&&i<3);return b.toFixed(1)+' '+u[i]}
function rate(b){return b>0?fmt(b)+'/s':'—'}
let VPN=false;
async function add(e){e.preventDefault();if(!VPN)return;let m=document.getElementById('m');if(!m.value.trim())return;
await fetch('/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'magnet='+encodeURIComponent(m.value.trim())+'&cat='+document.getElementById('cat').value});m.value='';tick()}
async function del(ih){if(!confirm('Remove from list? (downloaded files are kept)'))return;await fetch('/remove?ih='+ih,{method:'POST'});tick()}
async function ps(ih){await fetch('/pause?ih='+ih,{method:'POST'});tick()}
async function rs(ih){await fetch('/resume?ih='+ih,{method:'POST'});tick()}
async function rc(ih){if(!confirm('Force recheck? Re-verifies all downloaded pieces on disk.'))return;await fetch('/recheck?ih='+ih,{method:'POST'});tick()}
async function lo(){await fetch('/logout',{method:'POST'});location.href='/login'}
function reg(){try{navigator.registerProtocolHandler('magnet',location.origin+'/?magnet=%s');alert('Done. Magnet links will now open vpntorrent.')}catch(err){alert('Not supported here (needs HTTPS): '+err)}}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
let R=[];
var LIVE_GEN=0;
async function liveCheck(gen){
  if(!R.length)return;
  var batch=R.slice(0,20).map(function(t,i){return {i:i,url:t.url||'',magnet:t.magnet||'',torrent_url:t.torrent_url||'',nzb_id:t.nzb_id||'',seeders:t.seeders||0};});
  try{
    var r=await fetch('/livecheck',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(batch)});
    if(!r.ok||gen!==LIVE_GEN)return;               // a newer search superseded this check
    var d=await r.json();
    (d.results||[]).forEach(function(x){
      if(gen!==LIVE_GEN)return;
      var el=document.getElementById('live'+x.i);if(!el)return;
      if(x.live==='live'){el.style.color='#3fb950';el.textContent=(x.peers!=null&&x.peers>0)?('✓ '+x.peers+' seeding now'):'✓ available';}
      else if(x.live==='dead'){el.style.color='#f85149';el.textContent='✗ dead link';
        var row=el.closest('.t');if(row){row.style.opacity='.45';if(row.parentNode)row.parentNode.appendChild(row);}}
      else{el.textContent='';}
    });
  }catch(e){}
}
var AI_ON=false,AI_READY=false;
async function refreshAi(){try{var r=await fetch('/ai/status');var s=await r.json();AI_ON=!!s.enabled;AI_READY=!!s.reachable;var b=document.getElementById('aibtn');if(b)b.hidden=!AI_ON;}catch(e){AI_ON=false;AI_READY=false;}}
// On-demand GPU: if the AI is asleep, wake it and wait for it to come up, reporting progress via
// cb(seconds). Returns true once reachable, false on timeout. Model loads on the GPU on first use.
async function ensureAiReady(cb){
  if(AI_READY)return true;
  try{await fetch('/ai/wake',{method:'POST'});}catch(e){}
  var t0=Date.now();
  while(Date.now()-t0<170000){
    if(cb)cb(Math.round((Date.now()-t0)/1000));
    try{var s=await (await fetch('/ai/status')).json();if(s.state==='ready'){AI_READY=true;return true;}}catch(e){}
    await new Promise(function(r){setTimeout(r,2000);});
  }
  return false;
}
async function smartSearch(){var q=document.getElementById('q').value.trim();if(!q||!VPN)return;
var note=document.getElementById('ainote');note.hidden=false;
if(!AI_READY){var ok=await ensureAiReady(function(secs){note.innerHTML='✨ Waking the local AI — loading the model on the GPU… <b>'+secs+'s</b> <span style="color:#8b949e">(first run from cold can take ~60–90s; instant afterwards)</span>';});
  if(!ok){note.textContent='✨ AI didn’t come up in time — searching your text as-is.';search(new Event('submit'));return;}}
note.textContent='✨ AI is interpreting your request…';
try{var r=await fetch('/ai/smart',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:q})});var s=await r.json();
if(s.ai&&s.query){document.getElementById('q').value=s.query;if(s.category){var sel=document.getElementById('cat');for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===s.category){sel.selectedIndex=i;break;}}}
note.innerHTML='✨ Interpreted as “<b>'+esc(s.query)+'</b>” in <b>'+esc(s.category||'all')+'</b>';}
else{note.textContent='✨ AI unavailable — searching your text as-is.';}}catch(e){note.textContent='✨ AI unavailable — searching your text as-is.';}
search(new Event('submit'));}
async function explainResult(i,btn){var t=R[i];btn.disabled=true;btn.textContent='✨ …';
if(!AI_READY){var ok=await ensureAiReady(function(secs){btn.textContent='✨ waking '+secs+'s';});
  if(!ok){btn.disabled=false;btn.textContent='✨ Explain';return;}
  btn.textContent='✨ …';}
try{var ctx=(t.source?('Source: '+t.source):'')+(t.category?(' · Type: '+t.category):'')+(t.size?(' · '+fmt(t.size)):'');
var r=await fetch('/ai/explain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:t.title,context:ctx})});
var box=document.getElementById('aibox'+i);
if(!r.ok){
  // Never fail silently: the old code reset the button on ANY error, so a 403 or a
  // timeout looked exactly like "nothing happened" and there was nothing to report.
  var why=r.status===403?'the browser blocked the request — reload the page (Ctrl+Shift+R)'
        :r.status===401?'your session expired — reload and log in'
        :('the server returned '+r.status);
  if(box){box.textContent='Could not explain: '+why;box.hidden=false;}
  btn.disabled=false;btn.textContent='✨ Explain';return;}
var s=await r.json();
if(box){box.textContent=s.text||s.error||'(the local AI returned nothing — check the Engines tab)';box.hidden=false;}
btn.textContent='✨ Explained';}
catch(e){var box2=document.getElementById('aibox'+i);
  if(box2){box2.textContent='Could not reach the AI: '+(e&&e.message?e.message:e);box2.hidden=false;}
  btn.disabled=false;btn.textContent='✨ Explain';}}
async function search(e){e.preventDefault();let q=document.getElementById('q').value.trim();if(!q||!VPN)return;
let el=document.getElementById('results');el.innerHTML='<div class=empty>Searching dozens of sources…</div>';
let cat=document.getElementById('cat').value;
let r=await fetch('/search?q='+encodeURIComponent(q)+'&cat='+encodeURIComponent(cat));if(r.status==401){location.href='/login';return}
let d=await r.json();
if(!d.ready){el.innerHTML='<div class=empty>Search engine is still starting up — give it a minute and try again.</div>';return}
R=d.results;
if(!R.length){el.innerHTML='<div class=empty>No results found across any source.</div>';return}
var _cs=document.getElementById('cat');var _cv=_cs.value;var _cl=_cs.options[_cs.selectedIndex].text;
var _typed=(_cv&&_cv!=='all'&&_cv!=='other');var _hdr;
if(_typed&&d.scoped){_hdr=R.length+' '+esc(_cl)+' matching “'+esc(q)+'” — most relevant + best-seeded first';}
else if(_typed){_hdr=R.length+' results for “'+esc(q)+'” — no clear '+esc(_cl)+' matches, so showing all types';}
else{_hdr=R.length+' results for “'+esc(q)+'” (all types) — most relevant + best-seeded first';}
el.innerHTML='<h3>'+_hdr+'</h3>'+R.map((t,i)=>{
var seedTxt=t.nzb_id?'⚡ Usenet':((t.magnet||t.torrent_url)?('▲ '+t.seeders+' seeders'):'library source');
var seedCol=t.nzb_id?'#68f0a6':(t.seeders>0?'#3fb950':'#8b949e');
var qual=t.quality?('<span class=qual>'+esc(t.quality)+'</span>'):'';
var typ=t.category?('<span class=typ>'+esc(t.category)+'</span>'):'';
var dt=t.date?('<span style="color:#8b949e">'+esc(String(t.date).slice(0,10))+'</span>'):'';
var act;
if(t.magnet||t.torrent_url||t.nzb_id){act='<button class=sec onclick="dl('+i+',this)">⬇ Download</button>';}
else if(t.url){act='<a class="sec" style="text-decoration:none" href="'+esc(t.url)+'" target=_blank rel=noopener>Open ↗</a>';}
else{act='';}
var xp=AI_ON?('<button class=aiexplain onclick="explainResult('+i+',this)">✨ Explain</button>'):'';
return '<div class=t><div class=tn>'+esc(t.title)+'</div>'+
'<div class=meta><span class=tag>'+esc(t.source||t.tracker)+'</span>'+typ+
'<span style="color:'+seedCol+'">'+seedTxt+'</span>'+
'<span id=live'+i+' style="font-weight:600" title="liveness — is this actually retrievable right now?"></span>'+
(t.size?'<span>'+fmt(t.size)+'</span>':'')+qual+dt+xp+act+'</div>'+
'<div class=aibox id=aibox'+i+' hidden></div></div>';}).join('');LIVE_GEN++;liveCheck(LIVE_GEN);}
async function dl(i,btn){var t=R[i];btn.disabled=true;
// Say "Adding…" until the server actually confirms. This used to print "Added ✓"
// before the request was even sent, so a rejected add — or a usenet job that never
// appeared — still looked successful, with nothing to act on.
btn.textContent='Adding…';
var body='cat='+encodeURIComponent(document.getElementById('cat').value);
if(t.magnet)body+='&magnet='+encodeURIComponent(t.magnet);
else if(t.torrent_url)body+='&torrent_url='+encodeURIComponent(t.torrent_url);
else if(t.nzb_id)body+='&nzb_id='+encodeURIComponent(t.nzb_id);
try{
  var res=await fetch('/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body});
  if(!res.ok){
    var msg='';try{msg=(await res.text()).slice(0,140);}catch(e){}
    btn.disabled=false;btn.textContent='⚠ Retry';
    if(msg)btn.title=msg;
    alert('Could not add it: '+(msg||('server returned '+res.status)));
  } else {
    btn.textContent='Added ✓';
    // Usenet hands off to SABnzbd, so it shows up under Downloads as a "usenet" row
    // rather than in the torrent engine — nudge the user to look there.
    if(t.nzb_id)btn.title='Sent to the Usenet downloader — see the Downloads tab';
  }
}catch(e){btn.disabled=false;btn.textContent='⚠ Retry';alert('Could not reach the server to add it.');}
tick()}
async function tick(){let r=await fetch('/status');if(r.status==401){location.href='/login';return}let d=await r.json();
VPN=d.vpn;let v=document.getElementById('vpn');
if(d.vpn){v.className='vpn ok';v.innerHTML='<span><b>Protected</b> — traffic routed through the VPN · exit <code>'+esc(d.ip)+'</code></span>'}
else{v.className='vpn bad';v.innerHTML='<span><b>VPN not connected</b> — downloads are disabled until the tunnel is up.</span>'}
document.getElementById('go').disabled=!d.vpn;
let L=document.getElementById('list');
var UN=d.usenet||[];var TOT=d.torrents.length+UN.length;
var dc=document.getElementById('dlcount');if(dc)dc.textContent=TOT?'('+TOT+')':'';
document.getElementById('dlempty').style.display=TOT?'none':'block';
if(!TOT){L.innerHTML='';return}
// Usenet transfers live in SABnzbd, not in the torrent engine. They used to be
// invisible here — "added" and then nothing — so render them in the same list.
var uh=UN.map(u=>{var failed=u.state==='Failed';
var col=failed?'#f85149':(u.paused?'#8b949e':'#238636');
var acts='<button class=sec onclick="nzbDel(\''+u.id+'\',0)">✕ Remove</button>'+
         '<button class=sec onclick="nzbDel(\''+u.id+'\',1)">🗑 Remove + delete files</button>';
return '<div class=t><div class=tn>'+esc(u.name)+'</div>'+
'<div class=bar><div class=fill style="width:'+u.progress+'%;background:'+col+'"></div></div>'+
'<div class=meta><span class=tag>usenet</span><span class=tag>'+esc(u.cat)+'</span>'+
'<span>'+u.progress+'% · '+esc(u.state)+'</span>'+
(u.size?'<span>'+esc(String(u.size))+'</span>':'')+
(u.eta?'<span>ETA '+esc(u.eta)+'</span>':'')+
(u.error?'<span style="color:#f85149">'+esc(u.error)+'</span>':'')+
'</div><div class=acts>'+acts+'</div></div>';}).join('');
L.innerHTML=uh+d.torrents.map(t=>{let done=t.finished;let col=done?'#3fb950':(t.state[0]=='P'?'#8b949e':'#238636');
let b='';
if(done){b=`<button class=sec onclick="rc('${t.ih}')">↻ Recheck</button>`;}
else if(t.upaused){b=`<button class=sec onclick="rs('${t.ih}')" ${VPN?'':'disabled'}>▶ Resume</button><button class=sec onclick="rc('${t.ih}')">↻ Recheck</button>`;}
else{b=`<button class=sec onclick="ps('${t.ih}')">⏸ Pause</button><button class=sec onclick="rc('${t.ih}')">↻ Recheck</button>`;}
b+=`<button class=sec onclick="del('${t.ih}')">✕ Remove</button>`;
return `<div class=t><div class=tn>${esc(t.name)}</div>
<div class=bar><div class=fill style="width:${t.progress}%;background:${col}"></div></div>
<div class=meta><span class=tag>${t.cat}</span><span>${t.progress}% · ${t.state}</span>
<span>${fmt(t.done)} / ${fmt(t.size)}</span><span>↓ ${rate(t.dl)}</span><span>${t.peers} peers</span></div>
<div class=acts>${b}</div></div>`}).join('')}
async function nzbDel(id,withFiles){
  if(withFiles && !confirm('Remove this usenet download AND delete its files?'))return;
  try{var r=await fetch('/nzb/remove?id='+encodeURIComponent(id)+'&delete='+(withFiles?1:0),{method:'POST'});
    var j=await r.json();
    if(!j.ok)alert('Could not remove it — SABnzbd refused. It may have already finished.');
  }catch(e){alert('Could not reach the downloader to remove it.');}
  tick();}
var HUNT_EXPANDED={};var HUNT_RES={};var huntTimer=null;
function huntTabActive(){var p=document.getElementById('tab-hunt');return p&&!p.hidden;}
async function createHunt(e){e.preventDefault();var g=document.getElementById('hgoal').value.trim();if(!g)return;
var btn=document.getElementById('hgo');btn.disabled=true;btn.textContent='Starting…';
var body={goal:g,category:document.getElementById('hcat').value,pace:document.getElementById('hpace').value,description:document.getElementById('hdesc').value.trim(),watch:document.getElementById('hwatch').checked,sweep:document.getElementById('hsweep').value};
if(body.watch)reqNotifyPerm();
try{var r=await fetch('/hunt/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(r.status==401){location.href='/login';return}
document.getElementById('hgoal').value='';document.getElementById('hdesc').value='';}catch(err){}
btn.disabled=false;btn.textContent='🔦 Start hunt';loadHunts();}
var _huntStruct='';
async function loadHunts(){var r;try{r=await fetch('/hunt/list');}catch(e){return}if(r.status==401){location.href='/login';return}
var L=await r.json();var el=document.getElementById('hunts');if(!el)return;
huntNotifyCheck(L);loadBrainStatus();
if(!L.length){el.innerHTML='<div class=empty>No hunts running. Start one above — it keeps grinding in the background (even across reboots) until you stop it.</div>';_huntStruct='';return}
// The card STRUCTURE = which hunts exist + whether each is stopped (that changes the buttons). We
// rebuild the whole list ONLY when the structure changes; otherwise we update each card's live
// counters IN PLACE — so the expanded results you're scrolling are never destroyed (rebuilding the
// list collapsed them and threw you to the top every few seconds).
var struct=L.map(function(h){return h.id+(h.status==='stopped'?':S':':R')}).join(',');
if(struct!==_huntStruct){var y=window.scrollY;el.innerHTML=L.map(renderHunt).join('');window.scrollTo(0,y);_huntStruct=struct;}
else{L.forEach(updateHuntCard);}
for(var i=0;i<L.length;i++){if(HUNT_EXPANDED[L[i].id])loadHuntResults(L[i].id);}}
async function loadBrainStatus(){var el=document.getElementById('huntbrain');if(!el)return;
var s;try{s=await (await fetch('/hunt/brain')).json();}catch(e){return}
var col,icon,msg;
if(s.using_llm){col='#3fb950';icon='🧠';var la=(s.last_used_s!=null)?(' · last thought '+(s.last_used_s<60?(s.last_used_s+'s'):(Math.round(s.last_used_s/60)+'m'))+' ago'):' · warming up…';msg='Local AI brain <b>active</b> — inventing angles + judging finds on the GPU'+la;}
else if(s.reason==='ai-off'){col='#d29922';icon='💤';msg='Local AI is <b>off</b> — hunting in basic mode (works, just less clever). Turn it on in <b>Engines → Local AI</b> for smarter, deeper hunts + better filtering.';}
else if(s.reason==='gpu-not-ready'){col='#d29922';icon='⏳';msg='Local AI is on, <b>GPU warming up</b> (the model spins up when a hunt is active) — it\'ll kick in shortly.';}
else if(s.reason==='box-busy'){col='#d29922';icon='⏸';msg='Local AI <b>paused — box busy</b>; it resumes automatically when load drops (so other apps stay smooth).';}
else{col='#8b949e';icon='🧠';msg='Local AI status unavailable.';}
el.style.borderColor=col;el.innerHTML='<span style="color:'+col+'">'+icon+' '+msg+'</span>';}
function _hcol(st){return {running:'#3fb950',idle:'#d29922',stopped:'#8b949e'}[st]||'#8b949e';}
function _hstat(h){return (h.watch?('👁 watching·'+esc(h.sweep||'')+' · '):'')+esc(h.status)+' · '+esc(h.pace);}
function _hmeta(h){var s=h.stats||{};return '<span>🔁 '+(s.cycles||0)+' cycles</span><span>📦 '+(h.result_count||0)+' found</span><span>🧭 '+(s.leads||0)+' leads</span><span>⏳ '+(h.frontier_size||0)+' queued</span>'+(s.new_last?'<span style="color:#3fb950">+'+s.new_last+' new</span>':'')+(h.watch&&s.sweeps?'<span title="times re-swept for new uploads">🔄 '+s.sweeps+' sweeps</span>':'');}
function _hrec(h){var rr=(h.tried_recent||[]).slice(0,3).map(function(t){return esc(String(t.query||'').slice(0,54))}).join(' · ');return rr?('trying: '+rr):'';}
function _htog(h){return (HUNT_EXPANDED[h.id]?'▾ Hide':'▸ View')+' results ('+(h.result_count||0)+')';}
function renderHunt(h){
var btns=(h.status==='stopped')?'<button class=sec onclick="huntAct(\''+h.id+'\',\'resume\')">▶ Resume</button>':'<button class=sec onclick="huntAct(\''+h.id+'\',\'stop\')">⏸ Stop</button>';
btns+='<button class=sec onclick="huntAct(\''+h.id+'\',\'delete\')">✕ Delete</button>';
var exp=HUNT_EXPANDED[h.id];
return '<div class=hunt><div class=hunttop><div class=huntgoal><span class=huntdot id="hdot-'+h.id+'" style="background:'+_hcol(h.status)+'"></span>'+esc(h.goal)+'</div>'+
'<span class=huntstatus id="hstatus-'+h.id+'">'+_hstat(h)+'</span></div>'+
'<div class=meta id="hmeta-'+h.id+'">'+_hmeta(h)+'</div>'+
'<div class=huntrecent id="hrecent-'+h.id+'">'+_hrec(h)+'</div>'+
'<div class=acts><button class=sec id="htog-'+h.id+'" onclick="toggleHunt(\''+h.id+'\')">'+_htog(h)+'</button>'+btns+'</div>'+
'<div class=huntres id="hres-'+h.id+'" '+(exp?'':'hidden')+'></div></div>';}
function updateHuntCard(h){
var d=document.getElementById('hdot-'+h.id);if(d)d.style.background=_hcol(h.status);
var st=document.getElementById('hstatus-'+h.id);if(st)st.innerHTML=_hstat(h);
var mt=document.getElementById('hmeta-'+h.id);if(mt)mt.innerHTML=_hmeta(h);
var rc=document.getElementById('hrecent-'+h.id);if(rc)rc.innerHTML=_hrec(h);
var tg=document.getElementById('htog-'+h.id);if(tg)tg.textContent=_htog(h);}
function toggleHunt(hid){HUNT_EXPANDED[hid]=!HUNT_EXPANDED[hid];var el=document.getElementById('hres-'+hid);if(!el)return;el.hidden=!HUNT_EXPANDED[hid];var tg=document.getElementById('htog-'+hid);if(tg)tg.textContent=(HUNT_EXPANDED[hid]?'▾ Hide':'▸ View')+' results ('+((HUNT_RES[hid]||[]).length||0)+')';if(HUNT_EXPANDED[hid])loadHuntResults(hid);}
async function loadHuntResults(hid){var el=document.getElementById('hres-'+hid);if(!el)return;
var r;try{r=await fetch('/hunt/get?id='+encodeURIComponent(hid)+'&limit=100');}catch(e){return}if(!r.ok)return;var g=await r.json();
var res=g.results||[];HUNT_RES[hid]=res;
if(!res.length){if(el.dataset.sig!=='0'){el.innerHTML='<div class=empty style="padding:14px 0">No matches yet — still hunting. Results appear here as they turn up.</div>';el.dataset.sig='0';}return}
// skip re-rendering (and the scroll jump) when unchanged — but keyed on the DOM NODE (dataset), so
// a div recreated by a card re-render (which has no sig) always re-renders instead of staying blank.
var sig=res.length+'|'+((res[0]||{}).title||'')+'|'+((res[res.length-1]||{}).title||'');
if(el.dataset.sig===sig)return;
var _y=window.scrollY;el.dataset.sig=sig;
el.innerHTML=res.map(function(t,i){var act;
if(t.magnet||t.torrent_url||t.nzb_id)act='<button class=sec onclick="dlHunt(\''+hid+'\','+i+',this)">⬇ Download</button>';
else if(t.url)act='<a class=sec style="text-decoration:none" href="'+esc(t.url)+'" target=_blank rel=noopener>Open ↗</a>';else act='';
var seed=t.nzb_id?'⚡ Usenet':((t.magnet||t.torrent_url)?('▲ '+(t.seeders||0)+' seeders'):(t.source||''));
return '<div class=t><div class=tn>'+esc(t.title)+'</div><div class=meta><span class=tag>'+esc(t.source||'')+'</span>'+(t._via?'<span style="color:#8b949e">via “'+esc(String(t._via).slice(0,40))+'”</span>':'')+'<span>'+esc(seed)+'</span>'+act+'</div></div>';}).join('');window.scrollTo(0,_y);}
async function dlHunt(hid,i,btn){var t=(HUNT_RES[hid]||[])[i];if(!t)return;if(!VPN){alert('Connect the VPN before downloading.');return}
btn.disabled=true;btn.textContent='Added ✓';
var body='cat='+encodeURIComponent(t.category||'other');
if(t.magnet)body+='&magnet='+encodeURIComponent(t.magnet);else if(t.torrent_url)body+='&torrent_url='+encodeURIComponent(t.torrent_url);else if(t.nzb_id)body+='&nzb_id='+encodeURIComponent(t.nzb_id);
var res=await fetch('/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body});
if(!res.ok){btn.disabled=false;btn.textContent='⚠ Retry';}tick()}
async function huntAct(hid,act){if(act==='delete'&&!confirm('Delete this hunt and all its accumulated results?'))return;
try{await fetch('/hunt/'+act,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:hid})});}catch(e){}
if(act==='delete'){delete HUNT_EXPANDED[hid];delete HUNT_RES[hid];}loadHunts();}
function showTab(name){['search','sources','hunt','engines','downloads','library'].forEach(function(t){var p=document.getElementById('tab-'+t);if(p)p.hidden=(t!==name);var b=document.querySelector('.tabbtn[data-tab='+t+']');if(b)b.classList.toggle('active',t===name);});if(name==='library'&&!LIB_LOADED)loadLibrary();if(name==='engines'){loadEngines();loadAiSettings();loadNotifySettings();}if(name==='hunt'){loadHunts();if(!huntTimer)huntTimer=setInterval(function(){if(huntTabActive())loadHunts();},4000);}}
async function loadEngines(){var el=document.getElementById('engines');el.innerHTML='<div class=empty>Checking engines…</div>';
var r=await fetch('/engines');if(r.status==401){location.href='/login';return}
var E=await r.json();
el.innerHTML=E.map(function(e){var dot=e.ok?'#3fb950':'#f85149';var lbl=e.ok?'up':'down';
return '<div class=t><div class=meta style="justify-content:flex-start"><span style="color:'+dot+';font-size:16px">●</span><b style="min-width:230px;display:inline-block">'+esc(e.name)+'</b><span style="color:#8b949e">'+esc(e.detail)+'</span><span class=tag style="margin-left:auto;color:'+dot+'">'+lbl+'</span></div></div>';}).join('')}
async function loadAiSettings(){var el=document.getElementById('aisettings');if(!el)return;
var s={};try{s=await (await fetch('/ai/status')).json();}catch(e){}
var st=(s.state==='ready')?('<span style="color:#3fb950">● connected · model loaded</span>'):(s.state==='starting'?('<span style="color:#d29922">● waking up… the model is loading on the GPU (first run from cold ~60–90s). If this stays amber, check the Server address below.</span>'):(s.enabled?('<span style="color:#8b949e">● idle — starts automatically the moment you use AI, and stops when idle, so the GPU isn’t running in the background.</span>'):('<span style="color:#8b949e">● off</span>')));
var opts=(s.models||[]).map(function(m){return '<option'+(m===s.model?' selected':'')+'>'+esc(m)+'</option>';}).join('');
if(!opts)opts='<option>'+esc(s.model||'')+'</option>';
el.innerHTML='<div class=aiset><div class=meta style="justify-content:flex-start;margin-top:0">'+
'<h4>✨ Local AI</h4><label class=switch style="margin-left:auto"><input type=checkbox id=aitog '+(s.enabled?'checked':'')+' onchange="saveAi()"><span class=slider></span></label></div>'+
'<div style="font-size:12.5px;color:#8b949e;margin-top:6px">Optional. Uses your own local Ollama server for plain-English search and result explanations. Off by default; nothing leaves your machine. '+st+'</div>'+
'<div class=row><span style="font-size:12px;color:#8b949e;width:52px">Server</span><input type=text id=aiurl value="'+esc(s.url||'')+'" placeholder="http://192.168.1.50:11434"></div>'+
'<div class=row><span style="font-size:12px;color:#8b949e;width:52px">Model</span><select id=aimodel style="min-width:200px">'+opts+'</select><button class=sec onclick="saveAi()">Save</button></div></div>';}
async function saveAi(){var body={enabled:document.getElementById('aitog').checked,url:document.getElementById('aiurl').value.trim(),model:document.getElementById('aimodel').value};
try{await fetch('/ai/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});}catch(e){}
await loadAiSettings();refreshAi();}
async function loadNotifySettings(){var el=document.getElementById('notifysettings');if(!el)return;
var c={};try{c=await (await fetch('/notify/config')).json();}catch(e){}
if(c.available===false){el.innerHTML='';return;}
var k=c.kind||'ntfy';function opt(v,l){return '<option value="'+v+'"'+(k===v?' selected':'')+'>'+l+'</option>';}
el.innerHTML='<div class=aiset><div class=meta style="justify-content:flex-start;margin-top:0">'+
'<h4>🔔 Notifications</h4><label class=switch style="margin-left:auto"><input type=checkbox id=ntftog '+(c.enabled?'checked':'')+' onchange="saveNotify()"><span class=slider></span></label></div>'+
'<div style="font-size:12.5px;color:#8b949e;margin-top:6px">Get pinged when a background hunt finds new results — start a hunt for something rare and walk away. Sent over the VPN to public services only.</div>'+
'<div class=row><span style="font-size:12px;color:#8b949e;width:56px">Channel</span><select id=ntfkind onchange="notifyKindUI()">'+opt('ntfy','ntfy (phone push)')+opt('webhook','Webhook (Discord/Slack/custom)')+opt('telegram','Telegram')+'</select></div>'+
'<div id=nf_ntfy class=row><span style="font-size:12px;color:#8b949e;width:56px">Topic</span><input type=text id=ntf_ntfy value="'+esc(c.ntfy_url||'')+'" placeholder="a-secret-topic-name — install the ntfy app + subscribe to it"></div>'+
'<div id=nf_webhook class=row><span style="font-size:12px;color:#8b949e;width:56px">URL</span><input type=text id=ntf_webhook value="'+esc(c.webhook_url||'')+'" placeholder="https://discord.com/api/webhooks/…"></div>'+
'<div id=nf_telegram><div class=row><span style="font-size:12px;color:#8b949e;width:56px">Token</span><input type=password id=ntf_tgtoken placeholder="'+(c.has_telegram_token?'•••••• saved — blank keeps it':'bot token from @BotFather')+'"></div>'+
'<div class=row><span style="font-size:12px;color:#8b949e;width:56px">Chat ID</span><input type=text id=ntf_tgchat value="'+esc(c.telegram_chat||'')+'"></div></div>'+
'<div class=row><button class=sec onclick="saveNotify()">Save</button><button class=sec onclick="testNotify(this)">Send test</button><span id=ntftest style="font-size:12px;color:#8b949e"></span></div>'+
'<div style="font-size:11.5px;color:#6e7681;margin-top:4px">Also get alerts while this tab is open: <button class=sec onclick="reqNotifyPerm()">Enable browser alerts</button></div></div>';
notifyKindUI();}
function notifyKindUI(){var k=document.getElementById('ntfkind').value;
document.getElementById('nf_ntfy').style.display=k==='ntfy'?'':'none';
document.getElementById('nf_webhook').style.display=k==='webhook'?'':'none';
document.getElementById('nf_telegram').style.display=k==='telegram'?'':'none';}
function _notifyBody(){return {enabled:document.getElementById('ntftog').checked,kind:document.getElementById('ntfkind').value,
ntfy_url:document.getElementById('ntf_ntfy').value.trim(),webhook_url:document.getElementById('ntf_webhook').value.trim(),
telegram_chat:document.getElementById('ntf_tgchat').value.trim(),telegram_token:document.getElementById('ntf_tgtoken').value};}
async function saveNotify(reload){try{await fetch('/notify/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(_notifyBody())});}catch(e){}
if(document.getElementById('ntftog').checked)reqNotifyPerm();if(reload!==false)loadNotifySettings();}
async function testNotify(btn){btn.disabled=true;var s=document.getElementById('ntftest');s.textContent='sending…';s.style.color='#8b949e';
await saveNotify(false);
try{var r=await (await fetch('/notify/test',{method:'POST'})).json();s.textContent=r.ok?'✓ sent — check your device':('✗ '+(r.detail||'failed'));s.style.color=r.ok?'#3fb950':'#f85149';}catch(e){s.textContent='✗ error';}
btn.disabled=false;}
function reqNotifyPerm(){try{if('Notification'in window&&Notification.permission==='default')Notification.requestPermission();}catch(e){}}
var HUNT_COUNTS={};
function huntNotifyCheck(list){try{(list||[]).forEach(function(h){var prev=HUNT_COUNTS[h.id];var now=h.result_count||0;
if(prev!==undefined&&now>prev&&'Notification'in window&&Notification.permission==='granted'){
new Notification('🎯 Undertow found '+(now-prev)+' new result'+((now-prev)==1?'':'s'),{body:'Hunt: '+(h.goal||'').slice(0,80)});}
HUNT_COUNTS[h.id]=now;});}catch(e){}}
async function findSources(e){e.preventDefault();var q=document.getElementById('sq').value.trim();if(!q||!VPN)return;
var ext=document.getElementById('sext').value.trim().replace(/^\./,'');
var el=document.getElementById('srcresults');el.innerHTML='<div class=empty>Scanning search engines + probing servers… (this can take ~20s)</div>';
var r=await fetch('/sources?q='+encodeURIComponent(q)+'&ext='+encodeURIComponent(ext));if(r.status==401){location.href='/login';return}
var d=await r.json();
if(!d.ready){el.innerHTML='<div class=empty>Sources engine unavailable (SearXNG not up yet — give it a minute).</div>';return}
var S=d.sources||[];
if(!S.length){el.innerHTML='<div class=empty>No open directories confirmed for that query. Try a broader topic or a different file type.</div>';return}
var nc=S.filter(function(s){return s.via==='crawl'}).length;
var hdr='<h3>'+S.length+' open directories / file servers for “'+esc(q)+'”'+(ext?(' · '+esc(ext)):'')+'</h3>';
if(nc>0)hdr+='<div class=srcintro>🧭 <b>'+nc+' of these were found by CRAWLING</b> outward from the indexed hits (parent + sibling directories) — they appear in <b>no</b> search result. That\'s the deep layer.</div>';
el.innerHTML=hdr+S.map(function(s){
var via=s.via==='crawl'?'<span class=viacrawl title="found by crawling, not in any search index">🧭 crawled</span>':'<span class=viasearch title="found via search index">🔎 indexed</span>';
var badge=s.kind==='ftp'?'<span class=qual>FTP</span>':'';
var mt=s.matched>0?('<span style="color:#3fb950">'+s.matched+' matching</span>'):'';
var fc=s.files>0?('<span>'+s.files+' files/dirs</span>'):'';
return '<div class=t><div class=tn>'+esc(s.title||s.host)+'</div>'+
'<div class=meta>'+via+'<span class=tag>'+esc(s.host)+'</span>'+badge+mt+fc+
'<a class="sec" style="text-decoration:none" href="'+esc(s.url)+'" target=_blank rel=noopener>Browse ↗</a></div>'+
'<div style="font-size:11px;color:#6e7681;word-break:break-all;margin-top:4px">'+esc(s.url)+'</div></div>';}).join('')}

// ---- Library tab (Netflix-style media browser + in-browser player) ----
var LIB_ITEMS = [];
var LIB_LOADED = false;
var libMediaEl = null; // currently playing <video>/<audio>
var LIB_LAST_M3U = '', LIB_LAST_STRM = '', LIB_LAST_NAME = 'stream'; // for the .m3u/.strm download

function libEsc(s){ s = (s == null ? '' : String(s)); return (typeof esc === 'function') ? esc(s) : s.replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function libFmt(b){ return (typeof fmt === 'function') ? fmt(b) : (b == null ? '' : b + ' B'); }

function libHash(str){
  var h = 0, s = String(str || '?');
  for (var i = 0; i < s.length; i++) { h = (h << 5) - h + s.charCodeAt(i); h |= 0; }
  return Math.abs(h);
}

function libInitials(title){
  var words = String(title || '?').trim().split(/\s+/).filter(Boolean);
  if (!words.length) return '?';
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

// Build a deterministic colored SVG placeholder data URI from the title.
function libPlaceholder(item){
  var title = (item && item.title) || '?';
  var type = (item && item.type) || 'other';
  var hue = libHash(title) % 360;
  var hue2 = (hue + 38) % 360;
  var c1 = 'hsl(' + hue + ',55%,32%)';
  var c2 = 'hsl(' + hue2 + ',60%,16%)';
  var glyph;
  if (type === 'album') {
    glyph = '<g transform="translate(150,210)">'
      + '<circle r="78" fill="rgba(0,0,0,.55)"/>'
      + '<circle r="78" fill="none" stroke="rgba(255,255,255,.10)" stroke-width="1"/>'
      + '<circle r="60" fill="none" stroke="rgba(255,255,255,.10)" stroke-width="1"/>'
      + '<circle r="42" fill="none" stroke="rgba(255,255,255,.10)" stroke-width="1"/>'
      + '<circle r="26" fill="' + c1 + '"/>'
      + '<circle r="7" fill="rgba(0,0,0,.6)"/>'
      + '<text x="0" y="135" font-family="system-ui,sans-serif" font-size="60" fill="rgba(255,255,255,.92)" text-anchor="middle">&#9834;</text>'
      + '</g>';
  } else if (type === 'doc') {
    glyph = '<text x="150" y="245" font-family="system-ui,sans-serif" font-size="120" fill="rgba(255,255,255,.85)" text-anchor="middle">&#128196;</text>'
      + '<text x="150" y="330" font-family="system-ui,sans-serif" font-size="40" font-weight="700" fill="rgba(255,255,255,.9)" text-anchor="middle">' + libEsc(libInitials(title)) + '</text>';
  } else {
    glyph = '<g transform="translate(150,196)">'
      + '<circle r="56" fill="rgba(0,0,0,.45)" stroke="rgba(255,255,255,.25)" stroke-width="2"/>'
      + '<path d="M -18 -28 L 32 0 L -18 28 Z" fill="rgba(255,255,255,.92)"/>'
      + '</g>'
      + '<text x="150" y="330" font-family="system-ui,sans-serif" font-size="46" font-weight="800" letter-spacing="2" fill="rgba(255,255,255,.92)" text-anchor="middle">' + libEsc(libInitials(title)) + '</text>';
  }
  var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="300" height="450" viewBox="0 0 300 450">'
    + '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
    + '<stop offset="0" stop-color="' + c1 + '"/><stop offset="1" stop-color="' + c2 + '"/>'
    + '</linearGradient></defs>'
    + '<rect width="300" height="450" fill="url(#g)"/>'
    + glyph
    + '</svg>';
  return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
}

function libPosterSrc(item){
  return (item && item.poster) ? item.poster : libPlaceholder(item);
}

var LIB_TYPE_LABELS = { movie:'Movie', tv:'TV', album:'Album', doc:'Doc', other:'Other' };
function libTypeLabel(t){ return LIB_TYPE_LABELS[t] || 'Other'; }

function loadLibrary(){
  var grid = document.getElementById('libGrid');
  var count = document.getElementById('libCount');
  if (count) count.textContent = 'Loading…';
  fetch('/library', { headers: { 'Accept': 'application/json' } })
    .then(function(r){
      if (r.status === 401) { location.href = '/login'; throw new Error('auth'); }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function(data){
      LIB_ITEMS = (data && data.items) || [];
      LIB_LOADED = true;
      libRender();
    })
    .catch(function(e){
      if (e && e.message === 'auth') return;
      if (count) count.textContent = '';
      if (grid) grid.innerHTML = '<div class="lib-empty">Could not load library. <br>' + libEsc(e.message || e) + '</div>';
    });
}

function libRender(){
  var grid = document.getElementById('libGrid');
  var count = document.getElementById('libCount');
  var qEl = document.getElementById('lq');
  var q = (qEl ? qEl.value : '').trim().toLowerCase();
  if (!grid) return;

  if (!LIB_ITEMS.length) {
    grid.innerHTML = '<div class="lib-empty">No media yet — downloads will appear here once they finish.</div>';
    if (count) count.textContent = '';
    return;
  }

  var items = q ? LIB_ITEMS.filter(function(it){ return String(it.title || '').toLowerCase().indexOf(q) !== -1; }) : LIB_ITEMS;

  if (count) {
    count.textContent = items.length + (items.length === 1 ? ' item' : ' items')
      + (q ? ' matching “' + q + '”' : '');
  }

  if (!items.length) {
    grid.innerHTML = '<div class="lib-empty">No titles match your search.</div>';
    return;
  }

  // Security banner: total files quarantined across the whole library.
  var sb = document.getElementById('libSecBanner');
  if (sb) {
    var qn = 0;
    for (var z = 0; z < LIB_ITEMS.length; z++) qn += ((LIB_ITEMS[z].quarantined || []).length);
    sb.innerHTML = qn ? '<div class="lib-secbanner">🛡 ' + qn + ' file(s) flagged as malware or executables. They are KEPT for your review, not deleted — the app never runs them, and media only ever opens inside the isolated no-network sandbox. Open a flagged title to inspect and decide.</div>' : '';
  }

  var html = '';
  for (var k = 0; k < items.length; k++) {
    var it = items[k];
    var idx = LIB_ITEMS.indexOf(it);
    var type = it.type || 'other';
    var yr = it.year ? libEsc(it.year) : '';
    var shield = (it.scan === 'flagged') ? '<span class="lib-shield" title="Threat quarantined">⚠</span>' : '';
    html += '<div class="lib-tile" onclick="libOpen(' + idx + ')">'
      + shield
      + '<img class="lib-poster" loading="lazy" alt="" src="' + libEsc(libPosterSrc(it)) + '">'
      + '<div class="lib-meta">'
      + '<div class="lib-title">' + libEsc(it.title || 'Untitled') + '</div>'
      + '<div class="lib-sub">'
      + (yr ? '<span class="lib-year">' + yr + '</span>' : '')
      + '<span class="lib-badge t-' + libEsc(type) + '">' + libEsc(libTypeLabel(type)) + '</span>'
      + '</div></div></div>';
  }
  grid.innerHTML = html;
}

function libFilter(){ libRender(); }

function libOpen(idx){
  var it = LIB_ITEMS[idx];
  if (!it) return;
  var body = document.getElementById('libModalBody');
  var modal = document.getElementById('libModal');
  if (!body || !modal) return;

  var type = it.type || 'other';
  var yr = it.year ? ' (' + libEsc(it.year) + ')' : '';
  var overview = it.overview ? libEsc(it.overview) : 'No description available.';

  var files = it.files || [];
  var filesHtml = '';
  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    var dlUrl = '/stream?id=' + encodeURIComponent(it.id) + '&f=' + f.i;
    var playBtn = '';
    if (f.playable && (f.kind === 'video' || f.kind === 'audio')) {
      playBtn = '<button class="lib-play" onclick="libPlay(' + idx + ',' + i + ')">▶ Play</button>'
              + '<button class="lib-vlc" onclick="libExternal(' + idx + ',' + i + ')">📺 VLC / app</button>';
    }
    filesHtml += '<div class="lib-file">'
      + '<span class="lib-fname">' + libEsc(f.name || ('file ' + f.i)) + '</span>'
      + '<span class="lib-fsize">' + libFmt(f.size) + '</span>'
      + playBtn
      + '<a class="lib-dl" href="' + libEsc(dlUrl) + '" download>⬇ Download</a>'
      + '</div>';
  }
  if (!filesHtml) filesHtml = '<div class="lib-fsize">No files.</div>';

  var sec;
  if (it.scan === 'flagged') {
    var qlist = (it.quarantined || []).map(function(q){ return libEsc(q.name) + ' (' + libEsc(q.reason || 'risky') + ')'; }).join(', ');
    sec = '<div class="lib-sec lib-sec-bad">🛡 ' + (it.quarantined || []).length + ' file(s) flagged as malware/executables: ' + qlist + '. KEPT for your review — the app will not run them; only media can be opened, and only inside the isolated no-network sandbox. Decide yourself whether to keep or delete them. Any clean media below is safe to play.</div>';
  } else if (it.scan === 'clean') {
    sec = '<div class="lib-sec lib-sec-ok">🛡 Scanned — no threats found.</div>';
  } else {
    sec = '<div class="lib-sec lib-sec-pending">🛡 Scan pending — the antivirus checks new downloads shortly.</div>';
  }

  body.innerHTML =
    '<div class="lib-dhead">'
    + '<img class="lib-dposter" alt="" src="' + libEsc(libPosterSrc(it)) + '">'
    + '<div class="lib-dinfo">'
    + '<div class="lib-drow"><span class="lib-badge t-' + libEsc(type) + '">' + libEsc(libTypeLabel(type)) + '</span>'
    + '<span class="lib-dsize">' + libFmt(it.size) + '</span></div>'
    + '<h2 class="lib-dtitle">' + libEsc(it.title || 'Untitled') + yr + '</h2>'
    + '<p class="lib-overview">' + overview + '</p>'
    + '<div class="lib-actions"><button class="lib-del" onclick="libDelete(' + idx + ')">🗑 Delete from library</button></div>'
    + '</div></div>'
    + sec
    + '<div class="lib-player" id="libPlayer"></div>'
    + '<div class="lib-ext" id="libExt"></div>'
    + '<div class="lib-files"><h4>Files</h4>' + filesHtml + '</div>';

  modal.hidden = false;
  document.addEventListener('keydown', libEscKey);
}

async function libDelete(idx){
  var it = LIB_ITEMS[idx]; if(!it) return;
  if(!confirm('Permanently delete “'+(it.title||'this item')+'” and all its files from disk?\nThis cannot be undone.')) return;
  try{
    var r = await fetch('/library/delete?id='+encodeURIComponent(it.id), {method:'POST'});
    if(r.status===401){ location.href='/login'; return; }
    var d = await r.json();
    if(d && d.ok){ libCloseModal(); loadLibrary(); }
    else { alert('Delete failed — the files may already be gone, or the item is outside the download folder.'); }
  }catch(e){ alert('Delete failed: '+e); }
}

function libPlay(idx, fileIdx){
  var it = LIB_ITEMS[idx];
  if (!it) return;
  var f = (it.files || [])[fileIdx];
  if (!f) return;
  var holder = document.getElementById('libPlayer');
  if (!holder) return;

  libStopMedia();
  var tag = (f.kind === 'audio') ? 'audio' : 'video';
  // Native container (mp4/webm/etc.): serve directly — byte-range seekable, your device decodes.
  if (f.native) { libMount(holder, tag, '/stream?id=' + encodeURIComponent(it.id) + '&f=' + f.i); return; }
  // Non-native (mkv/avi/…): PREPARE a seekable MP4 once (remux, or GPU transcode for exotic
  // --- what can THIS browser actually decode? -------------------------------
  // Asking beats assuming. Hardcoding "browsers play HEVC" was true for Safari and
  // false for Chrome/Firefox, and the failure mode was a silent black picture. With a
  // real answer the server can remux (seconds) instead of re-encoding (~25 minutes)
  // whenever this browser can handle the original stream — and it keeps working when
  // new codecs show up, because we just ask about those too.
  var _libCaps = null;
  function libCaps(){
    if (_libCaps !== null) return _libCaps;
    var v = document.createElement('video');
    function can(mime){
      try {
        // MediaSource is what the player actually feeds; fall back to the element.
        if (window.MediaSource && MediaSource.isTypeSupported(mime)) return true;
      } catch(e){}
      try { return v.canPlayType(mime) === 'probably'; } catch(e){ return false; }
    }
    var out = [];
    // HEVC Main (8-bit) and Main 10 are separate capabilities: some devices decode
    // 8-bit only, and a 10-bit remux there would black-screen exactly like before.
    if (can('video/mp4; codecs="hvc1.1.6.L93.B0"'))  out.push('hevc');
    if (can('video/mp4; codecs="hvc1.2.4.L120.B0"')) out.push('hevc10');
    if (can('video/mp4; codecs="av01.0.05M.08"'))    out.push('av1');
    if (can('video/mp4; codecs="vp09.00.10.08"'))    out.push('vp9');
    _libCaps = out.join(',');
    return _libCaps;
  }

  // codecs), then play it with full seeking. Your browser decodes it on your own GPU.
  holder.innerHTML = '<div class="lib-prep"><span class="lib-spin"></span> Preparing for playback…</div>';
  fetch('/prep?id=' + encodeURIComponent(it.id) + '&f=' + f.i + '&caps=' + encodeURIComponent(libCaps())).then(function(r){return r.json();}).then(function(d){
    if (!d || d.state === 'error' || !d.key) { holder.innerHTML = '<div class="lib-prep lib-prep-err">Couldn’t prepare this file. Try 📺 VLC / app below.</div>'; return; }
    if (d.state === 'ready') { libMount(holder, tag, '/playfile?key=' + encodeURIComponent(d.key)); return; }
    libPollPrep(holder, tag, d.key);
  }).catch(function(){ holder.innerHTML = '<div class="lib-prep lib-prep-err">Prepare failed — try 📺 VLC / app.</div>'; });
}

function libMount(holder, tag, src){
  var el = document.createElement(tag);
  el.controls = true; el.autoplay = true; el.setAttribute('playsinline', '');
  el.src = src;
  holder.innerHTML = ''; holder.appendChild(el);
  libMediaEl = el;
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

var _prepTimer = null;
var _prepGen = 0;
function libPollPrep(holder, tag, key){
  var lbl = { 'remux': 'Remuxing (your device decodes it)', 'gpu-transcode': 'Transcoding on the GPU' };
  var myGen = _prepGen;            // a newer play/close invalidates this loop
  var idle = 0;                    // consecutive polls with no forward progress
  function tick(){
    if (myGen !== _prepGen) return;
    fetch('/prepstatus?key=' + encodeURIComponent(key)).then(function(r){return r.json();}).then(function(s){
      if (myGen !== _prepGen) return;
      if (s.state === 'ready') { libMount(holder, tag, '/playfile?key=' + encodeURIComponent(key)); return; }
      if (s.state === 'error' || idle > 600) { holder.innerHTML = '<div class="lib-prep lib-prep-err">Couldn’t prepare this file — try 📺 VLC / app.</div>'; return; }
      idle++;
      holder.innerHTML = '<div class="lib-prep"><span class="lib-spin"></span> ' + (lbl[s.mode] || 'Preparing') + '… ' + (s.progress || 0) + '%<br><small>one-time — then it plays instantly with full seeking</small></div>';
      _prepTimer = setTimeout(tick, 1500);
    }).catch(function(){ if (myGen === _prepGen) _prepTimer = setTimeout(tick, 2500); });
  }
  tick();
}

// Hand the raw file to an external player (VLC / Infuse / any) on YOUR device.
// It decodes locally, so ANY format plays at full quality with seeking, and the
// ZimaBoard only serves bytes. A short-lived token lets the player fetch it over
// Tailscale without the login cookie. URL uses location.origin so it matches
// however you're connected (Tailscale IP, LAN, etc.).
function libExternal(idx, fileIdx){
  var it = LIB_ITEMS[idx]; if (!it) return;
  var f = (it.files || [])[fileIdx]; if (!f) return;
  var box = document.getElementById('libExt'); if (!box) return;
  box.innerHTML = '<div class="lib-extbox">Preparing link…</div>';
  fetch('/token?id=' + encodeURIComponent(it.id) + '&f=' + f.i)
    .then(function(r){ if (r.status === 401){ location.href='/login'; throw 0; } return r.json(); })
    .then(function(d){
      var url = location.origin + '/stream?id=' + encodeURIComponent(it.id) + '&f=' + f.i + '&t=' + encodeURIComponent(d.t);
      var name = (it.title || 'video') + (f.name ? ' — ' + f.name : '');
      LIB_LAST_NAME = String(it.title || 'stream').replace(/[^\w.-]+/g, '_').slice(0, 60) || 'stream';
      LIB_LAST_M3U = '#EXTM3U\n#EXTINF:-1,' + name + '\n' + url + '\n';
      LIB_LAST_STRM = url + '\n';
      var enc = encodeURIComponent(url);
      var rest = url.replace(/^https?:\/\//, '');
      var scheme = location.protocol.replace(':', '');
      var android = 'intent://' + rest + '#Intent;scheme=' + scheme + ';type=video/*;package=org.videolan.vlc;end';
      var ios = 'vlc-x-callback://x-callback-url/stream?url=' + enc;
      var infuse = 'infuse://x-callback-url/play?url=' + enc;
      box.innerHTML =
        '<div class="lib-extbox">'
        + '<div class="lib-exttitle">📺 Open in an external player — any format, full quality, plays on your device</div>'
        + '<div class="lib-extrow"><input class="lib-exturl" id="libExtUrl" readonly value="' + libEsc(url) + '" onclick="this.select()"><button class="lib-btn" onclick="libCopyUrl()">Copy</button></div>'
        + '<div class="lib-extbtns">'
        + '<a class="lib-extlink" href="' + libEsc(ios) + '">VLC · iPhone/iPad</a>'
        + '<a class="lib-extlink" href="' + libEsc(android) + '">VLC · Android</a>'
        + '<a class="lib-extlink" href="' + libEsc(infuse) + '">Infuse · Apple</a>'
        + '<button class="lib-extlink" onclick="libDownloadPlaylist()">⬇ .m3u (desktop VLC)</button>'
        + '</div>'
        + '<div class="lib-exthint">Phone: tap your platform button (needs the VLC or Infuse app). '
        + 'Desktop: download the .m3u (opens in VLC), or in VLC use Media → Open Network Stream and paste the copied link. '
        + 'The link works for ~6 hours.</div>'
        + '</div>';
    })
    .catch(function(){
      box.innerHTML = '<div class="lib-extbox">Could not prepare the link — try again.</div>';
    });
}

function libCopyUrl(){
  var i = document.getElementById('libExtUrl'); if (!i) return;
  i.select();
  try { navigator.clipboard.writeText(i.value); } catch (e) { try { document.execCommand('copy'); } catch (e2) {} }
}

function libDownloadPlaylist(){
  var blob = new Blob([LIB_LAST_M3U || ''], { type: 'audio/x-mpegurl' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (LIB_LAST_NAME || 'stream') + '.m3u';
  document.body.appendChild(a); a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 1500);
}

function libStopMedia(){
  if (typeof _prepGen !== 'undefined') _prepGen++;   // invalidate any running prep-poll loop
  if (typeof _prepTimer !== 'undefined' && _prepTimer) { clearTimeout(_prepTimer); _prepTimer = null; }
  if (libMediaEl) {
    try { libMediaEl.pause(); } catch (e) {}
    libMediaEl.removeAttribute('src');
    try { libMediaEl.load(); } catch (e) {}
    libMediaEl = null;
  }
}

function libCloseModal(){
  libStopMedia();
  var modal = document.getElementById('libModal');
  if (modal) modal.hidden = true;
  var body = document.getElementById('libModalBody');
  if (body) body.innerHTML = '';
  document.removeEventListener('keydown', libEscKey);
}

function libModalBgClose(ev){
  if (ev.target && ev.target.id === 'libModal') libCloseModal();
}

function libEscKey(ev){
  if (ev.key === 'Escape') libCloseModal();
}

let mq=new URLSearchParams(location.search).get('magnet');
if(mq){document.querySelector('details').open=true;document.getElementById('m').value=decodeURIComponent(mq);history.replaceState({},'','/')}
tick();setInterval(tick,1500);refreshAi();
</script></body></html>"""
PAGE = PAGE.replace("__SAVE__", SAVE).replace("__OPTS__", OPTS)


def _transcoder_prepare(abspath, caps=""):
    """Ask the sandbox to PREPARE a seekable MP4 (remux for browser codecs, GPU NVENC for
    exotic). Returns {"key","state"} — the app then serves /playfile?key=... with ranges."""
    url = (TRANSCODER + "/prepare?path=" + quote(abspath)
           + "&caps=" + quote(caps or ""))
    try:
        return json.load(urllib.request.urlopen(url, timeout=20))
    except Exception:
        return {"state": "error"}


_last_touch = {}


def _maybe_touch(key):
    """Tell the sandbox this prepared file is in use (so LRU won't evict it mid-play), at
    most once/60s per key. Fire-and-forget — never blocks the byte-range serve."""
    if not re.fullmatch(r"[0-9a-f]{20}", key or ""):
        return
    now = time.time()
    if now - _last_touch.get(key, 0) < 60:
        return
    _last_touch[key] = now

    def _go():
        try:
            urllib.request.urlopen(TRANSCODER + "/touch?key=" + quote(key), timeout=3)
        except Exception:
            pass
    threading.Thread(target=_go, daemon=True).start()


def proxy_transcode(handler, abspath):
    """Stream a transcode from the locked-down decoder sandbox. ffmpeg never runs
    in this (privileged, VPN-key-holding) container — if a malicious file exploits
    the decoder, it's trapped in the no-network, no-caps, read-only sandbox."""
    url = TRANSCODER + "/transcode?path=" + quote(abspath)
    try:
        resp = urllib.request.urlopen(url, timeout=60)
    except urllib.error.HTTPError as e:               # e.g. 503 (sandbox busy)
        body = b""
        try:
            body = e.read()
        except Exception:
            pass
        handler._send(e.code, body or b"transcoder error", "text/plain")
        return
    except Exception:
        handler._send(502, "media sandbox unavailable", "text/plain")
        return
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "video/mp4")
        handler.send_header("Referrer-Policy", "no-referrer")
        handler.end_headers()
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            handler.wfile.write(chunk)
    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception:
        pass
    finally:
        try:
            resp.close()
        except Exception:
            pass


class H(BaseHTTPRequestHandler):
    # Socket timeout so a client that pauses/vanishes mid-stream can't block a handler
    # thread forever (which would also permanently hold the single transcode slot).
    # Generous enough for normal player buffering pauses.
    timeout = 300

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        # "same-origin", NOT "no-referrer": under no-referrer browsers serialize the
        # Origin header as the literal string "null" even for same-origin form posts,
        # which made the CSRF check below refuse the app's own login page. same-origin
        # still sends NO referrer to third parties (so media/stream tokens in URLs never
        # leak off-site) while keeping Origin intact for our own requests.
        self.send_header("Referrer-Policy", "same-origin")
        # Nothing here is ever meant to be framed; framing it is only useful for
        # clickjacking the download/delete controls.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _redirect(self, loc, headers=None):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()

    def _token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("vt_session="):
                return part[len("vt_session="):]
        return ""

    def _authed(self):
        exp = _sessions.get(self._token())
        return bool(exp and exp > time.time())

    def _ih(self):
        return (parse_qs(urlparse(self.path).query).get("ih") or [""])[0]

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/login":
            err = ('<div class=err>Wrong password</div>'
                   if urlparse(self.path).query == "e=1" else "")
            self._send(200, LOGIN_PAGE.replace("__ERR__", err))
        elif path in ("/stream", "/play", "/prep"):
            # Cookie OR a valid per-file token — so external players (VLC, etc.)
            # can fetch the file remotely without the login cookie.
            qs = parse_qs(urlparse(self.path).query)
            ih = (qs.get("id") or [""])[0]
            f = (qs.get("f") or ["0"])[0]
            tok = (qs.get("t") or [""])[0]
            if not (self._authed() or check_token(ih, f, tok)):
                self._send(403, "forbidden", "text/plain")
                return
            p = library.resolve_file(ih, f)
            if not p:
                self._send(404, "not found", "text/plain")
            elif path == "/stream":
                library.stream_file(self, p)      # raw bytes (no decode) — safe here
            elif path == "/prep":
                # Ask the sandbox to PREPARE a seekable MP4. The player sends what it can
                # decode so we remux (seconds) instead of re-encoding (~25 min) whenever
                # this browser can handle the original video.
                caps = (parse_qs(urlparse(self.path).query).get("caps") or [""])[0]
                self._send(200, json.dumps(_transcoder_prepare(p, caps)),
                           "application/json")
            else:
                proxy_transcode(self, p)          # legacy live decode in the sandbox
        elif path == "/playfile":
            # serve a PREPARED, seekable MP4 by cache key (byte-range) — the browser
            # decodes it on the client's own GPU. Cookie-authed (in-browser player).
            qs = parse_qs(urlparse(self.path).query)
            if not self._authed():
                self._send(403, "forbidden", "text/plain")
                return
            key = (qs.get("key") or [""])[0]
            cf = library.cache_file(key)
            if not cf:
                self._send(404, "not ready", "text/plain")
            else:
                _maybe_touch(key)          # keep it out of the LRU eviction path while watched
                library.stream_file(self, cf)
        elif path == "/prepstatus":
            if not self._authed():
                self._send(401, "auth required", "text/plain")
                return
            qs = parse_qs(urlparse(self.path).query)
            self._send(200, json.dumps(library.read_status((qs.get("key") or [""])[0])),
                       "application/json")
        elif not self._authed():
            if path in ("/status", "/library", "/token"):
                self._send(401, "auth required", "text/plain")
            else:
                self._redirect("/login")
        elif path == "/token":
            # Mint a short-lived URL token for an external player (VLC).
            qs = parse_qs(urlparse(self.path).query)
            self._send(200, json.dumps({"t": make_token(
                (qs.get("id") or [""])[0], (qs.get("f") or ["0"])[0])}),
                "application/json")
        elif path == "/library":
            self._send(200, json.dumps({"items": library.list_items()}),
                       "application/json")
        elif path == "/status":
            self._send(200, json.dumps({"vpn": vpn_ok, "ip": VPN_IP,
                                        "torrents": snapshot(),
                                        "usenet": usenet_snapshot()}),
                       "application/json")
        elif path == "/search":
            qs = parse_qs(urlparse(self.path).query)
            q = (qs.get("q") or [""])[0].strip()
            cat = (qs.get("cat") or [""])[0].strip()
            res = meta_search(q, cat) if q else {"ready": True, "results": []}
            self._send(200, json.dumps(res), "application/json")
        elif path == "/engines":
            self._send(200, json.dumps(_engine_status()), "application/json")
        elif path == "/ai/status":
            st = ai.status() if ai else {"enabled": False, "reachable": False,
                                         "url": "", "model": "", "models": []}
            self._send(200, json.dumps(st), "application/json")
        elif path == "/notify/config":
            cfg = notify.public_config() if notify else {"enabled": False, "available": False}
            if notify:
                cfg["available"] = True
            self._send(200, json.dumps(cfg), "application/json")
        elif path == "/hunt/list":
            self._send(200, json.dumps(hunt.list_hunts() if hunt else []),
                       "application/json")
        elif path == "/hunt/brain":
            st = hunt_brain.brain_status() if hunt_brain else {"using_llm": False, "reason": "unavailable"}
            self._send(200, json.dumps(st), "application/json")
        elif path == "/hunt/get":
            hid = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
            h = hunt.get_hunt(hid) if hunt else None
            self._send(200, json.dumps(h or {}), "application/json")
        elif path == "/sources":
            # Sources mode: return open directories / file servers, not files.
            qs = parse_qs(urlparse(self.path).query)
            q = (qs.get("q") or [""])[0].strip()
            ext = (qs.get("ext") or [""])[0].strip()
            if not q or discover is None:
                self._send(200, json.dumps({"ready": discover is not None,
                                            "sources": []}), "application/json")
            else:
                try:
                    src = discover.discover(q, ext)
                except Exception:
                    src = []
                self._send(200, json.dumps({"ready": True, "sources": src}),
                           "application/json")
        elif path in ("/", "/index.html"):
            self._send(200, PAGE)
        else:
            self._send(404, "not found")

    def _origin_ok(self):
        """Reject cross-origin state-changing requests (CSRF).

        The session cookie is SameSite=Lax, and "same site" ignores the PORT: another
        web app on this same host (http://host:8800) is same-site with http://host:8722,
        so its pages could forge POSTs — /add, /remove, /library/delete — with the
        user's cookie attached. Only Origin distinguishes by port, so we compare Origin
        against the host this request was actually addressed to.

        Reverse proxies matter here: Undertow is normally reached through an HTTPS front
        door (e.g. Tailscale Serve on :8723 -> 127.0.0.1:8722), which forwards the
        original host in Host and/or X-Forwarded-Host. Both are accepted, plus any
        origins the operator lists in TRUSTED_ORIGINS (comma-separated), so a different
        front door can be allowed without weakening the port check.

        A missing Origin is allowed: browsers always send it on cross-origin POSTs,
        while non-browser clients (curl, the installer's self-test) legitimately omit it
        — and those are not riding a victim's cookie.
        """
        # Sec-Fetch-Site is set by the browser itself and CANNOT be forged by page
        # script, which makes it a stronger signal than Origin. "same-origin" means the
        # request came from this very origin; "none" means the user typed the URL or
        # used a bookmark. Both are safe. Note we deliberately do NOT accept
        # "same-site": that is precisely the same-host-different-port case this check
        # exists to block. This also covers browsers that send Origin: null.
        sfs = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sfs in ("same-origin", "none"):
            return True

        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            p = urlparse(origin)
        except Exception:
            p = None
        candidates = set()
        for h in (self.headers.get("Host"), self.headers.get("X-Forwarded-Host")):
            if h:
                candidates.add(h.strip().lower())
        for extra in TRUSTED_ORIGINS:
            candidates.add(extra)
        if p and p.scheme in ("http", "https") and p.netloc:
            if p.netloc.lower() in candidates:
                return True
            # An operator may list a full origin ("https://host:8723") rather than a
            # bare host; accept that spelling too.
            if origin.strip().lower().rstrip("/") in candidates:
                return True
        # Rejected. Say exactly why, once per distinct origin — an unexplained 403 in
        # the middle of a login is the worst possible failure mode.
        key = (origin, self.headers.get("Host"))
        if key not in _csrf_seen:
            _csrf_seen.add(key)
            print("[vpntorrent] csrf: refused Origin=%r Host=%r X-Forwarded-Host=%r path=%s\n"
                  "             If this is your own front door, add it to TRUSTED_ORIGINS in .env"
                  % (origin, self.headers.get("Host"),
                     self.headers.get("X-Forwarded-Host"), urlparse(self.path).path),
                  flush=True)
        return False

    def do_POST(self):
        path = urlparse(self.path).path
        if not self._origin_ok():
            self._send(403, "cross-origin request refused", "text/plain")
            return
        if path == "/login":
            try: n = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError: n = -1
            if not (0 <= n <= 65536):
                self._send(400, "bad request", "text/plain"); return
            # Throttle BEFORE reading/comparing. The old defence was a 1s sleep on
            # failure, which does nothing on a threaded server: an attacker opens 200
            # connections and all 200 sleeps run in parallel. Count failures per client
            # instead and stop answering.
            ip = self.client_address[0] if self.client_address else "?"
            if _login_blocked(ip):
                self._send(429, "too many failed logins — wait and try again",
                           "text/plain")
                return
            pw = (parse_qs(self.rfile.read(n).decode()).get("pw") or [""])[0]
            if PASSWORD and hmac.compare_digest(pw, PASSWORD):
                _login_ok(ip)
                tok = secrets.token_hex(16)
                now = time.time()                        # prune expired tokens, then register
                for t in [t for t, e in _sessions.items() if e <= now]:
                    _sessions.pop(t, None)
                _sessions[tok] = now + _SESSION_TTL
                self._redirect("/", [("Set-Cookie",
                    f"vt_session={tok}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800")])
            else:
                _login_fail(ip)          # counts toward the per-IP lockout above
                time.sleep(1)            # plus a small per-connection delay
                self._redirect("/login?e=1")
            return
        if path == "/logout":
            _sessions.pop(self._token(), None)
            self._redirect("/login", [("Set-Cookie",
                "vt_session=; HttpOnly; Path=/; Max-Age=0")])
            return
        if not self._authed():
            self._send(401, "auth required", "text/plain")
            return
        if path == "/add":
            if not vpn_ok:
                self._send(403, "VPN not connected — downloads disabled")
                return
            try: n = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError: n = -1
            if not (0 <= n <= 65536):
                self._send(400, "bad request", "text/plain"); return
            data = parse_qs(self.rfile.read(n).decode())
            magnet = (data.get("magnet") or [""])[0].strip()
            turl = (data.get("torrent_url") or [""])[0].strip()
            nzb = (data.get("nzb_id") or [""])[0].strip()
            cat = (data.get("cat") or ["other"])[0].strip()
            if magnet.startswith("magnet:"):
                try:
                    add_magnet(magnet, cat)
                    self._send(200, "ok")
                except Exception as e:
                    self._send(400, f"bad magnet ({e})")
            elif turl.startswith("http://") or turl.startswith("https://"):
                try:
                    add_torrent_url(turl, cat)
                    self._send(200, "ok")
                except Exception as e:
                    self._send(502, f"could not fetch torrent ({e})")
            elif nzb:
                try:
                    add_nzb(nzb, cat)
                    self._send(200, "ok")
                except Exception as e:
                    self._send(502, f"usenet add failed ({e})")
            else:
                self._send(400, "bad request")
        elif path == "/livecheck":
            # Verify a batch of already-shown results are actually retrievable RIGHT NOW, so the
            # UI can badge dead links + push them down. SSRF-safe (verify.py validates every host).
            if verify is None:
                self._send(200, json.dumps({"results": []}), "application/json"); return
            try: n = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError: n = -1
            if not (0 <= n <= 262144):
                self._send(400, "bad request", "text/plain"); return
            try:
                items = json.loads(self.rfile.read(n) or b"[]")
            except Exception:
                items = []
            rows = []
            for it in (items if isinstance(items, list) else [])[:20]:
                if isinstance(it, dict):
                    rows.append({"i": it.get("i"),
                                 "url": str(it.get("url") or "")[:2000],
                                 "magnet": str(it.get("magnet") or "")[:3000],
                                 "torrent_url": str(it.get("torrent_url") or "")[:2000],
                                 "nzb_id": str(it.get("nzb_id") or "")[:200],
                                 "seeders": it.get("seeders") or 0})
            verify.verify_many(rows, timeout=7, max_n=20, workers=10)
            out = [{"i": r.get("i"), "live": r.get("_live", "unknown"),
                    "peers": r.get("_peers")} for r in rows]
            self._send(200, json.dumps({"results": out}), "application/json")
        elif path == "/notify/config":
            if notify is None:
                self._send(503, "notifications unavailable"); return
            try: n = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError: n = -1
            if not (0 <= n <= 65536):
                self._send(400, "bad request", "text/plain"); return
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                body = {}
            cfg = {}
            for k in ("enabled", "kind", "ntfy_url", "webhook_url", "telegram_chat", "telegram_token"):
                if k in body:
                    v = body[k]
                    # a blank/absent token is IGNORED (save_config merges) so the UI never has to
                    # re-send the secret; send "" only to keep, or a new value to change it.
                    if k == "telegram_token" and not str(v or "").strip():
                        continue
                    cfg[k] = bool(v) if k == "enabled" else str(v)[:500]
            try:
                out = notify.save_config(cfg)
                self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                self._send(500, f"save failed ({e})")
        elif path == "/notify/test":
            if notify is None:
                self._send(503, "notifications unavailable"); return
            ok, detail = notify.send_test()
            self._send(200, json.dumps({"ok": bool(ok), "detail": detail}), "application/json")
        elif path == "/remove":
            remove(self._ih())
            self._send(200, "ok")
        elif path == "/library/delete":
            # delete a downloaded item's files from disk + reindex (path-safe in library)
            qs = parse_qs(urlparse(self.path).query)
            iid = (qs.get("id") or [""])[0]
            res = library.delete_item(iid) if library else {"ok": False}
            # also drop any active torrent still pointing at that content, so it can't
            # re-download the files we just deleted.
            if res.get("ok") and res.get("rel"):
                try:
                    _remove_torrent_for_rel(res["rel"])
                except Exception:
                    pass
            self._send(200, json.dumps(res), "application/json")
        elif path == "/nzb/remove":
            # cancel a usenet transfer (queue or post-processing)
            qs = parse_qs(urlparse(self.path).query)
            nid = (qs.get("id") or [""])[0]
            dele = (qs.get("delete") or ["0"])[0] == "1"
            self._send(200, json.dumps({"ok": usenet_remove(nid, dele)}),
                       "application/json")
        elif path == "/pause":
            pause(self._ih())
            self._send(200, "ok")
        elif path == "/resume":
            resume(self._ih())
            self._send(200, "ok")
        elif path == "/recheck":
            recheck(self._ih())
            self._send(200, "ok")
        elif path.startswith("/ai/"):
            try:
                n = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                n = -1
            if not (0 <= n <= 65536):
                self._send(400, "bad request"); return
            try:
                data = json.loads(self.rfile.read(n).decode() or "{}")
            except Exception:
                data = {}
            if ai is None:
                self._send(200, json.dumps({"ok": False, "error": "ai unavailable"}),
                           "application/json"); return
            if path == "/ai/settings":
                self._send(200, json.dumps(ai.set_config(data)), "application/json")
            elif path == "/ai/wake":
                # on-demand: signal the watchdog to spin ollama up, return current lifecycle state
                ai.wake()
                self._send(200, json.dumps(ai.status()), "application/json")
            elif path == "/ai/smart":
                self._send(200, json.dumps(ai.smart_query(data.get("text", ""))),
                           "application/json")
            elif path == "/ai/explain":
                txt = ai.explain(data.get("title", ""), data.get("context", ""))
                self._send(200, json.dumps({"text": txt}), "application/json")
            else:
                self._send(404, "not found")
        elif path.startswith("/hunt/"):
            try:
                n = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                n = -1
            if not (0 <= n <= 65536):
                self._send(400, "bad request"); return
            try:
                data = json.loads(self.rfile.read(n).decode() or "{}")
            except Exception:
                data = {}
            if hunt is None:
                self._send(200, json.dumps({"ok": False, "error": "hunt unavailable"}),
                           "application/json"); return
            try:
                if path == "/hunt/create":
                    h = hunt.create_hunt(data.get("goal", ""), data.get("category", "all"),
                                         data.get("description", ""), data.get("pace", "normal"),
                                         watch=bool(data.get("watch")),
                                         sweep=str(data.get("sweep", "daily")))
                    self._send(200, json.dumps(h), "application/json")
                elif path == "/hunt/stop":
                    self._send(200, json.dumps({"ok": hunt.stop_hunt(data.get("id", ""))}),
                               "application/json")
                elif path == "/hunt/resume":
                    self._send(200, json.dumps({"ok": hunt.resume_hunt(data.get("id", ""))}),
                               "application/json")
                elif path == "/hunt/delete":
                    self._send(200, json.dumps({"ok": hunt.delete_hunt(data.get("id", ""))}),
                               "application/json")
                else:
                    self._send(404, "not found")
            except Exception as e:
                self._send(400, json.dumps({"ok": False, "error": str(e)[:120]}),
                           "application/json")
        else:
            self._send(404, "not found")


def _graceful_shutdown(*_):
    """On SIGTERM (docker stop / reboot), checkpoint state + resume data so no
    progress is lost, then exit within the stop grace window."""
    try:
        _save_state()
        with _lock:
            handles = [t["h"] for t in _torrents.values()]
        for h in handles:
            _save_resume(h)           # guarded: skips metadata-less magnets
        time.sleep(3)                 # let alert_pump flush the .resume blobs
    finally:
        os._exit(0)


if __name__ == "__main__":
    mode = f"VPN-bound to {VPN_IP}" if PROTECTED else "NO VPN — downloads DISABLED"
    print(f"[vpntorrent] libtorrent {lt.version} · {mode} · http://0.0.0.0:{PORT}", flush=True)
    signal.signal(signal.SIGTERM, _graceful_shutdown)
    if PROTECTED:
        os.makedirs(RESUME_DIR, exist_ok=True)
        threading.Thread(target=alert_pump, daemon=True).start()
        threading.Thread(target=restore_torrents, daemon=True).start()   # non-blocking: web UI up fast
        threading.Thread(target=resume_saver, daemon=True).start()
        threading.Thread(target=monitor, daemon=True).start()
        threading.Thread(target=jackett_setup, daemon=True).start()
    # The media library + player work regardless of the VPN (local files, served
    # to the logged-in user). Run start() in a thread so a slow first disk scan
    # never delays the web server coming up.
    _cfg_dir = os.path.dirname(PW_FILE) or "/config"
    threading.Thread(target=library.start, args=(SAVE, _cfg_dir, TMDB_API_KEY),
                     daemon=True).start()
    if hunt is not None:
        # Inject the LLM brain (Phase 2). The brain itself checks whether AI is on and
        # falls back to hunt's deterministic stub when it isn't, so this is safe to wire
        # unconditionally and keeps the app standalone on a GPU-less box. The executor
        # backend stays stubbed until Phase 3.
        if hunt_brain is not None:
            try:
                hunt.set_backends(generate=hunt_brain.generate, judge=hunt_brain.judge)
            except Exception:
                pass
        if hunt_exec is not None:
            # wire the executor to the REAL search infra (Phase 3). meta_search/discover
            # live here in vt.py, injected to avoid an import cycle.
            try:
                hunt_exec.set_search(meta_search=meta_search, discover=discover)
                hunt.set_backends(execute=hunt_exec.execute)
            except Exception:
                pass
        if verify is not None:
            # a background hunt should never accumulate dead links: verify each picked find is
            # still retrievable (bounded, ~1.2s/find) and drop confirmed-dead ones before record.
            try:
                hunt.set_backends(verify=lambda ms: verify.filter_live(ms, timeout=9, max_n=30))
            except Exception:
                pass
        if notify is not None:
            # push a notification when a background hunt surfaces new finds (debounced in notify.py)
            try:
                hunt.set_backends(notify=notify.notify_hunt)
            except Exception:
                pass
        threading.Thread(target=hunt.resume_all, daemon=True).start()  # resume from disk
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
