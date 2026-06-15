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
import json
import time
import hmac
import secrets
import threading
import subprocess
import http.cookiejar
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

import libtorrent as lt
import library  # local module: media library index + in-browser streaming

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
_sessions = set()                      # valid session tokens (in-memory)

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
    ("Movies", "movies"),
    ("TV", "tv"),
    ("Music", "music"),
    ("Documents", "documents"),
    ("Software", "software"),
    ("Other", "other"),
]
FOLDERS = {sub for _, sub in CATEGORIES}

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
    while True:
        ok = vpn_healthy()
        vpn_ok = ok
        with _lock:
            items = list(_torrents.items())
        for ih, t in items:
            h = t["h"]
            if not h.is_valid():
                continue
            s = h.status()
            if not ok:
                if not s.paused:
                    h.pause()             # VPN down -> pause (not a user pause)
                continue
            if s.is_finished:            # download-only: stop dead on completion
                if not s.paused:
                    h.pause()
                    try:
                        h.save_resume_data(_RESUME_FLAGS)   # persist completed state
                    except Exception:
                        pass
            elif s.paused and not t["user_paused"]:
                h.resume()               # VPN back & user didn't pause it -> resume
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
    # pause() (and would auto-seed completed torrents), so turn it off.
    p.flags &= ~lt.torrent_flags.auto_managed
    h = ses.add_torrent(p)
    ih = str(h.info_hash())
    with _lock:
        _torrents[ih] = {"h": h, "cat": cat, "user_paused": False}
    _save_state()
    try:
        h.save_resume_data(_RESUME_FLAGS)   # checkpoint once metadata arrives
    except Exception:
        pass
    return ih


def remove(ih, delete_files=False):
    with _lock:
        t = _torrents.pop(ih, None)
    if t is not None:
        ses.remove_torrent(t["h"], lt.options_t.delete_files if delete_files else 0)
    try:
        os.remove(os.path.join(RESUME_DIR, ih + ".resume"))
    except Exception:
        pass
    _save_state()


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
    """Persist each torrent's category + user-paused flag so a restart restores
    it to the right folder and state (the .resume blob holds the rest)."""
    try:
        with _lock:
            data = {ih: {"cat": t["cat"], "user_paused": t["user_paused"]}
                    for ih, t in _torrents.items()}
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
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
                        buf = lt.write_resume_data_buf(a.params)
                        ih = str(a.handle.info_hash())
                        with open(os.path.join(RESUME_DIR, ih + ".resume"), "wb") as f:
                            f.write(buf)
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
            try:
                if h.is_valid():
                    h.save_resume_data(_RESUME_FLAGS)
            except Exception:
                pass
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
            atp.flags &= ~lt.torrent_flags.auto_managed
            h = ses.add_torrent(atp)
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
            with _lock:
                _torrents[ih] = {"h": h, "cat": cat, "user_paused": up}
            if up:
                h.pause()
            print(f"[vpntorrent] restored {ih} -> {cat}", flush=True)
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
        elif s.state == lt.torrent_status.downloading_metadata:
            state = "Fetching info…"
        elif s.paused or t["user_paused"]:
            state = "Paused"
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
INDEXERS = ["thepiratebay", "1337x", "yts", "eztv", "nyaasi", "limetorrents",
            "torlock", "btdigg", "torrentgalaxy", "yourbittorrent", "glodls",
            "torrentdownloads", "ext"]
TRACKERS = ["udp://tracker.opentrackr.org:1337/announce",
            "udp://open.tracker.cl:1337/announce",
            "udp://tracker.openbittorrent.com:6969/announce",
            "udp://exodus.desync.com:6969/announce"]
_jkey = None
_jop = None
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


def jackett_setup():
    """Wait for Jackett, then ensure the target indexers are configured (idempotent)."""
    global _jkey, _jop
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
                for ind in INDEXERS:
                    if ind in have or ind not in avail:
                        continue
                    try:
                        cfg = json.load(op.open(f"{JACKETT}/api/v2.0/indexers/{ind}/config?apikey={key}", timeout=20))
                        req = urllib.request.Request(
                            f"{JACKETT}/api/v2.0/indexers/{ind}/config?apikey={key}",
                            data=json.dumps(cfg).encode(),
                            headers={"Content-Type": "application/json"}, method="POST")
                        op.open(req, timeout=40)
                        have.add(ind)
                        print(f"[vpntorrent] search: added indexer {ind}", flush=True)
                    except Exception as e:
                        print(f"[vpntorrent] search: skip {ind} ({e})", flush=True)
                with _jlock:
                    _jkey, _jop = key, op
                print(f"[vpntorrent] search: ready, {len(have)} indexers configured", flush=True)
                return
            except Exception as e:
                print(f"[vpntorrent] search: waiting for Jackett ({e})", flush=True)
        time.sleep(5)


def jackett_search(q):
    """Return normalized results sorted by seeders, or None if search isn't ready."""
    with _jlock:
        key, op = _jkey, _jop
    if not key:
        return None
    url = f"{JACKETT}/api/v2.0/indexers/all/results?apikey={key}&Query={quote(q)}"
    data = None
    for attempt in (1, 2):
        try:
            if op is None:
                op = _jackett_opener()
                with _jlock:
                    globals().__setitem__("_jop", op)
            data = json.load(op.open(url, timeout=60))
            break
        except Exception:
            op = None
            if attempt == 2:
                return []
    out = []
    for x in data.get("Results", []):
        magnet = x.get("MagnetUri")
        ih = x.get("InfoHash")
        if not magnet and not ih:
            continue
        title = x.get("Title", "")
        if not magnet:
            magnet = ("magnet:?xt=urn:btih:" + ih + "&dn=" + quote(title)
                      + "".join("&tr=" + quote(t) for t in TRACKERS))
        out.append({
            "title": title,
            "tracker": x.get("Tracker", ""),
            "seeders": x.get("Seeders") or 0,
            "size": x.get("Size") or 0,
            "magnet": magnet,
        })
    out.sort(key=lambda r: r["seeders"], reverse=True)
    return out[:60]


# ----------------------------------------------------------------------------- web UI
OPTS = "".join(f'<option value="{sub}">{label}</option>' for label, sub in CATEGORIES)

LOGIN_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>vpntorrent — login</title><style>
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3;display:flex;min-height:100vh;align-items:center;justify-content:center}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:28px;width:300px;text-align:center}
h1{font-size:20px;margin:0 0 4px}.s{color:#8b949e;font-size:13px;margin-bottom:18px}
input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #30363d;background:#0e1116;color:#e6edf3;margin-bottom:10px}
button{width:100%;padding:10px;border:0;border-radius:8px;background:#238636;color:#fff;font-weight:600;cursor:pointer}
.err{color:#f85149;font-size:13px;margin-bottom:10px}
</style></head><body><form class=box method=post action=/login>
<h1>🛡 vpntorrent</h1><div class=s>Enter password to continue</div>
__ERR__
<input type=password name=pw placeholder=Password autofocus>
<button>Log in</button></form></body></html>"""

PAGE = r"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>vpntorrent</title><style>
*{box-sizing:border-box}body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0e1116;color:#e6edf3}
.wrap{max-width:820px;margin:0 auto;padding:24px 16px}
.top{display:flex;justify-content:space-between;align-items:baseline}
h1{font-size:22px;margin:0 0 4px}.sub{color:#8b949e;font-size:13px;margin-bottom:16px}
a.lo{color:#8b949e;font-size:12px;text-decoration:none}a.lo:hover{color:#e6edf3}
.vpn{display:block;padding:10px 14px;border-radius:10px;font-size:14px;font-weight:600;margin-bottom:16px}
.ok{background:#15301c;color:#3fb950;border:1px solid #21482b}
.bad{background:#3d1518;color:#f85149;border:1px solid #5c1f23}
form.add,form.search{display:flex;gap:8px;margin:14px 0;flex-wrap:wrap}
details{margin:6px 0 14px}summary{cursor:pointer;color:#8b949e;font-size:13px}
h3{font-size:14px;color:#8b949e;margin:18px 0 6px;font-weight:600}
input[type=text]{flex:1;min-width:240px;padding:10px 12px;border-radius:8px;border:1px solid #30363d;background:#161b22;color:#e6edf3}
select{padding:10px 12px;border-radius:8px;border:1px solid #30363d;background:#161b22;color:#e6edf3}
button{padding:10px 16px;border:0;border-radius:8px;background:#238636;color:#fff;font-weight:600;cursor:pointer}
button:disabled{background:#30363d;color:#8b949e;cursor:not-allowed}
button.sec{background:#21262d;color:#c9d1d9;border:1px solid #30363d;font-weight:500;font-size:12px;padding:5px 10px}
.t{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px 14px;margin:10px 0}
.tn{font-weight:600;word-break:break-all}
.bar{height:6px;background:#21262d;border-radius:99px;margin:8px 0;overflow:hidden}
.fill{height:100%;transition:width .4s}
.meta{color:#8b949e;font-size:12px;display:flex;gap:14px;flex-wrap:wrap;align-items:center}
.tag{background:#21262d;border:1px solid #30363d;border-radius:6px;padding:1px 7px;font-size:11px;text-transform:capitalize}
.acts{display:flex;gap:6px;margin-top:10px;flex-wrap:wrap}
.empty{color:#6e7681;text-align:center;padding:30px 0}
.tabs{display:flex;gap:4px;margin-bottom:18px;border-bottom:1px solid #30363d;flex-wrap:wrap}
.tabbtn{background:none;border:0;border-bottom:2px solid transparent;color:#8b949e;font:inherit;font-weight:600;padding:9px 14px;margin-bottom:-1px;cursor:pointer}
.tabbtn:hover{color:#e6edf3}
.tabbtn.active{color:#e6edf3;border-bottom-color:#238636}
.tab-panel[hidden]{display:none}
#tab-library{padding:0}
.lib-toolbar{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.lib-search{flex:1 1 240px;min-width:0;background:#161b22;border:1px solid #30363d;border-radius:8px;color:#e6edf3;font:inherit;font-size:15px;padding:10px 14px;outline:none}
.lib-search::placeholder{color:#8b949e}
.lib-search:focus{border-color:#3fb950;box-shadow:0 0 0 2px rgba(63,185,80,.25)}
.lib-btn{background:#21262d;border:1px solid #30363d;border-radius:8px;color:#e6edf3;font:inherit;font-size:14px;cursor:pointer;padding:10px 14px;white-space:nowrap;transition:background .15s,border-color .15s}
.lib-btn:hover{background:#30363d;border-color:#3fb950}
.lib-count{color:#8b949e;font-size:13px;margin:0 0 14px}
.lib-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:16px}
.lib-tile{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;cursor:pointer;position:relative;transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease}
.lib-tile:hover{transform:scale(1.045);box-shadow:0 12px 28px rgba(0,0,0,.6);border-color:#3fb950;z-index:2}
.lib-poster{width:100%;aspect-ratio:2/3;object-fit:cover;display:block;background:#0e1116}
.lib-meta{padding:8px 10px 10px}
.lib-title{font-size:13.5px;font-weight:600;color:#e6edf3;line-height:1.25;margin:0 0 4px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.lib-sub{display:flex;align-items:center;gap:6px}
.lib-year{font-size:12px;color:#8b949e}
.lib-badge{font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 6px;border-radius:5px;color:#e6edf3;background:#30363d;border:1px solid #444c56}
.lib-badge.t-movie{background:rgba(35,134,54,.25);border-color:#238636;color:#3fb950}
.lib-badge.t-tv{background:rgba(56,139,253,.22);border-color:#1f6feb;color:#6cb6ff}
.lib-badge.t-album{background:rgba(188,140,255,.18);border-color:#8957e5;color:#d2a8ff}
.lib-badge.t-doc{background:rgba(210,153,34,.18);border-color:#9e6a03;color:#e3b341}
.lib-badge.t-other{background:#30363d;border-color:#444c56;color:#8b949e}
.lib-empty{color:#8b949e;text-align:center;padding:60px 20px;font-size:15px;border:1px dashed #30363d;border-radius:12px}
.lib-modal{position:fixed;inset:0;z-index:1000;background:rgba(1,4,9,.78);backdrop-filter:blur(3px);display:flex;align-items:flex-start;justify-content:center;padding:28px 16px;overflow-y:auto}
.lib-modal[hidden]{display:none}
.lib-dialog{background:#161b22;border:1px solid #30363d;border-radius:14px;width:100%;max-width:820px;box-shadow:0 24px 60px rgba(0,0,0,.7);position:relative;overflow:hidden}
.lib-close{position:absolute;top:12px;right:12px;z-index:3;width:34px;height:34px;border-radius:50%;background:rgba(13,17,23,.8);border:1px solid #30363d;color:#e6edf3;font-size:18px;line-height:1;cursor:pointer}
.lib-close:hover{background:#f85149;border-color:#f85149}
.lib-dhead{display:flex;gap:18px;padding:20px}
.lib-dposter{width:150px;flex:0 0 150px;aspect-ratio:2/3;object-fit:cover;border-radius:8px;background:#0e1116}
.lib-dinfo{min-width:0;flex:1}
.lib-dtitle{font-size:22px;font-weight:700;margin:4px 0 8px;color:#e6edf3}
.lib-drow{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.lib-dsize{color:#8b949e;font-size:13px}
.lib-overview{color:#c9d1d9;font-size:14px;line-height:1.5;margin:8px 0 0}
.lib-player{padding:0 20px}
.lib-player video,.lib-player audio{width:100%;border-radius:8px;background:#000;display:block}
.lib-player audio{background:#0e1116}
.lib-transnote{color:#e3b341;font-size:12px;margin:8px 0 0}
.lib-files{padding:16px 20px 22px}
.lib-files h4{margin:0 0 10px;font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
.lib-file{display:flex;align-items:center;gap:10px;padding:9px 10px;border:1px solid #30363d;border-radius:8px;margin-bottom:8px;background:#0e1116}
.lib-fname{flex:1;min-width:0;font-size:13.5px;color:#e6edf3;word-break:break-word}
.lib-fsize{font-size:12px;color:#8b949e;white-space:nowrap}
.lib-play,.lib-dl{font:inherit;font-size:12.5px;text-decoration:none;white-space:nowrap;padding:6px 10px;border-radius:7px;cursor:pointer}
.lib-play{background:#238636;border:1px solid #2ea043;color:#fff}
.lib-play:hover{background:#2ea043}
.lib-dl{background:#21262d;border:1px solid #30363d;color:#e6edf3}
.lib-dl:hover{background:#30363d}
.lib-vlc{font:inherit;font-size:12.5px;white-space:nowrap;padding:6px 10px;border-radius:7px;cursor:pointer;background:#ff8800;border:1px solid #e07b00;color:#1b1500;font-weight:600}
.lib-vlc:hover{background:#ff9a2e}
.lib-ext{padding:0 20px}
.lib-extbox{background:#0e1116;border:1px solid #30363d;border-radius:8px;padding:12px 14px;margin-top:4px}
.lib-exttitle{font-size:13px;font-weight:600;color:#e6edf3;margin-bottom:8px}
.lib-extrow{display:flex;gap:8px;margin-bottom:8px}
.lib-exturl{flex:1;min-width:0;font:inherit;font-size:12px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#8b949e;padding:7px 9px}
.lib-extbtns{display:flex;gap:8px;flex-wrap:wrap}
.lib-extlink{font:inherit;font-size:12.5px;text-decoration:none;white-space:nowrap;padding:7px 11px;border-radius:7px;cursor:pointer;background:#21262d;border:1px solid #30363d;color:#e6edf3}
.lib-extlink:hover{background:#30363d}
.lib-exthint{color:#8b949e;font-size:11.5px;margin-top:9px;line-height:1.45}
.lib-shield{position:absolute;top:6px;left:6px;background:#5c1f23;color:#ffb3b0;border:1px solid #f85149;border-radius:6px;font-size:10px;font-weight:700;padding:2px 6px;z-index:1}
.lib-secbanner{background:#3d1518;border:1px solid #5c1f23;color:#f0a9a7;border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:13px}
.lib-sec{border-radius:8px;padding:9px 12px;margin:0 20px 4px;font-size:13px;line-height:1.45}
.lib-sec-ok{background:#10271a;border:1px solid #1c3b27;color:#7ee2a8}
.lib-sec-bad{background:#3d1518;border:1px solid #5c1f23;color:#f0a9a7}
.lib-sec-pending{background:#1c2128;border:1px solid #30363d;color:#8b949e}
@media (max-width:520px){.lib-dhead{flex-direction:column;align-items:center;text-align:center}.lib-dposter{width:130px;flex-basis:auto}.lib-dtitle{font-size:19px}.lib-grid{grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:12px}}
</style></head><body><div class=wrap>
<div class=top><h1>vpntorrent</h1><a class=lo href=# onclick="lo()">log out</a></div>
<div class=sub>download-only · never seeds · saving to <code>__SAVE__</code></div>
<div id=vpn class=vpn>checking VPN…</div>
<div class=tabs>
<button class="tabbtn active" data-tab=search onclick="showTab('search')">🔍 Search</button>
<button class="tabbtn" data-tab=downloads onclick="showTab('downloads')">⬇ Downloads <span id=dlcount></span></button>
<button class="tabbtn" data-tab=library onclick="showTab('library')">🎬 Library</button>
</div>
<div id=tab-search class=tab-panel>
<form class=search onsubmit="search(event)">
<input type=text id=q placeholder="search for movies, shows, music, anything…" autocomplete=off>
<select id=cat>__OPTS__</select>
<button id=go>Search</button></form>
<details><summary>…or paste a magnet link directly</summary>
<form class=add onsubmit="add(event)">
<input type=text id=m placeholder="magnet: link" autocomplete=off>
<button>Download</button></form>
<button class=sec onclick="reg()">↪ Make magnet links open here</button></details>
<div id=results></div>
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
async function search(e){e.preventDefault();let q=document.getElementById('q').value.trim();if(!q||!VPN)return;
let el=document.getElementById('results');el.innerHTML='<div class=empty>Searching…</div>';
let r=await fetch('/search?q='+encodeURIComponent(q));if(r.status==401){location.href='/login';return}
let d=await r.json();
if(!d.ready){el.innerHTML='<div class=empty>Search engine is still starting up — give it a minute and try again.</div>';return}
R=d.results;
if(!R.length){el.innerHTML='<div class=empty>No results found.</div>';return}
el.innerHTML='<h3>'+R.length+' results for “'+esc(q)+'” — pick a category above, then Download</h3>'+R.map((t,i)=>`<div class=t><div class=tn>${esc(t.title)}</div>
<div class=meta><span class=tag>${esc(t.tracker)}</span><span style="color:${t.seeders>0?'#3fb950':'#8b949e'}">▲ ${t.seeders} seeders</span><span>${fmt(t.size)}</span>
<button class=sec onclick="dl(${i},this)">⬇ Download</button></div></div>`).join('')}
async function dl(i,btn){btn.disabled=true;btn.textContent='Added ✓';
await fetch('/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'magnet='+encodeURIComponent(R[i].magnet)+'&cat='+document.getElementById('cat').value});tick()}
async function tick(){let r=await fetch('/status');if(r.status==401){location.href='/login';return}let d=await r.json();
VPN=d.vpn;let v=document.getElementById('vpn');
if(d.vpn){v.className='vpn ok';v.textContent='● VPN connected — protected ('+d.ip+')'}
else{v.className='vpn bad';v.textContent='● VPN NOT CONNECTED — downloads disabled. Nothing can download until the VPN is up.'}
document.getElementById('go').disabled=!d.vpn;
let L=document.getElementById('list');
var dc=document.getElementById('dlcount');if(dc)dc.textContent=d.torrents.length?'('+d.torrents.length+')':'';
document.getElementById('dlempty').style.display=d.torrents.length?'none':'block';
if(!d.torrents.length){L.innerHTML='';return}
L.innerHTML=d.torrents.map(t=>{let done=t.finished;let col=done?'#3fb950':(t.state[0]=='P'?'#8b949e':'#238636');
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
function showTab(name){['search','downloads','library'].forEach(function(t){var p=document.getElementById('tab-'+t);if(p)p.hidden=(t!==name);var b=document.querySelector('.tabbtn[data-tab='+t+']');if(b)b.classList.toggle('active',t===name);});if(name==='library'&&!LIB_LOADED)loadLibrary();}

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
    sb.innerHTML = qn ? '<div class="lib-secbanner">🛡 ' + qn + ' file(s) were quarantined as malware or executables and moved to a locked folder — they can\'t be played or downloaded. Open a flagged title to see details.</div>' : '';
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
    sec = '<div class="lib-sec lib-sec-bad">🛡 ' + (it.quarantined || []).length + ' file(s) quarantined as malware/executables: ' + qlist + '. Moved to a locked folder — they can\'t be played or downloaded. The media below is safe to play.</div>';
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
    + '</div></div>'
    + sec
    + '<div class="lib-player" id="libPlayer"></div>'
    + '<div class="lib-ext" id="libExt"></div>'
    + '<div class="lib-files"><h4>Files</h4>' + filesHtml + '</div>';

  modal.hidden = false;
  document.addEventListener('keydown', libEscKey);
}

function libPlay(idx, fileIdx){
  var it = LIB_ITEMS[idx];
  if (!it) return;
  var f = (it.files || [])[fileIdx];
  if (!f) return;
  var holder = document.getElementById('libPlayer');
  if (!holder) return;

  libStopMedia();

  var src = (f.native ? '/stream' : '/play') + '?id=' + encodeURIComponent(it.id) + '&f=' + f.i;
  var tag = (f.kind === 'audio') ? 'audio' : 'video';
  var el = document.createElement(tag);
  el.controls = true;
  el.autoplay = true;
  el.setAttribute('playsinline', '');
  el.src = src;
  holder.innerHTML = '';
  holder.appendChild(el);
  libMediaEl = el;

  if (f.kind === 'video' && !f.native) {
    var note = document.createElement('p');
    note.className = 'lib-transnote';
    note.textContent = 'Transcoding to play in your browser — may stutter on heavy formats and seeking is limited. For full quality + seeking on any format, tap 📺 VLC / app below.';
    holder.appendChild(note);
  }
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
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
tick();setInterval(tick,1500);
</script></body></html>"""
PAGE = PAGE.replace("__SAVE__", SAVE).replace("__OPTS__", OPTS)


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
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Referrer-Policy", "no-referrer")  # don't leak stream tokens via Referer
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
        return self._token() in _sessions

    def _ih(self):
        return (parse_qs(urlparse(self.path).query).get("ih") or [""])[0]

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/login":
            err = ('<div class=err>Wrong password</div>'
                   if urlparse(self.path).query == "e=1" else "")
            self._send(200, LOGIN_PAGE.replace("__ERR__", err))
        elif path in ("/stream", "/play"):
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
            else:
                proxy_transcode(self, p)          # decode happens in the sandbox
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
                                        "torrents": snapshot()}), "application/json")
        elif path == "/search":
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0].strip()
            results = jackett_search(q) if q else []
            self._send(200, json.dumps({"ready": results is not None,
                                        "results": results or []}), "application/json")
        elif path in ("/", "/index.html"):
            self._send(200, PAGE)
        else:
            self._send(404, "not found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/login":
            n = int(self.headers.get("Content-Length", 0))
            pw = (parse_qs(self.rfile.read(n).decode()).get("pw") or [""])[0]
            if PASSWORD and hmac.compare_digest(pw, PASSWORD):
                tok = secrets.token_hex(16)
                _sessions.add(tok)
                self._redirect("/", [("Set-Cookie",
                    f"vt_session={tok}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800")])
            else:
                time.sleep(1)            # slow down brute force
                self._redirect("/login?e=1")
            return
        if path == "/logout":
            _sessions.discard(self._token())
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
            n = int(self.headers.get("Content-Length", 0))
            data = parse_qs(self.rfile.read(n).decode())
            magnet = (data.get("magnet") or [""])[0].strip()
            cat = (data.get("cat") or ["other"])[0].strip()
            if magnet.startswith("magnet:"):
                add_magnet(magnet, cat)
                self._send(200, "ok")
            else:
                self._send(400, "bad magnet")
        elif path == "/remove":
            remove(self._ih())
            self._send(200, "ok")
        elif path == "/pause":
            pause(self._ih())
            self._send(200, "ok")
        elif path == "/resume":
            resume(self._ih())
            self._send(200, "ok")
        elif path == "/recheck":
            recheck(self._ih())
            self._send(200, "ok")
        else:
            self._send(404, "not found")


if __name__ == "__main__":
    mode = f"VPN-bound to {VPN_IP}" if PROTECTED else "NO VPN — downloads DISABLED"
    print(f"[vpntorrent] libtorrent {lt.version} · {mode} · http://0.0.0.0:{PORT}", flush=True)
    if PROTECTED:
        os.makedirs(RESUME_DIR, exist_ok=True)
        threading.Thread(target=alert_pump, daemon=True).start()
        restore_torrents()        # bring back torrents from the previous run
        threading.Thread(target=resume_saver, daemon=True).start()
        threading.Thread(target=monitor, daemon=True).start()
        threading.Thread(target=jackett_setup, daemon=True).start()
    # The media library + player work regardless of the VPN (local files, served
    # to the logged-in user). Run start() in a thread so a slow first disk scan
    # never delays the web server coming up.
    _cfg_dir = os.path.dirname(PW_FILE) or "/config"
    threading.Thread(target=library.start, args=(SAVE, _cfg_dir, TMDB_API_KEY),
                     daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
