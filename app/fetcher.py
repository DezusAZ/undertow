"""Direct-download engine: plain file URLs (open directories, archive.org files, mirrors).

Deep Hunt's discovery layer finds FILES on the open web, but /add only knew magnets, .torrent
files and NZBs — so every open-directory or archive find was a dead end. This module queues a
URL, streams it through the VPN into the same category folders the torrent engine uses,
resumes partial files with HTTP Range, and shows up in the Downloads tab beside torrents and
Usenet jobs. The ClamAV watcher scans the folder like any other download (flag-and-keep).

Safety: http(s) only; the host must resolve to a PUBLIC address (never the LAN, loopback,
the sandbox or the Ollama box — same guard as the crawler); every redirect is re-validated;
a hard size cap; filenames are sanitised to a bare basename inside the category folder; the
file is never executed or opened here. Fetches run only while the VPN gate says so.
stdlib only. State is checkpointed to /config/direct.json so a restart resumes the queue.
"""
import os
import re
import json
import time
import shutil
import threading
import urllib.parse
import urllib.request

STATE_FILE = os.environ.get("DIRECT_STATE_FILE", "/config/direct.json")
MAX_BYTES = int(os.environ.get("DIRECT_MAX_BYTES", str(50 * 1024 ** 3)))    # 50 GB
WORKERS = max(1, int(os.environ.get("DIRECT_WORKERS", "2")))
CHUNK = 1 << 20
_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
_KEEP_DONE = 200                                   # finished/failed rows kept for the UI

_lock = threading.Lock()
_jobs = {}            # id -> job dict
_order = []           # ids in add order
_wake = threading.Event()
_stop = {}            # id -> Event (cancel a running fetch)
_save_dir = "/downloads"
_folders = set()
_vpn_ok = lambda: True
_started = False


def _now():
    return int(time.time())


def _save():
    try:
        tmp = STATE_FILE + ".tmp"
        with _lock:
            data = [_jobs[i] for i in _order if i in _jobs]
        with open(tmp, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass


def _load():
    try:
        data = json.load(open(STATE_FILE))
    except Exception:
        return
    if not isinstance(data, list):
        return
    with _lock:
        for j in data:
            if isinstance(j, dict) and j.get("id"):
                if j.get("state") == "downloading":      # interrupted by a restart -> resume
                    j["state"] = "queued"
                _jobs[j["id"]] = j
                _order.append(j["id"])


def _public_host(url):
    """The crawler's SSRF guard when available (pinned public IP), else a conservative
    fallback that refuses private/loopback/link-local resolutions."""
    try:
        import discover
        h = urllib.parse.urlsplit(url).hostname or ""
        return bool(discover._is_public_host(h))
    except Exception:
        pass
    try:
        import socket
        import ipaddress
        h = urllib.parse.urlsplit(url).hostname or ""
        for fam, _t, _p, _c, sa in socket.getaddrinfo(h, None):
            ip = ipaddress.ip_address(sa[0])
            if not ip.is_global:
                return False
        return True
    except Exception:
        return False


def _opener():
    try:
        import discover
        return discover._SAFE_OPENER                 # pinned-IP handlers + redirect re-validation
    except Exception:
        return urllib.request.build_opener()


def _safe_name(name, url):
    name = urllib.parse.unquote(name or "")
    if not name or name in (".", ".."):
        name = urllib.parse.unquote(os.path.basename(urllib.parse.urlsplit(url).path)) or "download"
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().lstrip(".")
    name = re.sub(r"\s+", " ", name)[:180] or "download"
    return name


def _unique(path):
    base, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(path) or os.path.exists(path + ".part"):
        path = "%s-%d%s" % (base, i, ext)
        i += 1
    return path


def start(save_dir, folders, vpn_check=None):
    """Wire the engine: where downloads go, which category folders exist, the VPN gate."""
    global _save_dir, _folders, _vpn_ok, _started
    _save_dir = save_dir
    _folders = set(folders or [])
    if vpn_check is not None:
        _vpn_ok = vpn_check
    if _started:
        return
    _started = True
    _load()
    for n in range(WORKERS):
        threading.Thread(target=_worker, name="direct-%d" % n, daemon=True).start()
    _wake.set()


def add(url, cat="other", name=None):
    """Queue a URL. Returns the job id. Raises ValueError with a user-readable reason."""
    url = (url or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("only http(s) URLs")
    if len(url) > 2048:
        raise ValueError("URL too long")
    if not _public_host(url):
        raise ValueError("host is not a public address")
    cat = cat if cat in _folders else "other"
    jid = "d-%x-%s" % (int(time.time() * 1000), os.urandom(2).hex())
    j = {"id": jid, "url": url, "name": _safe_name(name, url), "cat": cat, "state": "queued",
         "size": 0, "got": 0, "error": "", "added": _now(), "finished": 0, "dest": "",
         "host": urllib.parse.urlsplit(url).hostname or ""}
    with _lock:
        for o in _jobs.values():                     # same URL already queued/running -> no dupe
            if o.get("url") == url and o.get("state") in ("queued", "downloading"):
                return o["id"]
        _jobs[jid] = j
        _order.append(jid)
        _trim_locked()
    _save()
    _wake.set()
    return jid


def _trim_locked():
    done = [i for i in _order if _jobs.get(i, {}).get("state") in ("done", "failed")]
    while len(done) > _KEEP_DONE:
        i = done.pop(0)
        _order.remove(i)
        _jobs.pop(i, None)


def remove(jid, delete_files=False):
    with _lock:
        j = _jobs.get(jid)
        if not j:
            return False
        ev = _stop.get(jid)
        if ev:
            ev.set()
        j["state"] = "removed"
        dest = j.get("dest") or ""
        _order.remove(jid) if jid in _order else None
        _jobs.pop(jid, None)
    if dest:
        for p in (dest + ".part", dest) if delete_files else (dest + ".part",):
            try:
                if p.startswith(os.path.realpath(_save_dir)) or p.startswith(_save_dir):
                    os.remove(p)
            except OSError:
                pass
    _save()
    return True


def snapshot():
    """Rows shaped like the Downloads tab's usenet rows (+ kind='direct')."""
    out = []
    with _lock:
        jobs = [dict(_jobs[i]) for i in _order if i in _jobs]
    for j in jobs:
        size = j.get("size") or 0
        got = j.get("got") or 0
        pct = round(100.0 * got / size, 1) if size else (100.0 if j.get("state") == "done" else 0.0)
        st = j.get("state", "")
        state = {"queued": "Queued", "downloading": "Downloading", "done": "Done",
                 "failed": "Failed", "paused": "Paused (VPN down)"}.get(st, st)
        out.append({"id": j["id"], "kind": "direct", "name": j.get("name", ""), "cat": j.get("cat", "other"),
                    "progress": pct, "state": state, "paused": st == "paused",
                    "eta": "", "size": _human(size) if size else "", "done": st in ("done", "failed"),
                    "error": j.get("error", "") if st == "failed" else "",
                    "host": j.get("host", ""), "url": j.get("url", ""),
                    "speed": j.get("speed", 0) if st == "downloading" else 0})
    return out


def _human(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return ("%d%s" if u == "B" else "%.1f%s") % (n, u)
        n /= 1024.0
    return "%.1fPB" % n


def _next_job():
    with _lock:
        for i in _order:
            j = _jobs.get(i)
            if j and j.get("state") == "queued":
                j["state"] = "downloading"
                j["error"] = ""
                _stop[i] = threading.Event()
                return dict(j)
    return None


def _set(jid, **kv):
    with _lock:
        j = _jobs.get(jid)
        if j is not None:
            j.update(kv)


def _worker():
    while True:
        _wake.wait(timeout=5)
        _wake.clear()
        while True:
            if not _vpn_ok():
                break                                # queue waits for the tunnel
            j = _next_job()
            if not j:
                break
            try:
                _fetch(j)
            except Exception as e:                   # never let a worker die
                _set(j["id"], state="failed", error=str(e)[:160], finished=_now())
            _stop.pop(j["id"], None)
            _save()


def _fetch(j):
    jid, url = j["id"], j["url"]
    stop = _stop.get(jid) or threading.Event()
    folder = os.path.join(_save_dir, j.get("cat") or "other")
    os.makedirs(folder, exist_ok=True)
    dest = j.get("dest") or _unique(os.path.join(folder, j["name"]))
    part = dest + ".part"
    have = os.path.getsize(part) if os.path.exists(part) else 0
    headers = {"User-Agent": _UA, "Accept": "*/*"}
    if have:
        headers["Range"] = "bytes=%d-" % have
    req = urllib.request.Request(url, headers=headers)
    op = _opener()
    resp = op.open(req, timeout=45)
    try:
        code = getattr(resp, "status", 200)
        final = resp.geturl() or url
        if not _public_host(final):
            raise ValueError("redirected to a non-public host")
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if ctype.startswith("text/html") and not j["name"].lower().endswith((".html", ".htm")):
            raise ValueError("that URL is a web page, not a file")
        cd = resp.headers.get("Content-Disposition") or ""
        m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', cd)
        if m and not j.get("dest"):
            nm = _safe_name(m.group(1), url)
            if nm and nm != j["name"]:
                dest = _unique(os.path.join(folder, nm))
                part = dest + ".part"
                _set(jid, name=nm)
        if code == 206 and have:
            mode, got = "ab", have
            cr = resp.headers.get("Content-Range") or ""
            mm = re.search(r"/(\d+)", cr)
            total = int(mm.group(1)) if mm else 0
        else:
            mode, got = "wb", 0
            cl = resp.headers.get("Content-Length")
            total = int(cl) if cl and cl.isdigit() else 0
        if total and total > MAX_BYTES:
            raise ValueError("file is %s — over the %s cap" % (_human(total), _human(MAX_BYTES)))
        free = shutil.disk_usage(folder).free
        if total and total - got > free - (512 << 20):
            raise ValueError("not enough free space (%s needed, %s free)" % (_human(total - got), _human(free)))
        _set(jid, dest=dest, size=total, got=got)
        t0, g0 = time.time(), got
        with open(part, mode) as f:
            while True:
                if stop.is_set():
                    return                           # removed by the user
                if not _vpn_ok():
                    _set(jid, state="paused")
                    _wake.set()
                    return
                buf = resp.read(CHUNK)
                if not buf:
                    break
                f.write(buf)
                got += len(buf)
                if got > MAX_BYTES:
                    raise ValueError("exceeded the %s cap" % _human(MAX_BYTES))
                now = time.time()
                if now - t0 >= 1.0:
                    _set(jid, got=got, speed=int((got - g0) / (now - t0)))
                    t0, g0 = now, got
        if total and got < total:
            raise ValueError("connection ended early (%s of %s)" % (_human(got), _human(total)))
        os.replace(part, dest)
        _set(jid, state="done", got=got, size=total or got, finished=_now(), speed=0)
    finally:
        try:
            resp.close()
        except Exception:
            pass


def resume_paused():
    """Called by the app's VPN monitor when the tunnel comes back."""
    with _lock:
        for j in _jobs.values():
            if j.get("state") == "paused":
                j["state"] = "queued"
    _wake.set()
