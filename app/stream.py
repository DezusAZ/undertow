"""Stremio-style streaming from debrid.

"Stream" a search result instead of keeping it: resolve the magnet through the debrid
service (Real-Debrid / TorBox) to a direct HTTPS link, pull that link through the VPN into
a short-lived buffer under <downloads>/.stream/<sid>/, and point the EXISTING sandboxed
NVENC HLS transcoder at the buffer. The browser then plays it with the same hls.js player
the Library uses. When the viewer closes the player, the buffer is deleted — nothing is
kept.

Why a buffer at all: the decode sandbox has NO network (a malicious media file can't phone
home), so it can only read local files. The trusted VPN container does the network pull;
the sandbox does the decode; they meet on the filesystem. The buffer lives under
/downloads (which the sandbox mounts read-only) in a dot-dir the library scanner ignores.

Security: the debrid link is SSRF-checked (public host only) and fetched through fetcher's
pinned-IP safe opener (redirects re-validated), VPN-gated, and size-capped — identical
guards to the direct-download engine. Nothing here ever executes a file.

stdlib only; never seeds.
"""
import os
import time
import json
import shutil
import threading
import urllib.parse
import urllib.request

import fetcher          # reuse its SSRF guard + pinned-IP opener + size cap
import debrid

_save_dir = "/downloads"
_transcoder = "http://127.0.0.1:9000"
_vpn_ok = lambda: True

HEAD_BYTES = int(os.environ.get("STREAM_HEAD_BYTES", str(8 * 1024 * 1024)))   # buffer this much before transcoding
HEAD_WAIT = float(os.environ.get("STREAM_HEAD_WAIT", "45"))                   # ... but don't wait longer than this
MAX_SESSIONS = int(os.environ.get("STREAM_MAX_SESSIONS", "3"))               # bound concurrent buffers (disk)
SESSION_TTL = int(os.environ.get("STREAM_TTL", str(6 * 3600)))               # a forgotten session self-cleans

_sessions = {}          # sid -> {dir, buf, thread, stop, got, total, state, error, tsid, mode, filename, started}
_lock = threading.Lock()


def _stream_root():
    return os.path.join(_save_dir, ".stream")


def configure(save_dir, transcoder_base, vpn_check=None):
    """Inject paths + the VPN gate at startup, and sweep any buffers a previous run left."""
    global _save_dir, _transcoder, _vpn_ok
    _save_dir = save_dir or _save_dir
    _transcoder = transcoder_base or _transcoder
    if vpn_check is not None:
        _vpn_ok = vpn_check
    try:
        root = _stream_root()
        if os.path.isdir(root):
            shutil.rmtree(root, ignore_errors=True)       # stale buffers from a crash
    except Exception:
        pass
    threading.Thread(target=_reaper, daemon=True).start()


def _transcoder_get(path):
    return urllib.request.urlopen(_transcoder.rstrip("/") + path, timeout=45).read()


def _download(sid, url):
    """Pull the debrid link into the buffer file, through the VPN. Flushes as it goes so the
    transcoder sees new bytes. Honors the stop flag, the VPN gate, and the size cap."""
    s = _sessions.get(sid)
    if not s:
        return
    try:
        if not fetcher._public_host(url):
            _set(sid, state="failed", error="link host is not public")
            return
        op = fetcher._opener()
        req = urllib.request.Request(url, headers={"User-Agent": "vpntorrent"})
        resp = op.open(req, timeout=60)
        total = 0
        try:
            total = int(resp.headers.get("Content-Length") or 0)
        except Exception:
            total = 0
        if total and total > fetcher.MAX_BYTES:
            _set(sid, state="failed", error="file is over the size cap")
            return
        _set(sid, total=total)
        got = 0
        with open(s["buf"], "wb", buffering=0) as f:
            while not s["stop"].is_set():
                if not _vpn_ok():
                    _set(sid, state="failed", error="VPN dropped")
                    return
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                _set(sid, got=got)
                if got > fetcher.MAX_BYTES:
                    break
        if not s["stop"].is_set():
            _set(sid, state="complete")
    except Exception as e:
        _set(sid, state="failed", error=str(e)[:160])


def _set(sid, **kw):
    with _lock:
        s = _sessions.get(sid)
        if s:
            s.update(kw)


def start(magnet, cat="other", caps="", tier="high"):
    """Resolve -> buffer -> start the NVENC HLS session. Returns the transcoder result
    ({sid, mode, ...}) plus {local, filename} for the player, or raises with a readable reason."""
    if not debrid.active():
        raise RuntimeError("debrid is not set up — turn it on in Settings to stream")
    # bound concurrent buffers: stop the oldest rather than refuse (cleanup pops finished
    # sessions, so everything still in the map is live)
    with _lock:
        live = list(_sessions.items())
    if len(live) >= MAX_SESSIONS:
        oldest = min(live, key=lambda kv: kv[1].get("started", 0))[0]
        stop(oldest)
    info = debrid.resolve_for_stream(magnet)      # blocks; raises if not cacheable in time
    sid = "s-%x-%s" % (int(time.time() * 1000), os.urandom(3).hex())
    # compute the (sanitized) buffer name BEFORE creating the dir, so nothing can leave an
    # empty session dir behind if naming ever fails
    name = fetcher._safe_name(info.get("filename"), info["url"]) or "video"
    d = os.path.join(_stream_root(), sid)
    os.makedirs(d, exist_ok=True)
    buf = os.path.join(d, name)
    ev = threading.Event()
    with _lock:
        _sessions[sid] = {"dir": d, "buf": buf, "stop": ev, "got": 0, "total": info.get("size") or 0,
                          "state": "buffering", "error": "", "tsid": "", "mode": "",
                          "filename": info.get("filename") or name, "started": time.time()}
    t = threading.Thread(target=_download, args=(sid, info["url"]), name="stream-" + sid, daemon=True)
    with _lock:
        _sessions[sid]["thread"] = t
    t.start()
    # wait for a head before transcoding, but not forever
    t0 = time.time()
    while time.time() - t0 < HEAD_WAIT:
        s = _sessions.get(sid)
        if not s:
            raise RuntimeError("stream was cancelled")
        if s["state"] == "failed":
            _cleanup(sid)
            raise RuntimeError(s.get("error") or "could not fetch the stream")
        if s["got"] >= HEAD_BYTES or s["state"] == "complete":
            break
        time.sleep(0.5)
    # Hand the buffer to the sandboxed NVENC HLS transcoder (same pipeline the Library uses).
    # The transcoder ffprobes the file for duration first; a container with its header at the
    # FRONT (MKV, faststart MP4) probes fine from a small head, but a non-faststart MP4 keeps
    # its moov at the end, so retry as the buffer fills — that self-heals the "needs a little
    # more header" case without waiting for the whole file.
    r = None
    for attempt in range(4):
        s = _sessions.get(sid)
        if not s:
            raise RuntimeError("stream was cancelled")
        if s["state"] == "failed":
            _cleanup(sid)
            raise RuntimeError(s.get("error") or "could not fetch the stream")
        try:
            raw = _transcoder_get("/hls/start?path=" + urllib.parse.quote(buf)
                                  + "&caps=" + urllib.parse.quote(caps or "")
                                  + "&tier=" + urllib.parse.quote(tier or "high"))
            r = json.loads(raw or b"{}")
        except Exception as e:
            r = {"error": str(e)[:80]}
        if r and r.get("sid"):
            break
        if s["state"] == "complete":
            break                      # fully buffered and still no sid -> genuinely unplayable
        time.sleep(5)                  # let more of the file (and its header) arrive, then retry
    if not r or not r.get("sid"):
        _cleanup(sid)
        raise RuntimeError((r.get("error") if isinstance(r, dict) and r.get("error") else None)
                           or "couldn't open this file for streaming — try Download instead")
    _set(sid, tsid=r["sid"], mode=r.get("mode", ""), state="streaming")
    out = dict(r)
    out["local"] = sid
    out["filename"] = _sessions[sid]["filename"]
    return out


def status(sid):
    with _lock:
        s = _sessions.get(sid)
        if not s:
            return {"state": "gone"}
        return {"state": s["state"], "got": s["got"], "total": s["total"],
                "mode": s.get("mode", ""), "error": s.get("error", "")}


def _cleanup(sid):
    with _lock:
        s = _sessions.pop(sid, None)
    if not s:
        return
    try:
        s["stop"].set()
    except Exception:
        pass
    try:
        if s.get("tsid"):
            _transcoder_get("/hls/stop?sid=" + urllib.parse.quote(s["tsid"]))
    except Exception:
        pass
    try:
        shutil.rmtree(s["dir"], ignore_errors=True)
    except Exception:
        pass


def stop(sid):
    """Stop a stream: halt the download, stop the transcoder session, delete the buffer."""
    if sid in _sessions:
        _cleanup(sid)
        return True
    return False


def _reaper():
    while True:
        time.sleep(300)
        now = time.time()
        for sid, s in list(_sessions.items()):
            try:
                if now - s.get("started", now) > SESSION_TTL:
                    _cleanup(sid)
            except Exception:
                pass
