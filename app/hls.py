"""Just-in-time HLS streaming for the decoder sandbox.

WHY THIS EXISTS
The old playback path converted an entire film before a single frame played — roughly
ten minutes for a 1080p x265 rip and far worse for 4K. That is a terrible trade when you
only want to watch five minutes, or you are just checking a file is what it claims.

HLS flips it: the video is served as a list of short segments, and a segment is encoded
only when the player asks for it. Playback starts in seconds, seeking jumps straight to
the requested point (restarting the encoder there), and nothing beyond what you actually
watch is ever encoded.

DESIGN NOTES
- Segments are fixed-length by construction: we force a keyframe every SEG_SECONDS, so
  the playlist can be written up-front from the duration alone, without encoding
  anything. That static VOD playlist is what makes seeking work instantly.
- `-ss` before `-i` gives a fast input seek; `-output_ts_offset` then puts the segment
  timestamps back where they belong, so the player sees one continuous timeline even
  though the encoder restarted mid-film.
- A seek far outside the encoded window kills the encoder and restarts it at the new
  position. Seeking a little ahead just waits, because the encoder is usually already
  producing that region.
- This module runs INSIDE the network-isolated decoder sandbox, like every other ffmpeg
  invocation. It never runs in the app container.
"""

import errno
import hashlib
import math
import os
import re
import shutil
import subprocess
import threading
import time

import library

SEG_SECONDS = int(os.environ.get("HLS_SEG_SECONDS", "6"))
HLS_ROOT = os.path.join(library.CACHE_DIR, "hls")
# How far ahead of the requested segment the encoder may already be before we consider a
# restart pointless, and how far behind before a seek is "backwards".
LOOKAHEAD_SEGS = int(os.environ.get("HLS_LOOKAHEAD", "40"))
SEGMENT_WAIT = float(os.environ.get("HLS_SEGMENT_WAIT", "90"))   # seconds to wait for one
IDLE_KILL = float(os.environ.get("HLS_IDLE_KILL", "180"))        # kill unused encoders
SESSION_TTL = float(os.environ.get("HLS_SESSION_TTL", "21600"))  # scrub dirs after 6h
MAX_SESSIONS = int(os.environ.get("HLS_MAX_SESSIONS", "2"))      # concurrent encoders

_SID_RE = re.compile(r"^[0-9a-f]{20}$")
_lock = threading.Lock()
_sessions = {}          # sid -> dict(path, mode, dur, proc, start_seg, last_used, dir)


def _sid_for(real_path, mode):
    try:
        st = os.stat(real_path)
    except OSError:
        return None
    raw = "%s|%d|%d|%s|hls" % (real_path, st.st_mtime_ns, st.st_size, mode)
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:20]


def _dir_for(sid):
    return os.path.join(HLS_ROOT, sid)


def seg_path(sid, n):
    return os.path.join(_dir_for(sid), "seg%d.ts" % n)


# ----------------------------------------------------------------- session lifecycle
def start(real_path, caps=""):
    """Prepare an HLS session. Encodes nothing yet — returns the shape of the stream.

    Returns {} if the file is unusable. `mode` is informational for the UI.
    """
    dur = library._probe_duration(real_path)
    if not dur or dur <= 0:
        return {}
    try:
        plan = library.plan_playback(real_path, caps)
    except Exception:
        plan = "transcode"
    # A file the browser can already decode is better served by the existing quick remux
    # (a container swap, no re-encode); HLS exists for the expensive case.
    mode = "hls-gpu" if library._have_nvenc() else "hls-cpu"
    sid = _sid_for(real_path, mode)
    if not sid:
        return {}
    # If a full conversion of this file already exists (from the old prepare path),
    # hand that back instead: it plays with native byte-range seeking and needs no
    # encoder at all. Work already done should never be done twice.
    try:
        pk = library.cache_key(real_path, "transcode")
        if pk and os.path.exists(os.path.join(library.CACHE_DIR, pk + ".mp4")):
            return {"prepared": pk, "duration": round(dur, 3), "mode": "prepared"}
    except Exception:
        pass
    try:
        os.makedirs(_dir_for(sid), exist_ok=True)
    except OSError:
        return {}
    nsegs = int(math.ceil(dur / float(SEG_SECONDS)))
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            s = {"path": real_path, "mode": mode, "dur": dur, "nsegs": nsegs,
                 "proc": None, "start_seg": -1, "next_seg": -1,
                 "last_used": time.time(), "dir": _dir_for(sid)}
            _sessions[sid] = s
        else:
            s["last_used"] = time.time()
    return {"sid": sid, "duration": round(dur, 3), "segments": nsegs,
            "seg_seconds": SEG_SECONDS, "mode": mode, "plan": plan}


def playlist(sid):
    """The full VOD playlist, written from the duration — no encoding required.

    Because every segment is exactly SEG_SECONDS (we force keyframes there), the player
    can seek anywhere immediately; it just requests the segment covering that timestamp.
    """
    if not _SID_RE.match(sid or ""):
        return None
    with _lock:
        s = _sessions.get(sid)
        if not s:
            return None
        dur, n = s["dur"], s["nsegs"]
        s["last_used"] = time.time()
    out = ["#EXTM3U", "#EXT-X-VERSION:3",
           "#EXT-X-TARGETDURATION:%d" % SEG_SECONDS,
           "#EXT-X-MEDIA-SEQUENCE:0",
           "#EXT-X-PLAYLIST-TYPE:VOD",
           "#EXT-X-INDEPENDENT-SEGMENTS"]
    for i in range(n):
        left = dur - i * SEG_SECONDS
        out.append("#EXTINF:%.3f," % (SEG_SECONDS if left > SEG_SECONDS else max(left, 0.001)))
        # The URI must route back through the /hls/segment ENDPOINT. A bare "seg0.ts"
        # resolves (per RFC 3986) against /hls/playlist to /hls/seg0.ts — a URL that
        # does not exist — so every real player 404'd on its first segment while our
        # endpoint-poking tests passed. The player follows the playlist, not our tests.
        out.append("segment?sid=%s&n=%d" % (sid, i))
    out.append("#EXT-X-ENDLIST")
    return "\n".join(out) + "\n"


def _kill(s):
    p = s.get("proc")
    if p is not None:
        try:
            p.kill()
        except Exception:
            pass
        try:
            p.wait(timeout=10)
        except Exception:
            pass
    s["proc"] = None
    s["start_seg"] = -1


def _spawn(sid, s, from_seg):
    """(Re)start the encoder at `from_seg`. Caller holds no lock."""
    _kill(s)
    start_t = from_seg * SEG_SECONDS
    gpu = s["mode"] == "hls-gpu"
    d = s["dir"]
    # Keyframe exactly on each segment boundary, so segments are independently
    # decodable and land on the timestamps the static playlist promises.
    kf = "expr:gte(t,n_forced*%d)" % SEG_SECONDS
    cmd = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
           "-protocol_whitelist", "file,pipe"]
    if gpu:
        cmd += ["-hwaccel", "cuda"]
    cmd += ["-ss", "%.3f" % start_t, "-i", s["path"]]
    cmd += library._venc_args(gpu)
    cmd += ["-force_key_frames", kf,
            "-c:a", "aac", "-ac", "2", "-b:a", "160k",
            "-dn", "-sn",
            # put the timeline back where it belongs after the input seek, so a restart
            # mid-film does not look like a discontinuity to the player
            "-output_ts_offset", "%.3f" % start_t,
            "-f", "hls",
            "-hls_time", str(SEG_SECONDS),
            "-hls_playlist_type", "vod",
            "-hls_flags", "independent_segments+temp_file",
            "-hls_list_size", "0",
            "-start_number", str(from_seg),
            "-hls_segment_filename", os.path.join(d, "seg%d.ts"),
            os.path.join(d, "live.m3u8")]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except Exception as e:
        print("[hls] spawn failed: %s" % e, flush=True)
        return False
    s["proc"] = p
    s["start_seg"] = from_seg
    s["next_seg"] = from_seg
    s["err"] = []

    def _drain(pipe, sink):
        try:
            for ln in pipe:
                ln = ln.decode("utf-8", "replace").rstrip()
                if ln:
                    sink.append(ln)
                    del sink[:-8]
        except Exception:
            pass

    threading.Thread(target=_drain, args=(p.stderr, s["err"]), daemon=True).start()
    print("[hls] %s encoding from segment %d (%s)" % (sid[:8], from_seg, s["mode"]),
          flush=True)
    return True


def segment(sid, n):
    """Return the bytes of segment `n`, encoding it on demand.

    Returns (data, None) or (None, reason).
    """
    if not _SID_RE.match(sid or "") or n < 0:
        return None, "bad request"
    with _lock:
        s = _sessions.get(sid)
        if not s:
            return None, "no such session"
        if n >= s["nsegs"]:
            return None, "past end"
        s["last_used"] = time.time()

    path = seg_path(sid, n)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return _read(path), None

    # Decide whether the running encoder will ever reach this segment.
    with _lock:
        proc = s.get("proc")
        alive = proc is not None and proc.poll() is None
        start_seg = s.get("start_seg", -1)
    need_spawn = (not alive) or n < start_seg or n > start_seg + LOOKAHEAD_SEGS
    if need_spawn:
        _reap_if_needed(sid)
        if not _spawn(sid, s, n):
            return None, "could not start the encoder"

    deadline = time.time() + SEGMENT_WAIT
    while time.time() < deadline:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            # ffmpeg writes via a temp file, so existence already implies complete
            return _read(path), None
        with _lock:
            proc = s.get("proc")
        if proc is not None and proc.poll() is not None:
            # encoder exited; either it finished past this point or it failed
            if os.path.exists(path) and os.path.getsize(path) > 0:
                return _read(path), None
            err = " | ".join(s.get("err") or [])[:300]
            if proc.returncode not in (0, -9):
                print("[hls] encoder exited rc=%s: %s" % (proc.returncode, err),
                      flush=True)
                return None, err or "encoder failed"
            return None, "segment not produced"
        time.sleep(0.25)
    return None, "timed out waiting for the segment"


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _reap_if_needed(keep_sid):
    """Keep concurrent encoders bounded; drop the least recently used."""
    with _lock:
        live = [(sid, s) for sid, s in _sessions.items()
                if s.get("proc") is not None and s["proc"].poll() is None]
    if len(live) < MAX_SESSIONS:
        return
    live.sort(key=lambda kv: kv[1]["last_used"])
    for sid, s in live:
        if sid == keep_sid:
            continue
        print("[hls] %s stopping least-recently-used encoder" % sid[:8], flush=True)
        _kill(s)
        break


def stop(sid):
    """Stop a session's encoder (the segments already written stay cached)."""
    if not _SID_RE.match(sid or ""):
        return False
    with _lock:
        s = _sessions.get(sid)
    if not s:
        return False
    _kill(s)
    return True


def housekeeping():
    """Kill idle encoders and delete stale session directories."""
    now = time.time()
    with _lock:
        items = list(_sessions.items())
    for sid, s in items:
        p = s.get("proc")
        if p is not None and p.poll() is None and (now - s["last_used"]) > IDLE_KILL:
            print("[hls] %s idle — stopping encoder" % sid[:8], flush=True)
            _kill(s)
        if (now - s["last_used"]) > SESSION_TTL:
            _kill(s)
            try:
                shutil.rmtree(s["dir"], ignore_errors=True)
            except Exception:
                pass
            with _lock:
                _sessions.pop(sid, None)
    # Directories with no session at all (left by a restart of this process).
    try:
        for name in os.listdir(HLS_ROOT):
            d = os.path.join(HLS_ROOT, name)
            if not os.path.isdir(d):
                continue
            with _lock:
                known = name in _sessions
            if known:
                continue
            try:
                if now - os.path.getmtime(d) > SESSION_TTL:
                    shutil.rmtree(d, ignore_errors=True)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    pass
    except OSError:
        pass


def _housekeeper():
    while True:
        time.sleep(60)
        try:
            housekeeping()
        except Exception:
            pass


def init():
    try:
        os.makedirs(HLS_ROOT, exist_ok=True)
    except OSError:
        pass
    threading.Thread(target=_housekeeper, daemon=True).start()
