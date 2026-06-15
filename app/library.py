#!/usr/bin/env python3
"""library.py - media library index + in-browser streaming for vpntorrent.

Self-contained, stdlib-only. The web layer (vt.py) imports this and calls:
  start(save_dir, config_dir, tmdb_key)   -> launch scanner + TMDB enrichment
  list_items() / get_item(id)             -> the cached, browseable index
  resolve_file(id, i)                     -> safe absolute path of one file
  probe_vcodec(path)                      -> video codec name (for transcode choice)
  stream_file(handler, path)              -> HTTP serve with byte-range/seek (206)
  transcode_file(handler, path)           -> live ffmpeg remux/transcode to fMP4

Why a background scanner instead of walking on every request: the save dir lives
on an 11TB spinning disk; a full walk is slow and we don't want to block (or
hammer the disk on) every page load. We rebuild an in-memory index periodically
and serve all browse requests from RAM. TMDB lookups (posters/overviews) are done
by a separate worker so a downed VPN never stalls scanning, and results persist to
a JSON cache so we don't re-query on every restart.
"""
import os
import re
import json
import time
import hashlib
import threading
import subprocess
import mimetypes
import urllib.parse
import urllib.request
import urllib.error

# --- extension classification ---------------------------------------------
VIDEO_EXTS = {".mp4", ".m4v", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
              ".ogv", ".mpg", ".mpeg", ".m2ts", ".ts", ".vob", ".3gp", ".divx"}
AUDIO_EXTS = {".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac",
              ".wma", ".alac", ".aiff", ".ape"}
DOC_EXTS = {".pdf", ".epub", ".mobi", ".azw3", ".cbz", ".cbr", ".djvu",
            ".txt", ".doc", ".docx", ".odt", ".rtf"}

# Formats a modern browser plays natively (no transcode needed).
NATIVE_VIDEO = {".mp4", ".m4v", ".webm", ".ogv"}
NATIVE_AUDIO = {".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac"}

# Category subfolders we expect under the save dir.
_CATEGORIES = ("movies", "tv", "music", "documents", "software", "other")

# Junk we never count as media.
_TEMP_SUFFIXES = (".part", ".!qb", ".!qB")
_MIN_VIDEO_BYTES = 30 * 1024 * 1024     # below this a video is probably a sample

# --- module state ----------------------------------------------------------
_cfg = {"save_dir": "", "config_dir": "", "tmdb_key": ""}
_lock = threading.Lock()                 # guards _index and _meta
_index = []                              # list of item dicts (sorted by title)
_meta = {}                               # tmdb cache: key -> {poster,overview,...}
_started = False

# Re-query a negative (no-match) TMDB result at most this often, so a one-off
# miss (e.g. VPN was down) eventually gets retried but we don't spam the API.
_NEG_RETRY_SECS = 24 * 3600

# ===========================================================================
# Title cleaning
# ===========================================================================
# Scene-junk tokens stripped from release names (matched as whole words).
_JUNK = {
    "1080p", "2160p", "4k", "720p", "480p", "x264", "x265", "h264", "h265",
    "hevc", "xvid", "divx", "aac", "ac3", "eac3", "dts", "ddp5.1", "dd5.1",
    "5.1", "10bit", "hdr", "bluray", "blu-ray", "brrip", "bdrip", "webrip",
    "web-dl", "webdl", "hdrip", "dvdrip", "hdtv", "proper", "repack",
    "extended", "remastered", "unrated", "yify", "yts", "rarbg", "eztv",
    "amzn", "nf", "complete", "season",
}
_YEAR_RE = re.compile(r"\b(19\d{2}|20\d{2})\b")
# TV episode markers: S01E02 / s01.e02 / 1x02 / "Season 3"
_TV_SXXEXX = re.compile(r"\bS(\d{1,2})[\. _-]?E(\d{1,3})\b", re.I)
_TV_NXNN = re.compile(r"\b(\d{1,2})x(\d{2,3})\b", re.I)
_TV_SEASON = re.compile(r"\bSeason[\s\.]*\d{1,2}\b", re.I)


def _normsep(name):
    """Release names use . _ - as separators; turn them into spaces so the TV
    regexes' \\b word boundaries fire (underscore is a word char, so '_2x05_'
    wouldn't otherwise match)."""
    return re.sub(r"[._\-]+", " ", name)


def _is_tv_name(name):
    """True if a name looks like a TV episode/season release."""
    s = _normsep(name)
    return bool(_TV_SXXEXX.search(s) or _TV_NXNN.search(s)
                or _TV_SEASON.search(s))


def _clean_title(name, is_file):
    """Turn a release name into (clean_title, year_or_None).

    For TV the title is the part before the SxxExx/NxNN marker so all episodes of
    a show collapse to one title. For movies the title is everything before the
    first year token. Junk tokens are dropped and leftover punctuation trimmed.
    """
    if is_file:
        name = os.path.splitext(name)[0]

    # Normalise separators to spaces up front so TV regexes match (see _normsep).
    s = _normsep(name)

    # For TV, cut at the episode marker first — everything after is episode noise.
    m = _TV_SXXEXX.search(s) or _TV_NXNN.search(s) or _TV_SEASON.search(s)
    if m and m.start() > 0:
        s = s[:m.start()]

    s = re.sub(r"\s+", " ", s).strip()

    # Year detection: take the first year that comes after at least one word, so
    # a title that *starts* with a number (rare) isn't mistaken for a year.
    year = None
    ym = _YEAR_RE.search(s)
    if ym and ym.start() > 0 and s[:ym.start()].strip():
        year = int(ym.group(1))
        s = s[:ym.start()]

    # Drop scene-junk tokens (whole words, case-insensitive).
    kept = [w for w in s.split() if w.lower().strip("()[]{}") not in _JUNK]
    s = " ".join(kept)

    # Remove now-empty brackets/parens and stray punctuation at the edges.
    s = re.sub(r"[\(\[\{]\s*[\)\]\}]", " ", s)
    s = re.sub(r"\s+", " ", s).strip(" .-_([{)]}")
    s = s.strip()

    if not s:
        # Nothing survived cleaning — fall back to the raw (deseparated) name.
        s = re.sub(r"[._\-]+", " ", os.path.splitext(name)[0]).strip() or name

    # Only title-case when the source gave us no casing signal at all.
    if s == s.lower():
        s = s.title()
    return s, year


# ===========================================================================
# Scanning / indexing
# ===========================================================================
def _stable_id(rel_path):
    """12 hex chars derived from the item's path relative to the save dir.

    Stable across restarts (same path -> same id) and short enough for URLs.
    """
    return hashlib.md5(rel_path.encode("utf-8", "replace")).hexdigest()[:12]


def _file_kind(ext):
    if ext in VIDEO_EXTS:
        return "video"
    if ext in AUDIO_EXTS:
        return "audio"
    if ext in DOC_EXTS:
        return "doc"
    return "other"


def _collect_media(root):
    """Walk an item path and return media files as (abs_path, size) tuples.

    Skips temp/partial files, samples, and tiny videos (likely sample/extra
    clips) unless a tiny video is the only video present. Tolerant of permission
    errors and broken symlinks.
    """
    found = []          # (abs, size, kind, ext)
    if os.path.isfile(root):
        candidates = [root]
    else:
        candidates = []
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            for fn in filenames:
                candidates.append(os.path.join(dirpath, fn))

    for p in candidates:
        name = os.path.basename(p)
        if name.endswith(_TEMP_SUFFIXES):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext not in VIDEO_EXTS and ext not in AUDIO_EXTS and ext not in DOC_EXTS:
            continue
        if "sample" in name.lower():
            continue
        try:
            size = os.path.getsize(p)        # follows symlinks; broken -> raises
        except OSError:
            continue
        found.append((p, size, _file_kind(ext), ext))

    # Drop tiny videos unless they're the only video we have.
    videos = [f for f in found if f[2] == "video"]
    big_videos = [f for f in videos if f[1] >= _MIN_VIDEO_BYTES]
    if big_videos:
        keep_videos = set(id(f) for f in big_videos)
        found = [f for f in found if f[2] != "video" or id(f) in keep_videos]
    # else: keep all videos (the largest small one is the best we've got)
    return found


def _detect_type(cat, files, raw_name):
    """Classify an item using its category, its files, and its raw name."""
    has_video = any(f[2] == "video" for f in files)
    has_audio = any(f[2] == "audio" for f in files)
    has_doc = any(f[2] == "doc" for f in files)

    if cat == "music" or (has_audio and not has_video):
        return "album"
    if cat == "tv" or _is_tv_name(raw_name):
        return "tv"
    if cat == "movies" or has_video:
        return "movie"
    if has_doc and not has_video and not has_audio:
        return "doc"
    return "other"


# --- malware scan results (produced by the clamav container) ---------------
_SCAN_CACHE = {"mtime": -1, "files": {}}
_scan_lock = threading.Lock()


def _scan_results():
    """Read the clamav results map ({relpath: {verdict,reason,sig,ts}}), cached by
    the file's mtime. {} until the scanner has produced results."""
    path = os.path.join(_cfg["config_dir"], "clamav", "results.json")
    try:
        m = os.path.getmtime(path)
    except OSError:
        return {}
    with _scan_lock:
        if m != _SCAN_CACHE["mtime"]:
            try:
                with open(path) as f:
                    data = json.load(f)
                _SCAN_CACHE["files"] = data.get("files", {}) if isinstance(data, dict) else {}
                _SCAN_CACHE["mtime"] = m
            except Exception:
                pass
        return _SCAN_CACHE["files"]


def _scan_status(item_rel):
    """Aggregate the AV verdicts for files under one item. Returns
    (status, quarantined): status is 'clean'|'pending'|'flagged'; quarantined is
    a list of {name, reason} for files the scan removed to .quarantine."""
    files = _scan_results()
    if not files:
        return "pending", []
    key = item_rel.replace(os.sep, "/")
    prefix = key + "/"
    relevant = [(k, v) for k, v in files.items() if k == key or k.startswith(prefix)]
    if not relevant:
        return "pending", []
    quarantined = [{"name": os.path.basename(k), "reason": v.get("reason", "")}
                   for k, v in relevant if v.get("verdict") == "quarantined"]
    if quarantined:
        return "flagged", quarantined
    return "clean", []


def _build_item(save_dir, cat, entry_name):
    """Build one item dict from a category child entry, or None if no media."""
    item_path = os.path.join(save_dir, cat, entry_name)
    try:
        media = _collect_media(item_path)
    except Exception:
        media = []
    if not media:
        return None                      # nothing playable/readable -> skip

    is_file = os.path.isfile(item_path)
    title, year = _clean_title(entry_name, is_file)
    itype = _detect_type(cat, media, entry_name)

    # Sort files by name for a stable, human order; assign each an index.
    media.sort(key=lambda f: os.path.basename(f[0]).lower())
    files = []
    total = 0
    for i, (p, size, kind, ext) in enumerate(media):
        total += size
        playable = kind in ("video", "audio")
        native = (kind == "video" and ext in NATIVE_VIDEO) or \
                 (kind == "audio" and ext in NATIVE_AUDIO)
        files.append({
            "i": i,
            "name": os.path.basename(p),
            "kind": kind,
            "playable": playable,
            "native": native,
            "size": size,
        })

    rel = os.path.relpath(item_path, save_dir)
    meta = _lookup_meta(itype, title, year)
    scan, quarantined = _scan_status(rel)
    return {
        "id": _stable_id(rel),
        "cat": cat,
        "type": itype,
        "title": title,
        "year": year,
        "poster": meta.get("poster") if meta else None,
        "overview": meta.get("overview") if meta else None,
        "size": total,
        "files": files,
        "scan": scan,                    # "clean" | "pending" | "flagged"
        "quarantined": quarantined,      # [{"name","reason"}] removed by the AV scan
        "_rel": rel,                     # internal: used by resolve_file
    }


def _scan_once():
    """Rebuild the full index from disk. Never raises."""
    save_dir = _cfg["save_dir"]
    items = []
    try:
        for cat in _CATEGORIES:
            cat_dir = os.path.join(save_dir, cat)
            if not os.path.isdir(cat_dir):
                continue
            try:
                entries = os.listdir(cat_dir)
            except OSError:
                continue                 # unreadable category dir -> skip
            for entry in entries:
                if entry.startswith("."):
                    continue
                if entry.endswith(_TEMP_SUFFIXES):
                    continue
                try:
                    item = _build_item(save_dir, cat, entry)
                except Exception:
                    item = None
                if item:
                    items.append(item)
    except Exception:
        # A catastrophic error shouldn't wipe a previously-good index.
        return

    items.sort(key=lambda it: (it["title"].lower(), it.get("year") or 0))
    with _lock:
        _index[:] = items


def _scanner_loop():
    while True:
        _scan_once()
        time.sleep(300)                  # ~5 minutes between rebuilds


# ===========================================================================
# TMDB metadata cache + enrichment worker
# ===========================================================================
def _cache_path():
    return os.path.join(_cfg["config_dir"], "library-cache.json")


def _meta_key(itype, title, year):
    return f"{itype}|{title}|{year}"


def _load_cache():
    try:
        with open(_cache_path()) as f:
            data = json.load(f)
        if isinstance(data, dict):
            with _lock:
                _meta.update(data)
    except Exception:
        pass                             # missing/corrupt cache -> start empty


def _save_cache():
    try:
        with _lock:
            snapshot = dict(_meta)
        tmp = _cache_path() + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f)
        os.replace(tmp, _cache_path())   # atomic replace of the cache file
    except Exception:
        pass


def _lookup_meta(itype, title, year):
    """Return cached metadata for an item (no network), or None if not cached."""
    if itype not in ("movie", "tv"):
        return None
    with _lock:
        return _meta.get(_meta_key(itype, title, year))


def _tmdb_search(itype, title, year, key):
    """Query TMDB; return {poster, overview, tmdb_year} or {} on no-match.

    Raises on network error so the caller can leave the item un-cached and retry
    on a later pass (e.g. when the VPN comes back up).
    """
    if itype == "tv":
        base = "https://api.themoviedb.org/3/search/tv"
        yparam = "first_air_date_year"
        datefield = "first_air_date"
    else:
        base = "https://api.themoviedb.org/3/search/movie"
        yparam = "year"
        datefield = "release_date"

    params = {"api_key": key, "query": title}
    if year:
        params[yparam] = str(year)
    url = base + "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url, headers={"User-Agent": "vpntorrent/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))

    results = data.get("results") or []
    if not results:
        return {}                        # genuine no-match
    r = results[0]
    poster_path = r.get("poster_path")
    poster = ("https://image.tmdb.org/t/p/w500" + poster_path) if poster_path else None
    tmdb_year = None
    date = r.get(datefield) or ""
    if len(date) >= 4 and date[:4].isdigit():
        tmdb_year = int(date[:4])
    return {
        "poster": poster,
        "overview": r.get("overview") or None,
        "tmdb_year": tmdb_year,
    }


def _enrich_loop():
    key = _cfg["tmdb_key"]
    while True:
        if not key:
            return                       # no key -> nothing to do, ever
        try:
            _enrich_pass(key)
        except Exception:
            pass
        time.sleep(120)                  # check for new un-enriched items


def _enrich_pass(key):
    """One enrichment sweep over the current index. Throttled + fault-tolerant."""
    with _lock:
        targets = [(it["type"], it["title"], it.get("year")) for it in _index
                   if it["type"] in ("movie", "tv")]

    now = time.time()
    dirty = False
    for itype, title, year in targets:
        k = _meta_key(itype, title, year)
        with _lock:
            cached = _meta.get(k)
        if cached:
            # Re-query only stale negative results (no poster AND no overview).
            is_negative = not cached.get("poster") and not cached.get("overview")
            if not is_negative or (now - cached.get("ts", 0)) < _NEG_RETRY_SECS:
                continue

        try:
            res = _tmdb_search(itype, title, year, key)
        except Exception:
            # Network/VPN error: leave un-cached so a later pass retries.
            continue

        entry = {
            "poster": res.get("poster"),
            "overview": res.get("overview"),
            "tmdb_year": res.get("tmdb_year"),
            "ts": time.time(),
        }
        with _lock:
            _meta[k] = entry
        dirty = True
        _apply_meta_to_index(k, entry)
        time.sleep(0.3)                  # be polite to the TMDB API

    if dirty:
        _save_cache()


def _apply_meta_to_index(meta_key, entry):
    """Push freshly-fetched metadata into the live index without a full rescan."""
    with _lock:
        for it in _index:
            if _meta_key(it["type"], it["title"], it.get("year")) == meta_key:
                it["poster"] = entry.get("poster")
                it["overview"] = entry.get("overview")


# ===========================================================================
# Public API
# ===========================================================================
def start(save_dir, config_dir, tmdb_key=""):
    """Initialise config and launch the scanner + enrichment daemon threads.

    Safe to call exactly once at startup; never raises.
    """
    global _started
    try:
        _cfg["save_dir"] = os.path.abspath(save_dir)
        _cfg["config_dir"] = config_dir
        _cfg["tmdb_key"] = (tmdb_key or "").strip()
        if _started:
            return
        _started = True

        _load_cache()
        _scan_once()                     # have an index ready before serving

        threading.Thread(target=_scanner_loop, daemon=True,
                         name="lib-scanner").start()
        threading.Thread(target=_enrich_loop, daemon=True,
                         name="lib-enrich").start()
    except Exception:
        pass                             # startup must never bring down the app


def list_items():
    """Return a copy of the current index (internal fields stripped)."""
    with _lock:
        return [_public_item(it) for it in _index]


def get_item(item_id):
    """Return one item dict by id, or None."""
    with _lock:
        for it in _index:
            if it["id"] == item_id:
                return _public_item(it)
    return None


def _public_item(it):
    """Shallow copy of an item without internal (_-prefixed) keys."""
    return {k: v for k, v in it.items() if not k.startswith("_")}


def resolve_file(item_id, i):
    """Absolute path of file index `i` in item `item_id`, or None.

    Validates the resolved real path is inside the save dir to defeat path
    traversal / symlink escapes.
    """
    with _lock:
        item = None
        for it in _index:
            if it["id"] == item_id:
                item = it
                break
    if item is None:
        return None
    try:
        i = int(i)
    except (TypeError, ValueError):
        return None
    files = item["files"]
    if i < 0 or i >= len(files):
        return None

    # Rebuild the absolute path from item path + filename, then verify it really
    # lives under the save dir. We match by basename within the item's media set.
    save_dir = _cfg["save_dir"]
    item_abs = os.path.join(save_dir, item["_rel"])
    target_name = files[i]["name"]

    if os.path.isfile(item_abs):
        candidate = item_abs             # single-file item
    else:
        candidate = None
        for dirpath, _dirs, filenames in os.walk(item_abs, onerror=lambda e: None):
            if target_name in filenames:
                candidate = os.path.join(dirpath, target_name)
                break
    if not candidate:
        return None

    real = os.path.realpath(candidate)
    base = os.path.realpath(save_dir)
    if real != base and not real.startswith(base + os.sep):
        return None                      # escaped the save dir -> refuse
    if not os.path.isfile(real):
        return None
    return real


def probe_vcodec(path):
    """Return the first video stream's codec name (e.g. 'h264'), '' on failure."""
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe",
             "-select_streams", "v:0", "-show_entries", "stream=codec_name",
             "-of", "default=nw=1:nk=1", path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=20)
        return out.stdout.decode("utf-8", "replace").strip().splitlines()[0].strip() \
            if out.stdout.strip() else ""
    except Exception:
        return ""


# --- HTTP streaming helpers ------------------------------------------------
_CHUNK = 64 * 1024

# The ZimaBoard has a weak CPU and limited RAM; two concurrent ffmpeg
# transcodes/remuxes would thrash or OOM. Serialise: only one runs at a time.
_transcode_sem = threading.Semaphore(1)


def _content_type(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".mkv":
        return "video/x-matroska"
    if ext == ".mp4":
        return "video/mp4"
    ctype, _enc = mimetypes.guess_type(path)
    return ctype or "application/octet-stream"


def _parse_range(header, size):
    """Parse a single 'bytes=START-END' range. Returns (start, end) inclusive
    or None if absent/unsatisfiable. Supports open-ended and suffix ('-N') forms.
    """
    if not header or not header.strip().lower().startswith("bytes="):
        return None
    spec = header.split("=", 1)[1].strip()
    if "," in spec:                      # multi-range not supported -> serve full
        spec = spec.split(",", 1)[0].strip()
    if "-" not in spec:
        return None
    start_s, end_s = spec.split("-", 1)
    start_s, end_s = start_s.strip(), end_s.strip()
    try:
        if start_s == "":                # suffix range: last N bytes
            n = int(end_s)
            if n <= 0:
                return None
            start = max(0, size - n)
            end = size - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else size - 1
    except ValueError:
        return None
    if start > end or start >= size:
        return None
    end = min(end, size - 1)
    return start, end


def stream_file(handler, path):
    """Serve `path` over HTTP with full byte-range (206) support for seeking.

    Never raises; swallows client-disconnect errors (seek/close mid-stream).
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        try:
            handler.send_response(404)
            handler.end_headers()
        except Exception:
            pass
        return

    ctype = _content_type(path)
    rng = _parse_range(handler.headers.get("Range"), size)

    try:
        with open(path, "rb") as f:
            if rng is None:
                handler.send_response(200)
                handler.send_header("Content-Type", ctype)
                handler.send_header("X-Content-Type-Options", "nosniff")
                if not (ctype.startswith("video/") or ctype.startswith("audio/")):
                    handler.send_header("Content-Disposition", "attachment")  # never render non-media inline
                handler.send_header("Accept-Ranges", "bytes")
                handler.send_header("Content-Length", str(size))
                handler.end_headers()
                start, remaining = 0, size
            else:
                start, end = rng
                remaining = end - start + 1
                handler.send_response(206)
                handler.send_header("Content-Type", ctype)
                handler.send_header("X-Content-Type-Options", "nosniff")
                if not (ctype.startswith("video/") or ctype.startswith("audio/")):
                    handler.send_header("Content-Disposition", "attachment")  # never render non-media inline
                handler.send_header("Accept-Ranges", "bytes")
                handler.send_header("Content-Range",
                                   "bytes %d-%d/%d" % (start, end, size))
                handler.send_header("Content-Length", str(remaining))
                handler.end_headers()
                f.seek(start)

            while remaining > 0:
                chunk = f.read(min(_CHUNK, remaining))
                if not chunk:
                    break
                handler.wfile.write(chunk)
                remaining -= len(chunk)
    except (BrokenPipeError, ConnectionResetError):
        pass                             # client seeked/closed — normal
    except Exception:
        pass


def transcode_file(handler, path):
    """Live-remux/transcode `path` to fragmented MP4 so any container plays.

    h264 video is copied (cheap remux); anything else is re-encoded with
    libx264 ultrafast, capped at 720p (this CPU can't do real-time 1080p
    re-encode). Audio is always downmixed to stereo AAC (multichannel AAC is
    unsafe in browsers). No Content-Length: it's a live stream and the server
    closes the connection at EOF.

    Only one transcode/remux runs at a time (see _transcode_sem): the device is
    too weak to handle concurrent ffmpeg jobs, so a second request gets 503.
    Never raises.
    """
    # Serialise: bail out fast with 503 if another transcode is already running.
    if not _transcode_sem.acquire(timeout=2):
        try:
            body = (b"Another video is transcoding \xe2\x80\x94 only one at a "
                    b"time on this device. Try again shortly.")
            handler.send_response(503)
            handler.send_header("Content-Type", "text/plain; charset=utf-8")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        except Exception:
            pass
        return

    proc = None
    try:
        vcodec = probe_vcodec(path)
        if vcodec == "h264":
            # Source is already h264 — pure remux, no filtering or re-encode.
            vfilter = []
            vmap = ["-c:v", "copy"]
        else:
            # Re-encode: cap to 720p and use low-latency ultrafast x264.
            vfilter = ["-vf", "scale=-2:720"]
            vmap = ["-c:v", "libx264", "-preset", "ultrafast", "-crf", "23",
                    "-tune", "zerolatency", "-g", "48"]
        amap = ["-c:a", "aac", "-ac", "2", "-b:a", "160k"]

        # Hardening: -protocol_whitelist file,pipe stops a malicious input file from
        # making ffmpeg open URLs / other files itself (the concat/HLS SSRF+file-read
        # CVE class). -nostdin: don't read stdin. -dn/-sn: drop data/subtitle streams
        # (less parser surface). This runs in the locked-down transcoder sandbox too.
        cmd = (["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                "-protocol_whitelist", "file,pipe", "-i", path]
               + vfilter + vmap + amap
               + ["-dn", "-sn", "-flush_packets", "1",
                  "-movflags", "+frag_keyframe+empty_moov+default_base_moof",
                  "-f", "mp4", "pipe:1"])

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        handler.send_response(200)
        handler.send_header("Content-Type", "video/mp4")
        handler.end_headers()
        while True:
            chunk = proc.stdout.read(_CHUNK)
            if not chunk:
                break
            handler.wfile.write(chunk)
    except (BrokenPipeError, ConnectionResetError):
        pass                             # client closed the player — normal
    except Exception:
        pass
    finally:
        if proc is not None:
            try:
                proc.stdout.close()
            except Exception:
                pass
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        _transcode_sem.release()
