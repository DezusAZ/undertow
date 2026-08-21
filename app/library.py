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
import shutil
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
    (status, threats): status is 'clean'|'pending'|'flagged'; threats is a list of
    {name, reason, verdict} for files the scan flagged. verdict 'flagged' means the
    file was KEPT in place for the user to inspect/decide (default); 'quarantined'
    means it was moved to .quarantine."""
    files = _scan_results()
    if not files:
        return "pending", []
    key = item_rel.replace(os.sep, "/")
    prefix = key + "/"
    relevant = [(k, v) for k, v in files.items() if k == key or k.startswith(prefix)]
    if not relevant:
        return "pending", []
    threats = [{"name": os.path.basename(k), "reason": v.get("reason", ""),
                "verdict": v.get("verdict", "flagged")}
               for k, v in relevant if v.get("verdict") in ("flagged", "quarantined")]
    if threats:
        return "flagged", threats
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


def delete_item(item_id):
    """Delete a library item's files from disk (its folder, or single file) and reindex.
    Path-safety: only ever removes something strictly inside the save dir (no traversal /
    symlink escape). Returns {"ok", "rel", "freed"} — never raises."""
    save_dir = _cfg["save_dir"]
    with _lock:
        item = next((it for it in _index if it.get("id") == item_id), None)
    if not item or not save_dir:
        return {"ok": False, "rel": "", "freed": 0}
    rel = item.get("_rel", "")
    target = os.path.realpath(os.path.join(save_dir, rel))
    base = os.path.realpath(save_dir)
    # must live strictly UNDER the save dir (never the save dir itself, never outside)
    if target == base or not target.startswith(base + os.sep):
        return {"ok": False, "rel": rel, "freed": 0}
    freed = 0
    try:
        if os.path.isdir(target) and not os.path.islink(target):
            for dp, _d, fs in os.walk(target, onerror=lambda e: None):
                for f in fs:
                    try:
                        freed += os.path.getsize(os.path.join(dp, f))
                    except OSError:
                        pass
            shutil.rmtree(target, ignore_errors=True)
        elif os.path.exists(target):
            try:
                freed = os.path.getsize(target)
            except OSError:
                pass
            os.remove(target)
        else:
            return {"ok": False, "rel": rel, "freed": 0}
    except Exception:
        return {"ok": False, "rel": rel, "freed": 0}
    _scan_once()                             # rebuild the index without the deleted item
    return {"ok": True, "rel": rel, "freed": freed}


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


# ===========================================================================
# Prepare-to-seekable-MP4 (GPU) — the player's real engine
# ===========================================================================
# Instead of a live, un-seekable CPU transcode, we PREPARE a complete, faststart MP4 in
# a cache and serve it with byte-ranges (fully seekable). Video the browser can decode
# itself (h264/hevc/vp9/av1) is REMUXED (container swap, no re-encode) so YOUR machine's
# GPU decodes it — zero server transcode. Only exotic codecs get a GPU (NVENC) re-encode.
CACHE_DIR = os.environ.get("CACHE_DIR", "/cache")
# Video codecs a BROWSER can actually decode, so we can remux instead of re-encoding.
# HEVC is deliberately NOT here: Safari plays it, but Chrome and Firefox generally do
# not, so copying an HEVC stream into an mp4 produced a file that played audio with a
# black picture. x265 rips are extremely common, so this hit most downloads.
_BROWSER_VCODECS = {"h264", "vp9", "av1"}              # client can decode these directly
# audio we can safely COPY into mp4 for cross-browser playback. ac3/eac3/multichannel-aac
# play silently in Chrome/Firefox, so those are transcoded to stereo aac instead.
_BROWSER_ACODECS = {"aac", "mp3"}
# H.264 encoder selection. NVENC is much cheaper on CPU, but it exists only on NVIDIA
# hosts AND cannot encode 10-bit at all ("10 bit encode not supported"), so every
# encode forces 8-bit yuv420p and every caller can fall back to libx264.
_NVENC_OK = None


def _have_nvenc():
    """True only if NVENC can ACTUALLY encode right now.

    Checking that ffmpeg lists h264_nvenc is not enough: a container keeps its device
    nodes but its injected driver libraries go stale after a host driver update, so the
    encoder is listed while CUDA fails with "no CUDA-capable device". That made the app
    report mode "gpu-transcode" and then fail every time. So we run a real 2-frame
    encode once and believe the result.
    """
    global _NVENC_OK
    if _NVENC_OK is None:
        try:
            r = subprocess.run(
                ["ffmpeg", "-hide_banner", "-loglevel", "error",
                 "-f", "lavfi", "-i", "testsrc=size=256x256:rate=1", "-frames:v", "2",
                 "-c:v", "h264_nvenc", "-pix_fmt", "yuv420p", "-f", "null", "-"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
            _NVENC_OK = (r.returncode == 0)
            if not _NVENC_OK:
                print("[library] NVENC unavailable, using CPU: %s"
                      % r.stderr.decode("utf-8", "replace").strip()[-200:], flush=True)
        except Exception as e:
            print("[library] NVENC probe failed (%s) — using CPU" % e, flush=True)
            _NVENC_OK = False
    return _NVENC_OK


def _venc_args(gpu):
    """H.264 encoder args. yuv420p is mandatory: NVENC refuses 10-bit outright, and
    libx264 would happily emit High 10, which no browser can decode."""
    if gpu:
        return ["-c:v", "h264_nvenc", "-preset", "p5", "-cq", "23", "-b:v", "0",
                "-profile:v", "high", "-pix_fmt", "yuv420p"]
    return ["-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
            "-profile:v", "high", "-pix_fmt", "yuv420p"]


_CACHE_CAP_BYTES = int(os.environ.get("CACHE_CAP_GB", "80")) * 1024 * 1024 * 1024
_PREP_STALL_SECS = int(os.environ.get("PREP_STALL_SECS", "900"))   # kill a prep making no progress
_KEY_RE = re.compile(r"^[0-9a-f]{20}$")
_prep_lock = threading.Lock()
_prep_jobs = {}                                        # key -> True while a prep runs
_prep_procs = {}                                       # key -> live ffmpeg Popen (for cancel)
_prep_cancelled = set()                                # keys the user aborted


def _ffprobe1(path, entry, stream=None):
    cmd = ["ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe"]
    if stream:
        cmd += ["-select_streams", stream]
    cmd += ["-show_entries", entry, "-of", "default=nw=1:nk=1", path]
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
        s = out.stdout.decode("utf-8", "replace").strip().splitlines()
        return s[0].strip() if s else ""
    except Exception:
        return ""


def _probe_acodec(path):
    return _ffprobe1(path, "stream=codec_name", "a:0")


def _probe_achannels(path):
    try:
        return int(_ffprobe1(path, "stream=channels", "a:0") or 0)
    except ValueError:
        return 0


def _probe_duration(path):
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe",
             "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
        return float(out.stdout.decode().strip() or 0)
    except Exception:
        return 0.0


def cache_key(real_path, mode="transcode"):
    """Deterministic id for a prepared artifact (source identity + how it was prepared).

    The MODE is part of the key on purpose: the same film prepared as a remux (HEVC left
    intact, for a browser that can decode it) is NOT interchangeable with the H.264
    transcode a different browser needs. Keying on the file alone would hand one
    browser the other's artifact and play audio over a black screen.
    """
    try:
        st = os.stat(real_path)
    except OSError:
        return None
    raw = "%s|%d|%d|%s" % (real_path, st.st_mtime_ns, st.st_size, mode)
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:20]


def _probe_pixfmt(path):
    # NB: _ffprobe1 wants the full "stream=<field>" form. Passing a bare field name
    # returns "" silently, which would make every 10-bit file look 8-bit and get
    # remuxed to browsers that cannot decode it — the exact black-screen bug again.
    return (_ffprobe1(path, "stream=pix_fmt", "v:0") or "").strip().lower()


def _is_10bit(pix_fmt):
    return "10" in pix_fmt or "12" in pix_fmt        # yuv420p10le, p010le, ...


def plan_playback(real_path, caps):
    """Decide how to deliver this file to THIS client.

    `caps` is what the browser told us it can decode (see the player's probe). Remuxing
    is near-instant; transcoding a 2-hour film takes ~25 minutes. So we remux whenever
    the client can genuinely decode the source, and only re-encode when it cannot.

    This replaces a hardcoded "browsers can play HEVC" assumption that was wrong for
    Chrome and Firefox and produced silent black video. Asking the client is both
    faster for capable browsers (Safari, Chrome/Edge with hardware HEVC) and correct
    for the rest — and it keeps working when new codecs appear.

    Returns "remux" or "transcode".
    """
    have = set(x for x in (caps or "").lower().replace(" ", "").split(",") if x)
    vcodec = (probe_vcodec(real_path) or "").lower()
    tenbit = _is_10bit(_probe_pixfmt(real_path))

    if vcodec == "h264":
        # High 10 exists in the wild and no browser decodes it.
        return "transcode" if tenbit else "remux"
    if vcodec == "hevc":
        return "remux" if ("hevc10" if tenbit else "hevc") in have else "transcode"
    if vcodec in ("vp9", "av1"):
        return "remux" if vcodec in have else "transcode"
    return "transcode"                                # mpeg4, vc1, wmv3, ...


def _status_path(key):
    return os.path.join(CACHE_DIR, key + ".json")


def _out_path(key):
    return os.path.join(CACHE_DIR, key + ".mp4")


def _write_status(key, d):
    try:
        d = dict(d, ts=time.time())               # timestamp: lets a stale 'preparing' be detected
        tmp = _status_path(key) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, _status_path(key))
    except Exception:
        pass


def read_status(key):
    """{state: preparing|ready|error, progress, mode} — for the UI to poll. Key MUST be a
    real 20-hex cache id (no path traversal). A 'preparing' whose status hasn't been touched
    in _PREP_STALL_SECS is treated as dead (e.g. the transcoder crashed mid-prep)."""
    if not _KEY_RE.match(key or ""):
        return {"state": "unknown"}
    if os.path.exists(_out_path(key)):
        return {"state": "ready", "progress": 100}
    try:
        d = json.load(open(_status_path(key)))
    except Exception:
        return {"state": "unknown"}
    if d.get("state") == "preparing" and (time.time() - float(d.get("ts", 0))) > _PREP_STALL_SECS:
        return {"state": "error", "reason": "stalled"}
    return d


def _run_prep(cmd, key, mode, dur, tmp):
    """Run one ffmpeg prepare, reporting progress and capturing stderr.

    Both the GPU attempt and the CPU fallback go through here. The fallback used to be a
    plain blocking subprocess.run() with no -progress, so during a CPU retry the UI sat
    at "0%" for the entire encode with no way to tell whether it was working or hung —
    which is exactly what it looked like to the user.

    Returns (returncode, last stderr lines).
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with _prep_lock:
        _prep_procs[key] = proc
    err_tail = []

    def _drain_err(pipe, sink):
        try:
            for ln in pipe:
                ln = ln.decode("utf-8", "replace").rstrip()
                if ln:
                    sink.append(ln)
                    del sink[:-12]
        except Exception:
            pass

    threading.Thread(target=_drain_err, args=(proc.stderr, err_tail), daemon=True).start()

    stop_wd = threading.Event()

    def _watchdog():
        last_sz, last_change = -1, time.time()
        while not stop_wd.wait(30):
            try:
                sz = os.path.getsize(tmp)
            except OSError:
                sz = -1
            now = time.time()
            if sz != last_sz:
                last_sz, last_change = sz, now
            elif now - last_change > _PREP_STALL_SECS:
                try:
                    proc.kill()
                except Exception:
                    pass
                return

    threading.Thread(target=_watchdog, daemon=True).start()
    _write_status(key, {"state": "preparing", "progress": 0, "mode": mode})
    try:
        for line in proc.stdout:
            line = line.decode("utf-8", "replace").strip()
            if line.startswith("out_time_ms=") and dur > 0:
                try:
                    pct = min(99, int(int(line.split("=", 1)[1]) / 1e6 / dur * 100))
                    _write_status(key, {"state": "preparing", "progress": pct,
                                        "mode": mode})
                except Exception:
                    pass
    except Exception:
        pass
    proc.wait()
    stop_wd.set()
    with _prep_lock:
        _prep_procs.pop(key, None)
    return proc.returncode, err_tail


def _prep_worker(real, key, dur, plan="transcode"):
    out, tmp = _out_path(key), _out_path(key) + ".part"
    try:
        vcodec = probe_vcodec(real)
        acodec = _probe_acodec(real)
        achan = _probe_achannels(real)
        use_gpu = _have_nvenc()
        if plan == "remux":
            # The CLIENT told us it can decode this video, so ship the original stream
            # untouched — seconds instead of half an hour. hvc1 tagging matters because
            # Safari rejects the hev1 flavour inside mp4.
            pre, vmap, mode = [], ["-c:v", "copy"], "remux"
            if vcodec == "hevc":
                vmap += ["-tag:v", "hvc1"]
        else:
            # Re-encode to H.264. -hwaccel cuda decodes on the GPU when we have one;
            # _venc_args pins 8-bit yuv420p either way (NVENC cannot do 10-bit, and
            # libx264 would otherwise emit High 10 — both give a black picture).
            pre = ["-hwaccel", "cuda"] if use_gpu else []
            vmap = _venc_args(use_gpu)
            mode = "gpu-transcode" if use_gpu else "cpu-transcode"
        # copy audio only if it's stereo/mono aac|mp3; ac3/eac3/multichannel play silently
        # in Chrome/Firefox, so downmix those to stereo aac.
        if acodec in _BROWSER_ACODECS and 0 < achan <= 2:
            amap = ["-c:a", "copy"]
        else:
            amap = ["-c:a", "aac", "-ac", "2", "-b:a", "192k"]
        _write_status(key, {"state": "preparing", "progress": 0, "mode": mode})
        cmd = (["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                "-progress", "pipe:1", "-protocol_whitelist", "file,pipe"]
               + pre + ["-i", real] + vmap + amap
               + ["-dn", "-sn", "-movflags", "+faststart", "-f", "mp4", "-y", tmp])
        rc, _err_tail = _run_prep(cmd, key, mode, dur, tmp)

        if rc == 0 and os.path.exists(tmp) and os.path.getsize(tmp) > 0:
            os.replace(tmp, out)
            _write_status(key, {"state": "ready", "progress": 100, "mode": mode})
            return

        why = " | ".join(_err_tail[-4:]) if _err_tail else "no error output"
        print("[library] prepare failed (%s) for %s: %s"
              % (mode, os.path.basename(real), why[:400]), flush=True)
        try:
            os.remove(tmp)
        except OSError:
            pass

        # A GPU encode fails for reasons software encoding handles fine: no free NVENC
        # session, a busy GPU, an unsupported pixel format, or — seen in the wild — a
        # container whose injected driver libraries went stale after a host driver
        # update, giving "CUDA_ERROR_NO_DEVICE" even though the GPU is healthy. Retry in
        # software WITH progress reporting rather than declaring the file broken.
        with _prep_lock:
            was_cancelled = key in _prep_cancelled
        if was_cancelled:
            with _prep_lock:
                _prep_cancelled.discard(key)
            print("[library] prepare cancelled for %s" % os.path.basename(real), flush=True)
            _write_status(key, {"state": "error", "error": "cancelled", "mode": "cancelled"})
            return
        if mode == "gpu-transcode":
            print("[library] retrying %s with the CPU encoder"
                  % os.path.basename(real), flush=True)
            cpu_cmd = (["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                        "-progress", "pipe:1", "-protocol_whitelist", "file,pipe",
                        "-i", real]
                       + _venc_args(False) + amap
                       + ["-dn", "-sn", "-movflags", "+faststart",
                          "-f", "mp4", "-y", tmp])
            rc2, err2 = _run_prep(cpu_cmd, key, "cpu-transcode", dur, tmp)
            if rc2 == 0 and os.path.exists(tmp) and os.path.getsize(tmp) > 0:
                os.replace(tmp, out)
                _write_status(key, {"state": "ready", "progress": 100,
                                    "mode": "cpu-transcode"})
                return
            why = " | ".join(err2[-4:]) if err2 else why
            print("[library] cpu retry also failed: %s" % why[:400], flush=True)
            try:
                os.remove(tmp)
            except OSError:
                pass

        _write_status(key, {"state": "error", "mode": mode, "error": why[:200]})
    except Exception as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        _write_status(key, {"state": "error", "error": str(e)[:160]})
    finally:
        with _prep_lock:
            _prep_jobs.pop(key, None)
        _cache_sweep()


def cancel_prep(key):
    """Abort an in-flight prepare. Without this a long transcode could only be waited
    out — there was no way to stop it or reclaim the GPU/CPU."""
    if not _KEY_RE.match(key or ""):
        return False
    with _prep_lock:
        proc = _prep_procs.get(key)
        _prep_cancelled.add(key)
    if proc is None:
        return False
    try:
        proc.kill()
    except Exception:
        return False
    _write_status(key, {"state": "error", "error": "cancelled", "mode": "cancelled"})
    return True


def prepare_to_cache(real_path, caps=""):
    """Kick off (or reuse) preparation of a seekable MP4 for `real_path`. Returns
    {"key", "state"}; poll read_status(key) until 'ready', then serve cache_file(key).

    `caps` is the calling browser's decode capability list; it decides whether we can
    get away with a fast remux or must re-encode."""
    try:
        mode = plan_playback(real_path, caps)
    except Exception:
        mode = "transcode"                          # unknown source -> the safe path
    key = cache_key(real_path, mode)
    if not key:
        return {"state": "error"}
    if os.path.exists(_out_path(key)):
        return {"key": key, "state": "ready"}
    with _prep_lock:
        if key in _prep_jobs:
            return {"key": key, "state": "preparing"}
        _prep_jobs[key] = True
    dur = _probe_duration(real_path)
    try:
        threading.Thread(target=_prep_worker, args=(real_path, key, dur, mode),
                         daemon=True).start()
    except Exception:                              # never leak the _prep_jobs slot
        with _prep_lock:
            _prep_jobs.pop(key, None)
        _write_status(key, {"state": "error"})
        return {"key": key, "state": "error"}
    return {"key": key, "state": "preparing"}


def touch_cache(key):
    """Bump the mtime of a prepared file on SERVE, so LRU eviction (which sorts by mtime —
    atime is unreliable) never evicts something being watched. Transcoder-side (cache rw)."""
    if not _KEY_RE.match(key or ""):
        return False
    try:
        now = time.time()
        os.utime(_out_path(key), (now, now))
        return True
    except OSError:
        return False


def cache_reaper():
    """Run once at transcoder startup: clear crash debris. Delete orphaned *.part (no live
    job) and flip any 'preparing' status with no output to 'error' — so a prep interrupted
    by a restart doesn't leave a UI polling forever or a multi-GB .part leaking."""
    try:
        names = os.listdir(CACHE_DIR)
    except OSError:
        return
    for n in names:
        try:
            if n.endswith(".part"):
                os.remove(os.path.join(CACHE_DIR, n))
            elif n.endswith(".json"):
                key = n[:-5]
                if os.path.exists(_out_path(key)):
                    continue
                try:
                    d = json.load(open(os.path.join(CACHE_DIR, n)))
                except Exception:
                    d = {}
                if d.get("state") == "preparing":
                    _write_status(key, {"state": "error", "reason": "interrupted"})
        except OSError:
            pass


def cache_file(key):
    """Absolute path of a prepared MP4 for `key`, or None. Key must be our 20-hex id."""
    if not re.fullmatch(r"[0-9a-f]{20}", key or ""):
        return None
    p = _out_path(key)
    return p if os.path.isfile(p) else None


def _cache_sweep():
    """Keep the cache under its size cap by evicting the least-recently-served prepared
    files. Sort by MTIME (bumped on serve via touch_cache — atime is unreliable through the
    ro mount / relatime), never evict something served in the last 10 min (likely mid-play),
    and count in-flight *.part toward the total so preps can't blow past the cap. Never raises."""
    try:
        now = time.time()
        total = 0
        for n in os.listdir(CACHE_DIR):                 # in-flight preps count too
            if n.endswith(".part"):
                try:
                    total += os.path.getsize(os.path.join(CACHE_DIR, n))
                except OSError:
                    pass
        files = []
        for n in os.listdir(CACHE_DIR):
            if not n.endswith(".mp4"):
                continue
            fp = os.path.join(CACHE_DIR, n)
            try:
                stt = os.stat(fp)
            except OSError:
                continue
            files.append((stt.st_mtime, stt.st_size, fp))
            total += stt.st_size
        files.sort()                                    # least-recently-served first
        for mtime, sz, fp in files:
            if total <= _CACHE_CAP_BYTES:
                break
            if now - mtime < 600:                       # protect a file being watched now
                continue
            try:
                os.remove(fp)
                total -= sz
                st = fp[:-4] + ".json"
                if os.path.exists(st):
                    os.remove(st)
            except OSError:
                pass
    except Exception:
        pass


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
            # Re-encode: cap to 720p, low latency. -pix_fmt yuv420p is REQUIRED —
            # without it a 10-bit source (any Main 10 / x265 rip) yields H.264 High 10,
            # which browsers cannot decode: audio plays over a black picture.
            vfilter = ["-vf", "scale=-2:720"]
            vmap = ["-c:v", "libx264", "-preset", "ultrafast", "-crf", "23",
                    "-tune", "zerolatency", "-g", "48", "-pix_fmt", "yuv420p"]
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
                    proc.wait()          # reap so the SIGKILLed child isn't left a zombie
                except Exception:
                    pass
        _transcode_sem.release()
