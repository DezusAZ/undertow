#!/usr/bin/env python3
"""On-demand ClamAV malware watcher for a Dockerized torrent app.

Polls category subfolders under DOWNLOADS, scans settled items with a single
`clamscan` invocation per item (one DB load per item -> low RAM), quarantines
risky executables and infected files, and writes an accumulating results.json
that the main app reads.

stdlib only; runs as root inside its container.
"""

import json
import os
import subprocess
import sys
import time
import traceback

DOWNLOADS = os.environ.get("DOWNLOADS", "/downloads")
CONFIG = os.environ.get("CONFIG", "/config")        # results + seen state live in CONFIG/clamav/
POLL = int(os.environ.get("POLL", "60"))            # seconds between sweeps
SETTLE = int(os.environ.get("SETTLE", "90"))        # file must be unmodified this long before scanning

# What to do when a file is infected or a risky executable:
#   "flag"       -> DO NOT touch the file. Record it as "flagged" so the app warns
#                   loudly, but keep it in place so the user can inspect it and
#                   decide. (Default — the user asked to keep + decide.) The app
#                   never EXECUTES downloads; media is only ever opened through the
#                   network-isolated, no-exec sandbox decoder, so a kept-but-flagged
#                   file is inert until the user acts on it.
#   "quarantine" -> move the file into DOWNLOADS/.quarantine (old behavior).
ACTION = os.environ.get("QUARANTINE_ACTION", "flag").strip().lower()
if ACTION not in ("flag", "quarantine"):
    ACTION = "flag"

CATEGORIES = ["movies", "tv", "music", "documents", "software", "other"]

STATE_DIR = os.path.join(CONFIG, "clamav")
RESULTS_PATH = os.path.join(STATE_DIR, "results.json")
SEEN_PATH = os.path.join(STATE_DIR, "seen.json")

QUARANTINE = os.path.join(DOWNLOADS, ".quarantine")
QUARANTINE_NAME = ".quarantine"

# Temp / partial download suffixes to ignore.
TEMP_SUFFIXES = (".part", ".!qb")  # compared case-insensitively; covers .part, .!qB, .!qb

# Extensions treated as risky executables -> quarantined on sight (except in "software").
RISKY_EXEC = {
    ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".msi", ".msp", ".vbs",
    ".vbe", ".js", ".jse", ".jar", ".ps1", ".psm1", ".lnk", ".hta", ".cpl",
    ".wsf", ".wsh", ".reg", ".gadget", ".scf", ".inf", ".dll", ".sys", ".apk",
    ".app", ".deb", ".rpm", ".run", ".sh", ".bash", ".command", ".out",
    ".elf", ".jnlp", ".msc", ".application",
}

CLAMSCAN_TIMEOUT = 3600  # seconds


def log(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# State (results.json / seen.json) helpers
# --------------------------------------------------------------------------- #
def ensure_state_dir():
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
    except OSError as e:
        log("error: could not create state dir %s: %s" % (STATE_DIR, e))


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        pass
    except (ValueError, OSError) as e:
        log("warn: could not read %s (%s); starting fresh" % (path, e))
    return {}


def atomic_write_json(path, obj):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as e:
        log("error: could not write %s: %s" % (path, e))
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def load_results():
    data = load_json(RESULTS_PATH)
    files = data.get("files")
    if not isinstance(files, dict):
        files = {}
    return files


def write_results(files):
    atomic_write_json(RESULTS_PATH, {"updated": int(time.time()), "files": files})


def load_seen():
    return load_json(SEEN_PATH)


def save_seen(seen):
    atomic_write_json(SEEN_PATH, seen)


# --------------------------------------------------------------------------- #
# Path / file helpers
# --------------------------------------------------------------------------- #
def is_temp_name(name):
    low = name.lower()
    return low.endswith(TEMP_SUFFIXES)


def rel_to_downloads(abspath):
    rel = os.path.relpath(abspath, DOWNLOADS)
    return rel.replace(os.sep, "/")


def iter_files(root):
    """Yield abspaths of regular files under root (recurse).

    Skips the quarantine dir and temp/part files. Tolerates unreadable dirs and
    files that vanish mid-walk. If root itself is a regular file, yields it.
    """
    try:
        if os.path.isfile(root) and not os.path.islink(root):
            if not is_temp_name(os.path.basename(root)):
                yield root
            return
    except OSError:
        return

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda e: None):
        # Never descend into a quarantine dir.
        dirnames[:] = [d for d in dirnames if d != QUARANTINE_NAME]
        for fn in filenames:
            if is_temp_name(fn):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.islink(fp):
                    continue
                if os.path.isfile(fp):
                    yield fp
            except OSError:
                continue


def item_signature(path):
    """(total file count, total bytes, max mtime) over all files under path.

    Returns (count, total_bytes, max_mtime). max_mtime is 0.0 if no files.
    """
    count = 0
    total = 0
    max_mtime = 0.0
    for fp in iter_files(path):
        try:
            st = os.stat(fp)
        except OSError:
            continue
        count += 1
        total += st.st_size
        if st.st_mtime > max_mtime:
            max_mtime = st.st_mtime
    return [count, total, max_mtime]


# --------------------------------------------------------------------------- #
# Quarantine
# --------------------------------------------------------------------------- #
def quarantine(file_abspath):
    """Move file into the quarantine dir preserving its path relative to DOWNLOADS.

    Returns True on success, False otherwise (logged, never raises).
    """
    try:
        rel = os.path.relpath(file_abspath, DOWNLOADS)
        dest = os.path.join(QUARANTINE, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        os.replace(file_abspath, dest)
        log("quarantined: %s -> %s" % (rel_to_downloads(file_abspath), dest))
        return True
    except OSError as e:
        log("error: failed to quarantine %s: %s" % (file_abspath, e))
        return False


def handle_threat(records, fp, reason, sig, handled):
    """Deal with an infected/risky file per ACTION, then mark it handled so it is
    not later recorded as clean. In "flag" mode the file is KEPT in place and just
    recorded as "flagged"; in "quarantine" mode it is moved to .quarantine."""
    if fp in handled:
        return
    if ACTION == "quarantine":
        if quarantine(fp):
            record(records, fp, "quarantined", reason, sig)
        else:
            # move failed -> file is still present; flag it so it isn't marked clean
            record(records, fp, "flagged", reason, sig)
    else:
        record(records, fp, "flagged", reason, sig)
        log("flagged (kept for review): %s [%s%s]"
            % (rel_to_downloads(fp), reason, ((" " + sig) if sig else "")))
    handled.add(fp)


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def run_clamscan(path):
    """Run a single clamscan over path. Returns (rc, stdout_text).

    rc convention: 0=clean, 1=found, 2=error, -1=could not run / timeout.
    """
    cmd = [
        "clamscan", "-r", "--no-summary", "-i",
        "--max-filesize=4000M", "--max-scansize=4000M",
        "--stdout", path,
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=CLAMSCAN_TIMEOUT,
        )
        out = proc.stdout.decode("utf-8", "replace") if proc.stdout else ""
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        log("error: clamscan timed out on %s" % path)
        return -1, ""
    except (OSError, ValueError) as e:
        log("error: could not run clamscan on %s: %s" % (path, e))
        return -1, ""


def parse_found(stdout_text):
    """Parse `<filepath>: <SIGNATURE> FOUND` lines -> {abspath: signature}."""
    found = {}
    for line in stdout_text.splitlines():
        line = line.rstrip("\n")
        if not line.endswith(" FOUND"):
            continue
        idx = line.rfind(": ")
        if idx == -1:
            continue
        fpath = line[:idx]
        rest = line[idx + 2:]  # "<SIGNATURE> FOUND"
        sig = rest[:-len(" FOUND")].strip()
        found[fpath] = sig
    return found


def record(records, file_abspath, verdict, reason, sig):
    key = rel_to_downloads(file_abspath)
    records[key] = {
        "verdict": verdict,
        "reason": reason,
        "sig": sig,
        "ts": int(time.time()),
    }


def scan_item(cat, path):
    """Scan one item. Returns (records dict, scan_ok bool).

    scan_ok is False if clamscan errored (rc 2 / could-not-run) so the caller
    can avoid marking the item seen and retry next sweep.
    """
    records = {}
    handled = set()  # abspaths already recorded as flagged/quarantined

    # Enumerate files once (snapshot).
    all_files = list(iter_files(path))

    # (1) Risky executables (except in "software"): flag (kept) or quarantine.
    if cat != "software":
        for fp in all_files:
            ext = os.path.splitext(fp)[1].lower()
            if ext in RISKY_EXEC:
                handle_threat(records, fp, "executable", "", handled)

    # (2) ClamAV scan of the whole item in ONE invocation.
    scan_ok = True
    rc, out = run_clamscan(path)
    if rc == 2 or rc == -1:
        # Scan error: leave files unscanned, do NOT mark clean, do NOT update seen.
        log("scan error (rc=%s) on %s: leaving unscanned for retry" % (rc, rel_to_downloads(path)))
        scan_ok = False
        return records, scan_ok

    found = parse_found(out)
    infected_recorded = 0
    for fp, sig in found.items():
        if fp in handled:
            continue
        try:
            present = os.path.isfile(fp) and not os.path.islink(fp)
        except OSError:
            present = False
        if not present:
            continue
        handle_threat(records, fp, "infected", sig, handled)
        infected_recorded += 1

    # clamscan says infected (rc==1) but we couldn't attribute it to any file (e.g. a
    # newline in a filename can break the ": <SIG> FOUND" line parse). FAIL SAFE: flag
    # every file in the item rather than risk marking malware clean below.
    if rc == 1 and infected_recorded == 0:
        for fp in all_files:
            if fp in handled:
                continue
            try:
                still = os.path.isfile(fp) and not os.path.islink(fp)
            except OSError:
                still = False
            if still:
                handle_threat(records, fp, "infected", "Unattributed.Detection", handled)
        log("clamscan rc=1 but no file attributed on %s: flagged the whole item"
            % rel_to_downloads(path))

    # (3) Everything still present and not flagged -> clean.
    for fp in all_files:
        if fp in handled:
            continue
        try:
            still = os.path.isfile(fp) and not os.path.islink(fp)
        except OSError:
            still = False
        if not still:
            continue
        record(records, fp, "clean", "", "")

    n_clean = sum(1 for r in records.values() if r["verdict"] == "clean")
    n_threat = sum(1 for r in records.values()
                   if r["verdict"] in ("flagged", "quarantined"))
    log("scanned %s: %d clean, %d flagged (action=%s)"
        % (rel_to_downloads(path), n_clean, n_threat, ACTION))

    return records, scan_ok


# --------------------------------------------------------------------------- #
# Sweep
# --------------------------------------------------------------------------- #
def list_items(cat_dir):
    try:
        entries = os.listdir(cat_dir)
    except OSError as e:
        log("warn: cannot list %s: %s" % (cat_dir, e))
        return []
    items = []
    for name in entries:
        if name.startswith("."):
            continue
        if is_temp_name(name):
            continue
        items.append(os.path.join(cat_dir, name))
    return items


def sweep(seen):
    now = time.time()
    for cat in CATEGORIES:
        cat_dir = os.path.join(DOWNLOADS, cat)
        if not os.path.isdir(cat_dir):
            continue
        for item_path in list_items(cat_dir):
            try:
                sig = item_signature(item_path)
                count, total, max_mtime = sig

                # Empty item: nothing to scan, but mark seen so we don't recompute.
                if count == 0:
                    seen[item_path] = sig
                    continue

                # Still being written?
                if (now - max_mtime) < SETTLE:
                    continue

                # Unchanged since last scan?
                if seen.get(item_path) == sig:
                    continue

                records, scan_ok = scan_item(cat, item_path)

                # Merge records into accumulating results and persist.
                if records:
                    files = load_results()
                    files.update(records)
                    write_results(files)

                if scan_ok:
                    seen[item_path] = sig
                    save_seen(seen)
                # else: leave seen unchanged so it retries next sweep.

            except Exception:
                log("error processing item %s:\n%s" % (item_path, traceback.format_exc()))
    prune_state(seen)


def prune_state(seen):
    """Drop state for files the user has since deleted so results.json / the app's
    badges don't grow forever. 'quarantined' entries are kept — their original path
    is intentionally gone (the file was moved to .quarantine)."""
    try:
        files = load_results()
        changed = False
        for key in list(files.keys()):
            if files[key].get("verdict") == "quarantined":
                continue
            if not os.path.exists(os.path.join(DOWNLOADS, key)):
                del files[key]
                changed = True
        if changed:
            write_results(files)
    except Exception:
        pass
    try:
        gone = [k for k in list(seen.keys()) if not os.path.exists(k)]
        if gone:
            for k in gone:
                seen.pop(k, None)
            save_seen(seen)
    except Exception:
        pass


def main():
    log("clamav watcher starting: DOWNLOADS=%s CONFIG=%s POLL=%ds SETTLE=%ds"
        % (DOWNLOADS, CONFIG, POLL, SETTLE))
    ensure_state_dir()
    # Ensure results.json exists so the app can read a valid (empty) file.
    if not os.path.exists(RESULTS_PATH):
        write_results(load_results())

    while True:
        try:
            seen = load_seen()
            sweep(seen)
        except Exception:
            log("error in sweep:\n%s" % traceback.format_exc())
        time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
