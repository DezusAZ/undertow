#!/usr/bin/env python3
"""transcoder.py - the SANDBOXED media decoder for vpntorrent.

This runs in its own locked-down container (cap_drop ALL, read-only rootfs,
non-root, no-new-privileges, on an internal no-internet network, /downloads
mounted read-only). The main app proxies /play here instead of running ffmpeg
itself, so a malicious media file that exploits an ffmpeg decoder bug is trapped:
no network, no privileges, no access to the VPN keys / login secret / config.

It only ever DECODES files (never executes them) and only reads paths inside the
downloads dir. The heavy lifting (range/transcode logic) lives in library.py,
which is stdlib-only and imports no libtorrent.
"""
import os
import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import library

SAVE = os.environ.get("SAVE_PATH", "/downloads")
PORT = int(os.environ.get("TPORT", "8723"))
_BASE = os.path.realpath(SAVE)


def _safe(path):
    """Return the RESOLVED path if it's a real file inside the read-only downloads
    mount, else None. Returning the resolved path (and handing THAT to ffmpeg) means
    the validated path and the opened path are identical — no symlink/`..` gap."""
    real = os.path.realpath(path)
    if (real == _BASE or real.startswith(_BASE + os.sep)) and os.path.isfile(real):
        return real
    return None


class H(BaseHTTPRequestHandler):
    timeout = 300      # a vanished client can't hold the ffmpeg pipe / slot forever

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def _404(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == "/prepare":
            # PREPARE a seekable MP4. `caps` is the calling browser's decode capability
            # list, which decides remux (fast) vs re-encode (slow but universal).
            path = (qs.get("path") or [""])[0]
            caps = (qs.get("caps") or [""])[0]
            # Untrusted input that only ever gets membership-tested, but keep it to a
            # short, boring charset anyway.
            caps = re.sub(r"[^a-z0-9,]", "", caps.lower())[:120]
            real = _safe(path) if path else None
            if not real:
                self._json({"state": "error", "error": "not found"}, 404)
                return
            self._json(library.prepare_to_cache(real, caps))
        elif u.path == "/prepstatus":
            self._json(library.read_status((qs.get("key") or [""])[0]))
        elif u.path == "/touch":
            # mark a prepared file recently-used so LRU eviction won't drop it mid-play
            self._json({"ok": library.touch_cache((qs.get("key") or [""])[0])})
        elif u.path == "/transcode":
            # legacy live path (fallback)
            path = (qs.get("path") or [""])[0]
            real = _safe(path) if path else None
            if not real:
                self._404()
                return
            library.transcode_file(self, real)
        else:
            self._404()


if __name__ == "__main__":
    library.cache_reaper()          # clear crash debris (orphaned .part / stuck 'preparing')
    print(f"[transcoder] sandboxed decoder on http://0.0.0.0:{PORT} (reads {SAVE} ro)",
          flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
