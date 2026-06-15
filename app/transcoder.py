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
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import library

SAVE = os.environ.get("SAVE_PATH", "/downloads")
PORT = int(os.environ.get("TPORT", "8723"))
_BASE = os.path.realpath(SAVE)


def _safe(path):
    """Only allow real paths inside the read-only downloads mount."""
    real = os.path.realpath(path)
    return (real == _BASE or real.startswith(_BASE + os.sep)) and os.path.isfile(real)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path != "/transcode":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = (urllib.parse.parse_qs(u.query).get("path") or [""])[0]
        if not path or not _safe(path):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        library.transcode_file(self, path)   # live ffmpeg remux/transcode -> fMP4


if __name__ == "__main__":
    print(f"[transcoder] sandboxed decoder on http://0.0.0.0:{PORT} (reads {SAVE} ro)",
          flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
