# vpntorrent

The smallest possible "torrent downloader with a VPN built in." **One container.**
You paste (or click) a magnet link, it routes everything through ProtonVPN, and
downloads the file into a category folder. **Download-only** — it never seeds and
never shares your files. If the VPN isn't up, nothing downloads. Period.

No qBittorrent, no Transmission — just a tiny libtorrent engine and a one-box web page.

```
┌─────────────── one container ───────────────┐
│  WireGuard (ProtonVPN)  ── killswitch ──┐    │
│  libtorrent engine  ── bound to VPN IP ─┘    │
│  download-only · never seeds                 │
│  one-page web UI  :8722                      │
└──────────────────────────────────────────────┘
```

## Install / move to another machine

The whole stack is one Docker Compose project — copy the folder, run one script.
All machine-specific settings live in a `.env` the installer writes.

```sh
./install.sh            # interactive setup on this machine
./package.sh            # make vpntorrent-bundle.tar.gz to copy to another box
./uninstall.sh          # stop + remove (keeps your downloads + config)
```

To move it (e.g. to a ZimaBlade): `./package.sh` here, copy the tarball over,
then `tar xzf … && cd vpntorrent && ./install.sh`. Full walkthrough (incl. an
offline/no-internet option and the dashboard tile) is in **[MIGRATION.md](MIGRATION.md)**.

## Setup (one time)

1. **Get your Proton WireGuard config** (paid plan + a **P2P** server — see
   `config/proton.conf.example` for exact steps).
2. Save it as **`config/proton.conf`**.
3. Build and start:
   ```sh
   docker compose up -d --build
   ```
4. Open **http://<this-host>:8722**

The banner is green **● VPN connected** when protected, red when not.

## Use it

- **Log in** with the web password (see *Login* below).
- **Search** for anything in the search box, pick a **category**, and hit
  **⬇ Download** on a result. No need to visit any torrent site — results come
  from many indexers at once (see *Search* below).
- Or expand "…or paste a magnet link directly" to add a `magnet:` link by hand,
  pick a **category**, hit **Download**.
- Files are saved to the 11TB drive under
  `/media/HDD-Storage1/vpntorrent/<category>/` (movies, tv, music, documents,
  software, other).
- Live status for every download: progress bar, %, speed, peers, and state
  (Downloading / Paused / Checking / ✓ Complete).
- Per-download controls: **⏸ Pause**, **▶ Resume**, **↻ Recheck** (re-verify the
  pieces on disk), **✕ Remove** (drops it from the list; files are kept).
- **Library tab** — a Netflix-style grid of your finished downloads (poster art +
  descriptions if you add a TMDB key). Click a title to:
  - **▶ Play** in the browser — plays instantly for common formats (mp4/webm/mp3…);
    other containers (mkv/avi/HEVC) are transcoded on the fly, which can stutter on
    this CPU and has limited seeking.
  - **📺 VLC / app** — for *any* format at full quality with seeking: it hands the
    raw file to a player on **your** device. Tap **VLC·iPhone/iPad**, **VLC·Android**,
    or **Infuse·Apple**; on desktop download the **.m3u** (opens in VLC) or copy the
    link into VLC → *Open Network Stream*. Works remotely over Tailscale. The link
    is a short-lived (~6h) signed token scoped to that one file — no login needed in
    the external app, and it can't be reused for anything else.
- Click **"Make magnet links open here"** once to register the browser handler
  (needs HTTPS; on a plain-HTTP LAN address, just paste links instead).

## Login

The whole UI is behind a password — there's no way to reach the downloader,
the status, or any control without it. Set the password in `docker-compose.yml`:

```yaml
    environment:
      - VT_PASSWORD=your-password-here   # change this, then: docker compose up -d
```

(If `VT_PASSWORD` is unset it falls back to `config/password.txt`, and if that's
missing too it auto-generates one and prints it to the logs — so it is never open
by accident.) Sessions are cookie-based and reset when the container restarts.

## The rules it enforces

- **No VPN, no downloads.** If the tunnel isn't up at start, the app runs in a
  disabled state — the Download button is greyed out and the API refuses adds
  (HTTP 403). It never falls back to an unprotected connection.
- **VPN drops mid-download → everything pauses** automatically and resumes when
  the tunnel is back. A background monitor checks the WireGuard handshake every
  5 seconds.
- **Download-only, never seeds.** The moment a torrent finishes it is paused and
  disconnected from the swarm — completed files are never shared. Seeding limits
  are set to zero and local peer discovery (LSD) is disabled.
  *(During a download, BitTorrent still swaps small pieces with peers — that's
  how downloading works. It just never serves anything once complete.)*

## Search

A built-in search box queries many torrent indexers at once and shows combined,
seeder-sorted results — type a query, hit Download on a result, done. No visiting
sketchy sites to copy magnets.

- Powered by **Jackett**, which runs as a second container **inside the same VPN
  namespace** — so every search also goes out through Proton, not your real IP.
  It is not exposed to the host; only the vpntorrent app talks to it internally.
- Indexers are **auto-configured on startup**: The Pirate Bay, 1337x, YTS, EZTV,
  NYAA, LimeTorrents, KickAss, TorrentDownloads (others are attempted too;
  Cloudflare-protected ones like some 1337x mirrors may need FlareSolverr — a
  future optional add).
- Search needs the VPN up (it goes through the tunnel), same as downloads.

## Malware protection & sandboxing

Torrents can hide malware, so downloads are defended in depth:

- **Antivirus scan + quarantine.** A ClamAV container scans every finished
  download (on-demand, signatures auto-updated daily). Anything it flags — or any
  bare executable/script (`.exe`, `.scr`, `.bat`, `.js`, `.lnk`, …) found in a
  *media* category — is moved to a hidden, locked `.quarantine` folder it can never
  be played or downloaded from. (The `software` category is exempt from the
  executable rule, since you expect programs there; ClamAV still scans them.)
  The Library shows a scan badge per title: ✓ clean, ⏳ pending, or ⚠ with the list
  of quarantined files.
- **Sandboxed decoder.** The one place a malicious *media* file meets running code
  is the video decoder (ffmpeg). So playback/transcoding runs in a separate,
  locked-down container: **no internet** (internal network), no Linux capabilities,
  read-only filesystem, non-root, downloads mounted read-only. If a crafted file
  ever exploited an ffmpeg bug, it's trapped there — it can't reach the network,
  the VPN keys, your login secret, or the rest of the machine. ffmpeg is also run
  with `-protocol_whitelist file,pipe` so a malicious file can't make it open URLs.
- **Nothing is ever executed.** The app only streams bytes or decodes media; it
  never runs a downloaded file. Non-media files are served as forced downloads with
  `nosniff`, so a torrent's stray `.html`/`.js` can't run as a script in your browser.

## How the VPN protection works (two layers)

1. **Killswitch** — WireGuard comes up with `AllowedIPs = 0.0.0.0/0`, so
   `wg-quick` installs a kernel killswitch: any packet not going through the
   tunnel is dropped. DNS is forced through Proton too (no DNS leak).
2. **Socket binding** — the torrent engine is bound to the VPN's IP. If the
   tunnel drops that IP disappears, so the engine has no address to send from.

## Notes

- ProtonVPN **free tier blocks P2P** — you need a paid plan and a P2P server.
- Web UI is on port `8722` (host **and** container — kept identical so the ZimaOS
  dashboard tile always resolves). Change both in `docker-compose.yml` (and
  `PORT`) if it clashes.
- Downloaded files are owned by root (the container needs root for WireGuard);
  the category folders are world-writable so you can still manage files over Samba.
- Downloads survive a container restart: libtorrent fast-resume data is saved to
  `config/resume/` (plus `config/torrents.json` for category/paused state) and
  restored on startup, so a transfer continues from where it left off and stays in
  the Downloads tab. Completed files on disk are always safe.
- **Restarting the stack:** Jackett and FlareSolverr share vpntorrent's network
  namespace, so restarting *just* the `vpntorrent` container leaves them without
  network. Restart the whole stack (`docker compose restart`) or, after restarting
  vpntorrent alone, also run `docker restart vpntorrent-jackett vpntorrent-flaresolverr`.

## Files

| File | What |
|------|------|
| `app/vt.py` | the whole app: libtorrent engine + web UI + login + search + VPN monitor (stdlib only) |
| `jackett-config/` | Jackett's data (API key, configured indexers) |
| `jackett-resolv.conf` | forces Jackett's DNS through the tunnel |
| `app/entrypoint.sh` | brings up VPN, killswitch, DNS, derives bind IP; disabled mode if VPN fails |
| `Dockerfile` | debian-slim + python3-libtorrent + wireguard-tools + procps |
| `docker-compose.yml` | caps, tun device, port, 11TB volume |
| `config/proton.conf` | **you create this** from your Proton WireGuard config |
