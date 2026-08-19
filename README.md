# Undertow

**Search beneath the surface.** Undertow is a private, VPN-locked file-discovery
engine — one interface over ~99 torrent indexers, a self-hosted DHT crawler,
open-directory crawling, Usenet, and dedicated sources for papers, books, video,
music, code, datasets and images. It finds what other searches miss, then downloads
through your VPN into a tidy library.

**Download-only** — it never seeds or shares your files. Everything routes through
the tunnel behind a fail-closed kill-switch: **if the VPN isn't up, nothing moves.**
Every download is malware-scanned, and media can only be decoded inside an isolated
no-network sandbox.

> Internally the stack is still named `vpntorrent` (container/image/service names) for
> stability; "Undertow" is the product name shown in the UI.

```
┌──────────────── VPN network namespace ────────────────┐
│  WireGuard  ──  fail-closed iptables kill-switch      │
│  libtorrent engine (download-only, bound to VPN IP)   │
│  Jackett · FlareSolverr · SearXNG · Bitmagnet · SAB   │
│  one-page web UI  :8722                               │
└───────────────────────────────────────────────────────┘
        ClamAV scanner  ·  no-network decode sandbox
```

---

## Before you start — read this

- **You need a paid VPN plan that allows P2P.** ProtonVPN's free tier blocks P2P.
  Undertow is built and tested against Proton's WireGuard configs.
- **Your VPN config is your identity.** `config/proton.conf` contains a private key.
  Never commit it, never share it, never copy it to someone else's machine. If it ever
  leaks, revoke it in your VPN dashboard and generate a new one.
- **This tool does not make illegal things legal.** It hides your traffic from your ISP;
  it is not a licence to pirate. What you download is on you — check the law where you live.
- Requirements: Docker + Compose v2, amd64, `/dev/net/tun`, ~4 GB RAM for the full stack,
  and disk space for whatever you download. A GPU is optional (only the local-AI feature
  uses it).

---

## Install

```sh
./install.sh            # interactive setup (writes .env, builds, starts, self-tests)
```

Then put your VPN config at **`config/proton.conf`** (see
`config/proton.conf.example` for exactly where to get it) and re-run `./install.sh`
or `docker compose up -d`.

> **Endpoint must be an IP address, not a hostname.** The kill-switch has to allow the
> VPN server *before* any DNS exists, so a hostname endpoint can never connect.
> `install.sh` checks this for you.

Other commands:

```sh
./verify-anonymity.sh   # prove you are not leaking  (run this often)
./package.sh            # build a shareable bundle (strips your keys + history)
./uninstall.sh          # stop + remove (keeps downloads and config)
```

---

## Verify you're actually protected

"VPN connected" is not the same as "nothing leaks". Undertow ships a self-test that
checks the real invariants:

```sh
./verify-anonymity.sh
```

It verifies the tunnel is up with a fresh handshake, the firewall policy is `DROP`,
IPv6 can't escape, **your exit IP differs from your real IP**, every container that
shares the tunnel resolves DNS inside it, and the torrent engine is bound to the VPN
address. To prove the kill-switch really fails closed, it can pull the tunnel down and
confirm traffic stops:

```sh
./verify-anonymity.sh --drop-test    # briefly interrupts downloads, then restores
```

`install.sh` runs the read-only checks automatically and refuses to claim success if
they fail.

---

## Use it

- **Log in** with the password from `.env` (`VT_PASSWORD`).
- **Search**, pick a **category**, hit **⬇ Download**. Results merge many indexers at
  once and are ranked by relevance first, then by how downloadable they are — dead
  torrents with no seeders sink to the bottom.
- Or paste a `magnet:` link directly.
- Downloads land in `<MEDIA_PATH>/<category>/` — `MEDIA_PATH` is whatever you chose at
  install time (it's in your `.env`).
- **Deep Hunt** runs a long, patient crawl for hard-to-find things, optionally guided by
  a local LLM. It can keep watching and re-sweeping on a schedule, and notify you when
  something appears.
- **Library tab** — poster grid of finished downloads (add a TMDB key for art). Play in
  the browser, or hand the file to VLC/Infuse on your own device via a short-lived signed
  link scoped to that one file.

### Login

The whole UI is behind a password. It lives in **`.env`** as `VT_PASSWORD` (written by
`install.sh`, `chmod 600`). Change it there, then `docker compose up -d`.

If `VT_PASSWORD` is empty, Undertow falls back to `config/password.txt`, and if that's
missing it generates a strong random one and prints it to the container log — it is
never open by accident, and there is no default password.

---

## The rules it enforces

- **No VPN, no downloads.** If the tunnel isn't up, the app runs disabled — the API
  refuses adds (HTTP 403). It never falls back to an unprotected connection.
- **VPN drops mid-download → everything pauses** automatically, and resumes when the
  tunnel returns. The handshake is checked every 5 seconds.
- **Download-only, never seeds.** A torrent is paused the instant it completes; seed
  limits are zero and local peer discovery is off.
  *(While downloading, BitTorrent still exchanges pieces with peers — that is how
  downloading works. It just never serves anything once finished.)*
- **Nothing downloaded is ever executed.** The app streams bytes or decodes media; it
  never runs a file.

---

## How the protection actually works

Four independent layers, so no single failure exposes you:

1. **Fail-closed firewall.** Before the tunnel is even attempted, `entrypoint.sh` sets
   `iptables -P OUTPUT DROP` and allows only loopback, the LAN, the VPN server's
   endpoint IP, and the `wg` interface. IPv6 is dropped outright. This is armed *first*,
   so there is no window at startup — and it holds during every reconnect and failover.
2. **Socket binding.** The torrent engine binds its listen and outgoing sockets to the
   VPN IP. If the tunnel goes, the address goes, and it has nothing to send from.
3. **Shared network namespace.** Jackett, FlareSolverr, SearXNG, Bitmagnet and SABnzbd
   have no network of their own — they run *inside* the VPN container's namespace, so
   their traffic is subject to the same kill-switch. DNS for all of them is forced to the
   tunnel resolver, so your searches never leak to your ISP.
4. **Continuous self-healing.** A watchdog re-asserts the kill-switch every 15s (and
   re-arms it if anything relaxes it), re-attaches sidecars that lost the namespace, and
   restarts the app if its web UI stops responding.

### VPN failover

Drop extra WireGuard configs next to the primary — `config/proton-<name>.conf`, or any
`config/vpn/*.conf` — and Undertow builds a failover pool. Every candidate endpoint is
pre-authorised in the kill-switch up front, so rotating between servers can never open a
leak window. A server that doesn't complete a real handshake is skipped, and the app
rebinds automatically if the exit IP changes.

---

## Malware protection & sandboxing

- **Antivirus scan + quarantine.** ClamAV scans every finished download. Anything flagged
  — or any bare executable/script found in a *media* category — is moved to a locked
  `.quarantine` folder it can't be played or served from. Flagged files are **kept, not
  deleted**, so you decide. The Library shows ✓ clean / ⏳ pending / ⚠ per title.
- **Sandboxed decoder.** The one place a hostile media file meets running code is ffmpeg,
  so transcoding runs in a separate container with **no network**, no capabilities, a
  read-only filesystem, non-root, and downloads mounted read-only. ffmpeg runs with
  `-protocol_whitelist file,pipe` so a crafted file can't make it open URLs.
- Non-media files are served as forced downloads with `nosniff`, so a stray `.html`/`.js`
  in a torrent can't execute in your browser.

---

## When things go wrong

| Symptom | What's happening / what to do |
|---|---|
| Banner is red, downloads refused | Tunnel is down. `docker compose logs -f vpntorrent`. Usually a dead VPN server — add a second config for failover. |
| Download stuck at "Fetching info…" | It's finding peers via trackers/DHT. If it never moves, the torrent is likely dead (no seeders) — try another result. |
| Search returns nothing | A source may be rate-limiting. Undertow auto-disables failing sources and retries them later; check the Engines tab. |
| A sidecar shows "unhealthy"/exited | The watchdog re-creates it within ~15s. It exists because these containers share the VPN namespace and can't simply be restarted. |
| After a reboot nothing is up | `install.sh` installs `undertow.service` to start the stack at boot. Check `systemctl status undertow`. |
| You want to be sure you're safe | `./verify-anonymity.sh --drop-test` |

**Restarting:** use `docker compose restart` (or `up -d`) for the whole stack. Restarting
*only* the `vpntorrent` container orphans the five containers that share its network
namespace — the watchdog repairs that automatically, but restarting the stack is cleaner.

---

## Files

| Path | What |
|------|------|
| `app/vt.py` | the app: libtorrent engine, web UI, search, auth, VPN monitor |
| `app/hunt*.py` | Deep Hunt crawler + optional local-LLM guidance |
| `app/sources/` | one adapter per non-torrent source (papers, books, datasets…) |
| `app/entrypoint.sh` | kill-switch, WireGuard bring-up, failover, app supervisor |
| `undertow-heal.sh` | watchdog: kill-switch integrity, namespace repair, app liveness |
| `verify-anonymity.sh` | the self-test described above |
| `docker-compose.yml` | the whole stack |
| `config/proton.conf` | **you create this** from your VPN provider's WireGuard config |
| `.env` | your machine-specific settings + web password (never commit this) |

---

## Licence & disclaimer

Provided as-is, with no warranty of any kind, including no warranty that it will keep
you anonymous. Verify your own setup with `./verify-anonymity.sh`, keep your VPN
subscription active, and understand the law where you live. You are responsible for what
you download.
