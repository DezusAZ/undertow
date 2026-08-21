#!/bin/sh
# Undertow self-heal — fixes the #1 reboot/restart failure mode.
#
# Five services run with `network_mode: service:vpntorrent` (they SHARE the main
# app's network namespace so all their traffic exits through the VPN). Docker has a
# nasty gotcha here: if `vpntorrent` restarts on its own (OOM, crash, manual restart)
# WITHOUT those five, they don't just "keep running on a dead namespace" — Docker
# binds them to vpntorrent's SANDBOX id at create time, and when that sandbox is gone
# they can't even start: `docker restart` fails forever with
#   "No such container: <old-sandbox-hash>"  (exit 128).
# The ONLY thing that re-attaches them to the LIVE namespace is a compose *recreate*
# (which re-resolves `service:vpntorrent` to the current sandbox). `docker restart`
# CANNOT do it — that was the old bug that left this looping "not running -> restart"
# forever. We recreate instead.
#
# This is a no-op when everything is healthy, and safe to run every minute. Portable
# POSIX sh so it works in a tiny docker:cli sidecar (compose plugin included) with the
# project bind-mounted at its REAL host path (so the daemon resolves ./config paths).
set -u

PROJECT="vpntorrent"
# The compose file must be reachable at the SAME absolute path the host daemon sees,
# so relative bind mounts (./jackett-config, ...) resolve correctly. The watchdog
# mounts /DATA/projects/vpntorrent at the identical path for exactly this reason.
COMPOSE_DIR="${COMPOSE_DIR:-/DATA/projects/vpntorrent}"
COMPOSE_FILE="$COMPOSE_DIR/docker-compose.yml"

# --- GPU fail-safe -----------------------------------------------------------------
# The local LLM (Deep Hunt) must NEVER run on CPU — CPU inference of a 7B pegs every
# core and starves the other containers. The ollama-gpu container intermittently loses
# GPU access ("Failed to initialize NVML") and silently falls back to CPU. We DETECT
# that here (nvidia-smi inside the container) and RESTART ollama-gpu until the GPU is
# back, and publish a health flag the app reads to gate the LLM (no flag / not-ok =>
# the app skips the model and grinds CPU-free). /api/ps is NOT trustworthy for this.
OLLAMA_CTR="${OLLAMA_CTR:-ollama-gpu}"
# The endpoint the flag CERTIFIES — must equal the URL the app actually sends inference to
# (config/ai.json url), else the gate could pass while inference runs on a different CPU box.
OLLAMA_URL="${OLLAMA_URL:-}"    # set in .env if you run a local Ollama; never hardcode a LAN IP
GPU_FLAG="$COMPOSE_DIR/config/gpu_health.json"
GPU_STATE="$COMPOSE_DIR/config/.gpu_heal_state"     # "last_restart_epoch fail_count"
# ollama-gpu runs ONLY while Undertow has an active hunt (user 2026-07-14: don't burn power
# keeping AI up when not hunting). We start it on demand and stop the one WE started.
HUNTS_DIR="$COMPOSE_DIR/config/hunts"
OLLAMA_MARK="$COMPOSE_DIR/config/.ollama_by_undertow"   # present => we auto-started ollama (epoch inside)
OLLAMA_INST="$COMPOSE_DIR/config/.ollama_inst"          # the container StartedAt we own, so we never stop
                                                        # an instance someone (re)started themselves

AI_CONF="$COMPOSE_DIR/config/ai.json"
# On-demand GPU (user 2026-07-21: don't run the GPU 24/7). The app touches this file whenever
# AI is actually used; ollama runs only while it's FRESH (or a hunt is grinding) and is stopped
# once it goes stale — so the GPU idles at 0 VRAM between uses. The app refreshes it on every
# call, so it stays up during active use and stops ~WAKE_TTL after the last one.
WAKE_FILE="$COMPOSE_DIR/config/.ai_wake"
WAKE_TTL="${WAKE_TTL:-900}"                          # 15 min of no AI use (and no hunt) -> stop

hunts_active() {                                    # any hunt still grinding (running/idle)?
    for f in "$HUNTS_DIR"/*.json; do
        [ -e "$f" ] || continue
        grep -Eq '"status": *"(running|idle)"' "$f" 2>/dev/null && return 0
    done
    return 1
}

wake_fresh() {                                      # AI used within WAKE_TTL?
    [ -f "$WAKE_FILE" ] || return 1
    now=$(date +%s 2>/dev/null || echo 0)
    mt=$(stat -c %Y "$WAKE_FILE" 2>/dev/null || echo 0)
    [ "$now" -gt 0 ] && [ "$mt" -gt 0 ] && [ $((now - mt)) -lt "$WAKE_TTL" ]
}

ai_enabled() {                                      # the user's Local-AI toggle (config/ai.json)
    grep -Eq '"enabled"[[:space:]]*:[[:space:]]*true' "$AI_CONF" 2>/dev/null
}

# Stamp the ollama-gpu StartedAt we OWN, atomically — write to a temp file and mv only if the inspect
# gave a non-empty value, so a transient inspect failure can never leave a truncated/empty stamp that
# would confuse the ownership check.
write_inst() {
    if docker inspect -f '{{.State.StartedAt}}' "$OLLAMA_CTR" > "$OLLAMA_INST.tmp" 2>/dev/null \
            && [ -s "$OLLAMA_INST.tmp" ]; then
        mv "$OLLAMA_INST.tmp" "$OLLAMA_INST" 2>/dev/null
    else
        rm -f "$OLLAMA_INST.tmp" 2>/dev/null
    fi
}

# Keep ollama-gpu up whenever the user has Local AI ENABLED (or a hunt is grinding), NOT only during
# hunts — otherwise the Engines panel shows "not reachable" and AI search/explain silently can't run.
# The model still UNLOADS from VRAM after idle (ollama keep_alive), so an idle-but-running ollama uses
# no GPU/power; turning AI OFF stops the container entirely. We only stop the one WE started.
ollama_lifecycle() {
    run=$(docker inspect -f '{{.State.Running}}' "$OLLAMA_CTR" 2>/dev/null || echo missing)
    [ "$run" = "missing" ] && return               # ollama-gpu not installed -> nothing to do
    # Start ONLY on active use (a fresh wake from the app) or a grinding hunt — NOT merely because
    # the AI feature is toggled on. That's what keeps the GPU from running 24/7 (user 2026-07-21).
    if wake_fresh || hunts_active; then
        if [ "$run" != "true" ]; then
            # let the post-boot ai-keep-down window finish first so we don't fight it (that service
            # keeps AI down for its TimeoutStartSec ~400s). Wait comfortably past that to avoid churn.
            up=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 999999)
            [ "$up" -lt 450 ] && return
            echo "ollama: AI in use / hunt active -> starting $OLLAMA_CTR"
            if docker start "$OLLAMA_CTR" >/dev/null 2>&1; then
                date +%s > "$OLLAMA_MARK" 2>/dev/null              # epoch (gpu_heal's just-started guard)
                write_inst                                        # StartedAt stamp (atomic; never a truncated file)
            fi
        elif [ -f "$OLLAMA_MARK" ] && [ ! -s "$OLLAMA_INST" ]; then
            # we own it (marker set) but the stamp is missing — an earlier write_inst hiccup. This running
            # instance IS the one we started, so re-stamp it, else the auto-stop path would wedge forever.
            write_inst
        fi
    elif [ "$run" = "true" ] && [ -f "$OLLAMA_MARK" ]; then
        # AI idle (wake stale) AND no active hunts. Only stop the EXACT instance WE started — if its StartedAt no longer
        # matches, someone (re)started ollama-gpu themselves since, so we release ownership and DON'T stop it.
        our_inst=$(cat "$OLLAMA_INST" 2>/dev/null)
        cur_inst=$(docker inspect -f '{{.State.StartedAt}}' "$OLLAMA_CTR" 2>/dev/null)
        if [ -z "$our_inst" ] || [ -z "$cur_inst" ]; then
            # can't prove ownership either way (a transient inspect failure / missing stamp) -> do NOT stop.
            echo "ollama: instance identity unverifiable this cycle — not stopping"
        elif [ "$our_inst" != "$cur_inst" ]; then
            echo "ollama: $OLLAMA_CTR was (re)started elsewhere — releasing ownership, NOT stopping"
            rm -f "$OLLAMA_MARK" "$OLLAMA_INST"
        else
            owb=$(docker inspect -f '{{.State.Running}}' open-webui-open-webui-1 2>/dev/null || echo false)
            if [ "$owb" != "true" ]; then
                echo "ollama: AI idle + no active hunts -> stopping $OLLAMA_CTR (was auto-started)"
                # only drop the marker if the stop ACTUALLY worked, else keep it + retry next cycle (no leak).
                if docker stop "$OLLAMA_CTR" >/dev/null 2>&1; then
                    rm -f "$OLLAMA_MARK" "$OLLAMA_INST"
                else
                    echo "ollama: stop failed — keeping marker, will retry next cycle"
                fi
            fi
        fi
    fi
}

gpu_write_flag() {                                  # ok(true/false) detail
    now=$(date +%s 2>/dev/null || echo 0)
    printf '{"ok":%s,"ts":%s,"detail":"%s","endpoint":"%s"}' \
        "$1" "$now" "$2" "$OLLAMA_URL" > "$GPU_FLAG.tmp" 2>/dev/null \
        && mv "$GPU_FLAG.tmp" "$GPU_FLAG" 2>/dev/null || true
}

# Restart ollama-gpu on a cooldown (120s, 900s after >=5 straight failures), keeping trying
# until the GPU returns. Fail-safe: if we can't persist the attempt counter we SKIP the
# restart (a frozen counter would otherwise restart every cycle = a storm).
gpu_restart_backoff() {
    now=$(date +%s 2>/dev/null || echo 0)
    last=0; fails=0
    [ -f "$GPU_STATE" ] && read last fails < "$GPU_STATE" 2>/dev/null
    case "$last" in ''|*[!0-9]*) last=0 ;; esac     # sanitize to a pure integer
    case "$fails" in ''|*[!0-9]*) fails=0 ;; esac
    cooldown=120
    [ "$fails" -ge 5 ] && cooldown=900
    [ $((now - last)) -ge "$cooldown" ] || return
    if echo "$now $((fails+1))" > "$GPU_STATE" 2>/dev/null; then
        echo "gpu-heal: $OLLAMA_CTR lost the GPU -> restart (attempt $((fails+1)))"
        # a restart changes StartedAt — if WE own this container (marker present), refresh the
        # instance stamp so the on-demand stop still recognises it as ours (else it leaks forever).
        if timeout 90 docker restart "$OLLAMA_CTR" >/dev/null 2>&1; then
            [ -f "$OLLAMA_MARK" ] && write_inst        # keep our owned-instance stamp in sync (atomic)
        fi
    else
        echo "gpu-heal: cannot persist $GPU_STATE — skipping restart to avoid a storm"
    fi
}

gpu_heal() {
    run=$(docker inspect -f '{{.State.Running}}' "$OLLAMA_CTR" 2>/dev/null || echo missing)
    if [ "$run" != "true" ]; then
        # ollama intentionally down (on-demand AI policy) — do NOT auto-start it; the app
        # just grinds without the LLM. Flag not-ok so the app never assumes a model.
        gpu_write_flag false "ollama-down"
        return
    fi
    # DEVICE check. `timeout` so a wedged/D-state NVML can't pin the whole watchdog loop.
    if ! timeout 20 docker exec "$OLLAMA_CTR" nvidia-smi -L >/dev/null 2>&1; then
        # GPU access broken -> would run on CPU. Flag not-ok + restart until it recovers.
        gpu_write_flag false "nvml-broken-cpu"
        # but don't restart a container WE just started (<75s) — it may still be initializing.
        if [ -f "$OLLAMA_MARK" ]; then
            mk=$(cat "$OLLAMA_MARK" 2>/dev/null); now=$(date +%s 2>/dev/null || echo 0)
            case "$mk" in ''|*[!0-9]*) mk=0 ;; esac
            [ $((now - mk)) -lt 75 ] && return
        fi
        gpu_restart_backoff
        return
    fi
    # PLACEMENT check. nvidia-smi -L only proves the device is visible, not that there's
    # free VRAM: under pressure (Whisper/Frigate/other) Ollama SPLITS a model onto the CPU.
    # `ollama ps` PROCESSOR column shows "100% GPU" or "NN% CPU/..." — any CPU => not ok.
    # (No restart here: a restart won't free another container's VRAM; the app just skips
    # the LLM and grinds on the stub until VRAM frees up.)
    psout=$(timeout 15 docker exec "$OLLAMA_CTR" ollama ps 2>/dev/null)
    if printf '%s' "$psout" | grep -qi 'cpu'; then
        gpu_write_flag false "partial-cpu-offload"
        return
    fi
    gpu_write_flag true "gpu-ok"                    # device up + nothing split to CPU
    echo "0 0" > "$GPU_STATE" 2>/dev/null || true  # reset the restart backoff
}

# --- KILL-SWITCH INTEGRITY (anonymity fail-safe) ------------------------------------
# The entrypoint arms a fail-closed firewall at start, but nothing re-checks it afterwards.
# Anything that flushes or relaxes OUTPUT (a stray `iptables -F` in the shared namespace, a
# sidecar image's own firewall setup, a partially-applied rule set) would silently un-protect
# every container in this namespace while the UI still says "VPN: connected".
# We re-assert the invariant every cycle. DROP is the safe direction: the worst case of being
# wrong is that downloads stop, never that traffic escapes.
killswitch_guard() {
    pol=$(docker exec vpntorrent iptables -S OUTPUT 2>/dev/null | head -1)
    [ -n "$pol" ] || return 0                       # can't inspect (container busy) -> next cycle
    [ "$pol" = "-P OUTPUT DROP" ] && return 0       # already fail-closed
    echo "killswitch: OUTPUT policy is '$pol' — NOT fail-closed; re-arming now"
    # Only safe to force DROP if the tunnel-accept rule survives; otherwise the rule set was
    # wiped and a bare DROP would cut the container off with no way back. In that case let the
    # entrypoint rebuild the whole thing from scratch by restarting the container.
    if docker exec vpntorrent iptables -C OUTPUT -o wg -j ACCEPT >/dev/null 2>&1; then
        docker exec vpntorrent iptables -P OUTPUT DROP >/dev/null 2>&1 \
            && echo "killswitch: re-armed (-P OUTPUT DROP)" \
            || echo "killswitch: FAILED to re-arm — restarting vpntorrent to rebuild"
    else
        echo "killswitch: rule set is gone entirely -> restarting vpntorrent to rebuild it"
        docker restart vpntorrent >/dev/null 2>&1 || true
        # the dep loop below notices the new namespace and recreates the five sidecars
    fi
}

# --- TRANSCODER GPU INTEGRITY ------------------------------------------------------
# The decode sandbox keeps its /dev/nvidia* nodes across a host driver update, but the
# driver LIBRARIES injected at container-create time go stale — CUDA then fails with
# "no CUDA-capable device is detected" even though the GPU is perfectly healthy. The
# only fix is to recreate the container so the runtime re-injects current libraries.
# Symptom if unhandled: every video "Couldn't prepare this file", or a silent fall back
# to a much slower CPU encode. Checked rarely (it is a real encode) and only repaired
# when the HOST GPU is confirmed working, so a machine with no GPU is never touched.
GPU_TC_STATE="$COMPOSE_DIR/config/.transcoder_gpu_check"
transcoder_gpu_guard() {
    [ "$(docker inspect -f '{{.State.Running}}' vpntorrent-transcoder 2>/dev/null)" = "true" ] || return 0
    # only relevant if this deployment asked for a GPU at all
    docker inspect -f '{{json .HostConfig.DeviceRequests}}' vpntorrent-transcoder 2>/dev/null         | grep -q nvidia || return 0
    now=$(date +%s 2>/dev/null || echo 0)
    last=0
    [ -f "$GPU_TC_STATE" ] && last=$(cat "$GPU_TC_STATE" 2>/dev/null)
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    [ $((now - last)) -ge 900 ] || return 0          # at most once every 15 min
    echo "$now" > "$GPU_TC_STATE" 2>/dev/null
    if timeout 60 docker exec vpntorrent-transcoder ffmpeg -hide_banner -loglevel error             -f lavfi -i testsrc=size=256x256:rate=1 -frames:v 2 -c:v h264_nvenc             -pix_fmt yuv420p -f null - >/dev/null 2>&1; then
        return 0                                     # GPU fine
    fi
    # Confirm the HOST GPU works before blaming the container — otherwise we would
    # recreate it forever on a box whose GPU is genuinely absent or busy.
    if ! timeout 60 docker run --rm --gpus all --entrypoint nvidia-smi             "$(docker inspect -f '{{.Config.Image}}' vpntorrent-transcoder 2>/dev/null)"             -L >/dev/null 2>&1; then
        echo "transcoder: NVENC unusable and the host GPU is not available either — leaving it on CPU"
        return 0
    fi
    echo "transcoder: GPU broken inside the container but healthy on the host -> recreating"
    if [ -f "$COMPOSE_FILE" ]; then
        docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --no-deps --no-build             --force-recreate transcoder >/dev/null 2>&1             && echo "transcoder: recreated (driver libraries re-injected)"
    fi
}

# --- APP LIVENESS ------------------------------------------------------------------
# The app process can be alive while the web UI is wedged (a stuck thread, an exhausted
# handler pool). The container looks "running" and nothing recovers it. Probe the real HTTP
# surface; two consecutive failures (~2 min apart) trigger a restart, so a single slow
# response during a heavy search never causes a needless bounce.
APP_FAIL_STATE="$COMPOSE_DIR/config/.app_unhealthy"   # "<StartedAt> <consecutive_failures>"
# $1 = vpntorrent's StartedAt (already inspected by the caller; don't inspect twice)
app_liveness() {
    _started="$1"
    # BOOT GRACE. The app process does not exist for a long time BY DESIGN while the VPN
    # is being established: entrypoint.sh retries the whole server pool 6 times with a
    # ~14s handshake wait plus 6s sleeps before it ever launches the app. With one config
    # that is ~2 minutes; with three it is ~5. Restarting inside that window kills the
    # entrypoint mid-retry, destroys the namespace, orphans all five siblings and starts
    # the whole bring-up again — a slow VPN would become a permanent restart loop.
    # So: never probe a container younger than the worst-case bring-up.
    _age=$(docker exec vpntorrent sh -c 'awk "{print int(\$1)}" /proc/uptime' 2>/dev/null)
    case "$_age" in ''|*[!0-9]*) return 0 ;; esac       # can't tell -> do nothing
    if [ "$_age" -lt 600 ]; then
        return 0
    fi

    if docker exec vpntorrent python3 -c '
import urllib.request, sys
try:
    urllib.request.urlopen("http://127.0.0.1:8722/login", timeout=10)
except urllib.error.HTTPError:
    pass                      # any HTTP status means the server answered
except Exception:
    sys.exit(1)
' >/dev/null 2>&1; then
        rm -f "$APP_FAIL_STATE" 2>/dev/null
        return 0
    fi

    # Failing. Count consecutive strikes, but tie them to THIS container instance: if the
    # container restarted, the old strikes are meaningless and must not carry over.
    _prev_started=""; _fails=0
    [ -f "$APP_FAIL_STATE" ] && read _prev_started _fails < "$APP_FAIL_STATE" 2>/dev/null
    case "$_fails" in ''|*[!0-9]*) _fails=0 ;; esac
    [ "$_prev_started" = "$_started" ] || _fails=0      # different instance -> reset
    _fails=$((_fails + 1))
    echo "$_started $_fails" > "$APP_FAIL_STATE" 2>/dev/null
    if [ "$_fails" -ge 3 ]; then
        echo "app: web UI unresponsive $_fails cycles in a row -> restarting vpntorrent"
        rm -f "$APP_FAIL_STATE" 2>/dev/null
        docker restart vpntorrent >/dev/null 2>&1 || true
    else
        echo "app: web UI did not answer (strike $_fails/3)"
    fi
}

# The five services that SHARE vpntorrent's network namespace. (bitmagnet-postgres is
# intentionally NOT here — it lives on its own sandbox-net IP, so it is never orphaned.)
DEPS="jackett flaresolverr searxng bitmagnet sabnzbd"

# Recreate one service so it rejoins the live namespace. --no-deps: never touch
# vpntorrent or postgres. --no-build: use the prebuilt image (the sidecar can't build).
# True only when vpntorrent's kill-switch is LIVE. Checked against the running firewall,
# never a marker file (a file survives an OOM kill and lies).
killswitch_live() {
    [ "$(docker exec vpntorrent iptables -S OUTPUT 2>/dev/null | head -1)" = "-P OUTPUT DROP" ]
}

recreate() {
    svc="$1"
    # MANDATORY GATE. compose's `depends_on: service_healthy` protects the normal start
    # path, but `--no-deps` below deliberately bypasses depends_on — which is exactly the
    # post-crash path where the arming window is most likely. Without this check we would
    # re-attach a sibling to a namespace whose firewall is not up yet, and its first
    # packets would leave via the bridge as the operator's real IP. Wait instead: the next
    # heal cycle is only 15s away and the sibling being down is harmless.
    if ! killswitch_live; then
        echo "heal: kill-switch not armed yet — deferring recreate of $svc (no unprotected start)"
        return 1
    fi
    if [ -f "$COMPOSE_FILE" ]; then
        docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --no-deps --no-build \
            --force-recreate "$svc" >/dev/null 2>&1 && return 0
    fi
    # last-ditch fallback if compose is unavailable: a plain restart (works only if the
    # namespace is still alive, e.g. the dep crashed on its own, not an orphan).
    docker restart "vpntorrent-$svc" >/dev/null 2>&1 || true
}

# On-demand ollama, then the GPU fail-safe — both independent of vpntorrent's own state.
ollama_lifecycle
gpu_heal

main_run=$(docker inspect -f '{{.State.Running}}' vpntorrent 2>/dev/null || echo missing)
if [ "$main_run" != "true" ]; then
    # vpntorrent itself is down — the systemd unit / restart policy owns bringing it
    # back. If it is missing ENTIRELY, try to bring the whole stack up from compose.
    if [ "$main_run" = "missing" ] && [ -f "$COMPOSE_FILE" ]; then
        echo "heal: vpntorrent missing — docker compose up -d"
        docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --no-build >/dev/null 2>&1 || true
    fi
    exit 0
fi

main=$(docker inspect -f '{{.State.StartedAt}}' vpntorrent 2>/dev/null)
[ -n "$main" ] || exit 0

# Anonymity invariant first — it matters more than any availability concern.
killswitch_guard
transcoder_gpu_guard

for dep in $DEPS; do
    c="vpntorrent-$dep"
    status=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null) || continue
    case "$status" in
        created|restarting|paused|removing)
            # a deploy (compose up) is actively (re)creating this container — do NOT
            # fight it, or we race and leave mangled duplicate-named containers.
            continue ;;
        running)
            : ;;                          # fall through to the stale-namespace check
        *)                                # exited / dead -> orphaned, bring it back
            echo "heal: $c $status -> recreate (rejoin live namespace)"
            recreate "$dep"
            continue ;;
    esac
    st=$(docker inspect -f '{{.State.StartedAt}}' "$c" 2>/dev/null)
    [ -n "$st" ] || continue
    # If the dependent started BEFORE the current vpntorrent, it is on the old (dead)
    # namespace. Lexicographic sort of RFC3339Nano UTC timestamps == chronological.
    older=$(printf '%s\n%s\n' "$st" "$main" | sort | head -n1)
    if [ "$st" != "$main" ] && [ "$older" = "$st" ]; then
        echo "heal: $c orphaned on a stale namespace -> recreate"
        recreate "$dep"
    fi
done

# Availability check LAST: if this restarts the app, the next cycle re-attaches the
# five sidecars to the new namespace (that is exactly what the loop above is for).
# $main is vpntorrent's StartedAt, already inspected above — strikes are tied to it so a
# restart never counts its own boot window against itself.
app_liveness "$main"
