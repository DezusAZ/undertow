"""One door to the local model for the hunt brain.

Every call is schema-constrained (the server enforces the JSON shape), bounded (num_ctx,
num_predict, timeout), serialised through the hunt-wide gate, and counted PER ROLE so the
UI and the eval harness can see which stage ran, how often it fell back, and how long it
took. Thinking-family models get think=false on the hot path: reasoning tokens would eat
the output budget and add tens of seconds per cycle for no measurable gain on these tasks.
Never raises; returns None when the model gave nothing usable.
"""
import os
import time
import threading

import ai

# Only ever run a bounded number of LLM calls at once ACROSS ALL HUNTS (a GPU serialises
# them anyway; the gate stops N hunts from queueing N×timeout).
GATE = threading.Semaphore(max(1, int(os.environ.get("HUNT_LLM_CONCURRENCY", "1"))))
# Force full GPU offload: if the model can't fit, Ollama errors instead of silently
# splitting layers onto the CPU (the watchdog's GPU gate is the other half of this).
_GPU_OPTS = {"num_gpu": int(os.environ.get("HUNT_NUM_GPU", "999"))}

# Per-role budgets: (num_predict, timeout_s, temperature). Judge/plan are the hot path.
ROLES = {
    "profile": (1300, 200, 0.2),
    "plan": (900, 150, 0.7),
    "judge": (1600, 150, 0.0),
    "reflect": (700, 150, 0.3),
}

_lock = threading.Lock()
_stats = {}       # role -> {"calls","ok","fail","last_s","total_s","last_error"}


def _note(role, ok, secs, err=""):
    with _lock:
        s = _stats.setdefault(role, {"calls": 0, "ok": 0, "fail": 0, "last_s": None,
                                     "total_s": 0.0, "last_error": ""})
        s["calls"] += 1
        s["ok" if ok else "fail"] += 1
        s["last_s"] = round(secs, 1)
        s["total_s"] = round(s["total_s"] + secs, 1)
        if not ok:
            s["last_error"] = (err or "")[:160]


def stats():
    with _lock:
        return {k: dict(v) for k, v in _stats.items()}


def approx_tokens(text):
    """Cheap upper-ish estimate (~4 chars/token for English, less for JSON) for budgeting."""
    return len(text or "") // 3


def call(role, system, user, schema, max_prompt_tokens=None):
    """Schema-constrained call for `role`. Returns the parsed object or None."""
    num_predict, timeout, temp = ROLES.get(role, (600, 120, 0.2))
    budget = max_prompt_tokens or (ai.NUM_CTX - num_predict - 200)
    if approx_tokens(system) + approx_tokens(user) > budget:
        # Never let the server truncate the FRONT of the prompt (that's the system prompt).
        # Trim the user part from the end; callers keep the important material first.
        keep = max(500, (budget - approx_tokens(system)) * 3)
        user = user[:keep] + "\n…(truncated)"
    think = False if ai.model_thinks() else None
    t0 = time.time()
    with GATE:
        j = ai.chat_json(system, user, schema, timeout=timeout, think=think,
                         options=dict(_GPU_OPTS, num_predict=num_predict, temperature=temp))
    secs = time.time() - t0
    if j is None:
        err = ai.stats().get("last_error", "") or "empty/unparseable answer"
        _note(role, False, secs, err)
        return None
    _note(role, True, secs)
    return j
