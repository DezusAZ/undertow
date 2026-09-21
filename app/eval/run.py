#!/usr/bin/env python3
"""Drive the Deep Hunt loop synchronously against real infrastructure and SCORE it.

See eval/__init__.py for the idea. This never starts a hunt worker, never registers the
hunt in the app, never writes /config/hunts — it just uses the same primitives the worker
uses (_gen / _pop_best / _exec / _judge / _record) in a plain loop, so what it measures IS
the production behaviour. stdlib only.
"""
import os
import re
import sys
import json
import time
import argparse
import http.cookiejar
import urllib.parse
import urllib.request

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Evaluate WORKING-TREE code without rebuilding the image: copy app/ somewhere in the
# container and point EVAL_APP_DIR at it (the app process keeps running its own code).
if os.environ.get("EVAL_APP_DIR"):
    sys.path.insert(0, os.environ["EVAL_APP_DIR"])

APP_URL = os.environ.get("EVAL_APP_URL", "http://127.0.0.1:%s" % os.environ.get("PORT", "8722"))


# --------------------------------------------------------------------- app HTTP search
class _App:
    """meta_search through the RUNNING app's /search (so Jackett/Usenet/adapters/ranking are
    exactly what the UI gets), logged in with the app password."""

    def __init__(self, pw):
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        body = urllib.parse.urlencode({"pw": pw}).encode()
        req = urllib.request.Request(APP_URL + "/login", body, {
            "Content-Type": "application/x-www-form-urlencoded", "Origin": APP_URL,
            "Referer": APP_URL + "/login"})
        try:
            self.op.open(req, timeout=15)
        except urllib.error.HTTPError as e:
            if e.code not in (302, 303):
                raise
        if not any(c for c in self.cj):
            raise SystemExit("login failed (bad password?)")

    def meta_search(self, q, category=""):
        url = APP_URL + "/search?" + urllib.parse.urlencode({"q": q, "cat": category or ""})
        with self.op.open(url, timeout=60) as r:
            return json.load(r)


def _pw(args):
    if args.pw:
        return args.pw
    for k in ("VT_PASSWORD", "PASSWORD"):
        if os.environ.get(k):
            return os.environ[k]
    for p in (os.environ.get("PASSWORD_FILE", "/config/password.txt"), "/config/password"):
        try:
            return open(p).read().strip()
        except OSError:
            pass
    raise SystemExit("no app password: pass --pw or set VT_PASSWORD")


# --------------------------------------------------------------------- the eval loop
def _new_hunt(t, pace="aggressive"):
    """Same dict create_hunt builds, minus the thread/registry/disk."""
    import hunt
    now = int(time.time())
    h = {"id": "eval-" + t["id"], "goal": t["goal"], "category": t["category"],
         "description": t["description"], "pace": pace, "pace_seconds": 1,
         "watch": False, "sweep": "off", "sweep_seconds": 0, "last_sweep": now,
         "status": "running", "created": now, "frontier": [], "tried_recent": [],
         "results": [], "_tried_keys": [], "_result_keys": [], "method_stats": {},
         "stats": {"cycles": 0, "executed": 0, "found": 0, "leads": 0, "sweeps": 0,
                   "started": now, "last": 0, "new_last": 0}}
    hunt._add_strategies(h, hunt._stub_generate(h))
    return h


def _matches(t, r):
    s = (r.get("title") or "") + " " + (r.get("url") or "")
    return bool(re.search(t["sig"], s, re.I))


def _on_topic(t, r):
    s = (r.get("title") or "") + " " + (r.get("url") or "")
    return bool(re.search(t.get("topic") or t["sig"], s, re.I))


def run_target(t, args, app, recording, record_out):
    import hunt
    import hunt_exec
    import hunt_brain
    import ai

    h = _new_hunt(t)
    gen = hunt_brain.generate if args.brain == "llm" else hunt._stub_generate
    judge = hunt_brain.judge if args.brain == "llm" else hunt._stub_judge
    if args.brain == "llm" and hasattr(hunt, "_ensure_profile"):
        # wire the same L1/L7 backends vt.py wires at startup, so the loop below IS the worker
        hunt.set_backends(generate=hunt_brain.generate,      # _replenish() plans through this
                          profile=getattr(hunt_brain, "build_profile", None),
                          profile_min=getattr(hunt_brain, "minimal_profile", None),
                          reflect=getattr(hunt_brain, "reflect", None))
        t0 = time.time()
        hunt._ensure_profile(h)                  # L1: build the target profile like the worker does
        if not args.quiet:
            print("  profile step: %.1fs built_by=%s" % (time.time() - t0, (h.get("profile") or {}).get("built_by")), flush=True)
        p = h.get("profile") or {}
        if not args.quiet and p.get("built_by") == "llm":
            print("  profile: %s | aliases=%s | creators=%s | conf=%s" % (
                p.get("canonical_title"), p.get("aliases", [])[:4], p.get("creators", [])[:4],
                p.get("knowledge_confidence")), flush=True)

    def execute(strategy, hh):
        k = hunt._strat_key(strategy)
        if recording is not None:
            return list(recording.get(k, []))
        out = hunt_exec.execute(strategy, hh) or []
        if record_out is not None:
            record_out[k] = out
        return out

    st0 = ai.stats()
    first_hit, log = None, []
    t_start = time.time()
    for cycle in range(1, args.cycles + 1):
        if args.brain == "llm" and h["frontier"] and hasattr(hunt, "_replenish"):
            added = hunt._replenish(h)
            if added and not args.quiet:
                print("  plan: +%d strategies (%s)" % (added, ", ".join(
                    sorted({str(s.get("source") or s.get("method")) for s in h["frontier"]})[:8])), flush=True)
        if not h["frontier"]:
            new = gen(h) or []
            if not hunt._add_strategies(h, new):
                log.append({"cycle": cycle, "event": "exhausted"})
                break
        explore = (h["stats"].get("cycles", 0) % 3 == 2)
        strategy = hunt._pop_best(h, explore=explore)
        h["_tried_keys"].append(hunt._strat_key(strategy))
        h["tried_recent"] = ([strategy] + h.get("tried_recent", []))[:12]
        c0 = time.time()
        results = execute(strategy, h)
        try:
            matches, leads = judge(strategy, results, h)
        except Exception as e:
            matches, leads = list(results), []
            log.append({"cycle": cycle, "event": "judge-error", "err": str(e)[:120]})
        if args.verify:
            try:
                import verify
                matches = verify.filter_live(list(matches), timeout=9, max_n=30)
            except Exception:
                pass
        before = len(h["results"])
        hunt._record(h, strategy, matches, leads)
        h["stats"]["cycles"] += 1
        h["stats"]["executed"] += 1
        new = len(h["results"]) - before
        hunt._note_method(h, strategy.get("method", "search"), new, source=strategy.get("source"))
        hunt._event(h, kind="cycle", method=strategy.get("method", "search"),
                    source=strategy.get("source", ""), query=strategy.get("query", "")[:120],
                    why=strategy.get("why", "")[:120], results=len(results), kept=len(matches),
                    new=new, leads=len(leads or []))
        if args.brain == "llm" and hunt._reflect_fn is not None:
            try:
                if hunt._reflect_fn(h) and not args.quiet:
                    j = h.get("journal") or {}
                    print("  reflect: %s — %s" % (j.get("direction"), (j.get("note") or "")[:110]), flush=True)
            except Exception as e:
                log.append({"cycle": cycle, "event": "reflect-error", "err": str(e)[:120]})
        if args.debug and hasattr(hunt_brain, "_judge_v2") and getattr(hunt_brain._judge_v2, "LAST", None):
            for v in hunt_brain._judge_v2.LAST.get("verdicts", [])[:12]:
                print("      %-7s %.2f  %s  — %s" % (v.get("verdict"), v.get("confidence", 0),
                                                   v.get("title", "")[:60], v.get("reason", "")[:70]))
        hit_now = [r for r in h["results"][before:] if _matches(t, r)]
        if hit_now and first_hit is None:
            first_hit = cycle
        row = {"cycle": cycle, "method": strategy.get("method"), "query": strategy.get("query", "")[:80],
               "results": len(results), "matches": len(matches), "new": new,
               "leads": len(leads or []), "hit": bool(hit_now), "s": round(time.time() - c0, 1)}
        log.append(row)
        if not args.quiet:
            print("  c%02d %-8s %-58s res=%-3d kept=%-3d new=%-3d leads=%-2d %s %.1fs"
                  % (cycle, row["method"], row["query"][:58], row["results"], row["matches"],
                     row["new"], row["leads"], "HIT" if hit_now else "   ", row["s"]), flush=True)
        if first_hit and args.stop_on_hit:
            break
    st1 = ai.stats()
    stored = h["results"]
    found = [r for r in stored if _matches(t, r)]
    junk = [r for r in stored if not _on_topic(t, r)]
    summary = {
        "id": t["id"], "category": t["category"], "difficulty": t["difficulty"],
        "found": bool(found), "first_hit_cycle": first_hit, "cycles": h["stats"]["cycles"],
        "stored": len(stored), "true_finds": len(found), "junk": len(junk),
        "junk_rate": round(len(junk) / len(stored), 2) if stored else 0.0,
        "frontier_left": len(h["frontier"]), "method_stats": h.get("method_stats", {}),
        "llm_calls": st1["calls"] - st0["calls"], "llm_fail": st1["fail"] - st0["fail"],
        "llm_last_error": st1.get("last_error", ""), "seconds": round(time.time() - t_start, 1),
        "sample_finds": [r.get("title", "")[:90] for r in found[:5]],
        "sample_junk": [r.get("title", "")[:90] for r in junk[:5]],
        "log": log,
    }
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="all")
    ap.add_argument("--cycles", type=int, default=10)
    ap.add_argument("--brain", choices=("llm", "stub"), default="llm")
    ap.add_argument("--model", default="", help="override the configured Ollama model for this run")
    ap.add_argument("--verify", action="store_true", help="liveness-filter matches like the worker does")
    ap.add_argument("--stop-on-hit", action="store_true")
    ap.add_argument("--record", default="", help="write every executor response to this JSON")
    ap.add_argument("--replay", default="", help="serve executor responses from this JSON (offline)")
    ap.add_argument("--out", default="", help="write the summary JSON here")
    ap.add_argument("--pw", default="")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--debug", action="store_true", help="print the judge's per-row verdicts each cycle")
    args = ap.parse_args()

    # model override without touching the app's own /config/ai.json: point ai.py at a
    # scratch config that copies the real url and forces enabled + the chosen model.
    if args.model:
        real = "/config/ai.json"
        cfg = {"enabled": True, "url": "", "model": args.model}
        try:
            cfg["url"] = json.load(open(real)).get("url", "")
        except Exception:
            cfg["url"] = os.environ.get("OLLAMA_URL", "")
        p = "/tmp/eval-ai-%s.json" % re.sub(r"[^A-Za-z0-9.]+", "_", args.model)
        json.dump(cfg, open(p, "w"))
        os.environ["AI_CONFIG_FILE"] = p
    from eval.targets import BENCH, BY_ID
    import hunt_exec
    import discover

    recording = json.load(open(args.replay)) if args.replay else None
    record_out = {} if args.record else None
    app = None if recording is not None else _App(_pw(args))
    if app is not None:
        hunt_exec.set_search(meta_search=app.meta_search, discover=discover)
    targets = BENCH if args.target == "all" else [BY_ID[x] for x in args.target.split(",")]
    import ai
    print("eval: brain=%s model=%s targets=%d cycles=%d %s" % (
        args.brain, ai.get_config().get("model"), len(targets), args.cycles,
        "(replay)" if recording is not None else "(live)"), flush=True)
    out = []
    for t in targets:
        print("\n== %s [%s/%s] %s" % (t["id"], t["category"], t["difficulty"], t["goal"]), flush=True)
        s = run_target(t, args, app, recording, record_out)
        out.append(s)
        print("   -> found=%s first_hit=%s stored=%d true=%d junk=%d (%.0f%%) llm=%d/%dfail %.0fs%s"
              % (s["found"], s["first_hit_cycle"], s["stored"], s["true_finds"], s["junk"],
                 100 * s["junk_rate"], s["llm_calls"], s["llm_fail"], s["seconds"],
                 ("  err=" + s["llm_last_error"][:60]) if s["llm_fail"] else ""), flush=True)
    n = len(out)
    found = sum(1 for s in out if s["found"])
    stored = sum(s["stored"] for s in out)
    junk = sum(s["junk"] for s in out)
    print("\n=== SCORE: found %d/%d · junk %d/%d (%.0f%%) · llm calls %d (%d failed)" % (
        found, n, junk, stored, (100.0 * junk / stored) if stored else 0,
        sum(s["llm_calls"] for s in out), sum(s["llm_fail"] for s in out)))
    if args.record:
        json.dump(record_out, open(args.record, "w"))
        print("recorded ->", args.record)
    if args.out:
        json.dump({"args": vars(args), "results": out}, open(args.out, "w"), indent=1)
        print("summary ->", args.out)


if __name__ == "__main__":
    main()
