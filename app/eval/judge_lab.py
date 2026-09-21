#!/usr/bin/env python3
"""Judge lab: score brain.judge on LABELLED rows (no searching, one model at a time) so a
prompt or model change is measured in minutes, not hours. Rows are real titles the live hunt
surfaced (plus classic decoys); 1 = the target (exact or variant), 0 = not.

  docker exec -e EVAL_APP_DIR=/config/dev-app vpntorrent python3 /config/dev-app/eval/judge_lab.py qwen3.5:9b gemma4:12b
"""
import os
import re
import sys
import json
import time

if os.environ.get("EVAL_APP_DIR"):
    sys.path.insert(0, os.environ["EVAL_APP_DIR"])
sys.path.insert(1, "/app")

CASES = [
    {"goal": "Sintel Blender open movie 4K", "category": "movies",
     "description": "the 4K (2160p) master or highest-quality release of the 2010 Blender Foundation short film, surround audio preferred",
     "rows": [
         ("Sintel - Third Open Movie by Blender Foundation [14m48s]", 1, "page", 0, 0),
         ("Sintel Third Open Movie by Blender Foundation 818p mp4", 1, "torrent", 239e6, 12),
         ("Sintel [14m48s]", 1, "page", 0, 0),
         ("Sintel - HD [14m48s]", 1, "page", 0, 0),
         ("Sintel.2010.2160p.UHD.BluRay.x265-BLENDER", 1, "torrent", 4.1e9, 8),
         ("Sintel - Français - 3ème film libre de la fondation blender [14m48s]", 1, "page", 0, 0),
         ("Making Of Sintel - Blender Open Movie [58m26s]", 0, "page", 0, 0),
         ("Sintel Trailer [0m52s]", 0, "page", 0, 0),
         ("sintel [0m52s]", 0, "page", 0, 0),
         ("All.Together.Now.2020.4K.MULTI.2160p.HDR.WEB.EAC3.x265-Freek", 0, "torrent", 9e9, 40),
         ("Het laten springen van hoogovenslakken [0m35s]", 0, "page", 0, 0),
         ("Big Buck Bunny 4K 60fps", 0, "torrent", 700e6, 30),
     ]},
    {"goal": "Kankyo Ongaku Japanese ambient environmental music 1980s compilation", "category": "music",
     "description": "the Light in the Attic 'Kankyō Ongaku' compilation (2019) OR complete original 1980s Japanese ambient albums by Hiroshi Yoshimura, Satoshi Ashikawa or Takashi Kokubo; lossless FLAC preferred",
     "rows": [
         ("VA - Kankyō Ongaku. Japanese Ambient, Environmental and New Age Music 1980-1990 (2019) [FLAC]", 1, "torrent", 900e6, 22),
         ("Hiroshi Yoshimura - Music For Nine Post Cards (1982) FLAC", 1, "torrent", 250e6, 9),
         ("Satoshi Ashikawa - Still Way (Wave Notation 2) 1982 [24-96 vinyl rip]", 1, "torrent", 700e6, 3),
         ("Takashi Kokubo - Get At The Wave (1987) 320kbps", 1, "torrent", 120e6, 5),
         ("Hiroshi Yoshimura - Green (1986) mp3", 1, "usenet", 90e6, 0),
         ("Various - Pacific Breeze Japanese City Pop AOR 1976-1986 FLAC", 0, "torrent", 600e6, 40),
         ("Haruomi Hosono - Paradise View OST (1985) FLAC", 0, "torrent", 300e6, 10),
         ("Silence2.flac", 0, "file", 4e6, 0),
         ("mykleanthony - Infinity Evolving", 0, "file", 4e6, 0),
         ("Kanye West - Graduation (2007) FLAC", 0, "torrent", 400e6, 500),
         ("Environmental Music Vol 3 - Ocean Waves (1990) mp3", 0, "torrent", 100e6, 2),
         ("Yo-Yo Ma And Pro Musica Nipponia-Japanese Melodies-16BIT-WEB-FLAC", 0, "torrent", 300e6, 15),
     ]},
    {"goal": "Ubuntu 4.10 Warty Warthog install CD ISO", "category": "software",
     "description": "the original October 2004 Ubuntu 4.10 'Warty Warthog' i386 install ISO",
     "rows": [
         ("ubuntu-4.10-install-i386.iso", 1, "file", 600e6, 0),
         ("warty-release-install-i386.iso", 1, "file", 600e6, 0),
         ("Ubuntu 4.10 Warty Warthog i386 CD (archive.org)", 1, "page", 0, 0),
         ("ubuntu-4.10-live-i386.iso", 0, "file", 600e6, 0),
         ("Contents-i386.gz", 0, "file", 20e6, 0),
         ("ubuntu-24.04.1-desktop-amd64.iso", 0, "torrent", 5e9, 900),
         ("GenomeDepot demo server (VirtualBox drive file, based on Ubuntu Server)", 0, "page", 0, 0),
         ("NEST Desktop (3 files)", 0, "page", 0, 0),
     ]},
]


def run(model):
    os.environ["AI_CONFIG_FILE"] = "/tmp/judge-lab-%s.json" % re.sub(r"[^A-Za-z0-9.]+", "_", model)
    url = ""
    try:
        url = json.load(open("/config/ai.json")).get("url", "")
    except Exception:
        url = os.environ.get("OLLAMA_URL", "")
    json.dump({"enabled": True, "url": url, "model": model}, open(os.environ["AI_CONFIG_FILE"], "w"))
    for m in list(sys.modules):
        if m in ("ai", "hunt", "hunt_brain", "brain") or m.startswith("brain."):
            del sys.modules[m]
    import ai  # noqa
    from brain import profile, judge
    tp = fp = fn = 0
    t_all = time.time()
    for c in CASES:
        h = {"goal": c["goal"], "category": c["category"], "description": c["description"]}
        t0 = time.time()
        p = profile.build(c["goal"], c["category"], c["description"]) or profile.minimal(c["goal"], c["category"], c["description"])
        pt = time.time() - t0
        rows = []
        for title, y, kind, size, seeds in c["rows"]:
            r = {"title": title, "source": {"torrent": "Jackett", "usenet": "NZBGeek", "file": "Open dir · x", "page": "PeerTube"}[kind],
                 "seeders": seeds, "size": size, "date": "", "category": c["category"], "quality": ""}
            if kind == "torrent":
                r["magnet"] = "magnet:?xt=urn:btih:%032x" % abs(hash(title))
            elif kind == "usenet":
                r["nzb_id"] = "n" + str(abs(hash(title)))
            else:
                r["url"] = "http://x/" + re.sub(r"\W+", "_", title)
            rows.append(r)
        t0 = time.time()
        out = judge.judge({"query": c["goal"], "method": "search"}, rows, h, p)
        jt = time.time() - t0
        picked = set()
        if out:
            picked = {r["title"] for r in out[0]}
        truth = {t for t, y, *_ in c["rows"] if y}
        alln = {t for t, *_ in c["rows"]}
        ctp = len(picked & truth); cfp = len(picked - truth); cfn = len(truth - picked)
        tp += ctp; fp += cfp; fn += cfn
        print("  %-28s profile %.0fs (%s) judge %.0fs  P=%.2f R=%.2f  wrong=%s missed=%s" % (
            c["goal"][:28], pt, p.get("built_by"), jt, ctp / max(1, ctp + cfp), ctp / max(1, ctp + cfn),
            sorted(x[:34] for x in (picked - truth)), sorted(x[:34] for x in (truth - picked))), flush=True)
        for v in judge.LAST.get("verdicts", []):
            flag = ""
            if v["title"] in truth and v["verdict"] not in ("exact", "variant"):
                flag = "  <-- FALSE NEG"
            if v["title"] not in truth and v["verdict"] in ("exact", "variant") and v["confidence"] >= judge.MIN_CONF:
                flag = "  <-- FALSE POS"
            if flag:
                print("      %-7s %.2f %-50s %s | %s%s" % (v["verdict"], v["confidence"], v["title"][:50], v["reason"][:60], v.get("contradiction", "")[:40], flag))
    P = tp / max(1, tp + fp); R = tp / max(1, tp + fn)
    print("== %s: precision %.2f recall %.2f (tp=%d fp=%d fn=%d) in %.0fs" % (model, P, R, tp, fp, fn, time.time() - t_all), flush=True)
    return P, R


if __name__ == "__main__":
    for m in sys.argv[1:] or ["qwen3.5:9b"]:
        print("\n### MODEL", m, flush=True)
        try:
            run(m)
        except Exception as e:
            print("  ERROR", repr(e)[:200])
