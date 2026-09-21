"""Deep Hunt evaluation harness.

"Works" must mean a number. `eval.run` drives the hunt loop SYNCHRONOUSLY (no worker
thread, no disk checkpoints, nothing touches /config/hunts) against the real search
infrastructure inside the VPN-locked app container, for a fixed number of cycles per
benchmark target, and scores what got stored:

  found              did any stored result match the target's answer signature?
  first_hit_cycle    how many cycles until the first true find
  stored / junk      how many results were recorded, and what fraction are off-topic
  llm calls / fails  did the brain actually run, how often did it fall back, latency

Run inside the container (the crawl MUST go through the tunnel, never from the host):
  docker exec vpntorrent python3 -m eval.run --target sintel-4k --cycles 10
  docker exec vpntorrent python3 -m eval.run --target all --cycles 12 --model qwen3.5:9b
  ... --record rec.json   (save every executor response)   --replay rec.json (offline)
"""
