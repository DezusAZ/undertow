"""Deep Hunt v2 — the brain.

The intelligence of a hunt, rebuilt as layers that are each anchored on a real
understanding of the target and each measurable with the eval harness:

  llm.py       one door to the local model: schema-constrained calls with per-role
               budgets, timeouts and telemetry (never raises, never blocks a request)
  profile.py   L1  what IS the target — aliases, creators, identifiers, formats,
               near-misses to reject, the user's own definition of "found"
  manifest.py  L2  what each source can do, and how it has been performing
  planner.py   L3  invent the next strategies from profile + journal + yields
  judge.py     L5  per-row verdicts with confidence and a reason ("why this result")
  journal.py   L6  the hunt's memory: facts learned, dead ends, hosts, hypotheses

hunt_brain.py keeps its old public surface (generate / judge / brain_status) and
delegates here, so the runtime (hunt.py) and the executor did not have to change
shape. Everything degrades to the deterministic stubs when the model is off.
"""
