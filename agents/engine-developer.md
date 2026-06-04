---
role: engine-developer
summary: Owns the analytical core under src/atms/engines/ — STRIDE-AI enumeration, ATLAS/MAESTRO enrichment, DREAD-AI scoring, attack-path generation, boundary inference, and mitigation roll-up.
---

# Engine developer

This guide covers contributions to the algorithmic core of ATMS: threat
enumeration, enrichment, scoring, attack-path search, trust-boundary
inference, and mitigation prioritisation. Use it for any task that touches
"the scoring formula", "attack-path search", "boundary inference", or
"mitigation roll-up". It does NOT cover knowledge-base edits, report
rendering, or CLI/web wiring — those are separate areas.

## Area of ownership

`src/atms/engines/*.py` plus `src/atms/workflow.py` (which composes the
engines into the analyse pipeline). Specifically:

- `engines/stride_ai.py` — playbook-driven threat enumeration.
- `engines/mapping.py` — keyword-based ATLAS technique enrichment.
- `engines/maestro.py` — MAESTRO + OWASP-Agentic enrichment.
- `engines/risk.py` — DREAD-AI scoring + 5x5 severity matrix.
- `engines/attack_paths.py` — NetworkX DAG generation.
- `engines/boundaries.py` — trust-zone-driven boundary inference.
- `engines/mitigations.py` — mitigation collection + prioritisation.
- `workflow.py` — pipeline orchestration.

You may **read** `src/atms/models.py` and `src/atms/kb.py` to understand the
data shapes, but changes to those belong to other areas: Pydantic model
changes are a separate task, and knowledge-base changes belong to the
knowledge-base curator.

## Hard rules

1. **Engines are pure functions.** No module-level state. No I/O outside
   reading the KB (which is passed in). No global mutation. The only
   side-effect allowed is mutating the input `Threat` / `System` instances
   that you receive — and only for documented in-place transformations
   (e.g. assigning `t.risk_score`, appending to `system.trust_boundaries`).

2. **Dependency injection for the KB.** Every engine function takes
   `kb: KnowledgeBase | None = None` and falls back to `kb or get_kb()`.
   Don't import the KB at module top.

3. **Type hints on every function signature.** Same convention as the
   existing engines: `list[Component]`, `KnowledgeBase | None`, etc.

4. **No new dependencies.** The engines must run in the airgap-capable
   distribution. Adding a third-party library is a separate
   packaging/build task.

5. **Determinism.** Same input -> same output. No randomness, no
   `time.time()`-dependent values. If you need stable IDs, derive them from
   a hash of the seed (see `reporting/stix.py:_stix_id` for the pattern).

## Verification

After every change, run from the repo root:

```bash
python -m pytest tests/test_engines.py tests/test_v6_features.py tests/test_boundaries.py -q
PYTHONPATH=src python -m atms.cli selftest
```

If any sample's threat / path / mitigation count changes, **that is a
regression unless it's the deliberate goal of the task.** Investigate.

## Adding a new engine

1. Create `src/atms/engines/<name>.py` with one public function.
2. Wire it into `workflow.analyze()` in the right pipeline position.
3. If it adds a field to `Threat`, the model change is a separate task —
   raise it before relying on the field.
4. Add tests in `tests/test_engines.py` or `tests/test_v6_features.py`.

## What "done" looks like

- Diff is contained to `src/atms/engines/`, possibly `src/atms/workflow.py`,
  and `tests/`.
- Tests added for any new public function; a regression test added for any
  bug fix.
- A short summary of: files modified, count deltas on the rag / agentic /
  enterprise samples, and any follow-up Python edits required elsewhere.
