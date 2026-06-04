# Architecture

## Pipeline

```
┌──────────────────────┐
│ User-supplied YAML   │  (System: components, dataflows, trust boundaries)
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ stride_ai            │  Per-component playbook → Threats[]
│ (engines/stride_ai)  │  Pre-mapped OWASP LLM, ATLAS, STRIDE-AI labels.
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ mapping              │  Keyword-overlap suggestions of additional ATLAS techniques.
│ (engines/mapping)    │  Component-type-aware filtering.
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ risk                 │  DREAD-AI scoring + 5×5 likelihood/impact matrix.
│ (engines/risk)       │  Tweaks based on multi_tenant, trust_zone, agent tool_count.
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ attack_paths         │  NetworkX DAG. Edges respect ATLAS tactic ordering.
│ (engines/attack_paths)│ DFS up to N hops; rank by likelihood × impact.
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ mitigations          │  Per-threat mitigation collection from:
│ (engines/mitigations)│   - Inline playbook bullets
│                      │   - Referenced ATLAS Mitigations (AML.M*)
│                      │   - OWASP LLM mitigations
│                      │  Deduplicated, sorted ATLAS-first.
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ workflow.analyze()   │  Cross-link threats ↔ mitigations.
│                      │  Build summary (severity counts, OWASP coverage,
│                      │  ATLAS coverage, 5×5 matrix).
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ ThreatModel          │  → reporting/{markdown, html, stix, navigator, csv_export}
└──────────────────────┘
```

## Why deterministic core

LLM-based threat enumeration sounds attractive but produces:

- Fabricated technique IDs (e.g., `AML.T9999` that doesn't exist)
- Inconsistent severity scoring across runs
- Untraceable mappings ("the model said so")
- Non-zero cost per analysis

ATMS's core is pure Python over a curated knowledge base. Every threat ID, every ATLAS reference, every OWASP citation is grounded in a versioned YAML file in this repo. Analysis is reproducible and auditable.

LLM is reserved for *vision-based diagram parsing* — the one task where extraction from unstructured input genuinely needs a multimodal model. Even then, the output is a YAML document the user reviews before running analysis.

## Knowledge-base shape

- `kb/owasp_llm/llm_top10_2025.yaml` — 10 OWASP LLM Top 10 (2025) entries, each with patterns, example, mitigations, applicable component types.
- `kb/mitre_atlas/tactics.yaml` — 15 ATLAS tactics with their canonical IDs.
- `kb/mitre_atlas/techniques.yaml` — 41 ATLAS techniques with `tactics`, `keywords`, `applies_to` (component types).
- `kb/mitre_atlas/mitigations.yaml` — 25 ATLAS Mitigations.
- `kb/nist_ai_rmf/genai_profile.yaml` — Selected AI 600-1 entries.
- `kb/stride_ai_matrix.yaml` — STRIDE-AI subcategories per element.
- `kb/playbooks/<type>.yaml` — Per-component-type threat catalogues. Each threat references OWASP, ATLAS, mitigations.

## Data model (Pydantic)

```
System
  ├── components: list[Component]    (id, name, type, trust_zone, description, metadata)
  ├── dataflows: list[Dataflow]      (source, target, label, crosses_boundary, data_classification)
  └── trust_boundaries: list[TrustBoundary]

ThreatModel (output)
  ├── system: System                 (input echoed back)
  ├── threats: list[Threat]          (component_id, stride_ai, owasp_llm, atlas, severity, score)
  ├── attack_paths: list[AttackPath] (threat_ids, components, tactics_traversed, narrative)
  ├── mitigations: list[Mitigation]  (addresses_threat_ids, framework_refs, effort, risk_reduction)
  └── summary: dict                  (severity_breakdown, owasp_coverage, atlas_coverage, risk_matrix)
```

## Process boundaries

Single-process Python application. No external services required.

- **CLI** — `click` group invoked as `python -m atms.cli <cmd>`.
- **Web** — `uvicorn atms.web:app`. In-memory run cache. No DB.
- **KB** — loaded once per process (LRU singleton in `kb.py`).

## Hardening notes

- `defusedxml` declared as a hard dep for any future XML inputs (draw.io export).
- Jinja2 templates use autoescape on HTML, disabled on `.j2` markdown templates intentionally.
- The `/samples` query parameter is path-traversal-checked — only plain filenames inside `samples/` are loaded.
- Vision module is import-on-demand and raises clearly when the optional `anthropic` package or `ANTHROPIC_API_KEY` is missing — never silently fails open.
- HTML report and web UI never embed user-supplied YAML in script-context; they only display it as text.

## Extending

- Add a component type → drop YAML into `kb/playbooks/`, add to `ComponentType` literal in `models.py`.
- Add a framework → load it in `kb.py`, expose via `KnowledgeBase.search`.
- Add a report format → add a renderer under `reporting/`, wire into `cli.py` and `web.py`.
- Add a vision model → swap in `vision/analyzer.py`; the rest of the pipeline doesn't care.
