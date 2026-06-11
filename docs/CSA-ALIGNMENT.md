# CSA alignment

How ATMS aligns with **Cloud Security Alliance (CSA)** AI threat-modeling + risk-assessment guidance, and the **Singapore CSA** Guidelines on Securing AI Systems. Honest about what's covered and what isn't.

> Methodology note: ATMS's threat enumeration is *STRIDE-for-AI* and its per-threat score is *DREAD-derived* (Likelihood × Impact). Neither "STRIDE-AI" nor "DREAD-AI" is a published standard — they are ATMS extensions (see `kb/methodology_provenance.yaml`). CSA's capability method (CBRA) is implemented *alongside* DREAD-AI, not as a replacement.

## MAESTRO 6-step threat-modeling process → ATMS output

CSA's MAESTRO agentic threat-modeling framework (Cloud Security Alliance, AI Safety Initiative, 2025-02-06; CI/CD operationalization 2026-02) prescribes a 6-step process. ATMS executes the substance of each:

| MAESTRO step | What it asks for | Where ATMS produces it |
|---|---|---|
| **1. System decomposition** | Asset/component inventory + data-flow map + trust boundaries | "Scope" section (components, dataflows, inferred trust boundaries) + the Mermaid data-flow diagram |
| **2. Layer-specific threats** | Threats per MAESTRO layer (7 layers) | MAESTRO-tagged threats (`engines/maestro.py`, `kb/maestro/`), each threat carries `maestro_layers` + `maestro_threats` |
| **3. Cross-layer threats** | Cascades / stepping-stones across layers | The 5 cross-layer classes (M.X.01–05) + the **attack paths** (causal pre/post-condition derivation) + the CSA Table of Attack |
| **4. Risk assessment** | Score + prioritize | Per-threat **DREAD-AI** (L×I, 5×5) **and** per-system **CBRA** (Criticality × Autonomy × Access × Impact-Radius → tier) + the SG-CII risk register |
| **5. Mitigation** | Controls per threat, prioritized | Mitigation set + D3FEND mapping + the top-10 roadmap (+ AICM control mapping, where present) |
| **6. Implementation & monitoring** | Continuous / living | `atms diff` (model-to-model threat diff) + `atms ci` (fail-gate on severity, SARIF export) |

## CSA risk methods

- **CBRA — Capabilities-Based Risk Assessment** (CSA AI Safety Initiative, 2025-11). Implemented in `engines/cbra.py`: System Risk = Criticality × Autonomy × Access-Permissions × Impact-Radius, each a 1–4 anchor scale, product → Low/Medium/High tier. Every dimension traces to a real model field. Rendered in the report. *Complements* DREAD-AI (per-threat) with a per-system/per-agent capability score.
- **AICM — AI Controls Matrix** (CSA, v1.0.3): threats are cross-walked to AICM control objectives where present (`engines/aicm.py`, `kb/aicm/`). See the "CSA AICM control mapping" report section.
- **SG-CII risk register** (Singapore, Feb 2021 method): `reporting/csa_risk_register.py` — Likelihood = avg(D,E,R), Impact = max(C,I,A), 5×5 bands, the 8-element register with honest residual-risk (bands drop only when treatment is actually applied).

## Singapore CSA Guidelines on Securing AI Systems (Oct 2024)

Encoded as a curated KB (`kb/csa_singapore/guidelines.yaml`) across Plan / Develop / Deploy / Operate + cross-cutting Human-oversight & Transparency, with `also_see` cross-walks to NIST AI RMF and OWASP LLM. (The draft *Securing Agentic AI* Addendum, public consultation closed 2025-12-31, is tracked but **not** ingested while it remains a draft — per the source-faithful rule.)

## Honest gaps (not yet, or partial)

- AICM coverage is the MVP set (the AI-relevant control objectives that map to ATMS's threat catalog), not all 243 controls / 18 domains.
- CBRA residual-risk lever (compress a dimension via a control, re-score) is not yet wired to the mitigation set.
- Threat normalization against the CSA LLM Threats Taxonomy (2024) is partial (covered indirectly via OWASP LLM / ATLAS mappings).
- The "living" model is file-to-file (`diff`), not branch-aware threat-diffing.

## Sources

- CSA MAESTRO — Cloud Security Alliance, *Agentic AI Threat Modeling Framework: MAESTRO* (2025-02-06); CI/CD operationalization (2026-02).
- CSA CBRA — Cloud Security Alliance AI Safety Initiative, *Capabilities-Based Risk Assessment* (2025-11).
- CSA AICM v1.0.3 — Cloud Security Alliance, *AI Controls Matrix* (2025-07, updated 2025-10).
- Singapore CSA — *Guidelines on Securing AI Systems* + Companion Guide (Oct 2024).
