# ATMS architecture — narrative companion to `ARCHITECTURE.mmd`

The mermaid diagram in `docs/ARCHITECTURE.mmd` (also rendered at
`/architecture` in the running web UI) shows every subsystem at
once. This doc tells the same story in prose so you can read it
without a renderer.

## The big picture

ATMS is a pipeline. A user supplies an input artefact in one of
12 formats. A format-aware ingester translates it into the
canonical `System` Pydantic model. The `workflow.analyze()`
orchestrator passes that System through 24 engines that progressively
attach threats, paths, mitigations, framework refs, compliance
mappings, and FAIR-lite loss-range pricing. The resulting
`ThreatModel` is then offered up through 14 export renderers for
human + machine consumption, and surfaced via 5 delivery surfaces
(CLI · web UI · REST API · MCP server · PyInstaller .exe).

Nothing in the pipeline touches the network at analysis time. The
only optional network paths are explicit user-initiated commands:
`atms refresh-feeds` (KEV / EPSS snapshot), `atms cve-lookup`
(NVD / OSV), and the opt-in vision module (Anthropic, requires API
key).

## The Pydantic core

`src/atms/models.py` defines the data model:

- **`System`** — root container. Carries: `name`, `description`,
  `business_context`, `industry`, `deployment_stage`,
  `revenue_bucket`, `is_high_risk_under_eu_ai_act` (drives EU AI
  Act gating + FAIR loss-prior tier selection), and three child
  collections: `components`, `dataflows`, `trust_boundaries`.
- **`Component`** — one of 121 `ComponentType` literals. Carries
  `name`, `description`, `trust_zone`, `metadata` (vendor /
  product / version / cpe / purl / hostname / ip / fqdn — drives
  evidence matching), and `controls` (declared mitigations to
  suppress redundant threats).
- **`Dataflow`** — directed edge with a label (e.g. "HTTPS",
  "JWT bearer", "TLS SQL") and a `crosses_boundary` flag.
- **`TrustBoundary`** — 5 types (network / identity /
  data_classification / tenancy / deployment_zone).
- **`Threat`** — emission from a playbook or arch rule. Carries
  `component_id`, `severity`, `likelihood`, `impact`, framework
  refs (`stride_ai`, `owasp_llm`, `atlas_techniques`,
  `compliance_controls`, …), `evidence_status`, `disposition`.
- **`AttackPath`** — multi-step chain (NetworkX traversal honouring
  ATLAS tactic order).
- **`Mitigation`** — recommended control with `effort`,
  `risk_reduction`, `addresses_threat_ids`, `framework_refs`,
  `d3fend` (MITRE D3FEND technique IDs).
- **`ThreatModel`** — output container with all the above.

## Ingest pipeline

12 input formats; one ingester each.

| Format             | Module                          | Notes                                                            |
|--------------------|---------------------------------|------------------------------------------------------------------|
| System YAML        | (direct model load)             | Native input; passes through `yaml_autocorrect.py` for synonyms  |
| draw.io / mxGraph  | `ingest/drawio.py`              | 110+ style prefixes + label regex                                |
| Mermaid flowchart  | `ingest/mermaid.py`             | 9 node shapes; subgraph → trust boundary                         |
| Microsoft Visio    | `ingest/vsdx.py`                | Uses `vsdx` lib; stencil-based classification                    |
| MS Threat Modeling | `ingest/tm7.py`                 | TM7 = TM2016 XML; defusedxml parse                               |
| Terraform HCL      | `ingest/terraform.py`           | State / plan JSON or .tf source                                  |
| CloudFormation     | `ingest/cloudformation.py`      | 75 AWS resource types; rejects short-form tags with helper text  |
| Kubernetes         | `ingest/kubernetes.py`          | Multi-doc YAML; Service-selector → workload edges                |
| Bicep / ARM        | `ingest/azure_arm.py`           | DSL + JSON; ~60 resource types                                   |
| Pulumi YAML        | `ingest/pulumi_yaml.py`         | ~80 types across AWS / Azure / GCP / K8s                         |
| Open Threat Model  | `ingest/otm.py`                 | OTM 0.2 spec; round-trip via `reporting/otm_export.py`           |
| docker-compose     | `ingest/docker_compose.py`      | Services + networks                                              |
| (Diagram image)    | `ingest/vision/` (opt-in)       | Anthropic vision; pulls component graph from PNG/JPG             |

`atms scan` is the auto-detect super-command. It dispatches on
file suffix, then for ambiguous `.yaml` / `.json` it content-sniffs
(`AWSTemplateFormatVersion` → CFN; `apiVersion + kind` → K8s;
`runtime: yaml` → Pulumi; `$schema` containing `deploymentTemplate`
→ ARM; `<ThreatModel` → TM7; `otmVersion` → OTM; etc.).

## Engine pipeline (the heart of `workflow.py`)

Order matters — every engine builds on what the prior added.

1. **`engines/ai_scope.py`** — find AI primitives + compute
   blast-radius. Determines which components are "in scope" for
   AI-anchored threats; pure-IT systems short-circuit to general-
   purpose mode.
2. **`engines/boundaries.py`** — infer trust boundaries from
   zone metadata + annotate edges with `crosses_boundary`.
3. **`engines/applicability.py`** — filter playbook threats by
   topology applicability (e.g. multi-agent playbook only fires
   when ≥2 agents are present).
4. **`engines/stride_ai.py`** — per-component playbook fire.
   Loads 121 YAML playbooks; emits 3-13 threats per matched
   component with STRIDE-AI category + framework refs.
5. **`engines/architectural_rules.py`** — 25 topology-pattern
   rules across 6 themes (exposure / auth / secrets / supply-chain
   / operational controls / AI-specific). Emits threats with
   `A_*` ID prefix to distinguish from playbook threats.
6. **`engines/cloud.py`** — cloud-service catalogue enrichment
   (~500 AWS/Azure/GCP services). Tags threats with vendor
   provenance + canonical service IDs.
7. **`engines/attack_paths.py`** — NetworkX traversal across
   the dataflow graph. Honours ATLAS tactic ordering (recon →
   delivery → exploitation → installation → C2 → impact).
   Excludes `A_*` topology-rule threats from path computation.
8. **`engines/kill_chain.py`** — tag every threat with a
   Lockheed Martin Cyber Kill Chain phase.
9. **`engines/mapping.py` + `engines/frameworks.py`** — cross-walk
   each threat to OWASP LLM / Agentic / API, MITRE ATLAS,
   ATT&CK Cloud, ATT&CK Enterprise, OWASP ML 2023, MAESTRO.
10. **`engines/linddun.py`** — privacy threats (14 LINDDUN
    categories).
11. **`engines/maestro.py`** — MAESTRO 7-layer mapping.
12. **`engines/nist_ai_100_2.py`** — NIST AI 100-2 adversarial-ML
    taxonomy (13 entries).
13. **`engines/owasp_ml.py`** — OWASP ML Top 10 (2023) overlay.
14. **`engines/evidence.py`** — overlay VAPT / SARIF / STIX /
    Caldera / Atomic / BAS evidence on top; flip
    `evidence_status` from `hypothetical` → `likely` / `observed`
    / `exploited`.
15. **`engines/controls.py`** — suppress threats covered by
    explicitly declared `Component.controls` (e.g. `mfa_required`,
    `encryption_at_rest`).
16. **`engines/compliance.py`** — map threats to 117 controls
    across 15 frameworks (NIS2, DORA, EU AI Act, GDPR, HIPAA,
    NIST 800-53, NIST CSF, ISO 27001/27017/27018, OWASP MASVS,
    OWASP SAMM, PCI DSS, SEC Cyber, SOC 2).
17. **`engines/risk.py`** — severity rollup + register sort.
18. **`engines/quantitative.py`** — FAIR-lite ALE pricing
    using scale-aware loss priors (industry × revenue × deployment
    stage tier).
19. **`engines/mitigations.py` + `engines/d3fend.py`** — emit
    D3FEND-mapped mitigations with effort + risk-reduction +
    validation-test fields. Cross-walk to AWS SRA / Azure LZA
    reference-architecture patterns via
    `engines/reference_patterns.py`.
20. **`engines/structural.py`** — propose architecture edits
    (insert / split / relocate) where a cluster of threats has a
    single root-cause fix.

The orchestrator is `src/atms/workflow.py:analyze()`. The
declarative stage registry + invariants live in
`src/atms/pipeline.py`.

## Knowledge base (`kb/`)

166 YAML files, all loaded once at startup into `KnowledgeBase`
in `src/atms/kb.py`. **Pickle-cached** since v0.18.47 — 45×
faster cold-start; see `docs/PERFORMANCE.md` for details.

| Path                           | What's there                                          |
|--------------------------------|-------------------------------------------------------|
| `kb/playbooks/`                | 121 per-ComponentType YAML playbooks                  |
| `kb/compliance/controls.yaml`  | 117 controls across 15 frameworks                     |
| `kb/mitre_atlas/`              | 41 techniques + tactics + mitigations                 |
| `kb/mitre_attack_cloud/`       | 33 cloud techniques                                   |
| `kb/mitre_attack_enterprise/`  | 35+ enterprise + ICS techniques                       |
| `kb/owasp_llm/`                | 10 LLM Top 10 2025 entries                            |
| `kb/owasp_agentic/`            | 15 OWASP Agentic AI threats (T1–T15) + 2 ATMS ext                           |
| `kb/owasp_api/`                | 10 OWASP API Top 10 2023                              |
| `kb/owasp_ml/`                 | OWASP ML Top 10 (2023)                                |
| `kb/maestro/`                  | 7 MAESTRO layers + 55 layer/cross-layer threats       |
| `kb/linddun/`                  | 14 LINDDUN privacy categories                         |
| `kb/nist_ai_rmf/` + `nist_ai_100_2/` | NIST AI RMF + AI 100-2 adversarial taxonomy     |
| `kb/csa_singapore/`            | CSA Singapore AI security guidelines                  |
| `kb/devices/catalog.yaml`      | 274-entry vendor/product/version catalog              |
| `kb/cloud_catalog/`            | ~500 AWS / Azure / GCP service definitions            |
| `kb/vendor_threats/`           | 12 vendor overlays (aws_iam, aws_bedrock, etc.)       |
| `kb/d3fend/`                   | MITRE D3FEND mitigation taxonomy                      |
| `kb/priors/loss_priors.yaml`   | Scale-aware FAIR loss-magnitude priors                |
| `kb/reference_patterns/`       | AWS SRA / GenAI Lens / Azure LZA reference patterns   |
| `kb/methodology_provenance.yaml` | Per-STRIDE-row published-framework anchor           |
| `kb/stride_ai_matrix.yaml`     | The 9-row STRIDE-for-AI category definitions          |
| `kb/system.schema.json`        | JSON Schema for System YAML (editor validation)       |

## Reporting (14 modules)

| Module                                | Output                                  |
|---------------------------------------|-----------------------------------------|
| `reporting/markdown.py`               | `.md` full report                       |
| `reporting/html.py`                   | `.html` interactive (heatmap + filter)  |
| `reporting/exec_summary.py`           | `.exec.html` one-page leadership view   |
| `reporting/stix.py`                   | STIX 2.1 bundle                         |
| `reporting/navigator.py`              | MITRE ATT&CK Navigator layer JSON       |
| `reporting/sarif_export.py`           | SARIF (GitHub Advanced Security)        |
| `reporting/otm_export.py`             | OTM round-trip                          |
| `reporting/csv_export.py`             | Risk register + mitigations CSV         |
| `reporting/mermaid.py`                | Mermaid DFD inline in HTML report       |
| `reporting/compliance_matrix.py`      | `.compliance.html` + `.csv` coverage    |
| `reporting/jira_export.py`            | JIRA CSV + REST bulk-create JSON        |
| `reporting/roadmap_export.py`         | Prioritised mitigation roadmap MD + JSON |
| `reporting/sbom_export.py`            | CycloneDX 1.5 SBOM (full 121-ComponentType mapping) |

## Delivery surfaces

### CLI (`src/atms/cli.py`)
28 Click commands. Full reference in `docs/CLI.md`.

### Web UI (`src/atms/web.py`)
32 FastAPI routes. Highlights: `/`, `/editor`, `/report/{run_id}`,
`/attack-paths/{run_id}`, `/compliance`, `/methodology`, `/devices`,
`/samples`, `/playbooks`, `/maestro`, `/agentic`, `/architecture`,
`/diff`, `/capabilities` (live KB inventory).

### REST API
- `POST /api/v1/analyze` — JSON body (System YAML text), JSON response
- `POST /api/v1/scan` — multipart upload of any of 12 formats
- `GET /api/v1/metrics` — KB inventory snapshot
- `GET /healthz` — liveness probe

### MCP server (`src/atms/mcp_server.py`)
Pure-stdlib JSON-RPC 2.0 stdio. 5 tools: `atms_analyze`,
`atms_scan_text`, `atms_search_playbook`, `atms_search_compliance`,
`atms_metrics`. Wire-up in `docs/MCP.md`.

### PyInstaller .exe
Single-file Windows bundle. ~38 MB. `atms.exe version` /
`atms.exe selftest` / `atms.exe web` etc. — full feature parity
with `pip install`. Built via `scripts/build_installer.py`.

## Drift guards (the CI safety net)

- **`scripts/check_architecture_drift.py --strict`** — every
  `src/atms/engines/*.py` must be referenced in
  `src/atms/templates/web/architecture.html`. Forces the live
  diagram to stay in lockstep with the engines.
- **`scripts/gen_palette.py --check`** — the GUI editor's palette
  data must match `models.py:ComponentType`. Prevents the editor
  from offering a type the model doesn't know about.
- **Test-suite floor invariants** — pinned baseline numbers that no
  commit may regress without an explicit roadmap entry recording the
  planned reduction.
- **`tests/test_sbom_export.py:test_sbom_type_map_covers_every_component_type`** —
  Phase 1 invariant: every ComponentType has an explicit
  CycloneDX type mapping (no silent defaults).
- **CI workflow (`.github/workflows/ci.yml`)** — matrix tests on
  ubuntu + windows × py3.11/3.12/3.13, strict ruff, drift guard,
  coverage floor (≥82%).

For the live picture, open `/architecture` in a running web UI or
render `docs/ARCHITECTURE.mmd` in any Mermaid client.
