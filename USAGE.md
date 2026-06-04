# ATMS — Usage Guide

This is the day-to-day reference. The [README](README.md) covers the pitch.

## 0. Install

```bash
git clone https://github.com/anguiz7z/AITMS
cd AITMS
pip install -r requirements.txt
# OR for editable install with the `atms` script:
pip install -e .
```

If `pip install -e .` is too heavy, just use `PYTHONPATH=src python -m atms.cli ...` — it works the same.

## 1. Bring your own diagram (.vsdx) — optional shortcut

If you already have a Visio diagram of the system, skip the manual YAML:

```bash
# CLI: parse and emit YAML to stdout
atms ingest path/to/diagram.vsdx

# Or write to a file and chain straight into analysis
atms ingest path/to/diagram.vsdx --out my_system.yaml --analyze

# Web: open http://127.0.0.1:8765, upload the .vsdx in the form on the home page,
# review the auto-generated YAML, click Analyze.
```

ATMS reads shape labels and connector lines, classifies each shape into an AI component type using keyword heuristics (LLM / agent / vector store / MCP / training / etc.), and emits a draft `System` YAML. Components it can't classify get `type: other` with a "review needed" notice.

**Limitations.** Legacy binary `.vsd` is not supported — re-save as `.vsdx` in Visio (or LibreOffice Draw → File → Save As) first. Trust boundaries aren't extracted from the diagram (the .vsdx format has no canonical concept of one); add them manually in the resulting YAML before analysis.

**Always review the YAML.** The classifier is heuristic. A box labelled "Service" could be many things; ATMS will guess `external_api` and you may want `mcp_server` or `tool` instead. Open the YAML, fix any `other` types, and add `trust_boundaries:` if your model needs them.

## 2. Describe your system in YAML

Create a YAML document like `samples/rag_system.yaml`:

```yaml
name: My AI System
description: |
  One paragraph describing what this system does.
business_context: |
  Stakeholders, traffic class, regulatory context, blast radius.

components:
  - id: usr
    name: End user
    type: user
    trust_zone: internet
    description: Anonymous web user.

  - id: orch
    name: Orchestrator
    type: agent
    trust_zone: corp_dmz
    description: Tool-using LLM agent.
    metadata:
      tool_count: 3       # used by DREAD-AI heuristics
      multi_tenant: false

  - id: llm
    name: Hosted LLM
    type: llm_inference
    trust_zone: external_provider
    description: Anthropic Claude.

dataflows:
  - source: usr
    target: orch
    label: prompt
    crosses_boundary: true
    data_classification: confidential

trust_boundaries:
  - id: tb_internet
    type: network
    components_inside: [usr]
    components_outside: [orch, llm]
    description: Public internet ↔ corp DMZ.
```

### Component types

ATMS recognises these AI-system component types (matched to per-component playbooks):

```
llm_inference           rag_vector_store        agent           tool
mcp_server              training_pipeline       fine_tuning_pipeline
embedding_service       prompt_template_store   model_registry
guardrails              output_filter           data_source
external_api            user                    other
```

If your component doesn't fit, use `other` and ATMS will emit fallback STRIDE-AI threats with low confidence (0.3) so you can review and customise.

### Dataflows

Each `Dataflow` is directed: `source → target`. Set `crosses_boundary: true` when the flow crosses a trust boundary, and set `data_classification` to one of `public | internal | confidential | restricted`.

### Trust boundaries

Optional but recommended. Help the attack-path engine and reviewer reason about isolation. Types: `network`, `identity`, `data_classification`, `tenancy`, `deployment_zone`.

## 2. Run an analysis

```bash
# All formats to ./output/
PYTHONPATH=src python -m atms.cli analyze samples/rag_system.yaml

# Just Markdown + HTML
PYTHONPATH=src python -m atms.cli analyze my_system.yaml --format md --format html

# Custom output directory
PYTHONPATH=src python -m atms.cli analyze my_system.yaml --out reports/2026-q2/
```

Each run writes:

| File | Use |
|---|---|
| `<name>.md` | Reviewer-friendly Markdown |
| `<name>.html` | Print-ready dark-mode HTML |
| `<name>.stix.json` | STIX 2.1 bundle for SIEM/TIP ingestion |
| `<name>.navigator.json` | ATLAS Navigator layer ([navigator](https://mitre-atlas.github.io/atlas-navigator/)) |
| `<name>.risk_register.csv` | Spreadsheet risk register |
| `<name>.mitigations.csv` | Mitigation matrix |
| `<name>.json` | Full machine-readable model |

## 3. Run the web UI

```bash
PYTHONPATH=src python -m atms.cli web
# default: http://127.0.0.1:8765
```

Pages:

- `/` — paste/edit YAML, click **Analyze**, see the report inline + download buttons.
- `/editor` — graphical DFD editor; drag components, draw dataflows, save back to YAML.
- `/samples` — list and load bundled samples.
- `/kb` — search the knowledge base (ATLAS, OWASP LLM/Agentic/API/ML, MAESTRO, NIST AI RMF, NIST AI 100-2, MITRE ATT&CK Cloud/Enterprise, LINDDUN, compliance, devices).
- `/playbooks` — browse per-component threat catalogues (40 component types).
- `/maestro` — MAESTRO 7-layer browser.
- `/agentic` — OWASP Agentic AI threat browser.
- `/evidence` — VAPT evidence (Nessus / SARIF / STIX / CSV) drag-and-drop ingest.
- `/redteam` — red-team / BAS artefact (Caldera / Atomic / AttackIQ / Cymulate / SafeBreach) ingest.
- `/iac` — Infrastructure-as-Code (docker-compose, Terraform) ingest → ATMS YAML.
- `/compliance` — compliance-control browser (NIS2, DORA, EU AI Act, PCI, HIPAA, SOC2, ISO 27001, FedRAMP).
- `/devices` — device-type catalogue (40 component types, hardening tips).
- `/about` — design-choice reference.
- `/healthz` — liveness probe (returns `{"status":"ok"}`).

The web UI runs on a single Uvicorn worker and stores analysis runs in process memory. Restart loses runs — re-run the analysis.

## 4. Search the knowledge base

```bash
# Across all frameworks
PYTHONPATH=src python -m atms.cli kb-search "prompt injection"

# Only ATLAS
PYTHONPATH=src python -m atms.cli kb-search "model extraction" --framework atlas

# Only OWASP LLM
PYTHONPATH=src python -m atms.cli kb-search "supply chain" --framework owasp
```

## 5. Optional: vision-based diagram parsing

If you have a diagram image and don't want to write YAML by hand:

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...

python -c "
from atms.vision.analyzer import diagram_to_system_yaml
from pathlib import Path
print(diagram_to_system_yaml(Path('my_diagram.png')))
" > my_system.yaml

# Review and edit my_system.yaml, then:
PYTHONPATH=src python -m atms.cli analyze my_system.yaml
```

The vision analyzer asks Claude Opus to extract components, dataflows, and trust boundaries into a YAML document conforming to ATMS's schema. **Always review the output before running analyze** — the model can mislabel component types or miss components.

## 6. Adding a custom playbook

Drop a new YAML file in `kb/playbooks/<your-type>.yaml`. Example:

```yaml
component_type: feature_store
description: |
  Online feature store for ML serving. Includes Feast, Tecton, custom Redis.

threats:
  - id: T_FS_001
    title: Stale features cause prediction drift
    stride_ai: [Tampering, Repudiation]
    owasp_llm: []
    atlas: [AML.T0059]
    likelihood: 3
    impact: 3
    description: |
      Feature pipeline fails silently; serving picks up stale features and predictions degrade.
    mitigations:
      - "Freshness SLOs and alerting per feature"
      - "Canary serving comparing online vs offline distributions"
    refs: []
```

Then add `"feature_store"` to the `ComponentType` literal in `src/atms/models.py`. Tests will keep passing — the engine auto-discovers playbooks from the filesystem.

## 7. Adding a new ATLAS technique or OWASP entry

Edit `kb/mitre_atlas/techniques.yaml` or `kb/owasp_llm/llm_top10_2025.yaml`. Both are flat YAML lists. Add a `keywords:` list for the keyword-enrichment engine to pick up your entry.

## 8. Hardening the tool itself

ATMS is built to be safe-by-default for local use:

- `defusedxml` is a declared dep so future XML parsing (draw.io etc.) is hardened.
- HTML reports use Jinja2 autoescape; user input is escaped before render.
- The `/samples` web endpoint blocks path traversal (only filenames inside `samples/`).
- No user input is written to disk by the web UI.
- Optional vision module never loads unless `ANTHROPIC_API_KEY` is present.

If you expose the web UI beyond `127.0.0.1`, put it behind authentication — there is no built-in auth.

## 9. Troubleshooting

**`No module named 'atms'`** — run with `PYTHONPATH=src python -m atms.cli ...` or install editable: `pip install -e .`.

**YAML parse error** — most often an unquoted colon-after-space inside a `description:`. Wrap the value in `"..."` or use a `|` block scalar.

**Few threats / missing OWASP coverage** — check that every `component.type` matches a known type. Use `atms list-playbooks` to verify.

**Vision module errors** — the optional `anthropic` package is not installed by default. `pip install anthropic` and set `ANTHROPIC_API_KEY`.

## 10. CI

### Test loop (developers)

```bash
python -m pytest tests -v
ruff check src tests
```

The selftest command (`atms selftest`) runs all bundled samples and asserts basic invariants — useful as a smoke gate after KB edits.

### Pipeline gate (`atms ci`) — added v0.13

```bash
# Block the merge if any threat is at severity >= high
atms ci system.yaml --max-severity high --sarif-out atms.sarif

# In GitHub Actions:
#   - Upload atms.sarif via codeql/upload-sarif-action
#   - Non-zero exit code (2) when threats >= threshold survive
```

Pairs with the JSON-Schema at `kb/system.schema.json` for editor validation
during PR review.

## 11. Evidence ingestion — added v0.12

Fuse real findings into the threat model. Every threat carries an
`evidence_status` of `hypothetical | likely | observed | exploited`.

```bash
# VAPT scanner output
atms ingest-evidence findings.nessus system.yaml --out output

# SARIF (CodeQL / Semgrep / Trivy / Snyk / Bandit)
atms ingest-evidence semgrep.sarif system.yaml --out output

# STIX 2.1 threat-intel bundle
atms ingest-evidence ti-bundle.json system.yaml --out output

# Generic CSV with auto-sniffed columns
atms ingest-evidence findings.csv system.yaml --out output
```

CISA KEV CVEs force `severity=critical` and `evidence_status=exploited`.
EPSS scores decorate every evidence row that references a CVE.

### Refresh the bundled threat-intel snapshots

```bash
# Pull live CISA KEV + EPSS top-N (opt-in network — CLI-only)
atms refresh-feeds              # both
atms refresh-feeds --no-epss    # KEV only
atms refresh-feeds --top-n 500  # take more EPSS rows

# Look up a specific CVE on demand (NVD with OSV fallback)
atms cve-lookup CVE-2024-3400
```

Honours `HTTP_PROXY` / `HTTPS_PROXY` env vars. The deterministic core
NEVER reaches the internet on its own; these commands are explicit.

## 12. Red-team / BAS ingestion — added v0.14

Successful red-team chains flip matched threats to
`evidence_status=exploited` + `likelihood=5`.

```bash
# MITRE Caldera operations export
atms ingest-redteam ops.json system.yaml --out output

# Atomic Red Team invocation log (.json or .jsonl)
atms ingest-redteam atomic-log.jsonl system.yaml --out output

# AttackIQ / Cymulate / SafeBreach BAS CSV
atms ingest-redteam scenarios.csv system.yaml --out output
```

Or via the web UI: <http://127.0.0.1:8765/redteam> — drag-and-drop the
artefact + paste the System YAML.

## 13. Infrastructure-as-Code ingestion — added v0.14

Convert your IaC to a draft System YAML.

```bash
# docker-compose
atms ingest-iac docker-compose.yml --out drafted.yaml --analyze

# Terraform — single .tf or whole directory (skips .terraform/ cache)
atms ingest-iac ./infra --out drafted.yaml
atms ingest-iac main.tf --out drafted.yaml
```

Reference samples ship in `samples/iac/`:

- `samples/iac/docker-compose.yml` — RAG stack with Postgres + pgvector + Vault + Ollama.
- `samples/iac/main.tf` — AWS Bedrock+Lambda RAG architecture.

Both are part of the test suite (`tests/test_v14_samples.py`), so future
parser regressions are caught.

## 14. OTM (Open Threat Model) interop — added v0.13

Round-trip with IriusRisk / pyTM / OWASP Threat Dragon:

```bash
# Import: OTM → ATMS System YAML
atms ingest-otm model.json --out system.yaml

# Export: ATMS → OTM JSON (use --format otm with the analyze command)
atms analyze system.yaml --out output --format otm
```

## 15. Compliance + device catalog browse — added v0.13 / v0.11

```bash
# Browse the 10-framework compliance overlay (NIS2 / DORA / EU AI Act / ...)
atms compliance --framework NIS2
atms compliance --query "MFA"

# Browse the 200+ entry device catalog
atms devices --type plc
atms devices --query "Cisco Catalyst"
```

Same data is rendered at `/compliance` and `/devices` in the web UI.

## 16. Methodology selection — added v0.10

```bash
# Default: full pipeline (STRIDE-AI + ATLAS + MAESTRO + … + LINDDUN + NIST AI 100-2)
atms analyze system.yaml --methodology stride-ai

# Privacy-only filter (drops threats without a LINDDUN tag)
atms analyze system.yaml --methodology linddun

# PASTA attacker-simulation lens (keeps threats in attack paths or likelihood >= 4)
atms analyze system.yaml --methodology pasta
```

Same flag accepted on `atms ingest-evidence`, `atms ingest-redteam`,
and the web `/analyze` / `/editor/analyze` / `/evidence/ingest` /
`/redteam/ingest` form fields.

## 17. Compare two analyses — `atms diff`

When you re-analyse a system after fixing some threats, `atms diff` shows
exactly what changed.

```bash
atms diff before.json after.json
# Where before.json / after.json are the analysis JSONs produced by
# `atms analyze --format json` (or read from output/<sample>.json).

atms diff before.json after.json --md report-diff.md   # emit Markdown
```

Output sections:

- **Threats added / removed** — ID + title.
- **Risk-score deltas** — threats whose `risk_score` moved beyond a
  threshold.
- **Severity transitions** — `medium → high`, `high → critical`, etc.
- **Evidence transitions** — `hypothetical → exploited`.
- **Mitigation count delta** — total + per-threat.

Useful in PR review: paste the markdown diff into the description so a
reviewer sees the security impact of the change.

## 18. Fix `other`-typed components after ingest — `atms review`

`atms ingest` (VSDX / drawio) and `atms ingest-iac` (Terraform /
docker-compose) sometimes can't pick a precise type — those components
land as `type: other` in the YAML. `atms review` walks every `other`
component and prompts for the right type, with suggestions.

```bash
atms review system.yaml --in-place   # overwrite in place
atms review system.yaml --out fixed.yaml
```

Press Enter to keep `other` if you genuinely don't know; otherwise pick
from the suggested ATMS component types (40 to choose from, see
`/devices` in the web UI).
