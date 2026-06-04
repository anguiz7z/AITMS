# AI dependency status

**TL;DR — the shipped ATMS product has zero AI/LLM/network dependencies.**

You can run the installed `.exe` on a fully airgapped Windows machine with no internet, no API keys, and no telemetry. The threat-modelling workflow is deterministic Python over a curated YAML knowledge base.

## What's deterministic

Everything in the default workflow:

- **STRIDE-AI threat enumeration** — playbook lookup over `kb/playbooks/*.yaml`.
- **OWASP LLM Top 10 / OWASP Agentic AI / MAESTRO / MITRE ATLAS / NIST AI RMF mappings** — explicit YAML cross-references in the playbooks; no inference required.
- **DREAD-AI risk scoring** — pure-math heuristic on `likelihood × impact` plus component-type-aware weighting.
- **Attack-path generation** — `NetworkX` graph traversal honouring ATLAS tactic ordering.
- **Trust-boundary inference** — derived from `trust_zone` differences between components.
- **Mitigation roll-up** — KB lookups against ATLAS Mitigations + OWASP LLM mitigations + OWASP Agentic mitigations + inline playbook bullets.
- **Markdown / HTML / STIX 2.1 / ATLAS Navigator / CSV report generation** — Jinja2 templates + stdlib `csv`/`json`.
- **Visio (.vsdx) ingestion** — `vsdx` library (pure-Python OOXML reader) + regex-based shape classification.
- **OTM (Open Threat Model) round-trip** — pure JSON/YAML parsing (added v0.13).
- **Infrastructure-as-Code ingest** — docker-compose YAML parser + regex-based Terraform HCL parser (added v0.14). No `terraform` / `docker` binary required.
- **Evidence ingestion** — Nessus XML / SARIF / STIX 2.1 / generic CSV (added v0.12) plus Caldera JSON / Atomic Red Team / AttackIQ BAS CSV (added v0.14). Pure-Python parsers; no upstream tooling needed.
- **CISA KEV + EPSS scoring** — bundled YAML snapshots loaded at KB-init time. The optional `atms refresh-feeds` and `atms cve-lookup` commands DO reach the network — explicit opt-in, see below.
- **Compliance / D3FEND / NIST AI 100-2 / OWASP ML / LINDDUN catalogues** — all bundled YAML, no inference (added v0.10–v0.14).
- **SARIF + OTM exports** — stdlib JSON; suitable for GitHub code-scanning.
- **Web UI** — FastAPI + Jinja2, serves at `127.0.0.1:8765`. No outbound calls in the default workflow.
- **CLI** — Click + Rich, all local.

None of these touch an LLM. None require network access. None call out to a cloud service.

## What's optional and excluded from the .exe

The single AI-touching file in the source tree:

- **`src/atms/vision/analyzer.py`** — reads an architecture diagram (PNG/JPG) and asks Claude vision to extract a draft System YAML.

Status:

- It has **zero callers** in the default workflow. No CLI command, no web endpoint, no import from any non-vision file.
- It only runs if you call `from atms.vision.analyzer import diagram_to_system_yaml` from your own Python code, AND you `pip install anthropic`, AND you set `ANTHROPIC_API_KEY`.
- The PyInstaller spec excludes `atms.vision`, `atms.vision.analyzer`, `anthropic`, `openai`, `cohere`, `google.generativeai`, `huggingface_hub`, and `transformers`. None of those ship in `dist/atms.exe` or in the installer.
- A check is documented in [BUILDING.md](BUILDING.md) to verify post-build that no AI SDKs are bundled.

## How to verify

After installing the product (or building the .exe):

```powershell
# 1. The installed binary has no anthropic/openai bundled
.\atms.exe selftest                       # all 4 samples pass
& netstat -ano | Select-String "atms"     # only listens locally (when web is running)

# 2. No outbound HTTP calls from the default workflow
& Get-Process atms*                       # while running web, monitor with Sysmon if paranoid
```

You can also point a network monitor (Wireshark, Process Monitor, Fiddler, etc.) at the .exe while it runs every CLI command and the web UI; the deterministic core makes no outbound HTTP calls. The only network listener is the local FastAPI server on `127.0.0.1` when you explicitly run `atms web`.

**Two opt-in CLI commands are exceptions** and they are the only network egress points in the entire shipped product: `atms refresh-feeds` (downloads CISA KEV + FIRST EPSS to update the bundled threat-intel YAML) and `atms cve-lookup` (queries NVD + OSV for a single CVE on demand). Both are explicit user actions; neither runs as part of `analyze`, `selftest`, `ci`, or any default flow. If you want a network-quiet build, do not invoke them.

## Forward compatibility

If a future version of ATMS adds an opt-in AI feature (e.g., "summarise this threat narrative"), the policy is:

1. The feature must be opt-in via flag or env var, never default.
2. The dependency must be optional (`pyproject.toml` extras_require), never a hard requirement.
3. The PyInstaller spec must continue to exclude the SDK from the shipped installer.
4. Any future AI-touching feature must be documented here as an addition, not deleted from this list.

This file is a contract: **the installed ATMS thick client is, and will remain, AI-dependency-free by default**.
