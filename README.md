# ATMS — AI Threat Modeling Studio

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)

**A local, deterministic, fully-offline tool that analyzes an AI system's architecture and emits only the threats that exist *because of* its AI integration** — mapped to OWASP LLM & Agentic, MITRE ATLAS & ATT&CK, NIST AI RMF, and CSA frameworks.

Point it at a system description (YAML, or one of 13 diagram/IaC formats) and ATMS returns a framework-mapped threat model for your LLM, RAG, or agentic system — **no API key, no LLM, nothing sent over the network.**

**Who it's for:** security engineers, AI/ML platform teams, and threat modelers who need framework-mapped threat models for LLM, RAG, and agentic systems without sending their architecture to an API or running an LLM.

---

## Try it on a sample

ATMS ships with `samples/rag_system.yaml` — a *Customer Support RAG Assistant* (8 components, 11 dataflows, 3 trust boundaries):

```yaml
# samples/rag_system.yaml  (excerpt)
name: Customer Support RAG Assistant
components:
  - id: orch
    name: Support orchestrator (LLM agent)
    type: agent
    trust_zone: corp_dmz
  - id: kb_retriever
    name: Help-center vector retriever
    type: rag_vector_store
  - id: ticket_tool
    name: Ticket-lookup tool
    type: tool
  - id: llm
    name: Claude inference (Sonnet)
    type: llm_inference
dataflows:
  - { source: usr, target: chat_ui, label: question, crosses_boundary: true }
# ...8 components, 11 dataflows, 3 trust boundaries
```

Analyze it:

```bash
atms analyze samples/rag_system.yaml --out output
```

```text
# Illustrative — exact counts are produced by the deterministic engine
# and evolve as the knowledge base changes.
Analyzing: Customer Support RAG Assistant  (methodology=stride-ai)
  components=8  dataflows=11

Analysis complete.
  threats=...  attack_paths=...  mitigations=...
  severity:  critical=...  high=...  medium=...  low=...
  OWASP coverage: .../10  ATLAS techniques referenced: ...

Written:
  output/rag_system.md
  output/rag_system.html
  output/rag_system.stix.json
  output/rag_system.navigator.json
  output/rag_system.risk_register.csv
  output/rag_system.json
  ...
```

You get framework-mapped Markdown + HTML reports, STIX 2.1, ATLAS Navigator, SARIF, OTM, CSV, and a full JSON model — all on your machine. More samples (agentic, fine-tuning, multi-tenant, cloud, and more) live in [`samples/`](samples/).

---

## Install

**Python (clone, requires Python 3.11+):**

```bash
git clone https://github.com/anguiz7z/AITMS
cd AITMS
pip install -e .
```

**Or portable Windows installer (no Python needed):** double-click `dist/ATMS-Setup-1.0.6.exe` _(latest published build; the v1.0.7 installer is to follow)_.

## Quickstart

```bash
atms analyze samples/rag_system.yaml --out output
atms web        # then open http://127.0.0.1:8765
```

`atms web` opens a local UI with a drag-and-drop editor, the bundled samples, and report views.

---

## Features

- **Local, deterministic, fully offline core** — no API key or LLM required for analysis. Reproducible output, no hallucinated technique IDs.
- **AI-scope gate** — rejects pure-IT systems (zero AI components) at load time. For those, use OWASP Threat Dragon / Microsoft TMT / IriusRisk.
- **121 per-component playbooks** at 100% ComponentType coverage — LLM, RAG, agent, tool, MCP, training, fine-tune, plus cloud / IT / OT / identity / security tooling.
- **13 input formats**, auto-detected via `atms scan <file>`, with ingest commands for Visio, draw.io, Mermaid, Terraform, CloudFormation, Kubernetes, Pulumi, docker-compose, and `.tm7`.
- **Rich outputs per run** — Markdown + HTML reports, STIX 2.1, ATLAS Navigator JSON, SARIF, OTM, CSV, and a full JSON model dump.
- **Local web UI** at `http://127.0.0.1:8765` with a drag-and-drop editor, samples, and report views.
- **Deeper analysis** — multi-step attack-path graph, FAIR-lite quantitative risk, and a D3FEND-mapped mitigation roadmap.
- **~1,100 tests**; ships as a pip install from clone or a portable Windows installer.

## Inputs

System YAML (native) · draw.io / mxGraph · Mermaid · Microsoft Visio (`.vsdx`) · Microsoft Threat Modeling Tool (`.tm7`) · Terraform HCL · AWS CloudFormation · Kubernetes manifests · Azure Bicep · Azure ARM JSON · Pulumi YAML / `state.json` · Open Threat Model (OTM) · docker-compose — **13 formats**, auto-detected by `atms scan <file>`.

## Frameworks

OWASP LLM Top 10 (2025) · OWASP Agentic AI / ASI (2025) · MITRE ATLAS · MITRE ATT&CK (Cloud / Enterprise / ICS) · NIST AI RMF (AI 600-1) & NIST AI 100-2 · CSA MAESTRO · Singapore CSA Guidelines — plus **15 compliance frameworks / 117 controls**.

---

## A note on honesty

ATMS is deterministic and needs no LLM/API key to analyze. It evaluates **AI-induced risk only** and rejects pure-IT systems (no AI components) at load time. The threat enumeration is STRIDE applied to AI primitives ("STRIDE for AI") and scoring is Likelihood × Impact, DREAD-derived — there is no published "STRIDE-AI" / "DREAD-AI" standard. Output is **decision-support, not an authoritative assessment** — have a human review it.

## Documentation

- [Getting Started](docs/GETTING-STARTED.md)
- [CLI Reference](docs/CLI.md)
- [Benchmarks](docs/BENCHMARKS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Performance](docs/PERFORMANCE.md)
- [MCP Integration](docs/MCP.md)
- [Coverage](docs/COVERAGE.md)
- [Contributing](docs/CONTRIBUTING.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
