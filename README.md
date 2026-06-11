# ATMS — AI Threat Modeling Studio

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)

**A local, deterministic tool that analyzes an AI system's *architecture* and emits the threats that exist *because of* its AI integration** — mapped to OWASP LLM & Agentic, MITRE ATLAS & ATT&CK, NIST AI RMF, and CSA frameworks.

Point it at a structured system description (YAML, or one of 13 diagram/IaC formats) and ATMS returns a framework-mapped threat model for your LLM, RAG, or agentic system. **The analysis engine is fully offline and uses no LLM — deterministic, reproducible, nothing sent over the network.** (Two optional, clearly-separate features do reach out or use a model: `cve-lookup`/feed refresh fetch public CVE/EPSS feeds, and turning a *diagram image* into a model uses a local vision model. Structured inputs need neither. See [Honest scope](#honest-scope).)

It is **decision-support for AI-system design review — not a comprehensive enterprise platform.** It deliberately covers AI-induced risk only and rejects pure-IT systems; pair it with a general threat-modeling tool (Threat Dragon / IriusRisk / ThreatModeler) for non-AI scope.

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

- **Deterministic, fully-offline analysis core** — no API key or LLM in the analysis path. Reproducible output, no hallucinated technique IDs. (Image-diagram ingest and CVE/feed lookups are optional, opt-in, and clearly separate — see Honest scope.)
- **AI-scope gate** — rejects pure-IT systems (zero AI components) at load time. For those, use OWASP Threat Dragon / Microsoft TMT / IriusRisk.
- **121 per-component playbooks** at 100% ComponentType coverage — LLM, RAG, agent, tool, MCP, training, fine-tune, plus cloud / IT / OT / identity / security tooling.
- **13 input formats**, auto-detected via `atms scan <file>`, with ingest commands for Visio, draw.io, Mermaid, Terraform, CloudFormation, Kubernetes, Pulumi, docker-compose, and `.tm7`.
- **Rich outputs per run** — Markdown + HTML reports, STIX 2.1, ATLAS Navigator JSON, SARIF, OTM, CSV, and a full JSON model dump.
- **Local web UI** at `http://127.0.0.1:8765` with a drag-and-drop editor, samples, and report views.
- **Deeper analysis** — multi-step attack paths (causal pre/post-condition derivation, seeded from external entry points), **choke-point ranking** ("fix this component first"), FAIR-lite *indicative* loss ranges, and a D3FEND-mapped mitigation roadmap.
- **CSA-aligned risk + controls** — **CBRA** capabilities-based risk (Criticality × Autonomy × Access × Impact-Radius → Low/Med/High tier) *alongside* the per-threat score, and **AICM** control-domain + shared-responsibility ownership mapping. See [docs/CSA-ALIGNMENT.md](docs/CSA-ALIGNMENT.md) (MAESTRO 6-step crosswalk + citations).
- **Diagram-image ingest** via the `tm-from-image` skill (vision reads the picture → model → deterministic analysis).
- **1,200+ tests** (unit + browser-driven E2E); ships as a `pip install` from clone or a portable Windows installer.

## Inputs

System YAML (native) · draw.io / mxGraph · Mermaid · Microsoft Visio (`.vsdx`) · Microsoft Threat Modeling Tool (`.tm7`) · Terraform HCL · AWS CloudFormation · Kubernetes manifests · Azure Bicep · Azure ARM JSON · Pulumi YAML / `state.json` · Open Threat Model (OTM) · docker-compose — **13 formats**, auto-detected by `atms scan <file>`.

## Frameworks

OWASP LLM Top 10 (2025) · OWASP Agentic AI / ASI (2025) · MITRE ATLAS · MITRE ATT&CK (Cloud / Enterprise / ICS) · NIST AI RMF (AI 600-1) & NIST AI 100-2 · CSA MAESTRO · CSA AICM (v1.0.3) · CSA CBRA · Singapore CSA Guidelines — plus **15 compliance frameworks / 117 controls**.

---

## Honest scope

What ATMS is — and isn't, plainly:

- **Deterministic analysis, no LLM.** The analysis engine maps a system model to framework-tagged threats with rules + a curated knowledge base — no LLM call, reproducible output, no hallucinated IDs. *Two optional features are separate and use the network or a model:* `cve-lookup`/feed refresh fetch public CVE/EPSS/KEV data, and **image-diagram ingest uses a local vision model** (opt-in, off by default — turning a *picture* of an architecture into a model is fundamentally an AI task). Structured inputs (YAML / draw.io / IaC) need neither.
- **AI-induced risk only.** It evaluates threats that exist *because of* the AI integration and rejects pure-IT systems at load time. It is a focused complement to — not a replacement for — general platforms like OWASP Threat Dragon / Microsoft TMT / IriusRisk / ThreatModeler.
- **Methodology.** Threat enumeration is STRIDE applied to AI primitives ("STRIDE for AI"); scoring is Likelihood × Impact (DREAD-derived). There is no published "STRIDE-AI" / "DREAD-AI" standard — these are our extensions.
- **"OWASP coverage X/10" means breadth, not depth** — at least one threat referencing each category, not an exhaustive assessment of it.
- **Attack paths** are multi-step chains derived causally — each edge requires the upstream step's postcondition to satisfy the downstream's precondition, seeded from external entry points. A *heuristic* causal graph (pre/post-conditions inferred from ATLAS tactic + STRIDE category), not a formally verified one.
- **FAIR-lite loss ranges** are indicative, order-of-magnitude estimates from generic priors — for relative prioritization, not authoritative dollar figures.
- **Decision-support, not an authoritative assessment.** A human must review the output.

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
