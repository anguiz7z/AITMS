# ATMS contributor role guides

This directory holds a set of **optional, tool-agnostic role guides** for
contributing to ATMS — the AI Threat Modeling Studio. Each guide captures
the responsibilities, file-area ownership, conventions, verification steps,
and known gotchas for one part of the codebase.

They are written to be useful to **anyone** contributing to ATMS: a human
developer, or any AI coding assistant. Nothing here is required to use,
build, or run ATMS. Think of these as focused onboarding notes — read the
one that matches the area you're about to touch.

## How to use them

1. Identify which part of ATMS your change affects (engines, KB, reports,
   CLI, web UI, tests, docs, etc.).
2. Open the matching guide below.
3. Follow its area-of-ownership boundaries, hard rules, and verification
   commands. Each guide ends with a short "what done looks like" checklist.

Each guide is self-contained. If a change spans two areas (for example, a
new ingest format that also needs CLI and web wiring), read both guides and
keep each diff scoped to its area.

## Included roles

| Guide | Area |
|---|---|
| [engine-developer](engine-developer.md) | The analytical core: STRIDE-AI enumeration, ATLAS/MAESTRO enrichment, DREAD-AI scoring, attack paths, boundaries, mitigations (`src/atms/engines/`, `workflow.py`). |
| [applicability-engineer](applicability-engineer.md) | The applicability-predicate engine and the per-threat predicates that gate emission to prevent false positives. |
| [kb-curator](kb-curator.md) | The curated knowledge base: OWASP LLM/Agentic, MITRE ATLAS, MAESTRO, NIST AI RMF, and per-component playbooks (`kb/`). |
| [cloud-catalog-curator](cloud-catalog-curator.md) | The per-vendor cloud-service catalogs (`kb/cloud_catalog/`). |
| [content-validator](content-validator.md) | Read-only audit of threat content against published frameworks for coverage, accuracy, and tuning. |
| [framework-validator](framework-validator.md) | Read-only verification that framework IDs cited in the KB exist in their published catalogues. |
| [reporting-specialist](reporting-specialist.md) | Report renderers and templates: Markdown/HTML, Mermaid DFDs, STIX, ATLAS Navigator, CSV. |
| [ingestion-specialist](ingestion-specialist.md) | Diagram ingestion: the Visio parser and new format adapters (`src/atms/ingest/`). |
| [cli-developer](cli-developer.md) | The Click-based command-line interface (`src/atms/cli.py`). |
| [web-developer](web-developer.md) | The FastAPI web UI, inline templates, and bundled static assets. |
| [test-writer](test-writer.md) | The test suite: unit, integration, CLI, and web end-to-end tests (`tests/`). |
| [security-reviewer](security-reviewer.md) | Read-only security review: deserialisation, path traversal, XSS, secrets, shell injection, AI-dependency leaks. |
| [doc-writer](doc-writer.md) | The repo-root Markdown documentation. |

## Conventions shared across roles

A few principles recur in every guide and are worth stating once:

- **Determinism.** The same input must always produce the same output. No
  randomness, no wall-clock-dependent values. Stable IDs are derived from
  hashes of their seed.
- **Airgap-friendly.** ATMS ships as a self-contained, offline-capable
  distribution. No AI SDK is bundled, and the inline web report references
  only local `/static/` assets — never a CDN.
- **Scoped diffs.** Keep each change inside the area you're working in.
  Cross-area work is split into per-area changes.
- **Verify before claiming done.** Every guide lists the exact test and
  smoke-check commands for its area. Run them.
- **Read-only review roles** (content-validator, framework-validator,
  security-reviewer) find and report issues; they never apply fixes. Fixes
  are handled by the relevant code-owner area.

## License

ATMS is released under Apache-2.0. These guides are part of the project and
share that license.
