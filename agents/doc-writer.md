---
role: doc-writer
summary: Owns the repo-root Markdown documentation — README, USAGE, CHANGELOG, BUILDING, CONTRIBUTING, THREAT_MODEL, and AI_DEPENDENCIES.
---

# Documentation writer

This guide covers documentation work on the repo-root Markdown files. Use it
for tasks like "update the README", "add a CHANGELOG entry for the next
release", "document the new `--strict` flag", or "refresh BUILDING.md after
the installer change". It does NOT cover in-code docstrings — those belong
to whichever code-owner area touched the file.

## Area of ownership

Repo-root Markdown:

- `README.md` — project pitch, status, quickstart, structure overview.
- `USAGE.md` — end-user guide; CLI commands, web UI, sample inputs.
- `CHANGELOG.md` — Keep-a-Changelog format; one section per release.
- `BUILDING.md` — how to build the `.exe` and installer.
- `CONTRIBUTING.md` — how to contribute.
- `THREAT_MODEL.md` — ATMS modelling itself; lists `TM_001..TM_010`.
- `AI_DEPENDENCIES.md` — the AI-free contract.
- `LICENSE` (rarely; only if a change is genuinely needed).

In-code docstrings belong to the file's owning area, not here.

## Hard rules

1. **CHANGELOG follows Keep a Changelog format.** Every release gets a
   section: `## [X.Y.Z] - YYYY-MM-DD`. Sub-sections: `### Added`,
   `### Changed`, `### Fixed`, `### Removed`. Newest at the top. Don't break
   the format.

2. **README's status block stays accurate.** The numbers (test count, KB
   sizes, OWASP coverage, MAESTRO layers, sample count, playbook count) must
   match reality. If you change them, verify by running the relevant
   commands. The current release is **1.0.6 (stable)**; quote tests as
   "~1,100 tests (1,387 defined across 114 files; some gate hibernated
   features), ~80% line coverage" and keep it consistent with the top of
   `CHANGELOG.md`. Don't invent precise pass/coverage numbers that will
   drift.

3. **No screenshots in the repo.** The repo is text-only. If a section needs
   visual evidence, link to a public URL or describe it in prose.

4. **The disclaimer stays.** The "ATMS produces decision-support output, not
   authoritative security assessments" note appears in the README and the
   report templates. Don't water it down.

5. **Apache-2.0.** Don't change the license. Don't change the copyright
   header (`Copyright 2026 anguiz7z`).

6. **CONTRIBUTING.md mirrors the actual workflow.** If a step (pre-commit
   hooks, CI) isn't part of the real process, don't claim it is.

7. **Conventional commits.** Document the convention and cite real examples
   from the log.

## Reference facts (keep docs consistent)

- Version: **1.0.6**, a stable release.
- Web-UI default port: **8765**.
- Playbooks: **121** (every `ComponentType` has a playbook).
- Samples: **15** top-level system YAMLs directly under `samples/`, plus an
  IaC starter fleet under `samples/iac/` and a benchmark set under
  `samples/corpus/`.
- Installer artifact: `dist/ATMS-Setup-1.0.6.exe`.
- License: Apache-2.0.

## Verification

```bash
# README claims about test count, KB sizes, etc., are accurate
python -m pytest tests --collect-only -q | tail -5
PYTHONPATH=src python -c "from atms.kb import get_kb; k=get_kb(); print('owasp', len(k.owasp_llm), 'agentic', len(k.owasp_agentic), 'atlas', len(k.atlas_techniques), 'maestro', len(k.maestro_threats), 'playbooks', len(k.playbooks))"
ls samples/*.yaml | wc -l    # top-level sample count
```

If the numbers in your edited README don't match, fix the README, not the
code.

## Style

- Short sentences. Plain English. No marketing-ese.
- Code blocks are fenced with the right language tag.
- Cross-link generously: `[BUILDING.md](BUILDING.md)`, `[USAGE.md](USAGE.md)`.
- A reader who's never seen ATMS should be able to install it from the
  README alone.

## What "done" looks like

- Diff scoped to `*.md` files in the repo root.
- A CHANGELOG entry for any feature or fix that just shipped.
- README "Status" bullets match reality.
- A short note on which docs were touched and anything surprising (e.g. the
  README claimed something the code doesn't do — a finding for the relevant
  code-owner area).
