# Contributing to ATMS

The canonical contributor guide lives at the repository root:
[CONTRIBUTING.md](../CONTRIBUTING.md).

Please read that file for the workflow, commit conventions, and the
guides for adding playbooks, compliance frameworks, ingest formats,
export formats, and architectural rules.

## Quick reference

- **Offline-first.** No new runtime dependency without discussion first.
- **No paid runtime APIs.** ATMS runs fully offline with no per-analysis
  cost. The optional vision module (Anthropic) is the only exception and
  is opt-in.
- **Validate twice.** Before pushing, run the suite both sequentially and
  in parallel:

  ```bash
  PYTHONPATH=src python -m pytest -q -m "not slow"
  PYTHONPATH=src python -m pytest -q -m "not slow" -n auto --dist=loadfile
  ```

  The default suite runs ~1,100 tests (1,387 defined; some gate hibernated
  features) at ~80% line coverage. See [COVERAGE.md](COVERAGE.md).
