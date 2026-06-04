# Contributing

ATMS is a local-first workflow tool. Contributions that broaden coverage of AI threats while keeping the engine deterministic are most welcome.

## Workflow

1. Fork the repo from <https://github.com/anguiz7z/AITMS>.
2. Create a branch: `git checkout -b feat/my-change`.
3. Make changes — code, KB entries, playbooks, samples, docs.
4. Run tests: `PYTHONPATH=src python -m pytest tests -q` — ~1,100 tests
   (1,387 defined; some gate hibernated features), ~80% line coverage.
5. Run selftest: `PYTHONPATH=src python -m atms.cli selftest` — all bundled samples must pass.
6. If your change touches a security-critical contract, also re-read
   [SECURITY.md](SECURITY.md) — the table of contracts there names what
   each load-bearing line is doing.
7. Open a PR with a clear description of what changed and why.

## Conventional commits

Use the prefix `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`. Scope optional but encouraged:

```
feat(playbook): add feature_store component playbook
fix(engines/risk): tighten severity bucket boundaries
docs(usage): add custom-playbook example
```

## Adding a component playbook

```yaml
component_type: <new-type>
description: |
  What this AI component is, with examples.
threats:
  - id: T_<TYPE>_001
    title: <one-line title>
    stride_ai: [Spoofing, Tampering, ...]   # see kb/stride_ai_matrix.yaml
    owasp_llm: [LLMxx:2025]                  # see kb/owasp_llm/
    atlas: [AML.Txxxx]                        # see kb/mitre_atlas/techniques.yaml
    likelihood: 1..5
    impact: 1..5
    description: |
      Detail what the threat is and why it matters.
    mitigations:
      - "Concrete control, ideally specific to this AI threat"
    refs: [AML.Mxxxx]                         # ATLAS Mitigation IDs
```

Then add the new type to the `ComponentType` literal in `src/atms/models.py`. Add tests if behaviour changes.

## Updating ATLAS / OWASP / NIST data

Keep the KB grounded. If you add a technique ID, it must exist in the official ATLAS bundle. If you add an OWASP LLM mitigation, cite the OWASP source. If unsure, leave the entry off.

## DCO

By submitting a contribution you assert that you have the right to license it under Apache 2.0.

## Code style

- Python 3.11+.
- `ruff` for lint, `mypy` is run loose for now.
- Pydantic v2 models — keep them flat, JSON-serialisable.
- Docstrings on every module and every public function. Be terse but complete.
