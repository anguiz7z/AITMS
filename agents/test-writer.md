---
role: test-writer
summary: Owns the test suite under tests/ — unit, integration, CLI, and web end-to-end tests, plus regression tests for every bug fix.
---

# Test writer

This guide covers adding or modifying tests in `tests/`. Use it for tasks
like "write a test for X", "add a regression test for the bug we just
fixed", "improve test coverage on engine Y", or "add an end-to-end test
through the web UI". It does NOT cover production-code changes — those
belong to the relevant code-owner area.

## Area of ownership

`tests/*.py`. Existing test modules:

- `tests/conftest.py` — shared fixtures (sys.path patch, web TestClient).
- `tests/test_kb.py` — KB load + search.
- `tests/test_engines.py` — engine functions.
- `tests/test_reporting.py` — Markdown / HTML / STIX / Navigator / CSV.
- `tests/test_web.py` — FastAPI endpoints via TestClient.
- `tests/test_ingest.py` — Visio parser, CLI ingest, web upload.
- `tests/test_boundaries.py` — trust-boundary inference.
- `tests/test_v6_features.py` — Mermaid, mitigation prioritisation,
  `atms diff`, kb-search regression.
- `tests/test_static_and_defensive.py` — bundled Mermaid + defensive init.

## Hard rules

1. **Behaviour, not implementation.** A test that asserts
   `kb._search_cache_size == 1` breaks on every refactor; a test that
   asserts `kb.search('prompt injection')` returns `LLM01:2025` survives
   them. Aim for the latter.

2. **AAA — Arrange / Act / Assert.** Three sections, same convention as the
   existing tests.

3. **Use existing fixtures.** `client_module_scope` for FastAPI tests; the
   `rag_system` / `kb` patterns at the top of each test module. Don't
   re-invent them.

4. **Click commands tested via `CliRunner`; FastAPI routes via
   `TestClient`.** Both run in-process — sub-millisecond per call.

5. **Tests pass deterministically.** No reliance on `time.time()`, no real
   network, no hardcoded paths to a user's home dir. Use `tmp_path` for temp
   files.

6. **One assertion per concept.** Tests should fail with a clear message
   saying which expectation broke.

7. **Regression test for every bug fix.** The standard for a fix is "this
   test would have caught the bug" — your test must demonstrably do that.

## Verification

Run from the repo root:

```bash
python -m pytest tests -q                # the suite passes
python -m pytest tests/<your-file>.py -v # your changes specifically
```

If the default suite is much slower than expected, you've likely added an
expensive test — investigate (probably loading the KB more than necessary).

## When to write what kind of test

- **Pure-function unit test:** any new function in `engines/`. Direct call,
  assert on return value.
- **Integration test:** any new pipeline-level behaviour (a new stage in
  `workflow.py`, a new field on `Threat` propagating through reports). Run
  `analyze()` end-to-end on a sample, then assert.
- **CLI end-to-end:** any new subcommand. `CliRunner().invoke(cli, [...])`
  and assert `result.exit_code` + `result.output`.
- **Web end-to-end:** any new route. `TestClient(app).get/post(...)` and
  assert `r.status_code` + content substrings.

## What "done" looks like

- Diff contained to `tests/`.
- Every new feature lands with at least one test.
- Every bug fix lands with a regression test.
- A short summary of: the test-count delta, what the new tests cover, and
  which existing tests (if any) became redundant.
