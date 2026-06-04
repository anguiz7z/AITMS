# ATMS coverage report (historical snapshot — v0.18.52)

> **Historical snapshot.** For the current test count and line-coverage
> figures, see the README headline and CI. The numbers below are a
> point-in-time baseline kept for reference.

Generated 2026-05-16 via:

```bash
pytest -q -m "not slow" -n auto --dist=loadfile --cov --cov-report=term
```

Configuration lives in `pyproject.toml` under `[tool.coverage.run]`
and `[tool.coverage.report]`. Branch coverage is enabled.

## Overall — Phase A lift

| Metric                  | Phase 2 baseline | Phase A (current)  |
|-------------------------|------------------|--------------------|
| Total statements        |            6,860 |              6,904 |
| Statements covered      |    5,883 (82.7%) |      5,869 (85.0%) |
| **Line coverage**       |       **82.7%**  |          **85.0%** |
| Tests passing           |              924 |                995 |
| New tests this phase    |                — |                +53 |

## Phase A floor

**Acceptance for any future commit: total line coverage may not
drop below 85.0%.** CI workflow (`.github/workflows/ci.yml`)
enforces this via `--cov-fail-under=85`. Long-term target remains
90% as documented in `docs/ROADMAP.md`.

## Low-coverage hotspots (Phase 2 → Phase 3 follow-ups)

| Module                                  | Coverage | Statements | Notes                                                          |
|-----------------------------------------|---------:|-----------:|----------------------------------------------------------------|
| `src/atms/feeds/cve_lookup.py`          |    44.8% |        133 | Network-dependent NVD/OSV path; needs mock-based tests         |
| `src/atms/mcp_server.py`                |    47.4% |        203 | New in Cycle GGG; sub-cycles cover initialize / tools/list / metrics — scan_text format-branch arms still untested |
| `src/atms/cli.py`                       |    55.6% |        745 | Many CLI commands exercised via CliRunner; rare flag combos uncovered |
| `src/atms/evidence/stix.py`             |    59.7% |         43 | STIX evidence parser; corpus needs more STIX fixtures          |
| `src/atms/evidence/__init__.py`         |    60.6% |         23 | Evidence orchestrator                                          |
| `src/atms/paths.py`                     |    67.5% |         56 | Frozen-vs-source path resolution; both branches need fixtures  |
| `src/atms/ingest/tm7.py`                |    74.1% |        149 | Cycle EEE; ARM/JSON branch + complex stencil paths             |
| `src/atms/ingest/terraform.py`          |    74.2% |        210 | Many resource-type branches; corpus expansion in Phase 4       |
| `src/atms/evidence/redteam.py`          |    75.6% |        108 | Caldera + Atomic + BAS branches                                |
| `src/atms/engines/applicability.py`     |    75.6% |         71 | Topology-aware filter                                          |
| `src/atms/evidence/csv_parser.py`       |    77.8% |         69 | Header-detection branches                                      |
| `src/atms/ingest/pulumi_yaml.py`        |    77.9% |        158 | Per-cloud resource branches                                    |
| `src/atms/ingest/cloudformation.py`     |    79.4% |        127 | Resource-type branches                                         |
| `src/atms/ingest/otm.py`                |    79.8% |         70 | OTM 0.2 spec corners                                           |
| `src/atms/ingest/vsdx.py`               |    80.1% |        180 | Visio stencil resolution                                       |

## Highest-coverage modules (sanity check)

| Module                                  | Coverage |
|-----------------------------------------|---------:|
| `src/atms/reporting/markdown.py`        | 100.0%   |
| `src/atms/reporting/otm_export.py`      | 100.0%   |
| `src/atms/reporting/sarif_export.py`    | 100.0%   |
| `src/atms/reporting/stix.py`            |  98.2%   |
| `src/atms/reporting/sbom_export.py`     |  95.9%   |
| `src/atms/reporting/roadmap_export.py`  |  95.5%   |
| `src/atms/reporting/navigator.py`       |  95.2%   |
| `src/atms/reporting/mermaid.py`         |  94.2%   |
| `src/atms/workflow.py`                  |  93.9%   |
| `src/atms/web.py`                       |  88.3%   |
| `src/atms/yaml_autocorrect.py`          |  82.5%   |

Reporting layer is genuinely well-tested; ingest is the weakest
tier (corpus expansion in Phase 4 should lift those numbers).

## What's deliberately excluded

`pyproject.toml` `[tool.coverage.run].omit`:

- `src/atms/__main__.py` — `python -m atms` shim, trivially correct
- `src/atms/vision/*` — opt-in anthropic-vision dep, covered by a
  separate optional-suite when installed
- `src/atms/static/*` — vendored JS/CSS, not Python
- `src/atms/templates/*` — Jinja, exercised via the web integration
  tests but not Python-coverage-traceable

## How to regenerate

```bash
cd /path/to/atms
PYTHONPATH=src python -m pytest -q -m "not slow" -n auto --dist=loadfile \
    --cov --cov-report=term --cov-report=json:coverage.json \
    --cov-report=html:htmlcov/
# Open htmlcov/index.html in a browser for line-by-line drill-in.
```

The `coverage.json` artefact is git-ignored (regenerated per run);
the html report goes under `htmlcov/` (also git-ignored).
