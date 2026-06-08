# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.7] - 2026-06-08 - Security hardening

Hardening pass from an internal security review. No change to the
offline, deterministic execution model. Windows installer to follow;
`ATMS-Setup-1.0.6.exe` remains the latest published binary.

- Gate MAESTRO / OWASP-Agentic / framework citations on applicability;
  controls- and mTLS-aware architectural rules; proportionate,
  link-scoped evidence escalation; risk_score / severity consistency.
- Deterministic ids and timestamps: hash-seeded ids, sorted iteration,
  SOURCE_DATE_EPOCH-pinnable generated_at, deterministic STIX/SBOM ids.
- Exporter integrity (Jira scaling, Navigator layers, STIX references,
  roadmap labels) and CSV/formula-injection guards; exec-summary and
  CSA register internal consistency.
- Crash-hardened Azure/CloudFormation/Kubernetes/OTM/Mermaid ingest;
  sandboxed web /diff and /methodology paths; YAML alias-bomb rejection;
  HMAC-authenticated KB cache.
- Packaging: resolve bundled KB/samples from wheel shared-data; selftest
  fails loudly on empty corpora.

## [1.0.6] - 2026-06-01 - Post-1.0 refinements

Refinements on top of the v1.0.0 stable base (1.0.1 → 1.0.6):

- Un-hibernated the free / offline feature set (fixes vsdx and IaC uploads).
- Added the CSA Singapore "Table of Attack" threat library and the CSA
  Risk Register (D-E-R / C-I-A, 5×5 bands, 8-element register).
- Extended the taxonomy with STRIDE-LM (added Lateral Movement) for CSA
  alignment, surfaced on the on-screen analysis report.
- Corrected framework citation dates / attribution, added a
  citation-integrity guard, and eliminated indefensible architectural-rule
  false positives.

## [1.0.0] - 2026-05-23 - First stable release

ATMS v1.0 is the focused, shippable product the hibernation + Roadmap
V5 work built toward.

Core promise: give ATMS an AI system architecture (System YAML, a
drawio diagram, or a bundled sample) and get back the threats that
exist because of the AI - mapped to OWASP LLM Top 10, OWASP Agentic,
MITRE ATLAS, MAESTRO, and the Singapore CSA guidelines - as a clean
HTML + Markdown report on the web UI.

Release engineering:
- version -> 1.0.0; dev-status classifier -> Production/Stable.
- Wheel builds + installs into a clean venv; `atms version` + `atms
  selftest` pass at 1.0.0 (`scripts/verify_wheel.py` PASS).
- Project status refreshed; this CHANGELOG was
  rebuilt from the clean pre-V5 base (96161b2) after interrupted edit
  batches corrupted it (duplicate section headers + dropped entries).

Quality bar at release (full audit, all green): **969 default tests /
461 hibernated / 12 slow / selftest pass / ruff clean / KEEP-path
coverage 77.5%.**

Honesty note: Phases 5-7 were first pushed (v0.19.5-v0.19.7) with their
regression nets miscalibrated against wrong reference numbers (CSA
control count, fleet coverage floors, an `atms init` template name, an
import-sort lint) - so those three tagged commits were RED. v1.0.0
corrects all of them to a genuine green audit. The 40 hibernated
capabilities remain in the repo, one env-var flip away
(`ATMS_FEATURE_<NAME>=1`).

## Roadmap V5 - 6 months to v1.0 (polish the narrowed KEEP product)

After the hibernation work (v0.18.68-73) narrowed ATMS to a focused
product, V5 polished the KEEP surfaces toward a shippable v1.0. It did
NOT re-enable hibernated capabilities.

### [0.19.7] - 2026-05-23 - V5 Phase 7: performance & stability floor

Locks KEEP-path performance + concurrency so v1.0 can't regress.
Complements `test_perf_smoke.py`.

- `tests/test_v5_phase7_perf_stability.py` (4 slow tests): 20 parallel
  POST /analyze (10 workers) all return 200 with no shared-state
  corruption and stay independent; analyse + render HTML+MD for
  rag_system under 5s; a 60-component system analyses under 3s. All
  `@pytest.mark.slow` + xdist-skipped (perf-smoke convention).

### [0.19.6] - 2026-05-23 - V5 Phase 6: sample fleet & onboarding contract

First-run experience decides adoption; on inspection it was already
good, so Phase 6 is a regression net (no production change).

- `tests/test_v5_phase6_onboarding.py`: all four `atms init` templates
  (basic / rag / agentic / chatbot) scaffold systems that validate +
  analyse cleanly; init refuses overwrite without `--force`; the
  bundled fleet is large + diverse (>=12 samples, >=25 component types)
  and every sample analyses; every AI sample yields >=1 threat +
  mitigation; `docs/GETTING-STARTED.md` covers the core loop.

### [0.19.5] - 2026-05-23 - V5 Phase 5: KB-depth integrity net

Credibility = the core-promise framework mappings are real and
populated. Probing the KB found it already in good shape, so Phase 5
is a regression net (no content invented; no production change).

- `tests/test_v5_phase5_kb_depth.py`: KB loads >=10 CSA Singapore
  controls (13 present) + >=121 playbooks; every AI-primary playbook
  carries OWASP refs; fleet-level coverage floors per core-promise
  framework (measured across 1040 AI-fleet threats: OWASP LLM 59%,
  OWASP Agentic 32%, MITRE ATLAS 60%, MAESTRO 79%, CSA Singapore 55%);
  every core framework appears on >=1 threat; OWASP LLM refs resolve to
  real KB entries (no dangling ids).

### [0.19.4] - 2026-05-23 - V5 Phase 4: report-quality contract (HTML CSA pill fix)

The report is the deliverable a customer keeps.

- Real fix: the HTML report template (`report.html.j2`) rendered
  per-threat pills for every framework EXCEPT `csa_singapore`, even
  though CSA Singapore is in the core promise and is populated on
  threats (via KB playbook refs). HTML reports silently dropped CSA
  attribution; the Markdown report already rendered it. Added the CSA
  pill (after the NIST AI 100-2 pill).
- `tests/test_v5_phase4_report_quality.py` (all against real analyze()
  output): CSA refs render in HTML + MD; every core-promise framework
  on an agentic sample renders in both formats; all five render across
  the AI fleet's HTML reports; HTML is a well-formed standalone styled
  doc; exec-summary threat count == actual.

### [0.19.3] - 2026-05-23 - V5 Phase 3: web UI demo-surface contract + Phase 2 test fix

Phase 3 locks the web UI (the only shipping delivery surface). On
inspection the surface was already good, so this is a regression net;
no production change.

- `tests/test_v5_phase3_web_polish.py`: KEEP routes populated;
  /samples shows real names + Components column + Load links; styled
  `.alert` / `.alert-error` CSS non-empty; malformed YAML -> HTTP 400
  with a styled error (no 500, no traceback); valid system renders a
  report.
- Also corrected `tests/test_v5_phase2_analyze_robustness.py` to match
  the real contract (web form field is `yaml`; degenerate inputs raise
  clean typed errors rather than "never crash").

### [0.19.2] - 2026-05-23 - V5 Phase 2: analyze-loop robustness net

Pins the analyze loop's behaviour on degenerate inputs + the CLI/web
error paths.

- `tests/test_v5_phase2_analyze_robustness.py`: Hypothesis property
  test over generated valid Systems (analyze never raises); empty /
  dangling-dataflow / duplicate-id / pure-IT inputs rejected with clean
  typed errors; self-loop / cyclic / unicode / 60-component systems
  analyse fine; CLI + web never leak tracebacks or 500s.

### [0.19.1] - 2026-05-23 - V5 Phase 1: KEEP quality floor + report determinism fix

First V5 phase: an honest KEEP-path quality floor + a report
determinism floor. Two real fixes shipped:

- Determinism bug: report artefact IDs used `uuid.uuid4()`, making
  reports non-reproducible. Replaced with content-addressed
  `stable_id()` (SHA-256) at 6 ID sites (`src/atms/engines/_ids.py`).
- KEEP-path coverage measurement via `scripts/keep_coverage.py` (omits
  hibernated modules); `tests/test_v5_phase1_determinism.py` pins
  byte-identical HTML + Markdown across re-analysis.

## Roadmap V4 — Phases J onwards (parser hardening + remaining coverage hotspots)

Continuation of the iterative release pipeline. V1 (Phases 0-6) shipped
the consolidation roadmap; V2 (Phases A-D) targeted coverage hotspots;
V3 (Phases E-I) lifted cli.py + locked perf floors + caught up
documentation. V4 picks the highest-leverage remaining coverage gaps
in the parser tier — not for the coverage number, but because each
uncovered branch is a real defensive guard against parser bugs on
user IaC and on the evidence-ingestion data paths.

### [0.18.73] — 2026-05-23 — Bugfix: KEEP CLI auto-detect crashed on hibernated formats

Audit finding. The hibernation work (v0.18.68-72) gated every parser
entry point to raise `FeatureDisabledError` when its flag is off. The
two KEEP CLI commands auto-detect the input format and dispatch
directly to the matching parser, and neither caught that error:

- `atms scan <file>`   — raw Python traceback on a hibernated format
  (`.tf`, `.mmd`, `.vsdx`, `.bicep`, `.tm7`, `.otm`, CFN/K8s/Pulumi/ARM).
- `atms ingest <file>` — same.

(The web `POST /ingest` route was already graceful: its broad
`except Exception` renders a friendly 400 "Could not parse diagram"
page whose message includes the re-enable hint. A regression test now
locks that against a future 500.)

Fix (error handling only — no parser/flag/behaviour change):
- `src/atms/features.py` — new `graceful_hibernation` decorator:
  converts a `FeatureDisabledError` raised inside a KEEP command into a
  clean `click.UsageError` (exit 2, the canonical re-enable hint, no
  traceback).
- `src/atms/cli.py` — `scan_cmd` and `ingest` now carry
  `@graceful_hibernation`.
- `tests/test_hibernation_keep_dispatch.py` (9 tests) — CLI scan/ingest
  refuse hibernated formats cleanly; KEEP formats (System YAML +
  drawio) still work on CLI + web; web mermaid stays a friendly 400;
  `ATMS_FEATURE_INGEST_*=1` restores the format.

**Tests:** 880 default / 461 hibernated / 8 slow; selftest 11/11; ruff
clean.

### [0.18.67] — 2026-05-23 — Phase S: `atms info` diagnostic command

When a user opens an issue, the maintainer's first question is always
"what's your Python, your ATMS version, are you on the .exe or pip
install, is your KB intact?". Phase S adds a one-shot diagnostic.

- `src/atms/cli.py` — new `info` command:
  - Default: human-readable, lists ATMS version, Python + platform,
    frozen-exe status, and KB counts (playbooks, frameworks,
    controls, architecture rules, component types).
  - `--json`: machine-readable, same fields, suitable for CI logs
    and bug-report templates.
- `tests/test_phase_s_info_command.py` (9 tests): command appears in
  help, version line present, all five KB labels present, Python +
  platform + frozen-exe lines present, `--json` is valid JSON, all
  contract fields exist, KB counts match the v0.18.67 floor (≥121
  playbooks / ≥15 frameworks / ≥117 controls / ≥25 arch rules /
  ≥121 component types), version field matches `atms.__version__`,
  `frozen` is always a real bool.

**Tests:** 1217 → 1226 fast (+ 8 slow = 1234 total).

### [0.18.66] — 2026-05-23 — Phase R: pre-commit hooks

Contributors landing on the project without prior context kept
hitting ruff failures in CI that they could have caught locally —
but there was no `.pre-commit-config.yaml`, so no obvious local gate.
Phase R closes that gap.

- `.pre-commit-config.yaml` — pinned hook set:
  - `pre-commit-hooks v5.0.0` — trailing-whitespace, eof-fixer,
    check-yaml, check-json (excluding the generated
    `docs/system.schema.json`), check-toml, check-merge-conflict,
    check-added-large-files (`--maxkb=500`), mixed-line-ending
    (LF normalization).
  - `ruff-pre-commit v0.8.0` with `--fix` so safe lint issues
    auto-resolve.
  - Local hooks: `palette-drift` (triggers on edits to
    `models.py` / `yaml_autocorrect.py` / `kb/palette_meta.yaml`)
    and `schema-drift` (triggers on edits to `models.py`). Both run
    the existing generator scripts with `--check`.
- `docs/CONTRIBUTING.md` — new "Pre-commit hooks (recommended)"
  subsection in Dev setup with the canonical install command.
- `tests/test_phase_r_precommit.py` (7 tests) — pins the hook set
  so a future "cleanup" can't silently drop a guard.

**Tests:** 1210 → 1217 fast (+ 8 slow = 1225 total).

### [0.18.65] — 2026-05-23 — Phase Q: CI security + schema drift guard

The remaining honest gap after J-P was supply-chain security: 16
dependencies pinned in `pyproject.toml`, zero of them scanned for
known CVEs in CI. Phase Q closes that gap.

- `.github/workflows/ci.yml`:
  - New `security` job — runs `pip-audit` against the installed
    dependency set (runtime + dev extras), cross-referencing the
    Python Packaging Advisory Database + OSV. Non-blocking initially
    (`continue-on-error: true`) so a fresh CVE in a transitive
    doesn't stall unrelated PRs — but still surfaces in the CI
    summary. The flag should be removed once deps stabilise.
  - New step in the `test` job — `python scripts/gen_schema.py
    --check` drift-guards `docs/system.schema.json` (Phase O). Same
    pattern as the existing palette + architecture-diagram guards.
- `tests/test_phase_q_ci_security.py` (9 tests) — pins the CI yaml
  structure so a future "cleanup" can't silently drop any guard:
  - CI yaml parses
  - `security` job exists and references pip-audit
  - `gen_schema.py --check` step present
  - `gen_palette.py --check` step present (Phase 1 regression net)
  - `check_architecture_drift.py` step present (Phase 0 net)
  - `--cov-fail-under=86` floor unchanged (Phase E contract)
  - Python matrix covers 3.11 / 3.12 / 3.13 (matches pyproject)
  - OS matrix includes ubuntu-latest AND windows-latest (the .exe
    build path depends on Windows test coverage)
  - `security` job currently `continue-on-error: true` — documented
    as intentional so a future tightening (remove the flag) is a
    deliberate decision, not a silent drift

**Tests:** 1201 → 1210 fast (+ 8 slow = 1218 total).

### [0.18.64] — 2026-05-23 — Phase P: `atms schema` CLI command

Phase O shipped `docs/system.schema.json` for VSCode pinning. Phase P
adds the first-class CLI surface so the schema is reachable offline
or in scripts without depending on the docs file path.

- `src/atms/cli.py` — new `schema` command:
  - `atms schema` prints JSON to stdout (default indent 2).
  - `atms schema --out PATH` writes to a file with trailing newline.
  - `atms schema --indent 0` produces compact JSON for embedding /
    streaming contexts (no trailing newline in this mode).
  - Generated content matches `docs/system.schema.json` byte-for-byte
    when parsed back to a dict — pinned by `test_schema_cli_output_
    matches_committed_schema_file`.
- `tests/test_phase_p_schema_cli.py` (7 tests): help-text inclusion,
  stdout JSON validity, canonical `$schema` + `$id` URLs present,
  `--out` writes file with trailing newline, `--indent 0` produces
  compact output (no `": "` or `, "` spaces), CLI output matches
  committed file structurally, compact-mode `--out` writes WITHOUT
  trailing newline.
- `README.md` — extended the "Editor autocomplete on system YAML"
  section with the CLI invocations.

**Tests:** 1194 → 1201 fast (+ 8 slow = 1209 total).

### [0.18.63] — 2026-05-23 — Phase O: JSON Schema export for system YAML

ATMS users author `.system.yaml` files by hand. Without a published
JSON Schema, VSCode and other YAML tooling can't offer autocomplete
on `ComponentType` values or validate dataflow shapes. Phase O closes
that gap.

- `docs/system.schema.json` (8.9 KB) — generated from
  `atms.models.System.model_json_schema()`. Declares the canonical
  `$schema` (Draft 2020-12) and `$id` URLs so VSCode + jsonschema
  validators can resolve refs sensibly.
- `scripts/gen_schema.py` — deterministic generator with two modes:
  default writes the file; `--check` exits 1 if the file is stale
  (same drift-guard pattern as `gen_palette.py`).
- `Makefile` — adds `schema` + `schema-check` targets. Updated
  `.PHONY` block.
- `README.md` — documents the canonical schema URL for VSCode users
  to pin in `.vscode/settings.json`.
- `tests/test_phase_o_schema_export.py` (11 tests): file exists, is
  valid JSON, declares `$schema` + `$id`, every runtime
  `ComponentType` value present in the schema enum (the load-bearing
  invariant), `gen_schema.py --check` exits 0 on the committed file,
  required top-level fields present, size in sanity window
  (5KB-64KB), Makefile exposes both targets, generator is
  idempotent, `--check` detects drift when the file is corrupted,
  and the schema validates the bundled `samples/rag_system.yaml`
  (catches the bug where the schema gets too strict).
- `tests/test_phase_n_makefile_surface.py` — `REQUIRED_TARGETS`
  extended with `schema` + `schema-check`.

**Tests:** 1183 → 1194 fast (+ 8 slow = 1202 total).

### [0.18.62] — 2026-05-23 — Phase N: Makefile developer surface

Until v0.18.62, the canonical pytest invocations only lived in
pyproject.toml comments — new contributors had to spelunk to learn
that `pytest -q -m "not slow" -n auto --dist=loadfile` is the parallel
mode. The pre-existing Makefile listed 8 targets, missed the parallel
form, and didn't surface `coverage`, `verify-wheel`, `drift-check`,
or `build-installer`.

- `Makefile` rewritten as a discoverable developer surface:
  - `.DEFAULT_GOAL := help` — bare `make` lists every target.
  - 22 documented targets organised in 7 sections: discovery,
    testing (test / test-parallel / test-all / test-changed),
    coverage (coverage / coverage-ci / coverage-html), lint+typing
    (lint / lint-fix / mypy), CLI shortcuts (selftest / web /
    analyze / version), generated artefacts (palette / palette-check
    / drift-check), build + release (build / verify-wheel /
    build-exe / build-installer), maintenance (install / clean), and
    one aggregate `ci` target.
  - `make ci` runs the same bundle GitHub Actions runs (lint +
    parallel test + coverage-floor + selftest) — guards against the
    two surfaces drifting apart.
- `tests/test_phase_n_makefile_surface.py` (7 tests): every required
  target is present, every annotated target is in `.PHONY` (catches
  name-shadow bugs), the canonical pytest invocations are embedded
  verbatim, `make help` format is grep-friendly with ≥18 documented
  targets, `make analyze SAMPLE=...` usage hint is enforced, `make
  ci` deps cover lint + test-parallel + coverage-ci + selftest.

**Tests:** 1176 → 1183 fast (+ 8 slow = 1191 total). Pure surface
change — no production code change other than the Makefile itself
(which isn't shipped in the wheel).

### [0.18.61] — 2026-05-23 — Phase M: Terraform corpus + aws_elb mapping fix

- `samples/corpus/hashicorp_aws_two_tier.tf` (verbatim from
  `hashicorp/terraform-provider-aws/examples/two-tier/main.tf`,
  MPL-2.0). Closes the IaC corpus to the four major IaC tools:
  CloudFormation (Phase 4), Bicep (Phase D), Kubernetes (Phase 4),
  and now Terraform (Phase M). Terraform is the most-used IaC tool
  in industry — its absence was a real gap.
- `tests/test_cycle_jjj_terraform_corpus.py` (11 tests): file
  provenance (MPL-2.0 SPDX + canonical upstream snippets), 9-resource
  parsing, per-resource type mapping spot-checks, ≥10 reference-edge
  graph, ELB→subnet + ELB→instance + instance→SG edges,
  ≥5 analyse-time threats, vendor=AWS metadata on every component,
  `terraform_default` trust boundary, and SBOM type-map cross-check
  (load_balancer → application).
- **Real parser gap fixed** (surfaced by this corpus): `aws_elb`
  (legacy AWS ELB v1) was missing from `_RESOURCE_MAP` and was being
  silently classified as `other`. Added `"aws_elb": "load_balancer"`
  with a comment pointing back to this Phase M corpus entry. Before
  the fix the open-ingress finding on the HashiCorp sample's ELB SG
  was unobservable; after the fix it surfaces as a regular `T_LB_*`
  playbook threat.
- **Tests:** 1165 → 1176 fast (+ 8 slow = 1184 total). Sequential
  ~29s, parallel still ~17s.

### [0.18.60] — 2026-05-23 — Phase L: Microsoft TM7 parser hardening

- `tests/test_phase_l_tm7_hardening.py` adds 36 tests across the
  Microsoft Threat Modeling Tool (.tm7) ingester. TM7 is the de-facto
  threat-modelling format inside regulated enterprises (banks,
  defense, healthcare) — every uncovered branch was a parser bug
  waiting for a real customer migration.
  - **`_refine_type`** (keyword-based component refinement): all 10
    keyword families now driven — firewall, load balancer (incl. `lb `
    prefix + suffix forms), container/pod/deployment, agent, LLM
    family (gpt/claude/bedrock/openai/anthropic/model), generic
    process fallback; message-queue, stream-processor, KMS family
    (kms/cmk/hsm), cache (redis/memcached/elasticache), NoSQL
    (dynamodb/cosmos/mongo), config/configuration → data_source,
    generic data-store fallback, unknown-default passthrough.
  - **`_sanitise_id`**: non-alphanumeric replacement, empty-name
    fallback, 64-char truncation.
  - **`tm7_to_system` error paths**: no-path-no-text `ValueError`,
    malformed XML `ValueError` with the canonical prefix, wrong root
    element rejection, missing `<DrawingSurfaceList>`, empty surface
    raises `no recognisable elements`.
  - **`tm7_to_system` happy paths**: `BorderBoundary` → TrustBoundary,
    unknown-stencil silently skipped, duplicate-display-name id
    suffixing (User → user / user_2 / user_3), Connector with missing
    Value / missing SourceGuid / unknown-guid target → skipped, `Line`
    xsi:type variant accepted alongside `Connector`, empty-key KVP
    skipped, `text=` default name `tm7-import`, `system_name=`
    override wins, Model-NS Properties block fallback (not Abstract
    NS), path-input default name from file stem.
- **Coverage:** `tm7.py` 74.1% → **97.9%** (29 missed → 1).
  Overall 88.5% → **89.1%**. V4 cumulative (J + K + L): 86.8% →
  89.1%, +2.3 pp project-wide on the line floor.
- **Tests:** 1129 → 1165 fast (+ 8 slow = 1173 total). Sequential
  ~53 s, parallel still ~17 s. Phase L is pure test additions — no
  production code change.

### [0.18.59] — 2026-05-23 — Phase K: Evidence pipeline hardening

- `tests/test_phase_k_evidence_hardening.py` adds 55 tests across all
  four evidence-ingestion modules (the entry points where USER data
  flows into the threat model — every uncovered branch is a parser
  bug waiting for a real customer feed).
  - **`evidence/__init__.py`** (60.6% → **100%**): `parse_any`
    dispatch on `.nessus` / `.sarif` / `.csv` / `.json` (STIX
    sentinel) / `.json` (SARIF fallback); unsupported-extension
    `ValueError` message.
  - **`evidence/stix.py`** (59.7% → **98.5%**): `_severity_from`
    confidence buckets (90/70/40 cutoffs), label fallback paths,
    no-signals→medium default; `parse_stix` for the three top-level
    shapes (`{type:bundle,objects:[]}`, bare list, single object);
    non-dict skip, unknown-type filter, `CVE-*` harvest from
    `external_references`.
  - **`evidence/csv_parser.py`** (77.8% → **100%**):
    `_normalise_severity` over every alias bucket + CVSS-numeric
    (0..10) cutoffs + malformed-numeric fallback; `parse_csv` empty
    file → `[]`, malformed CVSS/EPSS columns default to None,
    semicolon-separated CVE lists; `Synopsis` description alias.
  - **`evidence/redteam.py`** (75.6% → **100%**): `_atomic_severity`
    success/partial/prevented buckets; `parse_caldera` v4 `state`
    semantics vs. v2 `status==0` semantics vs. neither-field
    (assume failure); non-dict op/link skip; no-technique-id branch;
    `parse_atomic_red_team` JSONL multi-record + single-record + empty
    file + non-dict invocation skip; `parse_bas_csv` empty + result-
    derived severity + explicit-severity-wins; `parse_redteam`
    dispatch across .csv/.json + unsupported-extension `ValueError`.
- **Coverage:** overall 87.5% → **88.5%**. V4 cumulative (Phase J +
  K): 86.8% → 88.5%, +1.7 pp on the project-wide line floor.
- **Tests:** 1074 → 1129 fast (+ 8 slow, total 1137). Sequential
  ~53 s, parallel still ~17 s. Phase K is pure test additions — no
  production code change.

### [0.18.58] — 2026-05-23 — Phase J: Terraform parser hardening

- `tests/test_phase_j_terraform_hardening.py` adds 27 tests across
  every uncovered branch of `src/atms/ingest/terraform.py`:
  - **`_mask_strings`** — `<<-EOT` dash-indent, `<<"EOT"` quoted
    marker, empty marker, unterminated heredoc bail, backslash-escape
    inside double-quoted strings.
  - **`_strip_comments`** — same heredoc variants from the comment
    scanner's perspective, plus `/* */` block comments (terminated +
    unterminated), `#` and `//` literals preserved inside strings.
  - **`_read_terraform`** — byte cap truncates directory walk with
    warning log, symlinked `.tf` files dropped, files whose `stat()`
    raises `OSError` skipped (not crashed on), `.terraform`/`.git`/
    `node_modules` vendored dirs are not recursed into.
  - **`parse_terraform`** — HCL pseudo-namespaces (`var`/`local`/
    `data`/`module`/`each`/`count`/`path`/`terraform`/`self`) do not
    fake-look-like cross-resource dataflows; non-AWS/Azure/Google
    vendors get no `vendor` metadata key; unclosed `{` brace blocks
    degrade gracefully (component still surfaces with body-to-EOF).
- **Coverage:** `terraform.py` 74.2% → **97.2%** (48 missed → 2).
  Overall project coverage 86.8% → **87.5%**. The 2 remaining
  uncovered branches in terraform.py (lines 415, 425) are defensive
  guards against impossible states: `_REF_RE` requires the prefix to
  contain `_`, and every value in `_hcl_pseudo` is plain alphanumeric
  — so the `if prefix in _hcl_pseudo: continue` is unreachable given
  the current regex. Documented; intentionally left uncovered.
- **Tests:** 1047 → 1074 fast (+ 8 slow, total 1082). Sequential
  wall-clock ~50 s, parallel ~17 s. Phase J is pure test additions —
  no production code change.

## Roadmap V3 — Phases A through I (post-v0.18.43 audit follow-ups)

Targeted-quality work after the V1 6-month roadmap (Phases 0-6)
shipped. Honest hotspot remediation rather than new feature breadth.

### [0.18.56] — 2026-05-16 — Phases G + H: property tests + perf floor

- **Phase G** — `tests/test_phase_g_property_based.py` adds
  Hypothesis-based property tests for the 4 most-used parsers
  (System YAML round-trip, Pulumi YAML resource graphs, OTM
  round-trip, drawio mxfile). 12 generated cases each. `hypothesis`
  declared as a dev-only optional dep.
- Surfaced + fixed a real bug:
  `src/atms/ingest/drawio.py:drawio_to_system` was `Path`-only,
  crashing on `str` inputs from `tempfile.mkstemp()`. Now accepts
  `str | Path`.
- **Phase H** — `tests/test_phase_h_performance_regression.py`
  pins 4 floor invariants matching the Phase 3 numbers in
  `docs/PERFORMANCE.md`: KB warm load < 1500ms, `analyze()` < 500ms,
  `import atms.cli` < 1500ms, KB cold load < 3000ms. Marked `slow`
  + skipped under xdist (parallel workers race over the on-disk
  pickle cache, invalidating timing assertions).

### [0.18.55] — 2026-05-16 — Phase E: cli.py 55.7% → 72.3% coverage

- `tests/test_cli_phase_e.py` adds 32 CliRunner exercises for the
  long-tail of `cli.py` commands: `refresh-feeds` (mocked network,
  KEV-only, KEV/EPSS failure paths), `cve-lookup` (success / exit-1
  on RuntimeError / ValueError), `list-playbooks`, `kb-search`,
  `compliance` (default / framework filter / empty result),
  `devices`, `review` (no-others + interactive prompt), `validate`
  (all 4 documented exit codes), `init` (basic / rag templates /
  overwrite-refuse / `--force`), `diff` (table / markdown / json /
  disposition-change branch), `ci`.
- Overall coverage 85.1% → 86.7%. CI floor bumped to 86%.

### [0.18.54] — 2026-05-16 — Phases B + C: feeds/refresh 100% + wheel verifier

- **Phase B** — `tests/test_feeds_refresh.py` 10 tests mocking
  `_http_get` to cover the KEV CSV parser (cveID/cveId variants,
  UTF-8 BOM, ransomware flag, non-CVE row filtering) + EPSS JSON
  parser (top-N cap, malformed-score skip, percentile 0-1 → 0-100)
  + `_http_get` itself (URLError → RuntimeError with proxy hint,
  User-Agent carries ATMS version). `feeds/refresh.py` 29.7% → 100%.
- **Phase C** — `scripts/verify_wheel.py` builds the wheel, installs
  into a throwaway venv, runs `atms selftest`. Confirms every
  kb/template/static asset ships in the wheel. Wired into
  `.github/workflows/ci.yml` as the `wheel-verify` job.

### [0.18.53] — 2026-05-16 — Phase D: 4th real-world corpus entry

- `samples/corpus/azure_keyvault.bicep` — pulled verbatim from
  Azure-Samples/azure-quickstart-templates (MIT). Two resources:
  a KeyVault + a child Secret using the Bicep `parent:` modifier.
- `tests/test_cycle_hhh_azure_bicep_corpus.py` — 6 floor asserts:
  provenance check, 2 resources parsed (kv + secret), `parent:` →
  dataflow edge, ≥5 threats produced, ≥1 arch-rule fires, cross-
  check Phase 1 SBOM invariant (secrets_vault → cryptographic-asset).

### [0.18.52] — 2026-05-16 — Phase A: coverage + 2 latent MCP bugs fixed

- **Bug 1** — `atms_scan_text` drawio dispatch imported a
  non-existent `_drawio_text_to_system`; always failed with a
  cryptic ImportError. Replaced with the temp-file path the other
  branches were using.
- **Bug 2** — Windows file-locking: `NamedTemporaryFile(delete=False, mode="w") as t` inside a `with` block kept the file
  write-locked, so downstream parsers opened empty handles. Symptom:
  `"no Resources section found"` on valid CFN input. Refactored to
  `tempfile.mkstemp` + `os.fdopen` + close-then-parse via a
  `_temp_file_dispatch()` helper.
- `tests/test_cycle_ggg_mcp_server.py` +24 tests (47.4% → 92.1%).
- `tests/test_cve_lookup.py` +28 tests mocking urllib (44.8% →
  95.6%).
- Overall coverage 82.7% → 85.0%. CI floor bumped to 85%.

### [0.18.51] — 2026-05-16 — Phase 5: documentation pass

- `docs/GETTING-STARTED.md` — 5-minute walkthrough (install, web
  UI, real-world corpus scan, MCP wire-up into Claude Code).
- `docs/CLI.md` — every CLI command with example invocations
  (top-3 workflows up front: scan / web / watch).
- `docs/CONTRIBUTING.md` — dev setup, 7 house rules (offline-first /
  no paid APIs / no shell-out / system-wide impact analysis /
  validate twice / drift guard / coverage floor), step-by-step for
  adding playbooks / frameworks / ingest formats / export formats /
  arch rules.
- `docs/ARCHITECTURE.md` — prose companion to ARCHITECTURE.mmd.

### [0.18.50] — 2026-05-16 — Phase 4b: AWS Lambda CFN corpus (negative-path)

- `samples/corpus/aws_cfn_lambda_sample.yaml` — Microsoft-published
  AWS sample (MIT-0). Uses short-form CFN intrinsic tags (!Sub,
  !GetAtt, !Ref). Pins the CFN ingester's friendly error contract:
  ATMS rejects with ValueError mentioning both the cause and the
  fix (`aws cloudformation convert-template`).

### [0.18.49] — 2026-05-16 — Phase 4a: Kubernetes Guestbook corpus

- `samples/corpus/k8s_guestbook.yaml` — the canonical multi-tier
  Kubernetes reference architecture (Apache-2.0, k8s.io/docs).
  6 manifests, 3 Service→workload edges inferred, 37 threats, 10
  attack paths, 43 mitigations.

### [0.18.48] — 2026-05-16 — Phase 6: ruff strict + CI coverage gate

- ruff `continue-on-error` removed; lint must pass.
- New CI `coverage` job with `--cov-fail-under` floor.
- 16 real duplicate-key entries removed from `pulumi_yaml._OTM_TYPE_MAP`
  (all dups mapped to the same value — no semantic change).
- ruff `--fix` cleaned 238 import-sort + UTC-modernisation issues.

### [0.18.47] — 2026-05-16 — Phase 3: KB pickle cache (920ms → 21ms)

- `src/atms/kb.py` — pickle cache invalidated by recursive YAML
  content-fingerprint `(file_count, total_bytes, max_mtime)`.
  Atomic-rename writes; self-healing on corrupt cache; version-
  gated (`_CACHE_VERSION = 2`); bypass via `ATMS_KB_NO_CACHE=1`.
- 7 tests for the cache (`tests/test_kb_cache.py`) + 45× speedup
  asserted as a floor.

### [0.18.46] — 2026-05-16 — Phase 2: test honesty + coverage baseline

- Removed 3 dead defensive `pytest.skip()` calls
  (`test_v016_features.py`, `test_jira_export.py`,
  `test_roadmap_export.py`) — all confirmed to never fire in
  practice; now assert their preconditions.
- Removed `--dist=loadfile` from `pyproject.toml` addopts (broke
  sequential runs).
- `docs/COVERAGE.md` published with 82.7% baseline + per-module
  breakdown.

### [0.18.45] — 2026-05-16 — Phase 1: SBOM type map 46 → 121

- `src/atms/reporting/sbom_export.py:_TYPE_MAP` now explicit for
  every one of the 121 ComponentType literals (was 38% covered;
  rest silently defaulted to "application"). 2 floor invariants in
  the test suite ensure no future ComponentType lands without an
  explicit SBOM mapping.

### [0.18.44] — 2026-05-16 — Phase 0: audit + V1 roadmap

- `docs/ARCHITECTURE.mmd` — comprehensive mermaid diagram (14
  subsystems, 12 input formats, 12 ingest modules, 24 engines,
  17 KB modules, 14 reporting modules, 6 evidence parsers).
- `docs/ROADMAP.md` — 6-month consolidation plan.
- Frozen baseline numbers (924 tests,
  18s suite, 19,838 src LOC, 25 arch rules, 11 frameworks, etc.)
  that no future commit may regress without explicit roadmap entry.

## Cycle ZZ → UU (the development sprint, condensed)

### [0.18.43] — 2026-05-16 — Cycle GGG: MCP stdio server

- `src/atms/mcp_server.py` — pure-stdlib JSON-RPC 2.0 stdio server.
  5 tools (`atms_analyze`, `atms_scan_text`, `atms_search_playbook`,
  `atms_search_compliance`, `atms_metrics`).
- `docs/MCP.md` — wire-up example for Claude Code `.mcp.json`.
- 11 tests including subprocess smoke.

### [0.18.42] — 2026-05-16 — Cycle FFF: BENCHMARKS.md + README refresh

- `docs/BENCHMARKS.md` — OWASP Threat Dragon hand-authored (14
  threats) vs ATMS auto-derived (39 threats / 10 paths / 131
  mitigations / 55 framework mappings).

### [0.18.41] — 2026-05-16 — Cycle EEE: Microsoft Threat Modeling Tool ingest

- 12th input format. defusedxml parse of TM7 (TM2016 XML). Stencil-
  shape → ATMS-type mapping. CLI: `atms scan x.tm7` auto-detects.

### [0.18.40] — 2026-05-16 — Cycle DDD: OWASP Threat Dragon corpus benchmark

- First real-world corpus entry. ATMS vs Threat Dragon comparison
  pinned as regression tests.

### [0.18.39] — 2026-05-16 — Cycle CCC: threat-tree SVG on /attack-paths

- Horizontal kill-chain visualisation per attack path, inline SVG,
  no JS dep.

### [0.18.38] — 2026-05-16 — Cycle BBB: pytest --dist=loadfile

- (Later reverted in Phase 2 — see v0.18.46.)

### [0.18.37] — 2026-05-16 — Cycle AAA: Bicep `for` loop + module support

- Closes 2 of the 4 Bicep limitations documented in Cycle DD.

### [0.18.36] — 2026-05-16 — Cycle ZZ: corpus snapshot tests

- Parse-output regression suite for the canonical-sample fleet.

### [0.18.35] — 2026-05-16 — Cycle YY: D3FEND coverage panel

- Per-D3FEND-tactic coverage chart on `/report`.

### [0.18.34] — 2026-05-16 — Cycle XX: Pulumi state.json ingest + AWS CDK detect

- 13th format (Pulumi state JSON). Closes the TypeScript/Python/Go
  Pulumi gap that the YAML ingester explicitly rejected.
- `atms scan` content-sniff also detects AWS CDK synth output
  (CFN templates with the CDK-specific `Metadata.aws:cdk:path`).

### [0.18.33] — 2026-05-16 — Cycle WW: 3 vertical samples

- `samples/healthcare_ehr_fhir.yaml`, `samples/fintech_payment_ledger.yaml`,
  `samples/ot_water_treatment.yaml`. Bring the sample inventory to
  15 systems across 6 industry verticals.

### [0.18.32] — 2026-05-16 — Cycle VV: 4 more compliance frameworks

- OWASP MASVS (mobile), OWASP SAMM, ISO 27017 (cloud), ISO 27018
  (PII in cloud). Brings total to 15 frameworks / 117 controls.

## [0.18.31] — 2026-05-16 — Cycle UU: /capabilities discovery page

20 cycles of feature work need a discovery surface. UU adds
`/capabilities` — a single page that enumerates every input
format, framework, export, arch rule, and endpoint, populated
live from the running KB + arch-rule registry so it can't go
stale.

### Added

- `GET /capabilities` route + `templates/web/capabilities.html`:
  - 9 cards in a responsive grid:
    1. **Input formats** (11) — every ingest format with the
       canonical file suffix.
    2. **Playbooks** ({{playbook count}}) — 100% ComponentType coverage.
    3. **Architectural rules** ({{arch rules}}) — every rule name
       rendered as a hover-titled pill.
    4. **Compliance frameworks** ({{count}}) — every framework as
       a pill, with the underlying control count.
    5. **Threat-intel & AI frameworks** — ATLAS + OWASP LLM +
       Agentic + API counts.
    6. **Device catalog** — vendor / product / version inventory.
    7. **Export formats** (12+) — every artifact `atms analyze`
       can produce.
    8. **REST API** — the 4 programmatic endpoints.
    9. **CLI commands** (20+) — every Click command as a pill.
  - Closing security-posture note documenting the offline-first
    design.

- Nav: new "Capabilities" link in `base.html` so the page is one
  click away from anywhere.

### Tests

  7 new tests in `tests/test_web_capabilities.py`:
    - Route returns 200
    - All major input formats listed
    - All 11 compliance frameworks render as pills
    - Spot-checks for arch rules from each batch (R/BB/RR)
    - Spot-checks for export formats (md / STIX / SARIF / Navigator /
      compliance / JIRA / CycloneDX)
    - All 4 REST endpoints mentioned by path
    - Nav link present on `/` (proves base.html addition propagated)

  Suite: 852 tests passing (was 845, +7), 17.12s wall-clock.

Security: read-only route; inventory derived from in-process KB —
no user input, no filesystem traversal, no network.

## [0.18.30] — 2026-05-16 — Cycle TT: /healthz + /api/v1/metrics endpoints

Production deployments need probes. Cycle TT adds two:
  - `GET /healthz`     liveness/readiness for LBs + k8s
  - `GET /api/v1/metrics` operational counts for dashboards

### Added

- `GET /healthz` — now returns `{"ok": true, "version": "<sem>"}` (was
  plain-text "ok"). Tiny body (<200 B) for high-frequency probes.
  Old plaintext route retired (the new JSON shape is friendlier for
  k8s `livenessProbe` HTTP-success checks that prefer a typed body).
- `GET /api/v1/metrics` — operational metrics:
    `version`, `runs_cached`, `runs_capacity`, and the KB inventory:
      - `playbooks` (now 121 — 100% ComponentType coverage)
      - `compliance_controls` (88 across 11 frameworks)
      - `atlas_techniques` (41)
      - `owasp_llm` (10), `owasp_agentic` (17), `owasp_api` (10)
      - `device_catalog` (274)
    + `arch_rules` count.

  Pin these in a Grafana / Datadog dashboard to confirm the KB
  hasn't drifted post-deployment.

### Tests

  8 new tests in `tests/test_monitoring_endpoints.py`:
    - /healthz returns 200 + ok + version
    - /healthz body is <200 B (probe-friendly)
    - /healthz unauthenticated (no auth header demand)
    - /api/v1/metrics returns kb inventory with floor checks
    - arch_rules count >= 25
    - frameworks list length matches compliance_frameworks
    - runs_cached starts at 0 in a fresh process
    - runs_cached increments after a POST /analyze
  + 1 updated test in `tests/test_web.py` (the legacy plaintext
    healthz test rewritten for the new JSON shape).

  Suite: 845 tests passing (was 837, +8), 17.18s wall-clock.

Security: read-only routes; no user input beyond URL path; no
secrets exposed in the metrics response (just counts).

## [0.18.29] — 2026-05-16 — Cycle SS: CycloneDX SBOM export

US Executive Order 14028 (May 2021) and EU Cyber Resilience Act
Article 13 both require an SBOM as procurement artefact for
software supplied to government / critical-infrastructure
customers. ATMS already inventories every component of a system;
SS turns that into a CycloneDX 1.5 SBOM with one render call.

### Added

- `src/atms/reporting/sbom_export.py`:
  - `render_sbom_cdx(model)` → CycloneDX 1.5 JSON string.
  - Each ATMS `Component` → CycloneDX `component`:
    - `type` mapped via `_TYPE_MAP` (application / data /
      cryptographic-asset / machine-learning-model / device / container).
    - `bom-ref` = ATMS component id (stable across runs).
    - Metadata fields (vendor / product / version / cpe / purl /
      hostname / ip / fqdn) flow into CycloneDX `supplier` /
      `version` / `cpe` / `purl` / `properties`.
  - Dataflows → CycloneDX `dependencies` (source `dependsOn`
    target).
  - Trust boundaries → CycloneDX `services` (logical boundary
    markers).
  - Metadata header includes the ATMS version + ISO-8601 timestamp
    + `urn:uuid:` serial number.

- CLI: `--format sbom` on `atms analyze` AND `atms scan` emits
  `<stem>.sbom.cdx.json`. Auto-included by `--format all`.

- Web: `/download/{run_id}/sbom` with
  `Content-Type: application/json` and `filename=<sys>.sbom.cdx.json`.
  "SBOM (CDX)" button on `/report` actions row, titled with the
  regulatory rationale.

### Tests

  11 new tests in `tests/test_sbom_export.py`:
    - Valid CycloneDX 1.5 JSON envelope
    - Required top-level fields (bomFormat, specVersion, serialNumber, …)
    - Per-component bom-ref matches ATMS id (round-trip stable)
    - `type` mapping correctness (LLM → machine-learning-model,
      DB → data, vault → cryptographic-asset)
    - Vendor / product / version / CPE survive the trip
    - ATMS-specific metadata propagates via CycloneDX `properties`
    - Dataflows correctly become `dependencies`
    - Empty-dataflows system handled gracefully
    - Web route returns correct MIME + filename
    - Report page advertises the SBOM button

  Suite: 837 tests passing (was 826, +11), 26.53s wall-clock.

Compliance / procurement value:
  - NIST SBOM minimum-elements (NTIA 2021) ✓
  - CycloneDX 1.5 spec ✓
  - Ingestible by Dependency-Track, OWASP DT, Syft, Trivy
  - Round-trips ATMS component IDs as bom-ref so external tools
    can correlate findings back to the threat model

Security: pure stdlib (`json`, `uuid`, `datetime`); no new deps;
no network calls; no eval.

## [0.18.28] — 2026-05-16 — Cycle RR: 5 more arch rules (25 total, AI-specific)

ATMS arch rules climbed to 20 in Cycle BB (operational controls).
RR closes the AI-specific gap — the threats every LLM/agent
deployment has but most competitors don't surface as topology
findings. Each rule maps to OWASP LLM Top 10 2025, MITRE ATLAS,
and where relevant the EU AI Act.

### Added — 5 new architectural rules (21-25)

 21. **missing_prompt_injection_guard** (high)
     LLM/agent receives inbound flows but no
     guardrails / content_safety_classifier / output_filter
     component exists, and no `prompt_injection_guard` /
     `guardrails` / `content_safety` control is declared.
     → OWASP LLM01:2025, MITRE-ATLAS-AML.T0051.
 22. **missing_pii_redaction_at_llm_boundary** (high)
     Sensitive datastore → LLM edge with no redaction hint
     (redact / scrub / mask / sanitise / DLP / tokenise) AND no
     `dlp` component in the system.
     → OWASP LLM06:2025, GDPR Art. 32.
 23. **missing_model_provenance** (medium)
     `model_registry` present but neither the registry nor any
     consuming LLM declares a provenance / signing control
     (sigstore / cosign / SLSA / SBOM / model_card).
     → MITRE-ATLAS-AML.T0010 (Supply-Chain Compromise: Model).
 24. **unbounded_agent_tool_access** (medium)
     `agent` with > 5 distinct `tool` / `mcp_server` /
     `external_api` targets and no `tool_access_control` /
     `function_call_allowlist` / `least_privilege_agent` control.
     → OWASP LLM08:2025, OWASP-AGT:AGT06.
 25. **missing_human_oversight_high_risk** (high)
     System flagged `is_high_risk_under_eu_ai_act=True`, contains
     AI components, but no `user` component sits downstream
     (directly or 1 hop) of the AI outputs.
     → EU AI Act Art. 14, NIST AI RMF GOVERN-4.1.

### Tests

  14 new tests in `tests/test_architectural_rules.py`:
    - 3 per rule (positive fire + 2 suppression paths) for 21-24
    - 2 for rule 25 (high-risk-but-no-user fires; user-downstream suppresses)
    - 1 negative (not-high-risk default doesn't fire rule 25)
    - registry-count test updated 20 → 25

  Suite: 826 tests passing (was 812, +14), 25.08s wall-clock.

### Architecture diagram

  `eng_arch_rules` description bumped from "20 rules across 5
  themes" to "25 rules across 6 themes"; new sixth theme called
  out with each rule's published-framework anchor; drift guard
  green.

Security: pure-engine addition; no new deps; no network calls.
Each rule respects the existing `controls` vocabulary so users
can declare out-of-band mitigations and silence the rule.

## [0.18.27] — 2026-05-16 — Cycle QQ: dedicated /attack-paths page

The main /report page lists attack paths near the bottom as a
collapsed text block. Reviewers asked for a focused page where
every multi-step kill chain has its full narrative expanded and
the tactics traversed are visualised as a flow. QQ delivers it.

### Added

- `GET /attack-paths/{run_id}` route that fetches the cached
  ThreatModel from `_RUNS` and renders a dedicated view.
- `src/atms/templates/web/attack_paths.html`:
  - Each path is a card with:
    - ID + title + impact / difficulty chips (5-dot bars)
    - Tactics traversed as a horizontal `→` flow with named steps
    - Components traversed listed as code-fenced chain
    - Full narrative in a preformatted block
    - Per-step threat pills coloured by severity
  - Sorted by `(business_impact desc, estimated_difficulty asc)`
    so the highest-impact, easiest-to-exploit paths appear first.
  - Empty state when no multi-step paths exist.
- "Attack paths" button added to the /report actions row.

### Tests

  7 new tests in `tests/test_web_attack_paths.py`:
    - Route returns 200 for known run_id; 404 for unknown
    - Page inherits base.html nav + heading
    - Empty state renders without 500 when no paths exist
    - Impact/Difficulty chip headings present
    - /report has the "Attack paths" button + link
    - Tactics flow rendered with `→` separator when present

  Suite: 812 tests passing (was 805, +7), 18.13s wall-clock.

Security: read-only route, no user input beyond the path
parameter. The run_id is validated against `_RUNS`, which is
an in-memory `OrderedDict` capped at 32 entries — no path
traversal, no DB.

## [0.18.26] — 2026-05-16 — Cycle PP: REST `/api/v1/scan` for non-YAML inputs

Pairs with `/api/v1/analyze` (Cycle KK). Same JSON-out shape but
accepts MULTIPART file uploads in any of the 11 supported formats.
CI/CD pipelines can now POST a `.drawio` / `.bicep` / `Pulumi.yaml`
/ `.tf` / CFN / K8s / etc. and receive the analysis JSON back —
no two-step ingest + analyze needed.

### Added

  POST `/api/v1/scan` (multipart):
    `file:`            uploaded artefact
    `format:`          "auto" (default) or one of:
                         drawio · mermaid · vsdx · terraform ·
                         bicep · arm · pulumi · cloudformation ·
                         kubernetes · docker-compose · otm · system-yaml
    `methodology:`     stride-ai (default) · linddun · pasta
    `allow_pure_it:`   "true" (default) · "false"

  Returns the standard analysis envelope plus a `detected_format`
  field showing which ingester actually ran (the auto-detect
  result, useful for CI logs).

### Auto-detection mirrors the CLI's `atms scan`:
  - `.drawio` / `.xml` → drawio
  - `.mmd` / `.mermaid` / `.md` → mermaid
  - `.vsdx` → vsdx
  - `.tf` → terraform
  - `.bicep` → bicep
  - `.otm` → otm
  - `.yaml` / `.json` content-sniff:
      AWSTemplateFormatVersion → cloudformation
      apiVersion + kind → kubernetes
      otmVersion → otm
      $schema=deploymentTemplate → arm
      runtime: yaml or aws:|azure-native:|gcp:|kubernetes: → pulumi
      services + version (no name) → docker-compose
      else → system-yaml

### Error handling

  - Unsupported explicit `format` → 400
  - Unknown file suffix with `format=auto` → 400 with hint
  - Unsupported methodology → 400
  - Ingest exception → 400 (`f"ingest failed ({fmt}): {exc}"`)
  - Analyse exception → 500

### Tests

  12 new tests in `tests/test_api_scan.py`:
    - 7 format auto-detect happy paths (drawio / mermaid / bicep /
      pulumi / cloudformation / kubernetes / system-yaml)
    - Explicit format override bypasses auto-detect
    - Unsupported explicit format → 400
    - Unknown suffix + format=auto → 400
    - Invalid methodology → 400
    - Response shape matches `/api/v1/analyze` + `detected_format`

  Suite: 805 tests passing (was 793, +12), 17.35s wall-clock.

Security: each upload lands in a `NamedTemporaryFile`, parsed by
the same ingesters the CLI uses, then unlinked in a `finally`
block. No retained temp files. JSON-out only; no echoing of
filename or content into HTML.

## [0.18.25] — 2026-05-16 — Cycle OO: print-friendly CSS (browser → PDF)

Users have been asking for PDF export. `WeasyPrint` is already an
optional dep, but installing it on Windows is fragile (C library
chain). OO solves the same problem the other way: a high-quality
`@media print` stylesheet so every browser's built-in "Save as
PDF" produces a clean, light-themed, chrome-free PDF — no server
dep, no installation cost.

### Added

`src/atms/templates/web/base.html` — new `@media print` block:
  - Forces light theme (`--bg: #ffffff`, dark text) — auditors
    read PDFs on paper / shared screens, not OLED dark mode.
  - Hides chrome: top nav, footer, action buttons, threat-table
    filter input + severity chips, palette search.
  - Tables: `page-break-inside: avoid` on `<tr>` so rows aren't
    split across pages; thead repeats on page breaks.
  - Severity chips: filled-colour → outlined so monochrome
    printers (and most office printers) preserve the hierarchy.
  - Risk heatmap: cell colours → border colours; counts remain.
  - External `http(s)` links append `(URL)` after the link text
    so paper readers can transcribe references.
  - Internal `/download/...` links suppressed (no point printing
    "download me" URLs on a static doc).
  - Mermaid block: shrinks to 9px, page-break-avoid so the DFD
    stays together.
  - Details/summary blocks expanded so attack-path narratives
    render fully on print.

### Tests

  6 new tests in `tests/test_web_print_css.py`:
    - `@media print` block present on every rendered page
    - Hides nav / actions / threat-filter
    - Forces light theme (`--bg: #ffffff`)
    - Outlines severity chips (`border: 1px solid #000`)
    - Heatmap print-style rules present
    - Table row break prevention (`page-break-inside`)

  Suite: 793 tests passing (was 787, +6), 17.13s wall-clock.

Workflow: open any `/report` page → File → Print → "Save as PDF".
Result: ~5-7 pages of clean B&W-safe analysis, no installation
required, no shell-out, no headless browser to manage.

Security: pure-CSS change; no runtime impact; no network calls.

## [0.18.24] — 2026-05-16 — Cycle NN: SOC 2 Trust Services Criteria

ATMS already shipped 10 compliance frameworks (NIS2, DORA, EU AI
Act, GDPR, PCI DSS, HIPAA, NIST 800-53, NIST CSF, ISO 27001, SEC
cyber). SOC 2 is the framework every B2B SaaS sells against —
glaringly missing from a tool that markets itself as auditor-
friendly. NN closes the gap.

### Added — 26 SOC 2 controls in `kb/compliance/controls.yaml`

  - **Common Criteria (CC)**: CC1.1, CC2.1, CC3.2, CC4.1, CC5.1,
    CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC6.8,
    CC7.1, CC7.2, CC7.3, CC8.1, CC9.1
  - **Availability (A1)**: A1.1 capacity, A1.2 backup + DR,
    A1.3 recovery testing
  - **Confidentiality (C1)**: C1.1 identification, C1.2 disposal
  - **Processing Integrity (PI1)**: PI1.1 objectives, PI1.4 quality checks
  - **Privacy (P*)**: P1.1 notice, P4.2 purpose limitation,
    P6.3 third-party disclosure

  Each control includes a `framework: SOC2`, `applies_to`
  (component types), `keywords` (substring matches against threat
  titles + descriptions), and a one-sentence `description` quoted
  from the TSC 2017 framework text.

Frameworks now bundled: **11** total (was 10):
  NIS2 · DORA · EU AI Act · GDPR · PCI DSS · HIPAA ·
  NIST 800-53 · NIST CSF · ISO 27001 · SEC Cyber · **SOC 2**

Compliance KB control count: 62 → 88 (+26).

### Tests

  6 new tests in `tests/test_soc2_controls.py`:
    - ≥25 SOC2 controls load
    - All 5 trust principles (CC / A / C / PI / P) represented
    - Every SOC2 entry has required fields
    - SOC 2 rows appear in `compute_coverage()` output
    - SOC 2 appears in `coverage_summary().frameworks` breakdown
    - CC6.1 (access control) is in-scope (not "n/a") on a
      system with mfa_service + identity_provider components

  Suite: 787 tests passing (was 781, +6), 16.73s wall-clock.

Security: pure KB-data addition. No runtime changes.

## [0.18.23] — 2026-05-16 — Cycle MM: mitigation roadmap export

The HTML report already shows a priority-ranked roadmap, but it's
locked inside the report. Cycle MM exposes it as a standalone
artefact for project planning workflows.

### Added

- `src/atms/reporting/roadmap_export.py`:
  - `render_roadmap_md(model, top_n=None)` — Markdown with one
    `- [ ]` checkbox per task. Grouped by `control_family`,
    headlined with effort + risk-reduction + threat count +
    top-severity badge. Validation tests, D3FEND tags, framework
    refs, and addressed-threat IDs all surfaced inline.
  - `render_roadmap_json(model, top_n=None)` — JSON `{system, tasks}`
    array suitable for piping into ticket-creation scripts.
    Per-task fields: rank, mitigation_id, title, family, effort,
    risk_reduction, automatable, d3fend, validation_test,
    addresses_threats, frameworks, top_addressed_severity,
    addressed_severities (per-bucket counts), ai_relevance.

- CLI: `--format roadmap` on `atms analyze` AND `atms scan`
  emits `<stem>.roadmap.md` + `<stem>.roadmap.json`. Auto-included
  by `--format all`.

- Web: `/download/{run_id}/roadmap_md` + `/download/{run_id}/roadmap_json`.
  Buttons added to the /report actions row.

### Tests

  11 new tests in `tests/test_roadmap_export.py`:
    - Markdown structure: H1 / checkboxes / family grouping
    - validation_test surfaced when present
    - top_n caps output
    - JSON structure: `{system, tasks}` envelope
    - Task field completeness (all 12 keys)
    - Rank sequence is 1..N
    - Web routes return correct MIME + attachment filename
    - Report page advertises both new buttons

  Suite: 781 tests passing (was 770, +11), 17.12s wall-clock.

Security: pure stdlib (no template engine; Markdown is hand-
formatted; JSON via `json.dumps`). No new deps; no network.

## [0.18.22] — 2026-05-16 — Cycle LL: `atms watch` mode (live re-analyse)

Developer-UX cycle. Adds a polling watcher that re-runs analysis
whenever the System YAML changes on disk, and prints the
threat-count + severity delta. Useful when iterating on a model:
edit, save, see the impact within seconds.

### Added

- `compute_run_delta(prev_model, new_model)` — pure function
  in `src/atms/cli.py` that returns:
    - threats_prev / threats_now counts
    - added_ids / removed_ids
    - severity_changed (list of `{id, from, to}`)
    - severity_breakdown_prev / _now / _delta

  Factored out of the watch loop so it's directly unit-testable
  without spinning up a real file-watch loop.

- `atms watch <yaml> [--interval=2.0] [--methodology stride-ai]`
  CLI command that:
    1. Stats the file every `--interval` seconds.
    2. When `mtime` advances, re-runs `analyze`.
    3. Prints a one-line delta plus the new severity breakdown.
    4. Up to 5 most recent severity-shift events listed per cycle.
    5. Survives YAML parse errors gracefully — bad edits don't
       crash the loop (catches both Exception and SystemExit).
    6. Stops on Ctrl-C with a clean "stopped" line.
- Hidden `--max-iters N` flag for testing (lets the loop exit
  cleanly after N polls).

### Tests

  8 new tests in `tests/test_cli_watch.py`:
    - `compute_run_delta` pure-function correctness:
      - first run (prev=None) treats every threat as added
      - identical models produce zero changes
      - adding a component (with edge to AI core) yields new threats
      - removing a component drops its threats
      - severity_breakdown sums match threats_now
    - CLI:
      - `--max-iters 2` runs and exits cleanly
      - file change between iters produces a `threats:` line
      - bad YAML logs an error but the loop keeps going

  Suite: 770 tests passing (was 762, +8), 17.03s wall-clock.

Security: no new deps; uses `pathlib.Path.stat()` + `time.sleep`.
The loop reads but never writes the watched file.

## [0.18.21] — 2026-05-16 — Cycle KK: REST API for analyse (CI/CD-friendly)

The CLI was the only programmatic surface. Cycle KK adds
`POST /api/v1/analyze` — JSON in, JSON out — so CI/CD pipelines
can drop a `curl | jq` call inline without parsing HTML or
shelling out to the CLI.

### Added

- `POST /api/v1/analyze` accepting JSON body:
    ```
    {
      "yaml": "<System YAML text>",
      "methodology": "stride-ai" | "linddun" | "pasta",  // optional
      "allow_pure_it": true,                              // optional
      "include_compliance_matrix": false,                 // optional
      "include_jira_payload": false                       // optional
    }
    ```
  returning:
    ```
    {
      "ok": true,
      "version": "0.18.21",
      "summary": { ...workflow summary... },
      "model": { ...ThreatModel.model_dump()... },
      "compliance_matrix": [...]   // when requested
      "jira": {"issueUpdates":[...]} // when requested
    }
    ```

- Validation errors return `400` with a JSON `detail` message:
    - missing / empty `yaml` field
    - invalid YAML syntax
    - YAML root not a mapping
    - System schema validation failure
    - unsupported methodology

- The returned `model` is bit-for-bit equivalent to
  `ThreatModel.model_dump_json()`; Pydantic can re-validate it
  losslessly (tested).

### Tests

  13 new tests in `tests/test_api_analyze.py`:
    - Happy path returns full ThreatModel JSON
    - Every ThreatModel top-level field present
    - Threat objects carry required fields (id/title/severity/L/I/component)
    - Missing / empty / non-mapping / invalid YAML → 400
    - Unknown methodology → 400 with helpful detail
    - LINDDUN methodology supported
    - `include_compliance_matrix` opt-in (default off)
    - `include_jira_payload` opt-in (default off)
    - Returned JSON round-trips through `ThreatModel.model_validate`

  Suite: 762 tests passing (was 749, +13), 15.71s wall-clock.

Security: same parsing path as `/analyze` (POST form) but JSON-
typed. `dict` body argument is JSON-only — no multipart, no
file uploads, no path traversal. Same `_METHODOLOGY_ALLOWLIST`
gate; same Pydantic validation; no `eval`, no shell-out.

## [0.18.20] — 2026-05-16 — Cycle JJ: filterable threat table on /report

The threat table on a /report page can have 100+ rows after a
real analysis. Cycle JJ adds a live substring filter + severity
quick-chips so reviewers can drill in fast. Pure inline JS, no
external deps; behaviour survives offline export of the report.

### Added

- Filter input above the threats table — case-insensitive
  substring match against every visible cell (ID / Component /
  Title / Severity / Risk / Status / Evidence pills / Kill chain /
  every framework reference pill).
- 4 severity quick-chips (critical / high / medium / low) —
  toggleable; multiple can be active at once; OR'd together.
- "Showing N of M" status text appears when a filter is active.
- `Escape` clears the filter. `×` clear-button also resets chips.
- Filter behaviour debounced at 120 ms — feels live without
  thrashing the DOM on every keystroke.

### Tests

  5 new tests in `tests/test_web_threat_filter.py`:
    - Filter input element exists with the expected ID
    - All 4 severity chips render with correct `data-severity`
    - Every threat row carries a `data-severity` attribute
    - Filter JS is present + inline (no `<script src=...>`)
    - Esc-clear handler is wired

  Suite: 749 tests passing (was 744, +5), 15.64s wall-clock.

Security: pure-template change; no new runtime deps, no network.
The IIFE is self-contained and uses only DOM standard APIs.

## [0.18.19] — 2026-05-16 — Cycle II: canonical sample fleet (6 new demos)

Every ATMS input format now ships with a working canonical demo
in `samples/iac/`. Closes the "no working starter file" gap that
existed for every ingest format added after `terraform.tf` and
`docker-compose.yml`. Parameterised round-trip tests guarantee
the demos stay parseable as ingest modules evolve.

### Added

  | Format        | File                                | Resources |
  | ------------- | ----------------------------------- | --------: |
  | draw.io       | `samples/iac/webapp.drawio`         |     ≥ 8 |
  | Mermaid       | `samples/iac/rag_pipeline.mmd`      |     ≥ 8 |
  | CloudFormation | `samples/iac/eks_microservices.cfn.yaml` |    ≥ 8 |
  | Kubernetes    | `samples/iac/k8s_microservices.yaml` |     ≥ 5 |
  | Azure Bicep   | `samples/iac/aoai_rag.bicep`        |    ≥ 10 |
  | Pulumi YAML   | `samples/iac/multi_cloud.pulumi.yaml` |   ≥ 10 |

Each sample is built to exercise the engine: real cross-references,
trust boundaries (VPC / VNet / Network), and a mix of compute /
storage / identity / secrets / observability components so the
playbooks + arch rules + compliance enricher all have something to
do.

### Tests

  - `tests/test_sample_fleet.py` (7 tests): parameterised round-
    trip through ingest + `analyze()` for every canonical sample,
    asserting ≥ component-count and ≥ threat-count floors.
  - A meta-test (`test_every_sample_file_is_in_the_parametrize_list`)
    fails when a new sample lands in `samples/iac/` without being
    wired into the round-trip suite — prevents drift.

  Suite: 744 tests passing (was 737, +7), 14.91s wall-clock.

Security: pure static fixture data; no runtime impact.

## [0.18.18] — 2026-05-16 — Cycle HH: Pulumi YAML ingest (11th input format)

Completes the IaC trifecta started by `cloudformation.py` (Cycle T)
and `azure_arm.py` (Cycle DD). Pulumi YAML is the declarative
dialect Pulumi ships as `runtime: yaml`; it maps cleanly to cloud
resources without requiring code execution.

### Added

- `src/atms/ingest/pulumi_yaml.py`: pure stdlib + PyYAML parser.
  Walks every `resources.<sym>` entry, maps `<provider>:<module>:<Type>`
  → ATMS component type. Pulumi template strings `${name.attr}` are
  collected recursively from `properties` / `options` / `get` and
  become `references` dataflows. VPC / VNet / GCP Network become
  `TrustBoundary("network")`.

- `_RESOURCE_MAP` covers ~80 types across:
    - **AWS**: S3 / Lambda / API Gateway / DynamoDB / RDS / Redshift /
      EKS / EC2 / VPC / SecurityGroup / KMS / SecretsManager / SNS /
      SQS / Bedrock / SageMaker / WAFv2 / GuardDuty / SecurityHub /
      CloudWatch Logs / Cognito.
    - **Azure (azure-native)**: Storage / WebApp / App Service Plan /
      SQL / Cosmos / Postgres / MySQL / Cache / KeyVault / Cognitive
      Services / ML workspaces / AKS / ACI / VNet / NSG / App Gateway /
      API Management / Log Analytics / App Insights / Logic Apps /
      Event Hub / Service Bus.
    - **GCP**: GCS / Cloud Functions v1+v2 / Cloud Run / Compute /
      Network / Firewall / GKE / Firestore / BigQuery / Pub/Sub /
      Secret Manager / KMS / AI Platform / Cloud SQL / Redis / API
      Gateway / DLP.
    - **Kubernetes (Pulumi-style)**: Deployment / StatefulSet /
      DaemonSet / Job / CronJob / Service / Ingress / Secret /
      ConfigMap / PVC / NetworkPolicy.

- CLI: `atms ingest-pulumi <path> [--out] [--name] [--analyze]`.
- `atms scan` auto-routes `.yaml` files with `runtime: yaml` or
  Pulumi-namespaced types (`aws:`, `azure-native:`, `gcp:`,
  `kubernetes:`).

### Limitations (documented for users)

  - Pulumi TypeScript / Python / Go programs are NOT supported.
    Reading them would require code execution — explicit security
    policy rejects this. Users can:
      - run `pulumi convert --language yaml` to produce parseable YAML
      - run `pulumi stack export` and parse the resulting JSON manually
  - `${name.attr}` references where `name` doesn't match a declared
    resource are silently dropped (no warning yet).

### Tests

  17 new tests in `tests/test_pulumi_yaml_ingest.py` + 1 in
  `tests/test_cli_scan.py`:
    - AWS / Azure / GCP / Kubernetes type-map coverage
    - Template-ref → dataflow conversion
    - Dataflow deduplication (multiple `.id`/`.arn`/`.name` refs collapse)
    - Trust boundary creation for VPC / VNet
    - Unknown-type fallback to `"other"`
    - Empty / invalid YAML rejection with helpful errors
    - Stack-name extraction from YAML `name:` field
    - System-name CLI override
    - `path=` vs `text=` arg both work
    - TypeScript Pulumi rejected with hint
    - `atms scan` content-sniffs Pulumi YAML correctly

  Suite: 737 tests passing (was 719, +18), 15.35s wall-clock.

### Architecture diagram

  New `i_pulumi` node added under the input column; drift guard green.

Security: zero new runtime deps; pure stdlib + already-bundled PyYAML.
No `eval`, no shell-out, no network. The TypeScript/Python/Go opt-out
is deliberate — code execution is a non-starter under this project's
security policy.

## [0.18.17] — 2026-05-16 — Cycle GG: JIRA-formatted backlog export

Closes the "how do these threats get into the engineering backlog"
gap. Adds JIRA-importable CSV + JIRA REST `issue/bulk` JSON so
security findings flow directly into JIRA without manual re-entry.

### Added

- `src/atms/reporting/jira_export.py`:
  - `render_jira_csv(model)` — Atlassian-compatible CSV with
    columns: Summary / Description / Issue Type / Priority /
    Status / Component/s / Labels / External ID.
  - `render_jira_json(model, project_key="SEC")` — REST API
    `{"issueUpdates": [{"fields": {...}}]}` bulk-create payload
    for `POST /rest/api/3/issue/bulk`.

- Severity → JIRA Priority mapping:
    critical → Highest, high → High, medium → Medium,
    low → Low, info → Lowest
- Disposition → JIRA Status mapping:
    open → Open, mitigated → Done,
    accepted / transferred / accepted_with_compensating_control → Won't Do,
    false_positive / duplicate → Closed, deferred → Backlog
- Label generation:
    `atms-threat` (constant marker for JQL discoverability),
    `severity:<bucket>`, `framework:<id>` (per reference),
    `stride:<row>`, `kill-chain:<phase>`.

- CLI: `--format jira` on `atms analyze` AND `atms scan`
  emits `<stem>.jira.csv` + `<stem>.jira.json`. Auto-included
  by `--format all`.

- Web: `/download/{run_id}/jira_csv` + `/download/{run_id}/jira_json`
  with correct MIME types + attachment headers. New "JIRA CSV"
  and "JIRA JSON" buttons in the report actions row.

### Description body

  Each issue's Description carries the threat narrative plus
  recommended mitigations, framework references, risk score
  (L × I), kill-chain phase, AI-relevance flag, and the original
  ATMS threat ID for traceback.

### Tests

  16 new tests in `tests/test_jira_export.py`:
    - CSV header order + one-row-per-threat invariant
    - Priority + Issue Type + External ID mapping correctness
    - `atms-threat` + `severity:<bucket>` labels always present
    - Summary truncation at 250 chars (JIRA cap is 255)
    - JSON payload structure (`issueUpdates` array, `fields`
      sub-object, project key, Issue Type=Risk)
    - Custom project key parameter honoured
    - Labels emitted as JSON array (not string) — JIRA REST contract
    - No whitespace in any generated label
    - Web routes return correct MIME + attachment filename

  Suite: 719 tests passing (was 703, +16), 14.79s wall-clock.

Security: zero new runtime deps; export is fully offline; no
network calls. Users feed the JSON to their own `curl`/CI tooling.

## [0.18.16] — 2026-05-16 — Cycle FF: web compliance-matrix download

Wires the v0.18.15 compliance matrix into the web report flow.
Every analyse run now auto-caches a compliance HTML + CSV
artefact; the `/report` page surfaces both as download buttons.
Mirrors the v0.18.11 Cycle AA pattern for exec-summary.

### Added

- `_store_run()` extended to render `compliance` (HTML) +
  `compliance_csv` for every cached model.
- `/download/{run_id}/compliance` returns the HTML matrix with
  `Content-Disposition: attachment; filename="<sys>.compliance.html"`.
- `/download/{run_id}/compliance_csv` returns the CSV with
  `Content-Type: text/csv` and `filename="<sys>.compliance.csv"`.
- New "Compliance matrix" + "Compliance CSV" buttons in the
  `/report` actions row.

### Tests

  4 new tests in `tests/test_web_compliance.py`:
    - Report page advertises both buttons.
    - HTML download returns a self-contained matrix doc.
    - CSV download returns a CSV with the expected header + MIME.
    - Unknown run-id 404s.

  Suite: 703 tests passing (was 699, +4), 14.37s wall-clock.

Security: no new network calls; reuses Cycle EE's escaped renderer.

## [0.18.15] — 2026-05-16 — Cycle EE: compliance coverage matrix export

Inverts the threat → control mapping into a control → threats view.
Every auditor-quoted compliance discussion uses this shape:
"show me coverage of NIST 800-53 AC-3" / "which ISO 27001 A.9.4.2
controls are missing" — and the data was already inside the model
(threats are tagged with `compliance_controls` by the existing
compliance enricher). This cycle exposes it as a self-contained
HTML + CSV artefact.

### Added

- `src/atms/reporting/compliance_matrix.py`:
  - `compute_coverage(model, framework=None)` → rows with status
    (`covered` / `mitigated` / `uncovered` / `not-applicable`),
    threat count, top severity, supporting threat IDs, supporting
    mitigation IDs, and applies_to scope.
  - `coverage_summary(rows)` → totals + per-framework breakdown.
  - `render_compliance_matrix_html(model, framework=None)` →
    self-contained HTML (no JS, no external CSS) with summary
    cards, legend, and the coverage table. XSS-safe (every user-
    derived string flows through `_esc`).
  - `render_compliance_matrix_csv(model, framework=None)` →
    auditor-friendly spreadsheet export.
- CLI: `--format compliance` (on `atms analyze` AND `atms scan`)
  produces `<stem>.compliance.html` + `<stem>.compliance.csv`.
- `--format all` now includes `compliance` so users opting into the
  full report bundle get the matrix automatically.

### Status semantics

  - **covered** — ≥1 in-scope threat references the control AND
    at least one is open (or in a non-closing disposition).
  - **mitigated** — ≥1 covered threat AND every covered threat is
    in a closing disposition (`mitigated` / `accepted_with_compensating_control`
    / `transferred` / `false_positive` / `duplicate`).
  - **uncovered** — 0 threats reference the control but `applies_to`
    overlaps a component type in the system. The honest gap.
  - **not-applicable** — 0 threats AND `applies_to` does not overlap.
    Informational, not a finding. Keeps the matrix from flooding
    auditors with frameworks that don't apply.

### Tests

  13 new tests in `tests/test_compliance_matrix.py` covering:
    - Framework filtering (rows only have the requested framework)
    - Status validity (every row in the 4-value enum)
    - Sort order (covered/mitigated above uncovered above n.a.)
    - In-scope vs not-applicable discrimination
    - Summary totals (4 statuses add up to total)
    - HTML structure (self-contained, no script/link tags)
    - HTML escape on user-derived strings (XSS protection)
    - CSV structure (header + per-row consistency)
    - Empty-filter behaviour (unknown framework → 0 rows)

  Suite: 699 tests passing (was 686, +13), 14.20s wall-clock.

Security: pure-stdlib + the existing `kb` module; zero new deps.
All HTML output escaped via `_esc`; CSV output via Python's
built-in `csv.writer` (handles quoting correctly).

## [0.18.14] — 2026-05-16 — Cycle DD: Azure Bicep + ARM template ingest (10th input format)

Adds Azure-side IaC ingest parity with the existing CloudFormation
support (Cycle T) and Terraform (`ingest-iac`). Auto-detects Bicep
DSL vs ARM JSON template via `$schema` content sniffing.

### Added

- `src/atms/ingest/azure_arm.py` — pure-stdlib + regex parser for:
    - **Bicep DSL** (`.bicep`) — strips line + block comments, finds
      every `resource SYM 'TYPE@VER' = {…}` block via brace
      matching, infers references from `<symbolic>.id` /
      `<symbolic>.properties.x` / `parent: <sym>` patterns.
      `Microsoft.Web/sites` is refined to `serverless_function`
      when `kind: 'functionapp'`.
    - **ARM JSON templates** — walks `resources[]` recursively
      (nested children supported), reads `dependsOn` for edges,
      requires a `$schema` claiming `deploymentTemplate` to
      reject random JSON.
- `_RESOURCE_MAP` (~60 entries): VMs / VMSS / Container Apps / AKS /
  ACI / ACR / App Service / Function Apps / SQL / Cosmos / MySQL /
  Postgres / Redis / Service Bus / Event Hub / Event Grid /
  SignalR / VNet / NSG / App Gateway / Front Door / Private Link /
  VPN Gateway / API Management / DNS / Bastion / KeyVault / AAD DS /
  Managed Identity / Log Analytics / App Insights / Action Groups /
  Sentinel onboarding / IoT Security / Cognitive Services (AOAI) /
  AML workspaces + endpoints / AI Search / Logic Apps /
  App Configuration / IoT Hub / DPS / FHIR.
- `Microsoft.Network/virtualNetworks` become `TrustBoundary("network")`.
- CLI command `atms ingest-azure <path> [--out] [--name] [--analyze]`
  mirrors `ingest-cfn` / `ingest-k8s`.
- `atms scan` auto-detects `.bicep` via suffix, and ARM JSON via
  `$schema=deploymentTemplate.json` content sniffing.

### Tests

  16 azure_arm-specific tests + 2 scan-routing tests:
    - Bicep DSL: resource detection, kind-based refinement,
      comment stripping (line + block), friendly-name extraction,
      `existing` keyword, conditional `if(...)`, unknown-type
      fallback, empty-file rejection, dedup'd edges.
    - ARM JSON: basic resources, schema-required rejection, empty
      resources rejection, nested children with kind refinement.
    - Auto-dispatch: DSL routes to bicep_to_system, JSON routes
      to arm_template_to_system.

  Suite: 686 tests passing (was 668, +18), 14.37s wall-clock.

### Architecture diagram

  New `i_azure_arm` node added under the input column; drift guard
  green; template + docs copy byte-identical.

### Limitations (documented for users)

  - Bicep `for` loops (resource fan-out): the looped resource is
    emitted once with the symbolic name; fan-out is not modeled.
  - Bicep `module foo 'bar.bicep' = {}` references: ignored. Users
    needing whole-project analysis should pre-compile via
    `bicep build *.bicep` and feed the resulting ARM JSON.
  - Conditional resources `if(...)`: always emitted regardless of
    the condition.

Security: zero new runtime deps; no `eval`, no shell-out, no
network. Bicep is a closed grammar so regex parsing is reasonable.

## [0.18.13] — 2026-05-16 — Cycle CC: Risk heatmap on the web report

Adds a 5×5 likelihood × impact heatmap above the architecture
diagram on every `/report` page. Each threat is bucketed by its
`(likelihood, impact)` integer pair (clamped 1..5). The cell colour
reflects the risk zone (`risk = L × I`: ≥20 critical, ≥12 high,
≥6 medium, else low). Cell tooltips list up to 12 threat IDs +
titles per bucket. Pure HTML + CSS — no JS, no SVG library, no
external dependencies.

### Added

- New heatmap block in `src/atms/templates/web/report.html`,
  inserted between the Severity row and the DFD section. Skipped
  silently when the threats list is empty (clean-system reports).
- CSS grid + zone colour-classes live inline in the template so
  the block remains self-contained for offline `/download/{id}/html`
  exports.
- 4 regression tests in `tests/test_web_heatmap.py` cover: section
  presence, no-JS guarantee, all 4 zone classes used, threat IDs
  appearing in tooltips.

### Tests

  Suite: 668 tests passing (was 664, +4), 19.23s wall-clock.

Security: pure-template change; no new runtime deps; no new
network or filesystem activity.

## [0.18.12] — 2026-05-16 — Cycle BB: 5 more arch rules (20 total, operational controls)

Continues the topology-rule expansion theme from Cycles R/V/Y with a
fifth theme: **operational security controls** — the day-2 controls
auditors and SOCs expect to see. Each rule is anchored to a named
NIST SP 800-53 control AND an ISO/IEC 27001 Annex A control so the
findings translate directly to compliance language.

Security note: research was read-only (NIST SP 800-53 Rev 5 control
catalog already in the project, ISO 27001 Annex A control names from
existing kb/frameworks). No new runtime deps; the implementation is
pure stdlib.

### Added — 5 new architectural rules (16-20)

 16. **missing_centralized_logging** (medium)
     ≥3 workloads in scope but no SIEM / log_aggregator /
     security_data_lake / observability_stack. Maps to NIST AU-2 /
     AU-6 and ISO A.12.4.1. Fires once per workload; suppressed if
     every workload declares a logging/audit control.
 17. **missing_backup_for_critical_data** (medium → high in prod)
     Sensitive datastore (DB / NoSQL / warehouse / lake / object /
     block / file storage) with no backup_service component AND no
     backup-labeled outbound dataflow AND no backup-related control.
     Maps to NIST CP-9 and ISO A.12.3.1. Severity escalates to
     `high` when `deployment_stage=production`.
 18. **missing_intrusion_detection** (medium)
     ≥3 workloads in production/pilot but no ids_ips / edr_agent /
     container_security / casb / dlp component. SIEM alone counts
     as passive logging; SI-4 requires active detection. Maps to
     NIST SI-4 and ISO A.13.1.1.
 19. **mfa_not_enforced** (high)
     user → (identity_provider / sso_service / ciam_platform /
     directory_service) edge with no MFA signal anywhere: no
     mfa_service component, no MFA hint in the edge label, no
     `mfa_required` control on the backend. Maps to NIST IA-2(1),
     NIST SP 800-63B §5.1, ISO A.9.4.2, OWASP A07:2021.
 20. **data_at_rest_unencrypted** (medium → high for sensitive)
     Sensitive datastore with no encryption-at-rest evidence:
     description / controls / metadata lack encryption / KMS / TDE /
     CMK hints AND no edge to kms_key / hsm. Maps to NIST SC-28 and
     ISO A.10.1.1. Severity `high` for database / NoSQL / data
     warehouse / secrets vault; `medium` for bulk object storage.

### Tests

  +20 tests in `tests/test_architectural_rules.py` (1 positive + 2-3
  suppression cases per rule). Existing `test_no_arch_threats_on_clean_topology`
  fixture extended to include backup_service / kms_key / mfa_service /
  edr / siem and encryption_at_rest controls so the baseline still
  produces ≤ 2 arch findings on a truly clean system.

  Suite: 664 tests passing (was 644), 18.86s wall-clock.

### Architecture diagram

  `eng_arch_rules` description bumped from "15 rules across 4 themes"
  to "20 rules across 5 themes"; new fifth theme called out with each
  rule's NIST anchor.

## [0.18.11] — 2026-05-16 — Cycle AA: web exec-summary view + download link

The CLI exec-summary feature (Cycle Z) is now reachable from the web
report page. Every analyse run caches an exec.html and the report
page surfaces a `/download/{run_id}/exec` button.

## [0.18.7] — 2026-05-15 — More arch rules + Kubernetes ingest (8 input formats)

Two cycles building on v0.18.5: doubling architectural rule coverage
and adding the 8th input format (Kubernetes manifests).

Security note: research for Cycle V was read-only (WebFetch on
Threagile public docs; MIT-license-compatible for clean-room
reimpl). No new runtime deps; both modules are pure stdlib +
already-bundled PyYAML.

### Added — Cycle V: 4 more architectural rules (10 total)

  7. **unencrypted_communication** (high)
     Cross-boundary dataflow with no encryption hint
     (tls/https/ssl/mtls/encrypted/vpn) in the label.
  8. **missing_authentication** (medium → high without IdP)
     Sensitive receiver has inbound edges where no auth signal
     (token/oauth/oidc/saml/jwt/mfa/sso/bearer/apikey) appears.
  9. **logs_capture_secrets** (medium)
     Secret-bearing source → logging sink without redaction hint.
 10. **unrestricted_external_egress** (low)
     Non-gateway workload with >2 outbound edges to external_api / user.

### Added — Cycle W: Kubernetes manifests ingest

`src/atms/ingest/kubernetes.py` parses multi-document Kubernetes YAML
(Helm output, `kubectl get all -o yaml`, single manifest files) into
structured ATMS Systems.

  Workload kinds   Deployment / StatefulSet / DaemonSet / Pod /
                    ReplicaSet / Job / CronJob → container_runtime / batch_compute
  Network          Service / Ingress / NetworkPolicy / Gateway / HTTPRoute
  Identity         ServiceAccount / Role(Binding) / ClusterRole(Binding)
  Storage          PersistentVolume / PersistentVolumeClaim / StorageClass
  Config           ConfigMap / Secret

Dataflow inference:
  - Service.spec.selector → matching workload labels
  - Ingress.spec.rules.backend.service.name → Service
  - Workload pod-template → Secret/ConfigMap/PVC references
    (envFrom, env.valueFrom, volumes)

Namespaces become tenancy trust boundaries.

CLI: `atms ingest-k8s manifest.yaml [--out system.yaml] [--analyze]`.

### Fixed

- Architectural-rule threats (id prefix `A_*`) are now EXCLUDED from
  `find_attack_paths` — they're topology findings, not chain nodes.
  Including them shifted path selection and broke the PASTA-lens
  invariant ("threats survive PASTA only if in-path OR L≥4 OR
  high/critical"). Fix: filter out `.A_` ids before running
  `find_attack_paths` (both initial + PASTA-rebuild calls).

### Architecture diagram

Updated: new `i_cfn` + `i_k8s` input nodes. Diagram drift guard
green (21 engines × template == docs copy).

### Tests

- **611 passing** (was 586, +25 across the 2 cycles).
- Selftest 12/12.

### Commits

| Cycle | Commit | Theme |
|---|---|---|
| V | 75a4728 | +4 architectural rules (10 total) |
| W | (this commit) | Kubernetes manifests ingest |

---

## [0.18.5] — 2026-05-15 — Architectural rules + CloudFormation + confidence pills

Three post-pivot cycles (R, S, T) that close major gaps surfaced by
the v0.18.5 read-only research pass (Threagile rule patterns +
GitHub prior art). Security note: research used only WebFetch on
public docs; no clones, no pip installs, no script execution. New
code is clean-room re-implementation in ATMS's own style.

### Added — Cycle R: architectural-pattern rule engine

The biggest comprehensiveness win of the v0.18.x line. Per-component
playbooks catch threats inherent to one component type; topology
threats emerge from how components are ARRANGED. New
`src/atms/engines/architectural_rules.py` ships 6 starter rules:

  - **unguarded_access_from_internet** (high → critical for data stores)
  - **missing_waf** (high)
  - **unguarded_direct_datastore_access** (high)
  - **missing_vault** (medium)
  - **missing_network_segmentation** (medium)
  - **orphan_secrets_vault** (low)

Pattern from Threagile (MIT) reimplemented in ATMS's own dataclass
style. Rules get id prefix `A_*` to avoid collision with playbook
`T_*` ids. Failure-tolerant: a buggy rule logs + skips, doesn't
crash the engine.

Selftest threat counts rose across the board after this cycle:
  aws_bedrock_agent: 106 → 109
  azure_openai_rag: 95 → 102
  enterprise_rag_agent: 84 → 89
  it_ot_factory: 68 → 72
  rag_system: 46 → 50

### Added — Cycle T: AWS CloudFormation YAML/JSON ingest (75 resource types)

Pairs with the existing Terraform IaC parser. `atms ingest-cfn
template.yaml` produces a draft System YAML. 75 AWS resource types
mapped (compute, storage, DB, network, identity, observability,
security, AI/ML). Refs / Fn::GetAtt / Fn::Sub / DependsOn become
dataflows; VPC + Subnet refs become TrustBoundaries. Short-form
intrinsic tags surface a friendly "convert to long-form" error.

### Added — Cycle S: classification-confidence pills in HTML report

Components from drawio/mermaid/cloudformation/vsdx ingest carry
`metadata.source` indicating HOW they were classified. The HTML
report's component headers now render a coloured pill:

  - **stencil** (green) — drawio matched an AWS/Azure/GCP stencil
  - **shape**   (green) — mermaid strong-shape semantic (cylinder/circle/…)
  - **label**   (amber) — label-regex match, medium confidence
  - **fallback** (red ⚠) — fell through to `other`, review needed

Hand-written YAML systems show no pills (metadata.source unset).

### Architecture diagram

Updated: new `eng_arch_rules` node in the engines column. Diagram
drift guard happy (21 engines referenced; template == docs copy).

### Tests

- **586 passing** (was 527, +59 across the 3 cycles).
- Selftest 12/12.
- Diagram-drift + palette-drift guards both green.

### Commits

| Cycle | Commit | Theme |
|---|---|---|
| S | 39216d0 | classification confidence pills |
| T | (cycle T commit) | CloudFormation ingest |
| R | (cycle R commit) | architectural rule engine |

---

## [0.18.2] — 2026-05-15 — Mermaid ingest + one-click auto-analyze

Two post-v0.18.0 cycles. The pivot was already shipped; this is
two user-asked-for follow-ons.

### Added — Cycle P: Mermaid flowchart ingest (7th input format)

`src/atms/ingest/mermaid.py` parses Mermaid `flowchart` / `graph`
source into structured System YAML. Common in markdown docs +
GitHub READMEs.

Coverage:
- 9 shape variants (rect / round / circle / cylinder / hexagon /
  parallelogram / trapezoid / asymmetric / subroutine), each mapped
  to an ATMS component-type hint.
- All arrow forms (`-->`, `---`, `==>`, `-.->`, `-->|label|`,
  `-- label -->`).
- Subgraphs with container-y labels (VPC / subnet / DMZ / cluster /
  namespace / tenant) auto-promote to TrustBoundary; crossings
  flagged on dataflows.
- Markdown files (`.md`) have their first ```mermaid``` fence
  extracted.

Strong-shape signal wins over label regex — closes a bug where
"Customer DB" would match the user regex's "customer" token and
beat the cylinder shape.

Also tightened `_classify_boundary_type` so "VPC: production"
classifies as network (not deployment_zone) — network keywords
now win over generic stage tokens.

Wired into `atms ingest` CLI + `POST /ingest` + the home-page
upload form.

### Added — Cycle Q: auto-analyse on diagram upload

The default ingest flow required two clicks (parse → review →
analyse). User feedback was that the upload should "automatically
identify boundaries, device types, assets, connections … should be
comprehensive threat model" in one step.

The home page upload form now has TWO submit buttons:
- "Parse diagram" — original review flow (unchanged)
- "Parse & analyse" — new one-click flow that runs the full
  threat-modeling pipeline immediately and renders the report

Pure-IT diagrams auto-detect (zero AI components) and run in
general-purpose mode without the user needing to set `--allow-pure-it`.

### Tests

- **550 passing** (was 527, +23 across the two cycles).
- 7/7 input formats (yaml, vsdx, drawio, xml, mmd, mermaid, md,
  png/jpg via opt-in vision) end-to-end.
- 12/12 sample-selftest cases pass.
- Architecture diagram updated with new `i_mermaid` input node;
  docs/ + template synced; drift guard green.

### Cycle commits

| Cycle | Commit | Theme |
|---|---|---|
| P | (mermaid) | mermaid flowchart ingest |
| Q | 457f510 | auto-analyse on upload |

---

## [0.18.0] — 2026-05-15 — General-purpose pivot (Cycles K-O)

User feedback "AI-only is not viable" triggered a major strategic
pivot: ATMS goes from AI-anchored-only to a general-purpose threat
modeler that **also** does AI well. Three research agents informed
the cycle design (an internal development workflow, competitor parity vs.
IriusRisk / ThreatModeler / Threat Dragon / pytm / Threagile,
diagram-parsing prior art).

### Added

- **General-purpose mode (Cycle K).** `analyze(system,
  require_ai_components=False)` accepts pure-IT and pure-OT
  systems. `atms analyze --allow-pure-it` flag. Every component is
  in scope; threats fire from every playbook. Default behaviour
  unchanged (legacy AI-anchored contract preserved unless explicit
  opt-in).

- **draw.io / diagrams.net XML ingest (Cycle L).** New
  `src/atms/ingest/drawio.py` with three-layer auto-classification:
  - 110+ style-prefix dict (mxgraph.aws4.* / mxgraph.azure.* /
    mxgraph.gcp2.*) — high-confidence cloud-stencil matches.
  - 45+ label-regex patterns — fallback for unstyled cells.
  - `other` fallback — surfaces to the user.
  Every component carries `metadata.source` = `drawio:style` /
  `drawio:label` / `drawio:fallback` for audit. Pure-stdlib XML,
  zero external deps, fully offline. `atms ingest <file>` and
  `POST /ingest` both dispatch on suffix.

- **Trust-boundary inference (Cycle M).** Container hierarchy
  (VPC / subnet / DMZ / cluster / namespace / tenant rectangles)
  becomes `TrustBoundary` objects on the System; components
  inherit their enclosing boundary's label as `trust_zone`;
  dataflows are flagged `crosses_boundary=True` when source and
  target live in different zones. Boundary classification
  (network / identity / data_classification / tenancy /
  deployment_zone) inferred from label hints.

- **Web upload UI (Cycle N).** `/ingest` and the home page accept
  `.drawio` + `.xml` (alias for raw mxGraph). The success notice
  reports the classification breakdown
  ("X via stencil style, Y via label, Z fallback") and the count of
  inferred trust boundaries.

- **Pure-IT sample (Cycle O).** `samples/pure_it_estate.yaml` — a
  customer-facing web app + DB + IdP + WAF + SIEM + EDR with 5
  trust zones. Selftest auto-detects pure-IT samples and runs them
  in general-purpose mode (12/12 samples pass, including the new
  one with 35 threats).

### Research findings (informing this release)

The three v0.17.4 research agents found:
- **ThreatModeler acquired IriusRisk** in Jan 2026; the field is
  consolidating. Window for an offline-first competitor is open.
- **draw.io XML is the dominant open format** (AWS / Azure / GCP
  all ship official mxGraph stencils with stable style prefixes;
  Visio / Lucidchart / Gliffy can export to it).
- **IriusRisk's OT coverage** (IEC 62443, MITRE ATT&CK for ICS,
  EMB3D) is their main moat — ATMS already covers most of this.
- **Top open-source priors**: secmerc/materialize-threats
  (drawio → property graph), Threagile (YAML + 40 risk rules),
  inframap (Terraform → simplified graph). All read for technique;
  none copied wholesale.

### Tests

- **527 passing** (was 472, +55 across 5 cycles). Wall-clock
  ~21–29s full, ~12s fast-iteration (`pytest -m "not slow"`).
- 12/12 selftest samples pass (added pure_it_estate.yaml).
- Architecture diagram updated for Cycles L+M (new i_drawio
  input node). Drift guard green.

### Cycle commits

| Cycle | Commit | Theme |
|---|---|---|
| K | d0e87f2 | lift AI-scope gate to opt-in |
| L | (commit) | draw.io XML ingest |
| M | b4c7d5d | trust-boundary inference |
| N | e1c71dc | web /ingest accepts .drawio |
| O | (this release) | pure-IT sample + selftest pickup |

---

## [0.17.3] — 2026-05-15 — Architectural review + 9 improvement cycles

Post-v0.17.0 the project went through an architectural review whose
output became a 9-cycle improvement loop (A–I). All cycles ship
behind tests + a CI drift guard so future contributors can't
regress what was fixed.

### Added — internals (Cycles A-C)

- **`src/atms/pipeline.py`** (Cycle A, closes review C1+C4): declares
  the 28 pipeline stages as a `Stage` dataclass with explicit
  `requires_before` clauses. `enforce_stage_order()` runs at module
  import time. Adds `validate_threats()` re-running Pydantic on
  every threat as a single mutation-checkpoint after the engine block.

- **`src/atms/engines/frameworks.py`** (Cycle B, closes review C3):
  unified registry-driven engine that replaces 4 near-duplicate
  framework enrichers (mapping/atlas, linddun, nist_ai_100_2,
  owasp_ml). Adding a new framework is now a 5-line `FrameworkSpec(...)`
  entry. The 4 original engines become thin wrappers; behaviour
  byte-identical (selftest counts unchanged).

- **`analyze(prior_run=...)`** (Cycle C, closes review S3): disposition
  carry-forward. Loads a previously-saved ThreatModel JSON and copies
  disposition + lifecycle context fields to matching new threats by
  id. Threats marked `mitigated` / `false_positive` / `duplicate` on
  the prior run drop out of `severity_breakdown` + ALE rollups via
  the new `CLOSED_DISPOSITIONS` constant + `is_closed()` helper.

### Added — UX (Cycles E, G, H, I)

- **POC automation (Cycle E):** CLI flags `--deployment-stage`,
  `--industry`, `--revenue-bucket` on `atms analyze` override System
  fields at runtime. Editor toolbar gets a deployment_stage dropdown.
  Lets users re-run the same YAML across scale tiers without editing
  YAML.

- **Web `/diff` route (Cycle G):** mirrors the CLI `atms diff` in
  HTML. Pass two saved ThreatModel JSONs via `?a=&b=` query params.
  Failure-tolerant: bad paths surface as friendly banners, never 500.

- **`atms validate` CI upgrade (Cycle H):** structured exit codes
  (0=valid, 2=bad YAML, 3=strict-other-violation, 4=no-AI-scope),
  `--strict`, `--check-ai-scope`/`--no-check-ai-scope`, `--json`
  output. Pre-commit-hook ready.

- **`atms init` scaffold (Cycle I):** generates a starter System
  YAML in one of 4 templates (basic / rag / agentic / chatbot). All
  templates default to `deployment_stage: poc` so first-run analyses
  get the conservative FAIR-priors tier.

### Added — polish + infra (Cycles D, F + diagram updates)

- **Pytest perf (Cycle D):** session-scoped read-only fixtures for the
  three hot canonical samples (aws_bedrock_agent, azure_openai_rag,
  rag_system) — saves ~5 s per run. `@pytest.mark.slow` marker on the
  3 explicit perf-budget tests; `pytest -m "not slow"` runs the
  dev-loop tier in 12 s instead of 26 s (55% faster).

- **Review M1+M2 polish (Cycle F):** `/architecture` page gets a
  JS-conditional "← ATMS" back link (visible only when served via
  http(s), hidden on `file://`). `engines/stride_ai.py` emits
  `logging.info` whenever the `other` catch-all playbook fires.

- **Architecture diagram** kept fresh: updated for Cycles A/B/C
  (new pipeline + frameworks + carry-forward nodes), again for
  Cycle G (new `/diff` output node). `scripts/check_architecture_drift.py`
  + CI step + tests/test_architecture_drift.py block future drift.

### Fixed — review findings

- **C1**: engine-ordering invariants now data, not comments.
- **C3**: 4 framework engines deduplicated into 1 registry.
- **C4**: threats re-validated post-mutation.
- **S3**: disposition lifecycle now feeds back into analysis.
- **M1**: `/architecture` had no nav.
- **M2**: `other` playbook fired silently.
- **M3** (already done pre-cycle): CLI autocorrect notice — verified
  present at cli.py:113-118.

### Verification

- **472 tests passing** (was 398 pre-review, +74). Wall-clock
  ~22 s full, ~12 s fast-iteration.
- `python scripts/check_architecture_drift.py --strict` → clean.
- `python scripts/gen_palette.py --check` → clean.
- `atms selftest` → 11/11 sample analyses, threat counts unchanged
  from v0.17.0 (all behaviour-preserving refactors).

### Commits

| Cycle | Commit | Theme |
|---|---|---|
| A | d425314 | type-safe stage pipeline |
| B | d64e86a | framework-enrichment registry |
| C | 0b1085b | disposition carry-forward |
| diagram | 8c648cb | diagram update + CI drift guard |
| D | d793bde | pytest perf |
| E | 09a5dc8 | POC automation |
| F | 14ed6db | review polish (M1+M2) |
| G | 209ea48 | web /diff route |
| H | 1bb3fc0 | atms validate CI-grade |
| I | 1628522 | atms init scaffold |

---

## [0.17.0] — 2026-05-11 — Phase 4: interactive risk heatmap + release rollup

Final phase of the v0.17.0 1-month plan. Promotes the rolled-up
work from v0.16.10 (palette + STRIDE cleanup), v0.16.11 (playbook
content + framework wiring), and the methodology provenance partial
into a single tagged release.

### Added

- **Interactive risk-heatmap on the HTML report.** The existing 5×5
  likelihood × impact matrix in `templates/report.html.j2` is now
  clickable: click any non-empty cell to filter the threat blocks
  below to that exact (L, I) bucket. Click the same cell again — or
  the "clear filter" link in the new status bar — to restore. Empty
  section headers are auto-hidden when filtered. Pure vanilla JS
  (~80 lines), no external libraries.
- Matrix cells now carry `data-l` / `data-i` attributes (1–5 each);
  threat blocks carry the same; the JS click handler reads them.
- `tests/test_heatmap.py` (3 tests) pins the DOM contract — every
  cell has data-l/i in (1..5, 1..5), every threat block carries the
  same, the filter-bar div + clear-button JS are present in output.

### Release rollup (full v0.17.0 vs v0.16.9 baseline)

| Surface | v0.16.9 | v0.17.0 |
|---|---|---|
| Component types in editor palette | 40 / 121 (33 %) | **121 / 121 (100 %)** |
| Palette search | none | **live filter, debounced** |
| Component-type playbooks | 94 / 121 | **121 / 121** |
| Playbooks with empty `refs:` arrays | 16 | **0** |
| Playbooks with < 3 threats | 19 | **0** |
| `STRIDE-AI` user-facing strings | 11 leaks | **0** |
| Methodology-provenance map | not present | **9 categories with published anchors** |
| `/methodology` per-threat drill-down | not present | **available** |
| Risk matrix | static counts | **click-to-filter interactive** |
| Frameworks integrated | 10 | 10 (NIST AI 100-2 + OWASP ML + LINDDUN + CSA Singapore now actually wired) |
| Tests | 381 | **398** |
| Test wall-clock | 113 s | **20–28 s** |

### Verification (end-of-cycle)

- `make palette-check` — clean (palette in sync with `models.py`).
- `pytest -q` — 398 passing in 28 s.
- `python -m atms.cli selftest` — 11 / 11 samples pass with
  threat-count increases on every sample after Phase 2.
- `grep -rn "STRIDE-AI\|DREAD-AI" src/atms/templates/` — only the
  about-page disclaimer paragraph (intentional + allowlisted).
- Sample report `samples/rag_system.yaml` renders the heatmap;
  clicking the L4×I5 cell hides 40+ threats and shows only the
  matching bucket.

---

## [0.16.11] — 2026-05-11 — v0.17.0 Phase 2: 121/121 playbook coverage + 4 orphan frameworks wired

Phase 2 of the v0.17.0 1-month plan. Closes the playbook content gaps
flagged in an internal content audit: every
`ComponentType` value now has a dedicated playbook (was 94/121),
every threat in those playbooks now carries ≥ 1 framework citation
(`refs:` array), and the four previously-orphaned frameworks (NIST
AI 100-2, OWASP ML 2023, LINDDUN, CSA Singapore) are referenced by
real threats instead of sitting in the KB unused.

Also includes Phase 3 partial: methodology-provenance map + the new
`/methodology` route answering "where does this STRIDE category come
from?"

### Added — 27 new component playbooks (~140 new threats)

**OT / SCADA** (6): `dcs`, `hmi`, `sis`, `rtu`, `ied`, `ot_jumphost`.
OT-specific threats use MITRE ATT&CK ICS technique IDs (T0801-class).

**Endpoint servers** (3): `server_linux`, `server_windows`,
`server_unix` (Solaris/AIX/HP-UX legacy).

**Mobile / IoT** (3): `mobile_device`, `mdm_emm` (Intune/Jamf),
`iot_gateway` (Greengrass/IoT Edge).

**Security infrastructure** (3): `soar`, `pam_vault`,
`security_data_lake`.

**Identity / PKI** (2): `certificate_manager`, `ciam_platform`.

**Build / IaC** (3): `build_runner`, `iac_template_registry`,
`file_transfer_service`.

**Compute variants** (3): `batch_compute`, `edge_compute`,
`high_performance_compute`.

**ML ops** (1): `ml_experiment_tracker` (MLflow / W&B / Comet).

**Other** (3): `reverse_proxy`, `mainframe`, `other` (catch-all
safety-net for unrecognised components — emits 4 generic threats at
playbook confidence instead of 0.3-confidence stubs).

### Fixed

- **19 hollow playbooks**: backfilled `refs:` arrays with real,
  published technique IDs (MITRE ATT&CK / ATLAS / D3FEND / NIST). No
  threat now has an empty `refs:` list.
- **19 sub-3-threat playbooks** promoted to ≥ 3 threats each.
- **Catch-all confidence regression**: `tests/test_engines.py
  ::test_enumerate_threats_unknown_type` now expects ≥ 3 threats
  with confidence ≥ 0.9 (was: 0 threats with confidence ≤ 0.3 as
  a no-playbook stub). The `other` playbook is the new safety-net.

### Wired — 4 previously-orphan frameworks

These framework catalogues are loaded by the KB but were not
referenced by any threat before v0.16.11. Now they appear on real
threats where they genuinely apply:

| Framework | Hits (was: 0) |
|---|---|
| **NIST AI 100-2** (Adversarial ML taxonomy) | **113** |
| **OWASP ML Top 10 (2023)** | **46** |
| **LINDDUN** (privacy categories) | **37** |
| **CSA Singapore Guidelines on Securing AI Systems** | **200** |

### Added — Phase 3 partial: methodology provenance

- **`kb/methodology_provenance.yaml`** — 9 entries mapping every
  STRIDE-for-AI category to its published framework anchor:
  - 6 standard STRIDE → Microsoft STRIDE (1999) + STRIDE for AI/ML (2022).
  - `Defense_Evasion` → MITRE ATT&CK TA0005.
  - `Bias_Fairness` → NIST AI RMF MANAGE 4.1 + ISO/IEC 24027:2021.
  - `Emergent_Behavior` → MITRE ATLAS AML.T0048 + OWASP LLM09:2025.
- **About page** grows a "Threat-category provenance" section
  rendering the table with standing pills (standard vs ATMS extension).
- **New `/methodology` route** — per-threat framework-citation
  drill-down. Loads a saved ThreatModel JSON via
  `?path=output/<file>.json`, renders every threat with its STRIDE
  category + OWASP + ATLAS + ATT&CK + MAESTRO + NIST + LINDDUN + CSA
  pills side-by-side. Lets reviewers answer "where does this threat
  come from?" without code-spelunking.
- **Nav bar** gets a Methodology link.

### Tests

- 395 passing (was 390). Wall-clock 21 s.
- 4 new tests:
  - `tests/test_methodology_branding.py::test_every_stride_category_has_methodology_provenance`
  - `tests/test_methodology_branding.py::test_methodology_provenance_entries_have_required_fields`
  - `tests/test_methodology_branding.py::test_about_page_renders_provenance_table`
  - `tests/test_methodology_branding.py::test_methodology_route_with_real_threats`

### Verification

- `python -m atms.cli selftest` → 11/11 samples pass; threat counts
  up across the board (e.g. enterprise_rag_agent 78 → 84,
  aws_bedrock_agent 104 → 106, chatbot 35 → 37).
- `PYTHONPATH=src python scripts/gen_palette.py --check` → clean
  (palette still in sync with `models.py`).

---

## [0.16.10] — 2026-05-11 — v0.17.0 Phase 1: comprehensive editor palette + STRIDE-AI cleanup

Phase 1 of the v0.17.0 1-month plan. Closes the 67% gap between the
editor's component palette (was 40/121 component types exposed) and
the underlying `ComponentType` Literal in `models.py`. Also retires
the legacy "STRIDE-AI" / "DREAD-AI" branding from every user-facing
template — leaves only the about-page disclaimer that documents the
historical name.

### Added

- **Comprehensive editor palette — 121/121 component types.** All
  ComponentType values are now reachable from the editor's drag-and-
  drop palette, organised into 13 groups that mirror the source-of-
  truth comment-header structure in `models.py`. Groups start
  collapsed except AI/ML primitives + Cloud compute, so a fresh user
  doesn't face a wall of 121 entries.
- **Palette search box.** Live substring filter on `type`, `group`,
  and synonym aliases. 150ms debounce. Matching groups auto-expand;
  groups with zero matches auto-hide. `Esc` clears. A small `×`
  button clears the filter.
- **Single source of truth via `scripts/gen_palette.py`.** Reads
  `ComponentType.__args__` + comment-header groupings from
  `models.py`, inverts `yaml_autocorrect._SYNONYMS` into per-type
  search aliases, applies `kb/palette_meta.yaml` emoji overrides,
  writes `src/atms/static/palette-data.json`. The editor JS fetches
  this at load time.
- **CI drift guard.** `make palette-check` (and the new
  `tests/test_palette.py::test_palette_generator_check_mode_passes`)
  fails if a dev edits `ComponentType` without re-running the
  generator.
- **New `Makefile` targets:** `palette` (regenerate) and
  `palette-check` (CI mode).

### Changed

- `src/atms/static/atms-editor.js` — `COMPONENT_TYPES` hardcoded
  array (40 entries) replaced by async `loadPalette()` fetching
  `palette-data.json`. New `buildPalette()` renders collapsible
  groups; new `wireSearch()` wires the filter input.
- `src/atms/templates/web/editor.html` — added search input row
  above the palette, new CSS for `.palette-search`,
  `.palette-group.collapsed`, `.palette-group.hidden`,
  `.palette-item.hidden`, chevron toggle, group-count badge.

### Fixed — STRIDE-AI / DREAD-AI naming cleanup (11 leaks)

Retired the legacy "STRIDE-AI" brand from every user-facing template
to "STRIDE for AI". The `value="stride-ai"` HTML attribute and the
internal `StrideAI` Literal stay unchanged — they're backend method
IDs / Python identifiers, not user-facing copy.

| File | Was | Now |
|---|---|---|
| `templates/web/editor.html:119` | `STRIDE-AI (full)` | `STRIDE for AI (full pipeline)` |
| `templates/web/evidence.html:37` | same | same |
| `templates/web/redteam.html:35` | same | same |
| `templates/web/agentic.html:9` | `<th>STRIDE-AI</th>` | `<th title="…">STRIDE</th>` |
| `templates/web/maestro.html:27` | same | same |
| `templates/web/playbooks.html:5` | `pre-mapped to STRIDE-AI` | `pre-mapped to STRIDE for AI` (linked to /about) |
| `templates/web/playbooks.html:11` | `<th>STRIDE-AI</th>` | `<th title="…">STRIDE</th>` |
| `templates/report.md.j2:42` | `Methodology \| stride-ai` | `Methodology \| STRIDE for AI (extended) · stride-ai` |
| `templates/report.html.j2:89` | `stride-ai` | `STRIDE for AI` (backend ID in tooltip) |
| `templates/web/report.html:34` | same | same |

The single remaining literal `DREAD-AI` is in `templates/web/about.html`
where it appears as part of the disclaimer paragraph documenting the
historical name — kept intentional and allowlisted in the new
regression test.

### Honest answer: is "STRIDE-AI" a published methodology?

No. "STRIDE-AI" as a branded name is not in any peer-reviewed
literature. Microsoft Learn published "Threat modeling AI/ML systems"
in November 2022 applying STRIDE to AI surfaces — that's the
legitimate technique; the 6 STRIDE categories themselves are
Microsoft 1999 and standard everywhere. ATMS additionally tags 3
extension categories (`Defense_Evasion`, `Bias_Fairness`,
`Emergent_Behavior`) which describe real AI threat vectors anchored
in MITRE ATT&CK / NIST AI RMF / MITRE ATLAS respectively. Phase 3 of
the v0.17.0 plan will add a methodology-provenance page showing
every category's published anchor.

### Tests

- 390 passing (was 381). +9 from new regression suites.
- Test wall-clock 29.3 s (under the 30 s budget).
- New `tests/test_palette.py` (7 tests) pins the palette contract.
- New `tests/test_methodology_branding.py` (2 tests) blocks future
  re-introduction of `STRIDE-AI` / `DREAD-AI` strings in user-facing
  templates.

---

## [0.16.9] — 2026-05-11 — Bug-hunt cleanup + 33 new component playbooks

Two parallel cycles converged here: a bug-hunter audit of v0.16.8
pathological inputs (15 findings) and a playbook expansion pass for
under-covered component types (33 new playbooks). All issues
resolved; tests at 381 passing.

### Added — 33 new component-type playbooks (103 new threats)

Coverage filled in the categories the v0.16.0 catalog expansion
missed:

- Storage / data: `container_registry`, `block_storage`, `file_storage`,
  `data_lake`, `backup_service`, `graph_database`, `time_series_database`.
- Pipelines / data movement: `etl_orchestrator`, `ml_pipeline_orchestrator`,
  `ml_feature_store`, `ml_data_labeling`.
- Network / edge: `service_mesh`, `private_link`, `transit_gateway`,
  `dns_service`, `ddos_mitigation`, `web_proxy`, `router`, `switch_l3`,
  `sdwan_edge`, `network_access_control`.
- AI-pipeline subtypes: `vision_pipeline`, `speech_pipeline`,
  `content_safety_classifier`.
- Cloud security tooling: `casb`, `dlp`, `cspm`, `container_security`.
- Observability: `tracing_platform`, `log_aggregator`, `metrics_platform`,
  `alerting_platform`.
- Platform: `feature_flag_service`.

Each playbook carries ATLAS / ATT&CK / NIST_GAI / CSA Singapore
citations; likelihood × impact distribution is spread (not all
defaulted to 4×5).

### Fixed — 15 bug-hunt findings

Crashes (4):

- **Bug-001** — Component names ≥ 132 chars no longer crash
  `analyze()` via the StructuralRecommendation 200-char title cap.
  Name is now clipped via `_safe_name()`.
- **Bug-002** — `/editor/save` returns 400 (was 500) on empty /
  malformed JSON bodies. `request.json()` is wrapped in try/except.
- **Bug-003** — `KnowledgeBase.lookup_loss_prior()` now accepts
  keyword-only invocations (`industry=…, deployment_stage=…`); all
  three params are optional.
- **Bug-013** — Duplicate `Component.id` is rejected at model-
  validation time (was: silently kept both, downstream lookup
  arbitrary). Same validator also rejects dangling dataflow refs.

Wrong-output (7):

- **Bug-004** — Tier-1 bank POC no longer produces ~$200M portfolio
  ALE on a 1-LLM system. New `freq_high_cap` field on priors tiers
  (implicit `1.0` when `frequency_multiplier ≤ 0.2`) puts a hard
  ceiling on per-threat annual frequency for POC/pilot.
- **Bug-006** — `_compute_confidence(threat, comp=None)` no longer
  short-circuits to 0.6; `needs_review` demotion + framework
  penalty now apply even when component lookup misses.
- **Bug-008** — YAML autocorrect handles `type: null` (was: skipped,
  user got the raw 40-name Pydantic literal_error blob).
- **Bug-009** — Reference-pattern enricher no longer tags AWS *and*
  Azure patterns on the same mitigation when vendor metadata is
  absent; falls back to inferring vendor from haystack tokens.
- **Bug-010** — Removed inert `id=…` kwarg in the workflow Bedrock-
  KB auto-synthesis Dataflow constructor.
- **Bug-011** — Loss-prior tier with `loss_low > loss_high` is now
  swapped (with a logged warning) at load time, instead of silently
  collapsing all ALEs to the wrong value.
- **Bug-012** — Empty `components: []` now raises a specific
  `ValueError("System has no components")` instead of the
  generic `NoAIComponentsError`.
- **Bug-014** — `format_validation_error()` includes the exception
  class name for non-Pydantic exceptions (was: stripped, user saw
  bare `str(exc)`).
- **Bug-015** — `EU_AI_ACT.50` is now also gated off when
  `is_high_risk_under_eu_ai_act=False` (was: leaked through the
  set-based gate while .13/.14/.15 were correctly suppressed).
  Gate is now prefix-based.

Slow (2):

- **Bug-005** — `_select_diverse_paths` rewritten from O(N×M×S)
  to O(N×M) by pre-computing signatures + tracking incremental
  min-distance per candidate. Candidate pool capped at top 200 by
  raw score. Test suite runtime: **114s → 20s** (5.5× speedup).
- **Bug-007** — `POST /analyze` now returns 413 for YAML bodies
  >2 MB (was: accepted any size, ~28s on a 50 MB blob).

### Verified

- 381 tests pass (was 368 before Cycle 9 / 367 before Cycle 10
  bug fixes; +13 v0.16.9 regression tests + 16 auto-discovered
  per-playbook tests for the new component types).
- Test suite runtime: 20.25s (down from 113.76s on v0.16.8 — net
  win from Bug-005 fix).
- All bug-hunter findings re-tested green via
  `tests/test_v0169_bugfixes.py` (13 tests, one per finding).

---

## [0.16.8] — 2026-05-10 — LLM-specific false-negative closure

Cycle 8 of v0.16 plan. Closes the three concrete LLM-specific false
negatives the v0.16.0 self-audit identified (and which were absent
from earlier ATMS reports).

### Added — 3 new threats on `llm_inference`

- **`T_LLMINF_011`** — Context-window stuffing / hijacking. Adversarial
  content drowns the system prompt out of the model's attention budget;
  particularly effective on 200K-token long-context models. Cross-walks:
  LLM01:2025, LLM10:2025, AGT01, AML.T0051, NIST_GAI_PROMPT_INJECTION_DIRECT.
- **`T_LLMINF_012`** — Provisioned-throughput exhaustion (per-tenant DoS).
  Multi-tenant Bedrock / Azure OpenAI / vLLM share a TPM/RPM pool; one
  abusive tenant degrades others. Cross-walks: LLM10:2025, API4:2023,
  AML.T0029 + T0034, MAESTRO M.L4.04, CSA_AI.DEPLOY.01.
- **`T_LLMINF_013`** — Guardrail bypass via adversarial encoding
  (base64, hex, unicode confusables, leet-speak, foreign language,
  multi-turn split, polyglot inputs that decode differently in the
  safety classifier vs the main model). Cross-walks: LLM01:2025,
  LLM02:2025, AGT01 + AGT06, AML.T0051 + T0054, NIST_GAI_ADVERSARIAL_MISUSE.

### Verified

- 352 unit tests still pass. Selftest 11/11.

## [0.16.7] — 2026-05-10 — Bias/fairness + Emergent-behaviour threat categories

Cycle 7 of v0.16 plan. Closes the v0.15.0 expert-review gap: "STRIDE
wasn't designed to describe bias / emergent behaviour. A biased model
isn't being attacked — it's failing in a way the framework doesn't
capture."

### Added

- `StrideAI` literal extended with two AI-native categories:
  - `Bias_Fairness` — discriminatory output / disparate impact /
    decision parity across protected classes.
  - `Emergent_Behavior` — capabilities not present at training time /
    out-of-spec actions / tool-chain composition beyond design intent.
- 5 new threats spanning these categories:
  - `llm_inference.T_LLMINF_009` — discriminatory output across protected classes
  - `llm_inference.T_LLMINF_010` — emergent capability beyond training spec
  - `training_pipeline.T_TRAIN_010` — training-data skew → disparate impact
  - `agent.T_AGENT_012` — emergent tool-chain composition beyond design intent
  - `agent.T_AGENT_013` — multi-agent collusion bypassing per-agent guardrails

Each new threat carries the appropriate cross-walks: ML02:2023 +
ML08:2023 for the training-data skew, AGT05 + AGT12 + AGT13 + AGT17
for the emergent / collusion threats, CSA_AI.HUMAN.02 for fairness,
CSA_AI.HUMAN.01 + CSA_AI.DEPLOY.01 for emergent-behaviour gating.

### Verified

- 352 unit tests still pass. Selftest 11/11.
- Bias/fairness threats only emit on `llm_inference` / `training_pipeline`;
  emergent-behaviour threats on `agent`. No false-positive bleed to
  non-AI components.

## [0.16.6] — 2026-05-10 — disposition lifecycle + delta-aware diff + 6 new vendor overlays

Cycle 6 of v0.16 plan. Closes security-architect critique finding A-05
("disposition is single-state — every threat re-runs as `open`; each
quarter's re-run is a 65-threat firehose at the CISO instead of a
6-threat delta against architectural decisions already taken").

### Added — lifecycle states + context fields

`Disposition` Literal extended:
- `accepted_with_compensating_control`
- `deferred`

`Threat` model gains 4 lifecycle context fields:
- `compensating_control_id: str` (e.g. `WAF-RULE-AI-PI-01`)
- `transferred_to_vendor: str` (e.g. `acquirer-cyber-insurance-2025`)
- `mitigated_by_commit: str` (e.g. `7c4d2a1`)
- `deferred_until: str` (ISO date)

### Added — delta-aware `atms diff`

`atms diff old.json new.json` now emits a `disposition_changed`
section in markdown + JSON output, plus a count line in the table
view:

```
$ atms diff old.json new.json
  threats: 65 -> 65  mitigations: 287 -> 287
  added=2 removed=2 severity_changed=3 score_changed=5 disposition_changed=6
```

Each disposition-change row surfaces the lifecycle context where
populated:

```
- `web.T_LLMINF_001` open -> mitigated_by_commit=7c4d2a1: Direct prompt injection
- `db.T_DB_001` open -> accepted_with_compensating_control=WAF-RULE-AI-PI-01: ...
```

A quarterly re-run is now a 6-threat delta to a CISO, not a 65-row
firehose.

### Added — 6 new vendor threat overlays (38 new threats)

All landed during this cycle:
- `kb/vendor_threats/anthropic_api.yaml` — 6 threats (Claude API key
  DoW, 200K-context stuffing, tool-result injection, Claude Code MCP
  filesystem, Computer-Use API, vision image-prompt)
- `kb/vendor_threats/openai_api.yaml` — 7 threats (client-side key
  leak, legacy-completions cost-DoW, Assistants thread cross-tenant,
  GPT-4o vision-URL exfil, function-calling injection, Custom GPT
  webhook, markdown link smuggling)
- `kb/vendor_threats/aws_sagemaker.yaml` — 7 threats
- `kb/vendor_threats/gcp_vertex_ai.yaml` — 6 threats
- `kb/vendor_threats/azure_ml.yaml` — 6 threats
- `kb/vendor_threats/databricks_ai.yaml` — 6 threats

Total vendor-specific threat overlays now 75 across 12 files.

### Verified

- 352 tests passing. Selftest 11/11.

## [0.16.5] — 2026-05-10 — structural mitigations + StructuralRecommendation model

Cycle 5 of the v0.16 improvement plan. Closes security-architect
critique finding A-03: "ATMS enumerates threats per component but never
proposes new components. That's a checklist over the existing DFD, not
a threat model an architect can act on."

### Added

- `models.py:StructuralRecommendation` — new Pydantic model.
  Fields: `id`, `title`, `summary`, `edit_kind` (insert / split /
  relocate / remove / harden_in_place), `proposed_component_type`,
  `affected_threats`, `affected_components`, `rationale`,
  `sample_dfd_edit`, `estimated_effort`.
- `ThreatModel.structural_recommendations: list[StructuralRecommendation]`.
- New engine `engines/structural.py:propose_structural_recommendations()`
  with four deterministic rules:
  1. Agent with ≥3 severe agentic threats + no guardrail layer →
     recommend inserting `policy_engine` / `guardrails`.
  2. LLM with ≥2 disclosure threats + no `output_filter` →
     recommend inserting `output_filter`.
  3. RAG store with ≥2 indirect-injection / ACL-bypass / poisoning
     threats + no `content_safety_classifier` → recommend inserting
     retrieval-time content safety.
  4. Agent with admin/write `tool_scope` + no PAM vault → recommend
     introducing a PAM broker.
- Markdown report renders a new top-level section listing the
  recommendations between Attack-paths and the Top-10 mitigation
  roadmap. Each recommendation includes a sample DFD edit so an
  architect can act on it without further translation.

### Verified

- On a synthetic agent-with-cluster system: 2 structural recommendations
  fire (policy_engine + PAM vault), addressing 13 affected threats.
- 352 unit tests still pass. Selftest 11/11 unchanged.

## [0.16.4] — 2026-05-10 — Reference-architecture cross-walk + attack-path diversity

Cycle 2 of the v0.16 improvement plan. Two substantial features:

### Added — Reference-architecture cross-walk (security-architect finding A-04)

**81 reference-architecture patterns** across 4 CSP frameworks at
`kb/reference_patterns/`:
- `aws_sra.yaml` — 27 AWS Security Reference Architecture patterns
  (Organizations / IAM Identity Center / KMS / VPC / CloudTrail / S3)
- `aws_genai_lens.yaml` — 18 AWS Well-Architected GenAI Lens IDs
  (Bedrock invocation logging, Guardrails, KB ACL propagation, etc.)
- `azure_lza.yaml` — 21 Azure Landing Zone patterns
  (hub-spoke + Bastion + PrivateLink, Entra CA + PIM, Defender, Key Vault)
- `azure_waf_ai.yaml` — 15 Azure WAF AI workloads patterns
  (Content Safety + Prompt Shields, OBO, private endpoints for Azure OpenAI)

Plus a new engine: `engines/reference_patterns.py` cross-walks each
emitted mitigation against the patterns by keyword + component-type +
vendor-aware filtering. Bias toward false negatives (no spurious AWS
tags on an Azure-only mitigation).

**Verified on the AWS RAG reference architecture:** 40 of 130 mitigations
now carry CSP pattern IDs. Top tagged mitigations like `AML.M0019`
("Control Access to ML Models") map to `AWS_SRA.IAM.5 +
AWS_GenAI_Lens.SEC-2 + AWS_GenAI_Lens.SEC-3`. Reviewers can now see
"this mitigation is part of AWS SRA pattern X" instead of "another
generic security tip."

`Mitigation.reference_patterns: list[str]` added to the model.
Report template renders the new row in every mitigation's detail block.

### Added — Attack-path diversity selection (red-team finding A-08)

Replaced naive "top-N by score" path selection with a diversity-aware
greedy selector. After the top-scoring path is chosen, each next path
is selected to maximise `(score + 5 × signature_distance)` against
already-selected paths. Signature: (entry threat, first tactic,
terminal threat, intermediate-tactic set).

**Closes the "all 10 paths are the same chain permuted" failure mode**
the red-team expert flagged in the v0.15.1 critique. New paths now
cover different entry points / different lateral-movement classes
instead of stacking permutations of indirect-prompt-injection →
no-rate-limit → weak-auth → CloudWatch-leak.

### Fixed

- 352 unit tests still pass. Selftest 11/11 unchanged.

## [0.16.3] — 2026-05-10 — tool-scope severity + Bedrock KB auto-synth + EU AI Act gating

Cycle 1 of the v0.16 improvement plan. Three small but high-leverage
engine fixes:

### Added
- **Tool-scope severity promotion.** Agents / MCP servers / tools with
  `metadata.tool_scope: write` get +1 to the DREAD-AI Damage score;
  `tool_scope: admin` gets +2 to Damage AND +1 to Affected Users.
  Materialises the comparator finding that `T_AGENT_001` excessive-agency
  on a Bedrock Agent with write-scope tools should be Critical, not High.
- **Bedrock Agent KB auto-synthesis.** When a component with
  `metadata: {vendor: aws, product: bedrock_agent}` is present without a
  paired `rag_vector_store`, the workflow auto-synthesises a placeholder
  `kb_auto` component with the AI-induced threats the KB would otherwise
  silently miss. The placeholder carries `metadata.auto_synthesized=True`
  + a "verify on diagram" hint in the description.
- **EU AI Act high-risk discriminator.** `System.is_high_risk_under_eu_ai_act:
  bool = False`. When False (the default), `enrich_with_compliance` no
  longer stamps `EU_AI_ACT.13` / `EU_AI_ACT.14` / `EU_AI_ACT.15` IDs
  onto threats — those bind only on Annex-III systems. Stops the
  v0.15.1 risk-assessment expert's "audit-bait mapping" finding from
  silently re-introducing.

### Fixed
- 352 unit tests still pass. Selftest 11/11 unchanged.

## [0.16.2] — 2026-05-10 — KB cross-walks alive + comparator-driven content + PII floor

### Headline

The four "dead-weight" KBs from the v0.16.0 content-validator audit are
no longer dead-weight: **205 new framework references** added across
19 playbook YAMLs, AND the engine now reads them so they flow through
to emitted threats. Plus 5 new high-priority threats sourced from the
cross-tool comparator agent's gap analysis vs IriusRisk / AWS GenAI
Lens / Azure WAF AI workloads.

### Fixed

- **Playbook cross-walk references now flow to threats** (the
  engineering gap the cross-walk agent flagged). `_threat_from_playbook`
  now reads `nist_ai_100_2`, `owasp_ml`, `csa_singapore` fields from
  playbook YAML. `Threat.csa_singapore: list[str]` added to the model.
  Verified on `samples/rag_system.yaml`: 29/35 threats carry CSA tags,
  21/35 NIST AI 100-2, 7/35 OWASP ML, 6/35 LINDDUN.
- **PII loss floor.** Threats touching PII / personal data (detected
  via `linddun` tag or PII-class NIST AI 100-2 ID) now have a
  $50k loss_low / $500k loss_high floor per IBM CoDB 2025 average
  per-record cost. Sub-$50k loss claims on a PII threat are
  indefensible to a regulator.

### Added — 205 KB cross-walks

Across 19 playbooks: 57 NIST AI 100-2 references, 33 OWASP ML 2023, 40
LINDDUN, 75 Singapore CSA Guidelines. Curation: prompt-injection
threats → `NIST_GAI_PROMPT_INJECTION_*`; data-poisoning →
`NIST_PAI_POISONING_*`; privacy → `NIST_PAI_PRIVACY_INVERSION /
MEMBERSHIP`; backdoor → `NIST_PAI_POISONING_BACKDOOR`; etc.

### Added — 5 content additions from cross-tool gap analysis

- **`agent.T_AGENT_011`** — Agent-identity lifecycle abuse / orphaned
  service accounts. Cross-walks to OWASP API5, ATT&CK T1078.004 +
  T1098.003, CSA `HUMAN.01 / DEPLOY.01 / OPERATE.03`. Gap relative to
  the existing playbook: AGT-coverage was scoped to runtime / tooling;
  this surfaces the lifecycle / cleanup gap explicitly.
- **`rag_vector_store.T_RAG_006`** — Identity-propagation failure into
  RAG grounding (OBO / Entra group-claim drift). Per-document ACL not
  carried into embedding metadata; agent's MI returns documents the
  user can't normally read. The most-cited gap in commercial AI threat
  modelers' Foundry / RAG patterns.
- **`llm_inference.T_LLMINF_008`** — Multimodal hidden-payload
  injection (steganographic image, audio adversarial signal). Vision
  / audio guardrails routinely don't inspect their modality. Maps to
  `NIST_GAI_PROMPT_INJECTION_INDIRECT`.
- **`cache_store.T_CACHE_003`** — Cross-user KV-cache leak in vLLM /
  TGI / SGLang. Multi-tenant LLM serving stacks default to prefix-
  caching that leaks across users when system prompts share a prefix.
- **`vendor_threats/aws_bedrock.yaml T_AWS_BEDROCK_007`** — Bedrock
  Agent action-group input-schema fuzzing → injected tool calls.
  Distinct from BOLA on session attributes — this uses the documented
  schema but values out-of-band for the backend, surfacing private
  state in error strings.

### Real-world re-test results (frozen .exe v0.16.2)

| Architecture | v0.16.0 | v0.16.1 | **v0.16.2** | Notes |
|---|---|---|---|---|
| `rag_system.yaml` (selftest) | 35 | 35 | **38** | T_AGENT_011 + T_RAG_006 + T_CACHE_003 fire |
| `multi_tenant_llm_platform.yaml` | 73 | 71 | **75** | KV-cache + ACL-drift threats fire |

352 unit tests passing. selftest 11/11.

### Limitations of this release (carried to v0.16.3)

- The comparator agent's recommendation to **auto-synthesise a
  knowledge_base component when an `agent` is present in AWS Bedrock
  vendor context** (so the KB confused-deputy threat class is always
  analysed even on incomplete diagrams) is deferred — needs careful
  scope-gate design to not introduce phantom components in the
  reviewer's diagram.
- Bedrock Agent severity-promotion rule: when an agent has
  write-scope tools, `T_AGENT_001` should be Critical regardless of
  default likelihood. Deferred — needs tool-scope metadata schema.

## [0.16.1] — 2026-05-10 — vendor overlays applied + scoring honesty + scale-aware priors

This release closes the three highest-leverage findings from the v0.15.1
expert critiques that v0.16.0 left deferred. Engine work only — no
playbook content changed beyond the cross-walk pass.

### Wired (v0.16.0 deferral)

- **Vendor threat overlays now apply during analysis.** `kb/vendor_threats/*.yaml`
  was loading correctly in v0.16.0 but the workflow didn't iterate them.
  `engines/stride_ai.py:_apply_vendor_overlays()` now emits each overlay
  threat for components whose metadata matches the overlay's
  applicability predicate. Real-world impact: on the AWS GenAI RAG
  reference architecture, **11 vendor-overlay threats now fire**
  (AWS IAM PassRole, Bedrock BOLA, Identity Center proliferation,
  IMDSv1 abuse, GuardDuty bypass, etc.) — content the red-team expert
  flagged as missing in v0.15.1.

### Fixed — risk-assessment expert findings R-1, R-5 + M-06

- **Per-threat computed confidence (R-5, M-05).** Dropped the hard-coded
  `confidence: 0.95` on every playbook threat. `engines/risk.py:_compute_confidence()`
  now derives confidence from component-metadata richness + framework-
  coverage breadth + generic-stub penalty. Confidence range now 0.4–0.95
  with real variation across threats.
- **Severity recalibration (M-06).** `_bucket_from_score()` collapses
  high-risk low-confidence threats to lower severity buckets via
  `effective_severity = bucket(risk_score × confidence)`. Takes the
  lower of (matrix bucket, score bucket) — caps severity by BOTH
  confidence-weighted score and the 5×5 matrix. Result: the rag_system
  selftest goes from **0 low / 35 high+critical** in v0.15.1 to
  **26 medium / 7 high / 1 critical / 1 low** in v0.16.1 — a real
  risk-register distribution.
- **Scale-aware FAIR priors (R-1, R-2).** New `kb/priors/loss_priors.yaml`
  with 14 tiers keyed on `(industry × revenue_bucket × deployment_stage)`.
  System YAML gets 3 new optional fields: `industry`, `revenue_bucket`,
  `deployment_stage`. Quantitative engine looks up the matching tier
  and caps loss ranges accordingly. The "$10B ALE on a POC" defect from
  the v0.15.1 risk-assessment expert critique is **fixed**:

  | Same `T_RAG_001` indirect prompt injection, same architecture | ALE range / year |
  |---|---|
  | tier1_bank / production / over_5b | $200M – $10B |
  | tier1_bank / poc / unknown | $40k – $100M |
  | tech_saas / production / 500m_to_5b | $200M – $2B |
  | smb_other / poc / under_50m | **$3k – $1.5M** |
  | midmarket_other / pilot / unknown | $3k – $1.5M |

### Added

- `kb/priors/loss_priors.yaml` — 14 industry-stage tier definitions
  (tier1 bank, regional bank/fintech/insurer, healthcare/pharma,
  govt/critical infrastructure, large tech, midmarket tech, SMB tech,
  industrial, generic midmarket, catchall).
- `kb.lookup_loss_prior(industry, revenue, stage)` — most-specific-tier
  resolution with case-insensitive matching.
- `System.industry`, `System.revenue_bucket`, `System.deployment_stage`
  — Literal-typed fields; defaults to (`midmarket_other`, `unknown`,
  `pilot`) so existing samples keep working.

### Real-world re-test results

| Architecture | v0.15.1 | v0.16.0 | **v0.16.1** | v0.16.1 severity |
|---|---|---|---|---|
| AWS GenAI Text/RAG | 65 | 59 | **70** | 1 crit / 24 high / 44 med / 1 low |
| AWS Bedrock Agent | 52 | 48 | **54** | 0 crit / 17 high / 36 med / 1 low |
| Azure Foundry Basic Chat | 40 | 39 | **39** | 1 crit / 14 high / 23 med / 1 low |
| Pure-IT 3-tier (control) | rejected | rejected | rejected | — |

Confidence histogram on the AWS RAG report (v0.16.1):
**16 threats at 0.80**, **54 at 0.90** — real differentiation, not
the constant 0.95 of every prior release.

352 unit tests passing. selftest 11/11.

## [0.16.0] — 2026-05-10 — comprehensive component catalog + applicability predicates

### Headline

ATMS now models **121 component types** (was 40) and ships catalogs for
**507 specific cloud services** across AWS / Azure / GCP / OCI / Alibaba.
Threats are gated by **applicability predicates** that suppress
vendor-mismatched emissions (Cognito-as-Active-Directory, CloudFront-as-F5
firmware, multi-agent threats on single-agent architectures). This is the
breadth-and-precision release.

### Added

- **41 new component types in `ComponentType`** spanning AI/ML expansion
  (`ml_feature_store`, `ml_pipeline_orchestrator`, `ml_inference_endpoint`,
  `vision_pipeline`, `speech_pipeline`, `content_safety_classifier`),
  cloud-compute (`cloud_compute`, `container_orchestrator`,
  `container_registry`, `edge_compute`, `batch_compute`,
  `high_performance_compute`), storage (`block_storage`, `file_storage`,
  `data_lake`, `data_warehouse`, `cache_store`, `backup_service`),
  databases (`nosql_database`, `graph_database`, `time_series_database`),
  streaming (`stream_processor`, `etl_orchestrator`), network
  (`cdn`, `service_mesh`, `private_link`, `transit_gateway`, `dns_service`),
  security appliances (`waf`, `ids_ips`, `ddos_mitigation`, `web_proxy`,
  `reverse_proxy`, `router`, `switch_l3`, `sdwan_edge`,
  `network_access_control`, `bastion_host`, `pam_vault`), identity
  (`identity_provider`, `sso_service`, `ciam_platform`,
  `certificate_manager`, `hsm`), security tooling (`siem`, `soar`,
  `edr_agent`, `vulnerability_scanner`, `casb`, `dlp`, `cspm`,
  `container_security`, `security_data_lake`), observability split
  (`log_aggregator`, `metrics_platform`, `tracing_platform`,
  `alerting_platform`), endpoints (`server_windows`, `server_linux`,
  `server_unix`, `mainframe`, `virtual_desktop`, `mobile_device`,
  `mdm_emm`), OT expansion (`rtu`, `ied`, `hmi`, `dcs`, `sis`,
  `iot_gateway`, `ot_jumphost`), and dev-infra (`file_transfer_service`,
  `code_repository`, `ci_cd_pipeline`, `artifact_registry`,
  `build_runner`, `feature_flag_service`, `iac_template_registry`).

- **5 cloud-service catalogs** at `kb/cloud_catalog/` totalling
  **507 specific cloud services**:
  - `aws.yaml` — 139 services (Compute, Storage, Database, Network,
    Security/Identity, Monitoring, DevOps, Messaging, Data, AI/ML
    including all Bedrock + AgentCore + SageMaker variants)
  - `azure.yaml` — 138 services (all Foundry / Cognitive Services /
    Azure ML / Entra / Defender / Synapse / Cosmos DB families)
  - `gcp.yaml` — 87 services (Vertex AI variants, BigQuery, Spanner,
    GKE, Cloud Run, Gemini API)
  - `oci.yaml` — 73 services (Autonomous Database, OCI Generative AI,
    Data Science, OKE)
  - `alibaba.yaml` — 70 services (PAI, Model Studio / Qwen, ECS, OSS)

  Each entry carries `vendor`, `product`, `component_type`,
  `service_category`, `applies_to_ai_workflows`, and an AI-specific
  context note. Users set `metadata: {vendor: AWS, product: dynamodb}`
  and the engine looks up the canonical component type and applicable
  threats.

- **Applicability-predicate engine** at `src/atms/engines/applicability.py`.
  Every threat in a playbook or vendor overlay can declare
  `requires:` (AND-conjunction of field matches), `not_applicable_to:`
  (OR-suppression list), and `applicable_to_topology:` (system-level
  predicates: `has_multi_agent`, `has_outbound_internet`,
  `has_mtls_internal`). Closes the false-positive class identified in
  v0.15.1 expert review:
  - Cognito (managed IdP) no longer gets Kerberoast / DCSync / GPO
    threats from the `directory_service` playbook.
  - AWS WAF / Cloud Armor / Cloudflare no longer get "outdated firmware
    on management plane" from the `firewall` playbook.
  - CloudFront / Azure Front Door no longer get F5 BIG-IP CVE
    threats from the `load_balancer` playbook.
  - Single-orchestrator architectures no longer get "Rogue agent in
    multi-agent system" emissions.

- **6 vendor-specific threat overlay files** at `kb/vendor_threats/` —
  36 cloud-vendor-specific threats:
  - `aws_iam.yaml` (8): cross-account confused-deputy via AssumeRole,
    PassRole abuse, Lambda role chaining → Bedrock invocation
    impersonation, IMDSv1 metadata abuse, IAM Identity Center
    proliferation, CloudTrail tampering.
  - `aws_bedrock.yaml` (6): BOLA on Bedrock Agent action-groups
    (sessionAttributes), function-name shadowing, prompt-extraction via
    `traceLevel=enabled`, cross-account `bedrock:InvokeAgent`, KB
    poisoning, Guardrails bypass.
  - `azure_appservice.yaml` (6): Easy Auth bypass via
    `X-MS-CLIENT-PRINCIPAL` header spoofing, managed-identity SSRF to
    `/MSI/token`, Kudu console abuse, slot-swap credential leak.
  - `azure_foundry.yaml` (5): connection-definition tampering, Cosmos
    DB exfil from MS-managed Agent Service backplane, AI Search BYO
    index poisoning, App Insights trace leakage.
  - `gcp_iam.yaml` (6): Service Account impersonation, IAP bypass via
    header injection, Workload Identity Federation misuse, GCE
    metadata abuse.
  - `gcp_vertex.yaml` (5): Agent Builder custom-container RCE, Model
    Garden supply-chain, custom-prediction-routine RCE, Gemini API
    content-safety bypass.

- **21 new component-type playbooks** at `kb/playbooks/` for
  previously-unmodelled types: `cloud_compute`, `container_orchestrator`,
  `waf`, `identity_provider`, `ml_inference_endpoint`, `nosql_database`,
  `siem`, `edr_agent`, `ids_ips`, `ci_cd_pipeline`, `code_repository`,
  `bastion_host`, `cache_store`, `stream_processor`, `data_warehouse`,
  `cdn`, `sso_service`, `artifact_registry`, `virtual_desktop`,
  `vulnerability_scanner`, `hsm`.

- **`engines/ai_scope.py`** — 8 new AI primary types
  (`ml_feature_store`, `ml_pipeline_orchestrator`, `ml_data_labeling`,
  `ml_experiment_tracker`, `ml_inference_endpoint`, `vision_pipeline`,
  `speech_pipeline`, `content_safety_classifier`).

- **200+ autocorrect synonyms** for the new types, so users can write
  `type: dynamodb` and ATMS infers `nosql_database`.

- **13 new applicability tests** in `tests/test_applicability.py`
  pinning the predicate-engine semantics + false-positive suppression.

### Changed

- `src/atms/engines/stride_ai.py` and `src/atms/workflow.py` now thread
  the `System` object through `enumerate_threats()` so topology
  predicates can resolve `has_multi_agent`, `has_outbound_internet`,
  `has_mtls_internal`.

### Test results

- 352 unit tests passing (was 339; +13 from applicability suite).
- 11 / 11 selftest samples pass — none broken by the gating.
- Real-world re-test against the 3 reference architectures:
  - AWS Generative AI App Builder Text/RAG: 65 → 59 threats; Cognito
    Kerberoast finding **suppressed**, WAF firmware finding
    **suppressed**, CloudFront F5 finding **suppressed**.
  - AWS Bedrock Agent: 52 → 48 threats; same suppressions.
  - Azure Foundry Basic Chat: 40 → 39 threats; AI-primary scoring
    unchanged.
  - Pure-IT 3-tier (negative control): rejected at load time.

### Known unfinished (v0.16.1 plan)

- Vendor threat overlays load but the engine doesn't yet **apply** them
  per-component. Wiring is a small change (~30 LOC) deferred to v0.16.1.
- 4 KBs are still under-referenced (NIST AI 100-2, OWASP ML, LINDDUN,
  CSA Singapore) per an internal content audit. Cross-walking these into
  existing playbooks lifts coverage in a single content pass.

## [0.15.1] — 2026-05-10

### Added

- **`TI_INGESTION.md`** — comprehensive threat-intelligence ingestion guide.
  Covers every input format (Nessus / SARIF / STIX 2.1 / generic CSV /
  Caldera / Atomic / BAS), the matcher's routing logic (CPE / pURL /
  CIDR-IP / hostname / product / vendor), the status-promotion model
  (`hypothetical → likely → observed → exploited`), and a pinned
  air-gapped workflow for environments with zero outbound HTTP.
- **`ROADMAP.md`** — public-facing positioning document grounded in
  published pain-point literature. Names which pains ATMS solves today,
  which it commits to fix in v0.15.2 / v0.16 / v0.17 / v0.18, and which
  features the project deliberately won't ship.

### Changed (repo cleanup ahead of open-source release)

- Local development scaffolding and editor/tooling config are gitignored
  and are not part of the open-source tree.
- CHANGELOG prose for v0.10–v0.15.0 release notes was reworded for
  brevity. Technical content unchanged.
- README dropped the development-tooling reference.

## [0.15.0] — 2026-05-10 — strategic refactor (BREAKING)

### Why

A v0.14.x report uploaded by the maintainer revealed a fundamental design flaw:
ATMS was happily analysing a banking ATM system (literal Automated Teller
Machine — Border Routers, Firewall Gateway, L2 Switches, ATM Front/Back-end,
AS400 LPAR, no AI components anywhere) and producing a report tagged with
`OWASP LLM01:2025`, `MITRE ATLAS AML.T0048`, `MAESTRO M.L1.04`. Real false
positives, at scale, against an audit-defensible product positioning.

Two simultaneous problems:

1. **Scope mismatch.** ATMS marketed itself as "AI Threat Modeling Studio"
 but had no gate preventing pure-IT systems from being analysed. The
 cloud / MAESTRO / OWASP-LLM enrichers ran unconditionally, tagging any
 component the user described.

2. **Methodology branding.** The README listed "STRIDE-AI" and "DREAD-AI"
 alongside OWASP LLM, MITRE ATLAS, NIST AI 100-2 — as if peer-reviewed
 methodologies. They aren't. STRIDE is real (Microsoft, 1999) and DREAD
 is real (deprecated by Microsoft in 2008). "STRIDE-AI" / "DREAD-AI" as
 named methodologies have no canonical source.

### What changed (BREAKING)

- **`src/atms/engines/ai_scope.py`** — new module that classifies every
 component as `primary` (AI/ML/agentic primitive), `adjacent` (non-AI but
 in the dataflow blast radius of an AI primary), or `out_of_scope`.
 `find_ai_components`, `compute_ai_blast_radius` (BFS forward + reverse,
 bounded at 3 hops), `ai_relevance`, `ai_provenance`, plus
 `NoAIComponentsError`.
- **`src/atms/workflow.py`** — analysis now starts with the AI-scope gate.
 A System with zero AI components raises `NoAIComponentsError` (extends
 `ValueError`) with a clear message pointing the caller at general-
 purpose threat modelers. For hybrid systems, only components in the AI
 blast radius produce threats; out-of-scope components emit zero. Every
 emitted threat carries `ai_relevance` + `ai_caused_by` provenance.
- **`src/atms/models.py`** — `Threat.ai_caused_by` (list of AI component
 IDs) and `Threat.ai_relevance` (`primary` / `adjacent` / `""`).
- **`src/atms/cli.py`** — `_load_system_yaml` warns at load time when no
 AI components are present. `run_analysis` catches `NoAIComponentsError`
 and exits cleanly with the friendly message instead of a stack trace.
- **`src/atms/web.py`** — the existing `except ValueError` catches the
 rejection automatically and shows the friendly HTML error.

### What's renamed (still BREAKING for docs)

- `STRIDE-AI` → `STRIDE for AI` in user-facing strings (about page,
 index page, methodology dropdowns, report templates).
- `DREAD-AI` → `Likelihood × Impact (DREAD-derived)` in user-facing
 strings. The risk-scoring math is unchanged; only the label.
- The `stride-ai` CLI methodology flag is kept as the backwards-
 compatible alias.

### What's added

- **`kb/csa_singapore/guidelines.yaml`** — 13 principles from the Singapore
 Cyber Security Agency's *Guidelines on Securing AI Systems* (October 2024),
 mapped to component types and cross-walked to OWASP LLM / MAESTRO / NIST.
- **`samples/bank_with_llm_fraud.yaml`** — the canonical hybrid demo. A
 retail bank's ATM + AS400 + Oracle core estate with a fraud-detection
 LLM bolted on. Customer-facing IT (ATM terminal, ATM private network,
 customer, web banking) is correctly out-of-scope and emits zero threats;
 the AI primaries + AI-adjacent core (DB, queue, IAM, vault, AS400-via-
 data-flow) get full coverage with `ai_caused_by` pointing at the LLM.
- **`tests/test_ai_scope.py`** — 10 explicit tests for the gate, blast
 radius, hop limit, provenance tagging, and the bank-sample correctness
 invariant. The pure-IT-rejection regression test pins the bug that
 motivated this release.
- Markdown + HTML report templates render `ai_relevance` and
 `ai_caused_by`.

### Test fixtures updated

10 test fixtures that previously used non-AI components (lone `vpn_gateway`,
lone `email_server`, etc.) now include an `llm_inference` so they pass the
new gate. Threat-count thresholds in three IaC / sample tests were lowered
(30 → 15, 40 → 25, 60 → 50) to reflect the more conservative scoping.

339 unit tests passing (was 329). selftest 11/11 (was 10/10; +bank_with_llm_fraud).

### Migration guide

If you have existing systems that ATMS analysed under v0.14.x:

- **Pure-AI systems (RAG, agentic, LLM-only)** — work unchanged.
- **Hybrid systems with at least one `agent` / `llm_inference` /
 `rag_vector_store` / etc.** — work unchanged but threat counts will
 drop (out-of-scope components no longer emit threats). The drop is the
 v0.15.0 fix; if you want the old behavior back, that means re-classifying
 the missing components as AI-bearing via `metadata.ai_integration: true`.
- **Pure-IT systems (no AI components)** — now rejected at load time with
 a clear message. Use OWASP Threat Dragon / IriusRisk / Microsoft Threat
 Modeling Tool instead.

## [0.14.10] — 2026-05-10

### Fixed — autocorrect now also applies to CLI `atms analyze`

v0.14.9 fixed the autocorrect path for the web UI but the CLI still
bounced users with the raw Pydantic blob. Extracted the helpers to
`src/atms/yaml_autocorrect.py` so both surfaces use the same code:

- `src/atms/cli.py:_load_system_yaml` now runs `autocorrect_system_yaml`
 before `model_validate`, prints a yellow notice when corrections
 were made, and uses `format_validation_error` for any error that
 survives. The CLI experience now matches the web UI: the exact
 `type: 'IoT Device'` regression no longer crashes either path.
- `src/atms/yaml_autocorrect.py` is the new shared home for the
 helpers (`coerce_component_type`, `autocorrect_system_yaml`,
 `format_validation_error`).

329 unit tests still pass.

## [0.14.9] — 2026-05-10

### Fixed — post-parse YAML editing was hostile to non-experts

A user uploaded a `.vsdx` and got a wall of Pydantic literal-error JSON when
they hand-edited a component's `type:` to `IoT Device` (the human label)
instead of `iot_device` (the enum slug). The error blob named all 40 valid
types in one paragraph; there was no actionable advice; and the
post-parse YAML was littered with empty-default noise (`controls: []`,
`metadata: {}`, `maestro_layers: []`) that made the file painful to scan.

Three fixes:

1. **Auto-correct unknown component types in `/analyze` and `/editor/analyze`.**
 - `src/atms/web.py` now slug-normalises (`'IoT Device'` → `'iot_device'`),
 resolves a small synonym dictionary (`vault → secrets_vault`,
 `kafka → message_queue`, `kubernetes → container_runtime`,
 `s3 → object_storage`, ...), and falls back to `other` when nothing fits.
 - The corrections list is surfaced as a notice banner on both the
 analyze form (re-render path) and the report (success path), so the
 reviewer sees what was changed.
2. **Friendly validation errors.** Pydantic's raw `1 validation error for
 System ... [type=literal_error, input_value=...]` is replaced by a
 per-component sentence: `Unknown component type 'IoT Device' on
 component 'Smart sensor' (try 'iot_device'). Use 'other' if no
 specific type fits.` The error block now also surfaces buttons to
 *Open visual editor* and *Load a sample*.
3. **Compact YAML on parse output.** The post-VSDX-parse / post-IaC-parse /
 editor-save YAML is now produced via `model_dump(exclude_defaults=True,
 exclude_none=True)` plus a recursive prune that drops empty list / empty
 dict / empty string fields. The 22-line VSDX output replaces the old
 80+-line dump for the same file.

### Other UX fixes

- VSDX descriptions are normalised: multi-line shape text + bullet dashes
 (`-VPN Tunnel\n-Encryption`) collapse to a single readable sentence
 (`Border Routers; VPN Tunnel; Encryption`). Caps at 500 chars.
- The web home page now has a one-line tip under the action row: *"editing
 raw YAML is fragile — use the visual editor for type dropdowns."* The
 Editor button is renamed *Open visual editor* (was just *Editor*).

### New tests (+25)

- `tests/test_yaml_autocorrect.py` — covers `_coerce_component_type`,
 `_autocorrect_system_yaml`, `_format_validation_error`, `_system_to_yaml`,
 the `IoT Device` regression specifically, the synonym dictionary, the
 invariant that VSDX `TYPE_KEYWORDS` keys are always valid `ComponentType`
 values, and that the VSDX classifier resolves IoT-shaped labels to
 `iot_device`.

329 unit tests passing (was 304). selftest 10/10. The fix path that
broke v0.14.8 in the screenshot is now a pinned regression test.

## [0.14.8] — 2026-05-10

### Fixed — substantive bugs

- **`src/atms/evidence/matcher.py`** — `match_evidence` now accepts CIDR
 / IP-range / single-IP `affected_asset` values via `ipaddress`. A
 Nessus row reporting `affected_asset=10.0.0.0/24` now routes to a
 component whose `metadata.ip` is inside that range; previously the
 exact-string compare missed every CIDR-shaped row. Component-level
 `metadata.cidr` is also honoured (network_segment overlap).
- **`src/atms/reporting/sarif_export.py`** — cap `shortDescription.text`
 at 256 chars so GitHub code-scanning accepts the SARIF for any threat
 with a long title. `fullDescription` was already capped at 1000.

### Added — coverage of previously-undocumented surface area

- **`SECURITY.md`** — vulnerability-disclosure policy + table of
 load-bearing security contracts (TM_001 / TM_011..015).
- **`THREAT_MODEL.md`** — TM_011 (XXE in Nessus / .vsdx via
 defusedxml), TM_012 (Mermaid `securityLevel: 'strict'` for HTML
 reports), TM_013 (DOM-API editor build, no `innerHTML`), TM_014
 (`/redteam/ingest` methodology allow-list), TM_015 (PyInstaller
 excludes enforcing the AI-free contract).
- **`TESTING.md`** — first-30-minutes tester onboarding guide.
- **`.github/workflows/ci.yml`** — pytest + selftest on Linux + Windows
 across Python 3.11/3.12/3.13; on tag pushes also builds `atms.exe`,
 the Inno Setup installer, and a draft GitHub release with both
 attached. Replaces the "CI build (future)" placeholder in
 `BUILDING.md`.
- **`samples/autonomous_coding_agent.yaml`** — 11-component sample
 modelling a long-running coding agent with MCP tooling, ephemeral
 sandbox, Vault-issued per-job secrets. 54 threats, 10 paths.
- **`samples/multi_tenant_llm_platform.yaml`** — 18-component sample
 modelling a tenant-isolated LLM platform (per-tenant KMS, per-tenant
 vector namespaces, shared inference + cache). 80 threats, 10 paths.
- **`tests/test_perf_smoke.py`** — 100-component synthetic system
 must analyse in <45s; determinism guard for re-runs.
- **`tests/test_vision_optional.py`** — vision module imports without
 `anthropic` installed; friendly error when no API key; AI-free
 contract regression test against `atms.spec` `excludes`.

### Documentation

- **`README.md`** — KB tree expanded from 15 playbooks to the actual 40
 (grouped by AI / cloud / identity / endpoint / OT / boundary). Architecture
 tree expanded from 5 modules to all 18+ source dirs (engines, evidence,
 feeds, ingest, reporting, paths, etc.). Tests count corrected.
- **`CONTRIBUTING.md`** — links to `SECURITY.md`; tests + selftest
 invocations corrected to use `PYTHONPATH=src`.

### Test coverage closed

- D3FEND first-match-wins (regression test against KB-reorder hazard).
- Quantitative engine survives inverted (`freq_low > freq_high`) and
 asymmetric author overrides without producing NaN / negative ALE.
- OTM round-trip with a typo in `attributes.atms_component_type`
 resolves to `other` rather than fuzzy-matching to a wrong type.
- Terraform heredoc with marker keyword inside the body — second
 resource after the heredoc must still parse.

304 unit tests passing (was 290 at v0.14.7; +14 new).

## [0.14.7] — 2026-05-10

### Fixed (test gaps + doc/UX)

Two release audits reviewed (a) test-suite coverage gaps and (b)
docs vs. code consistency. Returned 8 + 10 findings; the substantive
correctness ones land here.

#### MED — Navigator export silently empty for cloud-only systems

- **`src/atms/reporting/navigator.py:67-91`** — when a model has zero
 ATLAS techniques but non-zero ATT&CK Cloud / Enterprise IDs (e.g. a
 Terraform-ingested SCADA / database stack), Navigator emitted an
 empty ATLAS layer with `techniques: []`. The reviewer thinks nothing
 was found. The renderer now silently switches the layer's domain to
 `enterprise-attack` and populates from `attack_enterprise +
 attack_cloud` when ATLAS is empty. Single-dict shape preserved for
 backwards compatibility.
- Test: `test_navigator_falls_back_to_enterprise_for_cloud_only_systems`.

#### MED — duplicate Threat IDs silently merge in STIX export

- **`src/atms/workflow.py:81-105`** — STIX UUIDs are derived from
 Threat.id, so two threats sharing an ID collapse into one row in
 STIX consumers. The dedup is now explicit: drop later occurrences
 and emit a `logging.warning` listing the dropped IDs (capped at 5).
- Test: `test_workflow_drops_duplicate_threat_ids`.

#### LOW — KB threat-level dangling ATT&CK references

- **`kb/mitre_attack_enterprise/techniques.yaml`** — added `T1059`
 (parent of T1059.007) and `T1530` (Data from Cloud Storage) so the
 3 dangling references in `database/T_DB_003`, `scada/T_SCADA_001`,
 `scada/T_SCADA_002` resolve. The IDs are real upstream MITRE
 techniques; only our local catalogue subset was missing them.
- Cross-ref scan now reports zero dangling threat-level references.

### Documentation

- **`README.md`** — replaced stale `0.5.0` installer-filename strings
 (2 occurrences); test count `274` → `290`; "36 tests cover ..." →
 "290 tests cover ...".
- **`USAGE.md`** — added section 17 (`atms diff`) and section 18
 (`atms review`); web-UI page list expanded from 5 routes to all 14
 user-visible routes (`/editor`, `/maestro`, `/agentic`, `/evidence`,
 `/redteam`, `/iac`, `/compliance`, `/devices`, `/healthz`, ...).
- **`AI_DEPENDENCIES.md`** — softened the absolute "no outbound HTTP
 calls" line to clarify that `atms refresh-feeds` and `atms cve-lookup`
 are the explicit, opt-in egress points.

290 unit tests passing (+2 vs v0.14.6).

## [0.14.6] — 2026-05-10

### Fixed — Caldera flat-shape technique IDs

A blind smoke run on v0.14.5 surfaced a UX paper-cut: the Caldera red-team
parser only read `link.ability.technique_id`, the canonical v2/v4 nested
shape. Hand-rolled exports and a few third-party tools that put
`technique_id` directly on the link silently lost the technique anchor —
which meant downstream evidence correlation failed to promote the matched
threat to `exploited`.

- **`src/atms/evidence/redteam.py:95`** — `parse_caldera()` now falls back
 through `link.technique_id`, `link.technique`, `link.attack_id`, and
 `ability.attack_id` after the canonical `ability.technique_id`. The
 emitted Evidence row carries both `attack:<id>` and the bare ID in
 `references` so the existing matcher fires unchanged.
- **`tests/test_v14_pipelines.py`** — `test_caldera_flat_shape_link_technique_id`
 asserts both flat shapes (`technique_id` and `attack_id` directly on the
 link) emit the right `attack:<id>` reference.

288 unit tests passing (+1).

## [0.14.5] — 2026-05-10

### Fixed — release build-pipeline audit

A release audit audited the build pipeline (PyInstaller spec,
Inno Setup script, build scripts, paths, pyproject) — the one area
no previous reviewer had touched. Returned 1 HIGH, 2 MED, 2 LOW.

#### HIGH — wheel installs ship a broken Web UI

- **`pyproject.toml`** — `[tool.hatch.build.targets.wheel.shared-data]`
 bundled `kb` and `templates` but not `src/atms/static`. Users running
 `pip install atms` got the Web UI without
 `static/mermaid.min.js` / `atms-mermaid.js` / `atms-editor.js` —
 the inline DFD render and the `/editor` page silently broke. v0.14.5
 adds `"src/atms/static" = "atms/static"`. The `.exe` build was
 unaffected (PyInstaller spec declares static separately).

#### MED — installer fallback could silently mislabel a release

- **`installer/atms.iss:18`** — fallback `MyAppVersion "0.5.0"` was
 9 minor versions stale. If `build_installer.py` ever forgot to pass
 `/DMyAppVersion=...` (e.g. CI misconfiguration), the installer would
 ship labelled "0.5.0". v0.14.5 replaces the fallback with `#error`
 so a missing flag fails ISCC loudly instead of silently mislabeling.

#### MED — defensive PyInstaller `hiddenimports`

- **`atms.spec:42-82`** — declared every v0.10–v0.14 engine, ingest,
 reporting, evidence, and feeds module explicitly. PyInstaller's
 static analysis happens to find these today, but a future Python or
 PyInstaller release that tightens detection would have produced
 cryptic `ImportError`s. The cost of a comprehensive declaration is
 one block of code; the alternative is a brittle freeze.

#### LOW — defensive AI-leakage parity

- **`atms.spec:106-114`** — added `voyageai` to the SDK exclude list
 for parity with the device catalog (which mentions Voyage embeddings
 as an opt-in source). No runtime path imported it; defensive only.

#### LOW — version cross-check

- **`scripts/build_installer.py:read_version()`** now verifies
 `src/atms/__init__.py` `__version__` matches `pyproject.toml`
 `version`. Refuses to build a mislabeled installer if they drift.
 v0.14.5 is the first version to enforce this; running build with
 mismatched values now exits with a clear "update both, then retry"
 message.

#### Stale docs

- **`BUILDING.md`** — replaced v0.5.0 example version strings with
 `X.Y.Z` placeholders that match the user's actual build.

### Tests
- 287 total tests, all passing. 8/8 selftest samples pass.
- The version cross-check inside `build_installer.py` is a build-time
 invariant, not a unit test, so it doesn't add a regression test —
 but the build pipeline itself is the test.

## [0.14.4] — 2026-05-10

### Fixed

A release audit (web-developer + test-writer focus) audited
client-side code and the older test files. Two HIGH-severity findings
fixed plus several MED defence-in-depth + test-quality items.

#### HIGH — DOM XSS in editor

- **`src/atms/static/atms-editor.js:402`** — the dataflow row builder
 used `innerHTML` with raw `d.target` interpolation. A user setting a
 component ID to `<img src=x onerror=alert(1)>` would XSS the editor
 on next render. v0.14.4 rebuilds the row using DOM APIs
 (`createElement` + `textContent`) so user-controlled IDs never reach
 HTML parsing.
- **`escapeAttr`** now also escapes `<`, `>`, `'` (was only `&` and
 `"`). Defence-in-depth for any future template change to
 single-quoted attributes.

#### HIGH — Mermaid `securityLevel` defeat in standalone HTML report

- **`src/atms/templates/report.html.j2:206`** — the standalone HTML
 report inlines its own Mermaid bootstrap with `securityLevel: 'loose'`,
 which silently defeats the v0.13/v0.14.2 strict-mode hardening for
 any externally-emailed report. Component names are user-controlled
 and flow into the Mermaid source via `render_mermaid`. v0.14.4 sets
 `securityLevel: 'strict'` here too — matches the `static/atms-mermaid.js`
 contract.

#### MED — handler leak in editor

- **`src/atms/static/atms-editor.js`** — every render registered a new
 `mousemove` + `mouseup` listener on `window` per node, leaking O(N×renders)
 handlers. Replaced with a single global drag handler keyed off
 `state.draggingNodeId`. Page stays responsive after extended editing.

#### MED — status-message bug in editor

- **`src/atms/static/atms-editor.js:267`** — after the user connected
 two nodes, the status bar always reported `Connected ? -> targetID`
 because `state.edgeSource` was cleared two lines earlier. Now
 captures the source ID before clearing.

#### MED — tautological tests in `test_web.py`

- **`test_analyze_invalid`** previously asserted `"Error" in r.text or
 "error" in r.text` — `"error"` (lowercase) appears in the
 `.alert-error` CSS class on every render of `index.html`, so the OR
 always matched. v0.14.4 asserts the SPECIFIC `<strong>Error:</strong>`
 banner that only renders when an error is set.
- **`test_load_sample_path_traversal_blocked`** asserted
 `"/etc/passwd" not in r.text` — even a successful traversal that
 dumped `root:x:0:0:` doesn't contain the literal string `/etc/passwd`.
 v0.14.4 asserts the explicit `Sample not found.` message + a defence-
 in-depth check that no `root:x:` or `PRIVATE KEY` content appears.

#### Low

- **`src/atms/templates/report.md.j2`** — added a header comment
 documenting the autoescape-disabled contract (Markdown escaping
 rules differ from HTML; downstream consumers piping `.md` through
 HTML need to escape themselves).
- **`src/atms/ingest/docker_compose.py`** — bare-language image
 fallbacks (`python` / `node` / `openjdk` / `php`) used to default
 to `web_application`. Python images host ML jobs, agents, and
 batch processors as often as web apps; silent classification is
 worse than no classification. They now fall through to
 `container_runtime` (the safe default in `_classify_image`).
 Regression test:
 `test_compose_python_image_falls_back_to_container_runtime`.

#### Additional fixes (also v0.14.4)

A follow-up audit did a fresh blind smoke-test on the v0.14.3 `.exe`
and found two hard CLI failures + cosmetic version-stamp drift. All
fixed in this same release:

- **HIGH — CJK / non-ASCII CLI crash on Windows.** `console.print(f"Analyzing: {system.name}")` blew up with `UnicodeEncodeError` from rich's `legacy_windows_render` cp1252 path on any CJK / Cyrillic / Arabic component name. v0.14.4: force UTF-8 on `sys.stdout` / `sys.stderr` at CLI import (`sys.stdout.reconfigure(encoding="utf-8")`) AND construct rich's `Console` with `legacy_windows=False` to bypass the legacy code-page path entirely.
- **HIGH — malformed-input file leak.** `yaml.safe_load(path.read_text(encoding="utf-8"))` raised `UnicodeDecodeError` (non-UTF-8 file) or `yaml.YAMLError` (malformed YAML) straight to a stack trace. v0.14.4: every CLI command that loads a System YAML now goes through a `_load_system_yaml` wrapper that catches `UnicodeDecodeError`, `yaml.YAMLError`, and Pydantic `ValidationError`, and exits 2 with a one-line friendly message instead.
- **WARN — `tool_version` stamped as `0.2.0` in every generated report.** The default on `ThreatModel.tool_version` was a hard-coded literal that hadn't been bumped since v0.2. v0.14.4: now uses `Field(default_factory=lambda: __version__)` so reports always carry the actual ATMS version that produced them.
- **WARN — `/redteam/ingest` missing-file response was raw JSON 422.** A user submitting the form without picking a file got FastAPI's default validation JSON, not the friendly HTML error page that the v0.14.1 methodology allow-list already handled. v0.14.4: artefact_file is now optional at the FastAPI layer with a server-side check that returns the same friendly page when empty.

4 new regression tests in `tests/test_edge_cases.py`:
- `test_tool_version_in_threat_model_matches_package_version`
- `test_cli_friendly_error_on_non_utf8_yaml`
- `test_cli_friendly_error_on_malformed_yaml` and `_on_empty_yaml`
- `test_redteam_ingest_friendly_error_on_missing_file`

#### Tests
- **287 total tests**, all passing.

## [0.14.3] — 2026-05-10

### Fixed — STIX export catches up with v0.10-v0.13 framework additions

The release audit noted that v0.10-v0.13 enrichment fields
(owasp_ml / attack_cloud / attack_enterprise / linddun / nist_ai_100_2 /
compliance_controls / kill_chain_phase / evidence_status / ALE /
disposition / D3FEND on mitigations) never made it into the STIX
export. v0.14.3 closes that gap.

#### STIX 2.1 export

- **`reporting/stix.py`** — `_attack_pattern` now writes 13 new
 `x_atms_*` properties covering every framework field added since
 v0.10, plus an `external_references` entry with a working URL for
 each ATT&CK Cloud / Enterprise technique (in addition to the
 existing ATLAS / OWASP / MAESTRO refs). Compliance-control IDs
 surface under `source_name: "atms-compliance"`. Evidence summary
 fields (status, count, KEV flag, CVE list) flow through.
- **`_course_of_action`** — surfaces D3FEND mapping with
 `source_name: "mitre-d3fend"` external refs + `x_atms_d3fend`,
 `x_atms_control_family`, `x_atms_automatable`,
 `x_atms_validation_test`, `x_atms_vendor_examples`.
- **Performance**: `_now()` is now computed once per `render_stix`
 call instead of per-object (thousands of `datetime.now()` calls on
 big systems → one).

#### Navigator export

Left ATLAS-only by design — every existing consumer expects a single
ATLAS layer dict. The full ATT&CK reference surface is reachable via
the STIX export above. The internal `_build_layer` helper is now
factored out so a future `render_navigator_all_layers` (planned for
v0.15) can produce a multi-layer document without breaking the
single-layer caller contract.

#### Tests

- `test_stix_export_includes_v0_10_to_v0_14_fields` — asserts every
 new field appears for at least one threat in the AWS Bedrock sample.
- `test_stix_external_references_include_attack_enterprise` —
 asserts `mitre-attack` and `atms-compliance` source names appear
 in the IT/OT factory sample export.
- 281 total tests, all passing.

## [0.14.2] — 2026-05-10

### Fixed

A release audit (engine-developer focus) audited everything that
PRE-DATED v0.14 — older engines, vsdx ingest, OTM ingest/export, the
non-templated reporters. Fixed correctness bugs it surfaced. No new
features, no API changes; v0.14.1 system YAMLs analyse unchanged.

#### Correctness

- **`engines/cloud.py:64-79`** — OWASP API title-bonus could admit an
 entry with zero keyword overlap (the `score >= 3` clause bypassed
 the overlap threshold). A threat titled "API10 deprecation banner"
 with no API-related content was tagged as `API10:2023`. v0.14.2
 requires `overlap >= 2` regardless of title bonus.
- **`reporting/sarif_export.py:42-58`** — when two threats share a
 local rule_id (e.g. same playbook entry on different components),
 the SARIF rule definition now keeps the **most severe** variant
 instead of first-occurrence-wins. Tags are merged across all
 variants. v0.14.0 silently overrode high/critical rule details
 with the first-encountered low/medium variant.
- **`engines/quantitative.py`** — author overrides now respected for
 asymmetric values. Setting `freq_low=10, freq_high=0` previously
 silently undid the override; v0.14.2 fills the missing side from
 the likelihood-bucket default while preserving the explicit one.
- **`reporting/mermaid.py:_safe_id`** — non-ASCII component names
 (e.g. Japanese / Korean / Chinese) used to collapse to identical
 ids ("ユーザー" and "ユーザ" both became "_____"), breaking the
 resulting flowchart. Now appends a stable 6-char SHA-1 suffix on
 any non-ASCII input. Distinct names → distinct ids.
- **`reporting/mermaid.py:_label`** — `<`, `>`, `&` now HTML-escaped
 alongside `"` / `\` / `\n` / `|`. Defence-in-depth: Mermaid runs
 with `securityLevel: 'strict'` (set in v0.13) so JS in click
 directives is already blocked, but a system YAML name should never
 drive raw HTML into a rendered diagram.

#### Round-trip integrity (OTM)

- **`ingest/otm.py:_OTM_TYPE_MAP`** — extended with the slugs every
 ATMS ComponentType serialises to. `prompt_template_store`,
 `network_segment`, `iam_principal`, `secrets_vault`, `kms_key`,
 `message_queue`, `observability_stack`, `serverless_function`,
 `industrial_protocol`, `iot_device`, `mfa_service`,
 `legacy_mainframe`, plus 15 more — all now round-trip cleanly
 through OTM v0.2 export and back.
- **`ingest/otm.py:148-160`** — `parse_otm` now PREFERS
 `attributes.atms_component_type` over the OTM `type` slug when both
 are present. That's the lossless round-trip key the OTM exporter
 writes. Falls back to the slug-mapped type for OTM files coming
 from other tools.
- **`ingest/otm.py`** — removed the spurious `parent.component` →
 zone fallback. OTM `parent.component` references a parent COMPONENT,
 not a trust-zone, per spec.

#### Tests

- 7 new regression tests in `tests/test_edge_cases.py` covering each
 fix above (cloud title-bonus, SARIF rule collapse, quantitative
 asymmetric override, OTM type mapping, Mermaid id collision).
- 279 total tests, all passing. 8/8 selftest samples pass.

### Roadmap unchanged
The release audit surfaced more findings than this release shipped
(performance, test gaps, output parity for STIX/Navigator, vsdx edge
cases). Those are tracked in the release and triaged for v0.15+.

## [0.14.1] — 2026-05-10

### Fixed — three-agent QA pass after v0.14.0 release

A second-pass QA run (the release-audit checklist
documented in the release process) found a batch of issues across
correctness, robustness, and KB-content integrity. All fixed and tested in
this point release. **No new features**; v0.14.0 system YAMLs analyse
unchanged. **No public API changes**.

#### Correctness — false-positive "exploited"

- **Caldera success semantics now keyed on `state` first.** v0.14.0 accepted
 *both* `status==0` (v2/v4 success) and `status==1` (legacy v1 success),
 which silently flipped v2/v4 *failures* to "exploited". The new logic:
 trust `state` when present (it's unambiguous in v4), otherwise fall back
 to `status==0`, otherwise treat as failure. Documented at
 `src/atms/evidence/redteam.py:50-83`. Regression test:
 `test_caldera_v1_status_1_alone_does_not_promote_to_success`.
- **`link.collect=true` no longer treated as a success marker.** Caldera's
 `collect` field merely indicates stdout/stderr was captured — it's set
 on failed abilities too. Regression test:
 `test_caldera_collect_flag_does_not_promote_failure`.
- **Red-team status promotion now respects severity.** `evidence_status`
 only flips to `exploited` when the row's own severity is medium-or-
 higher. A KEV-tagged `info`/`low` row no longer auto-promotes either.
 Documented at `src/atms/engines/evidence.py:147-167`.
- **ATT&CK technique-ID regex tightened.** Bogus tokens like `TLS-1.2`
 and `TROJAN-9` in third-party CSVs no longer trigger ATT&CK matcher
 correlation. Format guard at `src/atms/engines/evidence.py:39`.
 Regression test: `test_attack_id_correlation_rejects_bogus_tokens`.

#### Correctness — Terraform parser

- **String-aware comment stripping.** `#`, `//`, `/* */` inside string
 literals (e.g. JSON policy bodies) no longer corrupt the parsed text.
- **String-aware brace counting.** `_balanced_block` now operates on a
 string-masked copy of the body, so a description like
 `"use { and } sparingly"` no longer truncates resource blocks.
 Regression test: `test_terraform_string_with_braces_doesnt_break_block_count`.
- **String-aware reference scanning.** `_REF_RE` only matches in the
 string-masked view, so `"my_company_logs.production"` inside a string
 literal no longer creates a fake `(my_company, logs)` dataflow.
 Regression test: `test_terraform_ref_in_string_literal_doesnt_create_dataflow`.
- **Symlinks skipped.** A `.tf` symlink in a parsed directory no longer
 follows out of the project root. Regression test:
 `test_terraform_skips_symlink`.
- **50 MB cap warning.** When the cumulative size cap is hit during a
 directory scan, the parser now emits a `logging.warning` naming the
 file at which it stopped, instead of silently truncating.
- **`utf-8-sig`** read on all `.tf` reads to tolerate the BOM
 PowerShell `Out-File` writes by default.

#### Correctness — docker-compose parser

- **Registry-port image splitting.** `localhost:5000/myimg` (no tag) no
 longer splits into name=`localhost`, version=`5000/myimg`. The
 rightmost `:` is now only treated as a tag separator when it appears
 after the last `/`. Regression test:
 `test_compose_image_with_registry_port_does_not_corrupt_version`.

#### Correctness — Atomic Red Team parser

- **CRLF + BOM tolerance.** PowerShell on Windows writes JSONL files
 with CRLF line endings and a UTF-8 BOM; the v0.14.0 detector required
 Unix `\n{` and would mis-route the whole batch to the single-record
 branch. New scan finds objects line-by-line on either CRLF or LF and
 skips `null` lines without crashing. Regression test:
 `test_caldera_jsonl_with_crlf_and_bom`.

#### KB content fixes (broken cross-references found by validator agent)

- **`kb/playbooks/iam_principal.yaml:96`** — `atlas: [AML.T0007]` →
 `atlas: []` (T0007 doesn't exist in the ATLAS catalog; the threat is
 already mapped via `attack_cloud: [T1136.003, T1098.001, T1525]`).
- **`kb/playbooks/directory_service.yaml:29`** — `attack_enterprise:
 [T1558.001, T1078]` → `[T1558, T1078]` (parent T1558 is in the
 catalog; subtechnique .001 is not).
- **`kb/playbooks/endpoint.yaml:30`** — `attack_enterprise: [T1566,
 T1059, T1204]` → `[T1566, T1566.001, T1059.007]` (T1059 parent and
 T1204 are not in the curated catalog; the new IDs are).
- **`kb/threat_intel/cisa_kev.yaml`** — three duplicate CVE rows
 removed (`CVE-2024-7593`, `CVE-2024-43461`, `CVE-2024-49039` each
 appeared twice with slightly different `date_added`). Canonical row
 kept; the later duplicate was removed.

#### CLI fix

- **`atms kb-search --framework`** now accepts `compliance` and
 `owasp_ml` (the engine and web KB browser already supported both;
 the CLI choice list was missing them). smoke test caught it.

#### Web defence-in-depth

- **`/redteam/ingest`** rejects unknown `methodology` values with HTTP
 400 + a clear error, instead of letting the engine raise and the
 message surface through the response. Same allow-list pattern as
 the editor's analyse route. Regression test:
 `test_redteam_ingest_rejects_bad_methodology`.

#### Tests

- 9 new regression tests in `tests/test_v14_pipelines.py` covering each
 fix above.
- `test_redteam_ingest_csv_round_trip` rewritten — the v0.14.0 version
 asserted only `"threats" in r.text.lower()`, which appears in nav
 chrome and was tautological. Now asserts the matched component name
 appears in the report and an `exploited` threat is rendered.
- New `tests/test_v14_samples.py` covering the bundled
 `samples/iac/docker-compose.yml` and `samples/iac/main.tf`.
- 262 total tests, all passing. 8/8 selftest samples pass.

### Roadmap unchanged
v0.15+ items (SQLite run history, multi-system portfolio, live LLM
red-teaming) deferred as before — they need design input.

## [0.14.0] — 2026-05-10

### Added — red-team / BAS evidence + IaC ingest + D3FEND mitigation actionability

v0.14 closes the remaining tier-1 gaps from the v0.12 design and the v0.13 evaluator review. Layer 2 of the evidence model lands (red-team artefacts), the mitigation list goes from wish-list to backlog (D3FEND), and code-as-system-input arrives (Terraform + docker-compose).

#### Red-team / BAS evidence parsers (NEW)

`src/atms/evidence/redteam.py` adds three parsers that produce `Evidence(source="red_team")` rows:

- **MITRE Caldera** — operations JSON export from the REST API or `operations.json`. Keeps only successful abilities (`status == 0`); promotes the ATT&CK technique ID into `references` so the matcher can correlate to MITRE-tagged threats.
- **Atomic Red Team** — Invoke-AtomicTest invocation logs (.json or .jsonl). Reads `attack_technique`, `Hostname`, `ExecutionResult`; severity normalises from "Success" → high, "Prevented" → low, etc.
- **AttackIQ / Cymulate / SafeBreach** — generic BAS CSV with case-insensitive header sniffing (Technique ID / Scenario / Target / Result / Severity).

`parse_redteam(path)` auto-routes by extension. The evidence engine flips matched threats to `evidence_status="exploited"` + `likelihood=5` — the whole point of red-team data.

CLI: `atms ingest-redteam <artefact> <system.yaml>`.
Web: `/redteam` page with drag-and-drop upload + analysis round-trip.

#### D3FEND mitigation actionability (NEW)

`kb/d3fend/mappings.yaml` ships a curated cross-walk between mitigation phrases (`mfa`, `waf`, `encryption at rest`, `siem`, `data diode`, `dp-sgd`, `prompt injection classifier`, etc.) and:

- **`control_family`**: preventive / detective / responsive / corrective / deterrent
- **`automatable`**: whether a CI / IaC test can verify the control
- **`validation_test`**: a one-liner saying how to confirm it works
- **`d3fend`**: MITRE D3FEND technique IDs (`D3-MFA`, `D3-NTPM`, `D3-DENCR`, …)
- **`vendor_examples`**: concrete tools that implement the control

`src/atms/engines/d3fend.py:apply_d3fend_actionability()` decorates every `Mitigation` after `collect_mitigations` runs. Honours explicit values — never clobbers what a playbook author already set.

New fields on `Mitigation`: `control_family`, `automatable`, `validation_test`, `d3fend`, `vendor_examples`.

Reports surface: roadmap table now shows Family / Auto / D3FEND / Validation columns inline. CSV mitigation export adds 5 new columns. Per-mitigation Markdown detail lists `Validation test` and `Example tooling`.

#### IaC ingest (NEW)

- **`src/atms/ingest/docker_compose.py`** — services → components, networks → trust zones, `depends_on` → dataflows, host-mapped ports → user-facing edge with `crosses_boundary=true`. Vendor / image / version sniffed from the image tag (postgres → database, hashicorp/vault → secrets_vault, ollama → llm_inference, weaviate → rag_vector_store, etc.).
- **`src/atms/ingest/terraform.py`** — pragmatic regex-based HCL parser. ~70 AWS / Azure / GCP resource types mapped to ATMS component types (aws_lambda_function → serverless_function, azurerm_key_vault → secrets_vault, google_compute_firewall → firewall, etc.). `depends_on` blocks + cross-resource interpolations → dataflows. Modules / count / for_each are best-effort; `terraform show -json` first if needed.

CLI: `atms ingest-iac <file-or-dir>` (auto-detects format; `--out path` writes YAML).
Web: `/iac` page with single-file upload that lands the YAML in the editor for review.

#### Tests
- `tests/test_v14_pipelines.py` — 30+ new tests (every parser, the D3FEND engine, CLI commands, web routes, CSV columns, end-to-end workflow with red-team evidence flipping threats to `exploited`).
- Total: **240 tests, all passing**.

### Migration
v0.13 system YAMLs analyse unchanged. New `Mitigation` fields are additive with sensible defaults. The IaC ingest doesn't replace `atms ingest` (Visio / PNG) — it's a separate path for shops that diagram in code.

### Roadmap remaining (v0.15+)
- SQLite-backed run history (`atms history`, `atms reopen`) — eval gap #1
- Multi-system portfolio dashboard
- Live LLM red-teaming hooks (opt-in like the vision module)

## [0.13.0] — 2026-05-10

### Added — compliance overlay, FAIR-lite ALE, threat disposition, OTM, SARIF, KEV/EPSS refresh, NVD/OSV CVE lookup

This release closes the longest-standing gaps in ATMS — the things that
keep CISOs / GRC teams / pen-test leads on commercial tools. Every
addition was driven either by my own gap analysis or by the independent
evaluator I ran in parallel against v0.12.

#### New: Compliance overlay (10 frameworks)

`kb/compliance/controls.yaml` ships a curated cross-walk between every
threat ATMS raises and the controls auditors actually quote:

- **NIS2** — Article 21(2)(a-j) measures
- **DORA** — ICT risk-management, detection, response, third-party, TLPT
- **EU AI Act** — Art. 9 / 10 / 12 / 13 / 14 / 15 / 50 (high-risk + GenAI)
- **GDPR** — Art. 5(1)(b/c), 17, 22, 32, 35, 44
- **PCI DSS v4.0** — Reqs 6, 7, 8, 10, 11
- **HIPAA** — 164.308(a)(1) + 164.312
- **NIST 800-53 r5** — selected AC/AU/IR/SC/SI/SR controls
- **NIST CSF 2.0** — Govern / Identify / Protect / Detect / Respond
- **ISO/IEC 27001:2022 Annex A**
- **SEC cybersecurity disclosure** — Reg S-K Item 106 + 8-K Item 1.05

`engines/compliance.py` maps threats to controls by component-type +
keyword + STRIDE-AI alignment. New `Threat.compliance_controls` field;
`/compliance` browse page; `/api/compliance` JSON; `atms compliance`
CLI; KB-search supports `--framework compliance|nis2|dora|...`.

#### New: FAIR-lite quantitative risk

Every threat now carries `loss_low / loss_high / freq_low / freq_high
/ ale_low / ale_high` derived from likelihood + impact (or explicit
overrides). `summary["ale"]` aggregates portfolio-wide ALE with top
contributors. Reports surface `$X – $Y / year`. Lets a CISO talk to
the board in money instead of a 5-point qualitative scale.

#### New: Threat-disposition lifecycle

Reviewers can mark each threat as `open | accepted | mitigated |
transferred | false_positive | duplicate`, with `reviewed_by`,
`reviewed_at`, `decision_rationale`, `due_date`, `owner` fields. Goes
straight into the JSON dump, the CSV register, and the OTM export so
disposition survives round-trip with IriusRisk / Threat Dragon.

#### New: Component controls reduce likelihood (Adam-Shostack-school)

`Component.controls: list[str]` — list controls already in place
(`mfa_required`, `waf`, `edr`, `segmentation`, `phishing_resistant_mfa`,
`tls_terminated`, `dp_sgd`, `guardrails_enabled`, …). The new
`engines/controls.py` lowers likelihood for threats those controls
plausibly mitigate. **Stops reports nagging about phishing on a
passwordless-MFA-only system.** 41 recognised control tokens shipped;
unrecognised ones are recorded in `Threat.references` for traceability.

#### New: OWASP ML Top 10 (2023)

`kb/owasp_ml/ml_top10_2023.yaml` — non-LLM ML coverage (input
manipulation, data poisoning, model inversion, membership inference,
model theft, supply-chain, transfer-learning, skewing, output
integrity, model poisoning). New `Threat.owasp_ml` field; `engines/
owasp_ml.py`; KB-search filter.

#### New: OTM (Open Threat Model) ingest + export

`atms ingest-otm <model.json>` converts an OTM v0.2 model from
IriusRisk / pyTM / OWASP Threat Dragon into ATMS System YAML.
`render_otm()` is a new report format that emits OTM JSON with every
ATMS attribute preserved (severity / disposition / kill-chain / ALE /
compliance / etc.). 60+ OTM component-type slugs map to ATMS
ComponentTypes; vendor / product / version metadata round-trips.

#### New: SARIF 2.1.0 output for CI

`atms ci <system.yaml> --max-severity high --sarif-out report.sarif`
runs the full pipeline and exits non-zero when any threat at or above
the threshold remains. SARIF output uploads cleanly to GitHub
code-scanning, Azure DevOps, GitLab, and any SARIF viewer. Severity
maps to SARIF level (`note | warning | error`); KEV / CVE / kill-chain
travel as result properties. Also available as `--format sarif` from
`atms analyze`.

#### New: JSON-Schema for System YAML

`kb/system.schema.json` — validate your System YAMLs in CI without
spinning up Python. `$id` points to the GitHub blob URL so editors
auto-fetch on the fly.

#### New: live-feed refresh + CVE lookup (opt-in network)

`atms refresh-feeds [--kev/--no-kev] [--epss/--no-epss]` pulls fresh
CISA KEV CSV + EPSS top-N JSON from canonical URLs and rewrites the
bundled YAML snapshots. Honours HTTP_PROXY / HTTPS_PROXY env vars.
Header line `# Refreshed: <iso-date>` is now parsed and surfaced as
`summary["kev_meta"]["refreshed"]`, displayed in every report so
readers can tell how stale the snapshot is.

`atms cve-lookup CVE-YYYY-NNNN` queries NVD 2.0 (with OSV.dev
fallback), normalises to a `CveLookupResult`, and cross-references
against the bundled KEV / EPSS so the user sees the local view next to
the upstream details.

The deterministic core never reaches the internet — both commands are
strict opt-in, mirroring the vision-module pattern. The shipped `.exe`
runs offline by default.

#### Reports + UI

- HTML / Markdown / inline web report and CSV all gain ALE-range,
 compliance-controls, disposition, evidence-unmatched columns and
 appendix sections.
- Dated KEV banner shows the snapshot date in every report.
- Top nav gains "Compliance" link; KB browser dropdown gains OWASP ML
 + Compliance filters; KB page lists the new feeds with their dates.

#### Evidence matcher upgrade (v0.12 fix)

The v0.12 matcher only matched on `metadata.hostname / .ip / .fqdn` and
dropped almost every Nessus row from a GUI-edited System (which sets
`vendor / product / version` instead). v0.13:
- Matches **CPE 2.3** strings (`metadata.cpe`) and **Package URL**
 (`metadata.purl`) first when present.
- Searches the threat's title AND description AND affected_asset
 (was: title only).
- Tolerates evidence with no asset field by falling back to vendor
 tokens.
- Surfaces `summary["evidence_unmatched"]` — losing evidence silently
 is the cardinal sin here, and v0.12 was doing it.

#### Defensive fixes (smells from the evaluator)

- `_RUNS` web store now uses an `OrderedDict` LRU eviction at 32
 entries — was leaking memory on long-running web sessions.
- Mermaid initialisation now uses `securityLevel: 'strict'`, blocking
 Mermaid `click` directives + raw HTML — closes a stored-XSS-via-
 component-name vector.
- `engines/attack_paths` caps DFS path enumeration at 5000 per source —
 prevents combinatorial explosion on 200+ component systems.
- Pydantic `Field(max_length=...)` on Component / Threat / Evidence
 text fields — caps malformed vision-module YAML output.
- `atms review` command's interactive type-list now includes the v0.10
 IT/OT/network/identity types (was: only the v0.7 types).

#### Tests
- `tests/test_v13_evolution.py` — 37 new tests covering KB load, every
 engine, OTM round-trip, SARIF export, JSON-Schema, evidence matcher
 fixes, defensive fixes, the new CLI commands and web routes,
 network-mocked refresh-feeds + cve-lookup.
- Total: **221 tests, all passing**.

### Migration
v0.12 system YAMLs analyse unchanged. New optional fields on Component
(`controls`) and Threat (`disposition`, `owner`, ALE fields, …) are
additive. `analyze()` signature unchanged. The CLI gains new commands
but no breaking changes to existing ones.

### What's still on the roadmap (v0.14)
- Caldera / Atomic Red Team / AttackIQ / Cymulate red-team artefact
 parsers (Layer 2 of the evidence model from the v0.12 design doc).
- Terraform / docker-compose / CloudFormation / Helm IaC ingestion
 (alongside the OTM ingest that landed in v0.13).
- SQLite-backed run history + `atms history` / `atms reopen`
 (eval gap #1).
- More mitigation actionability (D3FEND mapping, vendor examples,
 validation tests) — eval gap #5.

## [0.12.0] — 2026-05-10

### Added — VAPT / SARIF / STIX / CSV evidence ingestion + CISA KEV + EPSS

v0.12 fuses **architecture-derived threats** (the deductive layer ATMS has had since v0.1) with **evidence** (the inductive layer most TM tools never close the loop on). Hypothetical findings stay tagged as `hypothetical`; confirmed findings bump to `observed`; KEV-listed CVEs and red-team hits flip to `exploited`. This closes the single biggest gap separating ATMS from the commercial leaders.

#### Evidence model (NEW)

- New `Evidence` Pydantic model with fields: `source`, `source_type`, `source_id`, `title`, `description`, `severity`, `cve`, `cvss`, `epss`, `kev`, `affected_asset`, `observed_at`, `references`.
- New `Threat.evidence: list[Evidence]` and `Threat.evidence_status: Literal["hypothetical", "likely", "observed", "exploited"]`.

#### Parsers (`src/atms/evidence/`) — NEW

- **Nessus / Tenable `.nessus`** XML — extracts findings with CVE list, CVSS, hostname, severity. Uses `defusedxml` (already a dep).
- **SARIF 2.1.0** — the standard for GitHub code-scanning + most modern SAST/DAST (CodeQL, Semgrep, Trivy, Snyk, Bandit, Brakeman). Maps SARIF level → ATMS severity.
- **STIX 2.1 bundles** — open standard for sharing threat intel. Reads indicators / vulnerabilities / attack-patterns.
- **Generic CSV** with column auto-sniffing for CVE / Severity / CVSS / EPSS / Asset / Title / Description / References. Handles numeric-CVSS severities (9.8 → critical) and 1–5 risk scales.
- `parse_any(path)` auto-detects the format from the file extension.

#### Matcher + engine — NEW

- `atms.evidence.matcher.match_evidence(evidence, components)` — maps each finding to a list of components by hostname / IP / FQDN / product+version / vendor token / component-name substring (in that priority order).
- `atms.engines.evidence.apply_evidence(threats, components, evidence)` — attaches matched evidence to threats and adjusts:
 - any KEV CVE → severity = critical, likelihood = 5, status = `exploited`
 - red-team hit → likelihood = 5, status = `exploited`
 - high/critical scanner hit → likelihood + 1, confidence raised, status = `observed`
 - TI signal → status = `likely`
- Wired into `workflow.analyze(system, methodology=..., evidence=[...])` between framework enrichment and risk scoring, so KEV-driven severity flows into the final risk-matrix.

#### Bundled threat-intel snapshots — NEW

- **`kb/threat_intel/cisa_kev.yaml`** — curated CISA Known Exploited Vulnerabilities snapshot (~75 CVEs covering the highest-impact entries that intersect ATMS' device catalog products: Palo Alto, Fortinet, Cisco, Ivanti, Microsoft, Citrix, Veeam, SolarWinds, Apache, Linux kernel, etc.).
- **`kb/threat_intel/epss_top.yaml`** — EPSS top-N snapshot (~70 CVEs) with score + percentile.
- KB loader exposes `kb.kev_cves`, `kb.kev_entries`, `kb.epss_scores`.

#### CLI (NEW)

- **`atms ingest-evidence <evidence_file> <system.yaml>`** — auto-detects format, runs the full pipeline with evidence applied, writes Markdown / HTML / CSV to `--out DIR`.
- `--format auto|nessus|sarif|stix|csv` for explicit format selection.
- `--methodology stride-ai|pasta|linddun` to combine evidence with a methodology lens.

#### Web UI (NEW)

- **`/evidence`** browse + upload page with drag-and-drop file input, system-YAML textarea, methodology selector.
- **`POST /evidence/ingest`** parses the upload, runs analysis, renders the standard report with evidence rows.
- Top nav gains an "Evidence" link.

#### Reports

- HTML, Markdown, inline web report, CSV all gain:
 - **Evidence-status breakdown** (`hypothetical | likely | observed | exploited`) as metric tile + appendix.
 - **KEV-hits** counter with critical-red styling.
 - Per-threat **Status** + **Evidence** columns; KEV badges in red.
 - Per-threat detail rows list every evidence row with source / source_type / source_id / KEV flag / CVSS / EPSS / affected asset.
- New summary keys: `evidence_status_breakdown`, `evidence_total`, `evidence_kev_hits`.

#### Tests
- `tests/test_v12_evidence.py` — 26 new tests covering the bundled KEV/EPSS snapshots, every parser, the matcher, the engine, the workflow integration, web routes, the CLI command and CSV columns.
- Total: **184 tests, all passing**.

### Migration
v0.11 system YAMLs analyse unchanged. The new `evidence` parameter to `analyze()` is optional and defaults to `None`.

### Why this matters
Every commercial threat-modelling tool worth its price (IriusRisk, Threat Modeler, ThreatModeler.io) is model-driven and, at best, has limited support for ingesting actual pentest findings. None of them surface CISA KEV / EPSS natively. v0.12 closes that gap on the open side: every threat now carries a confidence-grounded `evidence_status`, so a CISO can tell at a glance which findings are theoretical vs. confirmed vs. actively exploited in the wild.

## [0.11.0] — 2026-05-09

### Added — device catalog, PNG ingestion, NIST AI 100-2, Cyber Kill Chain, PASTA

v0.11 turns ATMS from "model in YAML" into "pick the actual product from a catalog and model that". It also adds three new lenses for meaningful threat-modelling beyond STRIDE: PASTA (attacker simulation), Cyber Kill Chain (per-threat phase), and NIST AI 100-2 (the canonical adversarial-ML taxonomy).

#### Device & product catalog (NEW)

`kb/devices/catalog.yaml` ships **200+ curated entries** — real, currently-deployed products keyed by ATMS component type:

- **AI**: Claude (4.7/4.6/4.5), GPT (5/4o/o3), Gemini 2.5, Bedrock, Azure OpenAI, Vertex AI, Hugging Face, Groq, Together, Fireworks, Cohere, AI21, Ollama, vLLM, TGI, Triton, LM Studio
- **Vector / RAG**: Pinecone, Weaviate, Chroma, Qdrant, Milvus, pgvector, OpenSearch, Elasticsearch, Azure AI Search, Vertex Matching Engine, FAISS
- **Agentic**: LangChain, LangGraph, AutoGen, CrewAI, LlamaIndex, Semantic Kernel, smolagents, Agno, Bedrock Agents, Azure AI Agent, Copilot Studio
- **Cloud**: AWS / Azure / GCP IAM, Vault, KMS, S3 / Blob / GCS, VPC / VNet, Lambda / Functions, EKS / AKS / GKE, OpenShift, SQS / Service Bus / Pub/Sub, Kafka, Splunk, Datadog, Microsoft Sentinel, QRadar
- **Databases**: SQL Server (2022–2014), Oracle (23ai/19c/12c/11g), Postgres (17–13), MySQL, MariaDB, Db2, MongoDB, Redis, DynamoDB, CosmosDB
- **Network**: Palo Alto PAN-OS (11.2), Fortigate FortiOS (7.6), Cisco FTD/ASA, Checkpoint Gaia (R82), SonicWall, Cisco Catalyst/Nexus, Arista, Juniper EX, Aruba CX, F5 BIG-IP, HAProxy, NGINX, GlobalProtect, AnyConnect, OpenVPN, WireGuard, Zscaler ZPA
- **Identity**: AD DS (WS 2025–2012R2), Entra ID, ADFS, OpenLDAP, FreeIPA, Okta, Ping, JumpCloud, Duo, Microsoft Authenticator, Yubikey 5, RSA SecurID, Passkey/FIDO2
- **Email**: Exchange Online, Exchange Server (SE/2019/2016/2013), Google Workspace, Postfix, Sendmail, Proofpoint, Mimecast
- **Endpoints**: Windows 11 (24H2), Windows 10 (22H2 EOL), macOS 17/15/14/13, Ubuntu (24.04/22.04), iOS 18, Android 15, Falcon / Defender / SentinelOne sensors
- **Legacy**: IBM z/OS (3.1/2.5/2.4), IBM i (7.6/7.5/7.4/7.3), AIX 7.3, Solaris 11.4, HP-UX 11i v3, OpenVMS x86-64 9.2, Unisys ClearPath, HP NonStop
- **OT**: Siemens S7-1500/1200/300, Allen-Bradley ControlLogix/CompactLogix/MicroLogix, Schneider Modicon M580/M340, Omron NJ, Mitsubishi iQ-R, GE PACSystems
- **SCADA / Historian**: AVEVA InTouch (Wonderware), Siemens WinCC, FactoryTalk, GE iFix/CIMPLICITY, ABB 800xA, Honeywell Experion, OSIsoft PI, Aspen IP.21, Schneider EcoStruxure
- **Industrial protocols**: Modbus TCP/RTU, OPC UA/DA, DNP3, EtherNet/IP, PROFINET, BACnet, IEC 61850, IEC 60870-5-104, S7Comm
- **IoT**: Hikvision / Dahua / Axis / Bosch IP cameras, Zigbee, LoRaWAN, Niagara BMS, Raspberry Pi 5

The catalog drives:
- A new **`/devices` browse page** with vendor / category / version search.
- A new **`/api/devices` JSON endpoint** consumed by the GUI editor.
- A new **vendor / product / version picker** in the editor's right-hand properties panel — selections write to `component.metadata` so reports cite the exact platform you're modelling.
- A new **`atms devices`** CLI command (filter by `--type`, search by `--query`).

#### PNG / image ingestion (NEW)

`/ingest` now accepts `.png`, `.jpg`, `.jpeg`, and `.webp` in addition to `.vsdx`. Image parsing routes through the existing **opt-in vision module** (`atms.vision.analyzer`), which uses Claude to extract a System YAML from an architecture diagram. Requires `ANTHROPIC_API_KEY` and the `[vision]` extra; the deterministic shipped `.exe` returns a clear error message explaining how to enable it. The vision prompt now knows about all 40 v0.10 component types and emits `metadata.vendor / .product / .version` when visible.

#### NIST AI 100-2 — adversarial ML taxonomy (NEW)

`kb/nist_ai_100_2/taxonomy.yaml` — the canonical NIST adversarial-ML reference, curated to 14 entries across:

- **Predictive AI**: Evasion, Poisoning (data, backdoor, label-flip), Privacy (membership inference, model inversion, attribute inference)
- **Generative AI**: Prompt injection (direct + indirect), training-data / system-prompt extraction, adversarial misuse / jailbreak, backdoor, resource exhaustion / DoS

`Threat.nist_ai_100_2` field; `engines/nist_ai_100_2.py` enrichment engine (component-type filter + keyword overlap + STRIDE-family bonus); `summary["nist_ai_100_2_coverage"]`.

#### Cyber Kill Chain mapping (NEW)

Every threat is now tagged with a Lockheed Martin Cyber Kill Chain phase: **Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command_and_Control → Actions_on_Objectives**. Pure-Python phase-mapper at `engines/kill_chain.py` (keyword-scored with STRIDE-AI fallback). `Threat.kill_chain_phase` field; `summary["kill_chain_breakdown"]`.

#### PASTA methodology (NEW)

`atms analyze --methodology pasta` (CLI), `--methodology=pasta` form field (web), `methodology="pasta"` parameter (Python). The PASTA lens runs the full pipeline, then keeps only threats that participate in attack paths OR have likelihood ≥ 4 OR are high/critical severity — the attacker-priority subset. Attack paths are then re-derived against the surviving threat set so the report stays internally consistent.

We considered VAST, OCTAVE and Trike too. They're enterprise-process methodologies, not threat-discovery lenses, so adding them would have been a checkbox without changing what ATMS finds. We left them out deliberately.

#### Reports + UI

- HTML, Markdown, inline web report and CSV gain **NIST AI 100-2** + **Cyber Kill Chain** columns / metric tiles / appendix sections / kill-chain breakdown.
- KB browser dropdown gains **NIST AI 100-2** filter.
- Home page methodology selector adds PASTA option.
- Inline web report threat table now shows kill-chain phase prominently.

#### Tests
- `tests/test_v11_coverage.py` — 24 new tests (catalog, NIST AI 100-2, kill-chain, PASTA, /devices + /api/devices, PNG-ingest fallback message + mocked-vision happy path, CLI).
- Total: **158 tests, all passing**.

### Migration
v0.10 system YAMLs analyse unchanged. New optional `component.metadata` field is additive. The PNG ingestion path is opt-in and inert without `ANTHROPIC_API_KEY`.

## [0.10.0] — 2026-05-09

### Added — IT, OT, network, identity coverage + drag-and-drop GUI editor + LINDDUN privacy

v0.10 closes the last big coverage gap: real-world systems are not just "AI on cloud" — they are AI bolted onto an IT estate (Active Directory, Exchange, MFA, endpoints, databases, web apps), running over a network spine (firewalls, VPNs, switches, load balancers), often with legacy plumbing (AS/400, z/OS) and OT zones (PLCs, SCADA, industrial protocols, IoT). v0.10 adds first-class threat-modelling for all of those, plus a new privacy lens (LINDDUN), a drag-and-drop visual editor, and methodology selection.

This is the release that gets ATMS into "competing with IriusRisk / Threat Modeler" territory while remaining free, deterministic, and AI-free.

#### New component types (15)

Added to `ComponentType`:

**IT / Identity / Apps**
- `database` — Oracle / SQL Server / Postgres / MySQL / MariaDB
- `web_application` — custom in-house web apps and SPAs
- `email_server` — Exchange / M365 / Google Workspace / Postfix
- `directory_service` — Active Directory / Entra ID / LDAP / IDP
- `mfa_service` — Duo / Okta / RSA SecurID / authenticator apps
- `endpoint` — workstations, laptops, BYOD

**Network**
- `firewall` — Palo Alto / Fortigate / Checkpoint / Cisco FTD
- `vpn_gateway` — GlobalProtect / AnyConnect / OpenVPN / WireGuard
- `network_switch` — Cisco Catalyst / Arista / Juniper EX
- `load_balancer` — F5 BIG-IP / HAProxy / NGINX / NetScaler

**Legacy + OT**
- `legacy_mainframe` — IBM AS/400 / iSeries / z/OS / HP-UX / Solaris
- `plc` — Siemens S7 / Allen-Bradley / Schneider / Modicon
- `scada` — HMI / historian / DCS / engineering workstation
- `industrial_protocol` — Modbus / OPC-UA / DNP3 / EtherNet-IP / PROFINET
- `iot_device` — IP cameras / smart sensors / building automation

Each ships with a **per-component playbook** (3–4 threats apiece, pre-mapped to STRIDE-AI / OWASP / MITRE ATT&CK Enterprise + ICS / MAESTRO). **48 net-new playbook threats**.

#### New framework KBs (2)

- **MITRE ATT&CK Enterprise + ICS (curated)** at `kb/mitre_attack_enterprise/techniques.yaml`. 35+ techniques covering the IT-side attack chain (`T1190` Exploit Public-Facing App, `T1078` Valid Accounts, `T1003` OS Credential Dumping, `T1558` Steal/Forge Kerberos Tickets, `T1566` Phishing, `T1621` MFA Request Generation, `T1110` Brute Force, `T1114.003` Email Forwarding, `T1499` Endpoint DoS, …) plus ICS techniques (`T0855` Unauthorized Command, `T0836` Modify Parameter, `T0856` Spoof Reporting, `T0830` AitM in ICS).
- **LINDDUN privacy** at `kb/linddun/threats.yaml`. 14 privacy threats across all 7 LINDDUN categories — Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness, Non-compliance — focused on AI-system privacy concerns (training-set linking, embedding inversion, prompt PII leak, third-party API oversharing, secondary use for training, log-trace PII overcapture, GDPR Art. 22 / Art. 35 gaps).

#### New engines

- **`engines/linddun.py`** — privacy enrichment. Tags threats with LINDDUN IDs based on component type + keyword overlap + privacy-context bonus. Wired into `workflow.analyze` as stage 2d.
- **`engines/cloud.py`** extended to also enrich with ATT&CK Enterprise + ICS technique IDs (same algorithm as ATT&CK Cloud).

#### Models + workflow + methodology selection

- `Threat` gains `attack_enterprise: list[str]` and `linddun: list[str]` fields.
- `summary["attack_enterprise_coverage"]`, `summary["linddun_coverage"]` and `summary["methodology"]` exposed.
- `analyze(system, methodology=...)` accepts a methodology lens:
 - `stride-ai` (default) — full pipeline
 - `linddun` — privacy-only filter (drops threats with no LINDDUN tag)
- `KnowledgeBase` loads + searches both new frameworks. CLI `kb-search --framework` accepts `attack_enterprise`, `linddun`, and the `attack` umbrella alias for Cloud + Enterprise + ICS combined.

#### GUI editor (NEW)

A drag-and-drop visual editor at **`/editor`** lets users build systems from scratch on a canvas:
- 40-component palette grouped by AI / Cloud / IT / OT
- Click-and-drag positioning
- Wire mode for dataflows (click source → click target)
- Live YAML preview
- Save-as-YAML download
- One-click Analyse — round-trips through the same pipeline as the YAML form
- Methodology selector inline
- Pure vanilla SVG + JS, no heavy library, fully offline (no CDN)

#### Visio classifier

Added 28 new keyword regex patterns covering:
- IBM AS/400, z/OS, HP-UX
- Cisco Catalyst / Nexus, Arista, Juniper EX, F5 BIG-IP, HAProxy, NetScaler
- Palo Alto, Fortigate, Checkpoint, Sophos, Cisco FTD, NGFW
- GlobalProtect, AnyConnect, OpenVPN, WireGuard, ZTNA
- Active Directory, Entra ID, LDAP, ADFS
- Duo, Okta, RSA SecurID, authenticator apps
- Exchange, M365, Google Workspace, Postfix
- Siemens S7, Allen-Bradley, Schneider Modicon, Omron, Mitsubishi
- Wonderware, iFix, OSIsoft historian
- Modbus, OPC-UA, DNP3, EtherNet/IP, PROFINET, BACnet
- IP camera, Hikvision, Zigbee, Z-Wave, LoRaWAN
- Oracle, SQL Server, MariaDB, Sybase, DB2

Patterns are ordered carefully: identity stencils > IT specifics > cloud > generic AI > catchall — so "IAM role for orchestrator" stays `iam_principal`, "Siemens S7-1500 PLC" stays `plc`, "Fortigate edge firewall" stays `firewall`.

#### Reports + UI

- Markdown + HTML + inline web reports gain ATT&CK Enterprise and LINDDUN columns + metric tiles + per-threat detail rows + appendix coverage lists.
- CSV risk-register gains `owasp_api`, `attack_cloud`, `attack_enterprise`, `linddun` columns.
- KB browser dropdown gains "ATT&CK Enterprise + ICS" and "LINDDUN privacy" filters.
- Home page gains a methodology selector.

#### MAESTRO mapping

`DEFAULT_LAYER_MAP` extended with sensible layer assignments for all 15 new types (most live in L4 Deployment & Infrastructure; identity controls touch L6 Security & Compliance; SCADA touches L5 Observability; user-facing endpoints / web apps touch L7 Agent Ecosystem).

#### Mermaid

15 new node-shape mappings so the auto-generated DFD visually distinguishes IT / OT / network / legacy components from AI ones.

#### Sample

`samples/it_ot_factory.yaml` — a realistic mid-size manufacturing site: 26 components across corporate IT (AD, M365, Duo, ERP-on-SQL-Server, AS/400 ledger), network spine (Fortigate edge firewall, Cisco FTD IT/OT firewall, Catalyst core switch, F5 LB, GlobalProtect VPN), OT zone (Siemens S7-1500 + Allen-Bradley CompactLogix PLCs, Wonderware HMI, OSIsoft historian, Modbus + OPC-UA bus, IP cameras), and a tacked-on AI predictive-maintenance pilot (S3 historian export, Bedrock embeddings, pgvector, Claude on Bedrock, LangGraph agent, KMS, Splunk). Analyses to **103 threats / 433 mitigations**.

#### Tests

- `tests/test_v10_coverage.py` — 25 new tests (KB load, model fields, MAESTRO map, LINDDUN engine, methodology selection, IT/OT sample, Visio classifier, reports, CLI, web editor backend, methodology form field).
- Total: **136 tests, all passing**.

### Changed
- `_tokenize` helpers in cloud / linddun / maestro engines now coerce non-string keyword values defensively, so a stray YAML int never crashes a run.
- KB `search()` likewise stringifies keywords before joining.

### Migration
v0.9 system YAMLs analyse unchanged in v0.10 — all new component types are additive; the only widened API is `analyze(system, methodology=...)` which defaults to `stride-ai`.

## [0.9.0] — 2026-05-09

### Added — Cloud-AI: cloud component types + OWASP API + MITRE ATT&CK Cloud

ATMS previously treated cloud infrastructure as a black box. v0.9 makes cloud a first-class layer alongside the AI side: a real "AWS Bedrock Agent" or "Azure OpenAI RAG" system can now be modelled with full fidelity (IAM roles, S3 buckets, secrets vaults, VPCs, Lambda, API Gateway, KMS keys, message queues, observability stacks) and threats on those components map to the canonical cloud security frameworks.

#### New component types (10)

Added to `ComponentType`:

- `iam_principal` — IAM role / user / service principal / managed identity
- `secrets_vault` — Secrets Manager / Key Vault / Secret Manager
- `object_storage` — S3 / Blob / GCS
- `network_segment` — VPC / VNet / subnet / security group
- `serverless_function` — Lambda / Azure Functions / Cloud Run
- `api_gateway` — API Gateway / API Management / Cloud Endpoints / WAF
- `container_runtime` — ECS / Fargate / EKS / AKS / GKE
- `kms_key` — KMS / Cloud KMS / Key Vault keys
- `message_queue` — SQS / SNS / Service Bus / Pub/Sub
- `observability_stack` — CloudWatch / App Insights / Cloud Logging / Datadog / Splunk

Each gets a per-component playbook in `kb/playbooks/`, with 3-6 threats pre-mapped to STRIDE-AI / OWASP / ATLAS / ATT&CK Cloud / MAESTRO. **44 net-new playbook threats**.

#### New framework KBs (2)

- **OWASP API Security Top 10 (2023)** at `kb/owasp_api/api_top10_2023.yaml`. All 10 entries (API1 BOLA -> API10 Unsafe Consumption of APIs) with patterns, examples, applicable component types, and mitigations. Most AI workloads are exposed via APIs; this catalogue is essential.
- **MITRE ATT&CK Cloud (curated subset)** at `kb/mitre_attack_cloud/techniques.yaml`. 33 techniques across the cloud attack chain — `T1078.004 Valid Accounts: Cloud`, `T1098.001 Account Manipulation: Additional Cloud Credentials`, `T1530 Data from Cloud Storage Object`, `T1552.005 Unsecured Credentials: Cloud Instance Metadata API`, `T1496 Resource Hijacking`, `T1486 Data Encrypted for Impact`, etc.

#### New engine

- **`engines/cloud.py`** enriches every threat with OWASP API IDs and ATT&CK Cloud technique IDs based on keyword overlap + component-type match. Wired into `workflow.analyze` as stage 2c. Same deterministic-Python pattern as the MAESTRO engine; no LLM required.

#### Models + workflow

- `Threat` gains `owasp_api: list[str]` and `attack_cloud: list[str]` fields.
- `summary["owasp_api_coverage"]` and `summary["attack_cloud_coverage"]` exposed.
- `KnowledgeBase` loads + searches the new frameworks; `kb.search()` accepts `framework="owasp_api"` and `framework="attack_cloud"`.

#### Reports + UI

- Markdown + HTML reports gain "OWASP API" and "ATT&CK Cloud" metric tiles, threat-table columns, per-threat detail rows, and appendix coverage lists.
- Inline web report mirrors the same.
- Web KB browser dropdown gains both new frameworks; "Bundled frameworks" list updated.
- CLI `kb-search --framework` accepts `owasp_api` and `attack_cloud`.

#### Visio classifier

- 60+ new cloud-stencil regexes covering AWS / Azure / GCP product names. `iam_principal` / `secrets_vault` / `kms_key` regexes promoted to the top of the priority list so unambiguous identity-stencil names beat AI patterns (e.g. "IAM role for orchestrator" -> `iam_principal`, not `agent`).

#### MAESTRO mapping

- `DEFAULT_LAYER_MAP` extended for all 10 new types — most map to `M.L4` (Deployment & Infrastructure); `iam_principal` / `secrets_vault` / `kms_key` also touch `M.L6` (Security & Compliance); `observability_stack` lives in `M.L5` + `M.L6`.

#### Mermaid

- Distinct node shapes for cloud components — circles for `iam_principal` / `kms_key`, subroutines for `secrets_vault` / `container_runtime`, asymmetric for `serverless_function`, trapezoid for `api_gateway`. Reviewers spot cloud vs AI elements at a glance.

#### Two new realistic samples

- `samples/aws_bedrock_agent.yaml` — 22-component AWS Bedrock Agent customer-support system. CloudFront -> API Gateway -> Lambda authoriser -> Bedrock Agent (with KB + Action Groups + Guardrails) -> RDS / S3 / Secrets Manager / KMS / CloudWatch. **107 threats, 340 mitigations**.
- `samples/azure_openai_rag.yaml` — 19-component Azure OpenAI RAG internal knowledge assistant. Front Door -> APIM -> AKS orchestrator -> Azure OpenAI + AI Search + Prompt Shield, plus a separate AKS-hosted ingest pipeline. **89 threats, 314 mitigations**.

#### Tests

- 19 new tests in `tests/test_v9_cloud.py` covering: KB loading, model literal extension, engine enrichment, MAESTRO mapping, classifier precedence, CLI flags, report content, web UI dropdown + framework filter, both new samples. **111 tests passing total** (was 92).

### Known invariants verified

All 7 bundled samples pass selftest; threat counts on prior samples (rag_system, agentic_system, enterprise_rag_agent, etc.) **unchanged** (no false-positive matches from the new frameworks on AI-only components).

## [0.8.0] — 2026-05-09


### Notes

- 0.8.0 introduced optional internal tooling for larger, cross-cutting changes; most development remains single-session.
- Internal development tooling was validated before commit.
- 92/92 tests still pass; all 5 bundled samples still pass selftest.

## [0.7.0] — 2026-05-09

### Fixed

- **Mermaid "Syntax error in text" bomb-icon when viewing raw templates / airgapped**. Reproducer was opening `src/atms/templates/web/report.html` directly in a browser: Jinja didn't run, the literal `{{ mermaid_dfd }}` was sitting inside `<pre class="mermaid">`, the CDN-loaded Mermaid auto-init tried to parse it and rendered a giant error bomb. The same hazard hit anyone who tried to view the downloadable HTML report on a machine with no internet.

### Added — airgap-safe diagram rendering

- **Bundled Mermaid 10.9.5** (~3.2 MB minified) at `src/atms/static/mermaid.min.js`. New `scripts/fetch_mermaid.py` re-fetches a pinned version on demand. Committed to the repo so end users never need internet to view the inline web report.
- **`src/atms/static/atms-mermaid.js`** — defensive initialiser. Walks every `<pre class="mermaid">`, validates the text content starts with a known Mermaid keyword (`flowchart`, `graph`, `sequenceDiagram`, `classDiagram`, `stateDiagram`, `erDiagram`, `gantt`, `pie`, `journey`, `mindmap`, `gitGraph`, `timeline`), and only renders the vetted blocks. Invalid blocks (raw Jinja placeholders, empty strings, garbage) are hidden and replaced with a tidy "Diagram unavailable — render this report through ATMS" notice. `startOnLoad: false`; manual `mermaid.run({ nodes: validBlocks })`. Wraps the call in try/catch so a Mermaid bug can't take down the rest of the page.
- **FastAPI `/static/` route**. `app.mount("/static", StaticFiles(directory=...))` so the inline web report can load `/static/mermaid.min.js` and `/static/atms-mermaid.js` from the same origin — no CDN call from the inline UI, fully airgap-capable.
- **Downloadable HTML report keeps CDN** (it's meant to be shared) but now ships with the same defensive init script inlined, so opening it offline gracefully degrades instead of showing the bomb icon.
- **`paths.static_dir()`** helper alongside `kb_dir`/`samples_dir`/`templates_dir`, with the same dev / wheel / PyInstaller `_MEIPASS` resolution.
- **`atms.spec`** now bundles `src/atms/static` and declares `fastapi.staticfiles`, `starlette.staticfiles`, `aiofiles` as hidden imports.
- **`aiofiles>=23.0`** added to `requirements.txt` and `pyproject.toml` (used by Starlette's StaticFiles backend).

### Tests

- 7 new tests covering: bundled Mermaid presence + size sanity, helper script content, FastAPI static-route serving, 404 for unknown static, inline web report references local `/static/` paths and not the CDN, downloadable HTML report has the defensive init guard, downloadable HTML displays a friendly fallback when Mermaid fails to load. **91/91 tests pass** (was 84).

### Triple-checked end-to-end through the rebuilt .exe

- `atms.exe selftest` passes all 5 samples.
- `atms.exe web` serves `/static/mermaid.min.js` (3.3 MB, status 200) and `/static/atms-mermaid.js` (3 KB, status 200, includes `isLikelyMermaid` guard).
- `POST /analyze` with the 20-component enterprise sample returns a 77 KB inline report whose script tags reference only local `/static/` paths — zero `cdn.jsdelivr.net` references.
- The exact failure mode from the screenshot (literal `{{ mermaid_dfd }}` text inside `<pre class="mermaid">`) is rejected by the defensive guard's regex; verified with a Python re-implementation of the same regex.

## [0.6.0] — 2026-05-09

### Added

- **Mermaid data flow diagram in every report**. New `reporting/mermaid.py` renders a `flowchart LR` from the analysed System: nodes shaped by component type (stadium for users, hexagon for agents, cylinder for LLMs / vector stores / data sources, rhombus for guardrails / output filters, parallelogram for tools, parallelogram-alt for MCP servers), `subgraph` clusters per `trust_zone` coloured by risk level (internet/external/training/prod), thick `==>` arrows for boundary crossings vs `-->` for in-zone flows. Embedded as a code fence in Markdown reports (rendered natively on GitHub) and as a live JS-rendered diagram in HTML reports + the inline web-UI report (Mermaid 10 CDN, dark theme).
- **Proper risk-matrix heatmap**. Replaces the old count grid with a 5x5 gradient grid coloured by the cell's intrinsic severity bucket (info/low/medium/high/critical) plus a legend. Empty cells are dim; populated cells inherit the severity colour. Visible at a glance.
- **Top-10 mitigation roadmap**. New `engines/mitigations.prioritise_mitigations()` ranks mitigations by `risk_reduction × addressed-severity-weight / effort_cost`. Severity weight: critical=5, high=4, medium=3, low=2. Effort cost: low=1, medium=2, high=3. Surfaced as a "Recommended roadmap (top 10)" section at the top of the mitigation block in Markdown / HTML reports and the inline web report. The full mitigation list still follows below.
- **`atms diff <old.json> <new.json>`** CLI command. Compares two `atms analyze` JSON dumps and reports added threats, removed threats, severity changes, and large risk-score changes (delta >= 5). Output formats: `table` (default; Rich-formatted), `markdown`, `json`. Lets reviewers track progress over iterations of the same system.
- **Realistic enterprise sample** at `samples/enterprise_rag_agent.yaml` — 20 components, 28 dataflows, 3 trust zones (internet / corp / external_provider / training_vpc), full RAG + agentic + MCP + fine-tune pipeline. Used as the v0.6 stress test and now part of the bundled samples (selftest covers it).
- **10 new tests** for Mermaid rendering, mitigation prioritisation, the enterprise sample, and `atms diff` (table / markdown / json formats). 84/84 passing total.

### Triple-checked end-to-end through the frozen .exe

- `atms.exe selftest` passes all 5 samples (incl. the new 69-threat enterprise system).
- `atms.exe analyze samples/enterprise_rag_agent.yaml` writes all 7 outputs; STIX has 1408 objects, Navigator has 34 techniques, JSON exposes 10 priority mitigation IDs.
- `atms.exe diff` produces correct added / removed / severity-changed listings in markdown and json formats.
- `atms.exe web` serves a fully populated inline report after a YAML upload — mermaid DFD, heatmap, roadmap, threat tables, attack paths, downloads all live.

## [0.5.0] — 2026-05-09

### Added — Windows installer + AI-dependency audit

- **Windows installer** (`ATMS-Setup-0.5.0.exe`, ~37 MB). Built via Inno Setup 6 from `installer/atms.iss`. Drives a wizard that installs `atms.exe` + samples + docs to `%LOCALAPPDATA%\Programs\ATMS`, drops a Start Menu group with shortcuts (ATMS Web UI, ATMS Command Prompt, README, Open Samples Folder, Uninstall), optionally adds Desktop shortcut, optionally adds `atms.exe` to PATH, and registers an uninstaller in Add/Remove Programs. Silent install (`/VERYSILENT`) and silent uninstall both supported. **No admin privileges required.**
- **`scripts/build_installer.py`** — single command to produce the installer end-to-end. Runs PyInstaller, reads version from `__init__.py`, locates `ISCC.exe`, compiles the .iss with `/D MyAppVersion=`. `--skip-exe` flag for fast iterative installer testing.
- **[`AI_DEPENDENCIES.md`](AI_DEPENDENCIES.md)** — audit + contract documenting that the shipped product has zero AI/LLM/network dependencies. The default workflow is deterministic Python over a curated YAML KB. The optional `vision/analyzer.py` module is the only AI-touching code; it has zero callers in the default workflow and is now explicitly excluded from the PyInstaller bundle alongside `anthropic`, `openai`, `cohere`, `google.generativeai`, `huggingface_hub`, `transformers`, and `atms.vision*` itself. Verifiable post-build.
- **Updated `atms.spec`** with the expanded `excludes` list above so the installer ships airgap-capable.

### Smoke-tested

- Silent install completes (exit 0) without admin.
- All 4 bundled samples pass `selftest` from the installed location (`%LOCALAPPDATA%\Programs\ATMS\atms.exe selftest`) — same threat counts as the dev install (49/27/26/36).
- `ingest samples/test_diagram.vsdx` works from the installed location.
- Local web UI works from the installed location: `/`, `/healthz`, `/playbooks`, `/maestro`, `/agentic` all return 200; MAESTRO and OWASP Agentic browser pages render correctly.
- Silent uninstall completes (exit 0); install dir + Start Menu entries + Add/Remove Programs entry + PATH entry all cleanly removed.

## [0.4.0] — 2026-05-09

### Added — risk-fix release + Windows portable .exe

- **Trust-boundary inference (`engines/boundaries.py`)**. For any system with >1 distinct `trust_zone` value, ATMS now auto-derives one `TrustBoundary` per zone, with that zone's components inside and the rest outside. User-declared boundaries are preserved and never duplicated. The same engine auto-flags `crosses_boundary=True` on dataflows whose source and target zones differ. Runs at the start of every `analyze()` so vsdx-ingested systems get reasonable boundaries without manual editing.
- **Classifier hardening (`ingest/vsdx`)**. Expanded keyword coverage with cloud-stencil names: AWS Bedrock / Bedrock Agents / Bedrock Guardrails / SageMaker, Azure OpenAI / Azure AI Search / Azure ML, Vertex AI / Matching Engine, plus managed LLM hosts (vLLM, Ollama, TGI, Triton), more SaaS connectors, broader pipeline / RAG terms.
- **`atms analyze --strict`**. Exits 3 if any component still has `type: other`. Useful as a CI/sanity gate after vsdx ingestion.
- **`atms review SYSTEM.yaml [--in-place|--out PATH]`**. Walks every `other`-typed component and prompts for the correct type from the validated literal set. Preserves all other fields.
- **Auto data-classification on dataflows**. Connector labels containing `api key`, `secret`, `password`, `cert`, `phi`, `hipaa`, `pci` → `restricted`. Labels with `pii`, `customer data`, `confidential`, `gdpr`, `nda`, `financial` → `confidential`. `public` / `marketing copy` → `public`. Default `internal`.
- **Vague-connector flagging**. Labels like empty, `->`, `→`, `LINE`, `connector` get surfaced in CLI/web notices for re-labelling.
- **Web UI cards** for `other`-classified components and vague-labelled dataflows after a vsdx upload — list every offending entry by ID so reviewers can fix them precisely before clicking Analyze.
- **Windows portable .exe build**. New `atms.spec` + `scripts/build_exe.py`: produces `dist/atms.exe` (~35 MB single file) bundling Python runtime, every dependency, the YAML KB, Jinja templates, and bundled samples. Copy to any 64-bit Windows machine — no Python install required. Runs `analyze`, `ingest`, `review`, `selftest`, `kb-search`, `web` (FastAPI server), etc.
- **`src/atms/paths.py`** — central resource-path lookup. Handles editable install, installed wheel, and PyInstaller `sys._MEIPASS` modes. `ATMS_KB_DIR` / `ATMS_SAMPLES_DIR` env vars override (handy for forks and tests).
- **`src/atms/__main__.py`** — thin `python -m atms` entry point also used as the PyInstaller entry script.
- **`BUILDING.md`** — full build + deploy + rollback instructions for the portable .exe.
- **Annotated git tags** for v0.1.0, v0.2.0, v0.3.0, v0.4.0 → `git checkout vN.N.N` to roll back any time.

### Changed

- `analyze()` now augments the system with inferred boundaries + crosses_boundary flags before running the threat engines, so all reports get the new context for free.
- Path lookups across `kb.py`, `web.py`, `cli.py`, `reporting/markdown.py`, `reporting/html.py` now go through `paths.py` (behaviour-preserving).
- `atms web` in a frozen .exe passes the FastAPI app object directly to uvicorn (the import-string path doesn't work in PyInstaller bundles); `--reload` is documented as unsupported in frozen mode.

### Tests

- 11 new tests (boundaries, classifier hardening, data-classification, vague-label detection, review CLI). **74/74 passing** (was 63).

## [0.3.0] — 2026-05-09

### Added — Visio (.vsdx) ingestion

- **`atms ingest <file.vsdx>` CLI**. Parses a Visio diagram into a draft System YAML. `--out PATH` to write to a file, `--analyze` to chain straight into the analysis pipeline, `--name` to override the system name.
- **Web UI upload**. New form on the Analyze page accepts a .vsdx, parses it server-side, pre-populates the YAML textarea so the user can review/edit before submitting Analyze. 10 MB hard cap. .vsd / non-vsdx / malformed-zip uploads return a clean 4xx instead of crashing.
- **`atms.ingest.vsdx` module**. Walks every page, classifies shapes into ATMS component types via 70+ keyword regexes (covering vector store / RAG / LLM / agent / MCP / training / fine-tune / embedding / guardrail / output filter / data source / external API / user / etc.), pairs `BeginX` and `EndX` connector endpoints into a single dataflow per connector, sanitises shape-data-property leakage out of the displayed name, and surfaces a clear "X components classified as 'other'" notice for review.
- **Test artifact** `samples/test_diagram.vsdx` — a small RAG-style diagram (End User → Support Agent → Vector Store) shipped with the repo so contributors can verify the round-trip without a Visio install.
- **15 new tests** for the parser, CLI command, and web upload (negative paths: .vsd / wrong extension / oversize / malformed zip / missing file / orphan shapes). Total now **63 tests**.

### Fixed

- Parser bugs caught during debug: (a) `data_properties` values were being concatenated into the displayed component name; now used only for type classification. (b) connect-pairing was reading the connector's own shape ID instead of its endpoint targets — rewrote the algorithm to group by `connector_shape_id` and pair `BeginX`/`EndX` endpoints.

### Known limitations

- Legacy binary `.vsd` is not supported (Visio Open XML only). Convert in Visio (Save As → .vsdx) or LibreOffice Draw first.
- Trust boundaries are not extracted from .vsdx (the format has no canonical concept of a trust boundary). Add them manually in the YAML before analysis.
- Shape classification is keyword-heuristic; ambiguous labels fall back to `type: other` and are flagged so the user can correct them.

## [0.2.0] — 2026-05-09

### Added — MAESTRO + OWASP Agentic AI

- **MAESTRO** (Cloud Security Alliance, 2026): the 7-layer agentic-AI reference architecture is now a first-class framework in the KB. Layers `M.L1`..`M.L7` plus 5 cross-layer threats. Each component is mapped to default layers; users can override via the new `component.maestro_layers` field.
- **OWASP Agentic AI Threats and Mitigations** (OWASP ASI, 2026): all 17 threats `T1`..`T17` (`AGT01`..`AGT17`) loaded with descriptions and mitigations. Memory poisoning, tool misuse, goal manipulation, rogue agents, MCP/A2A protocol abuse, and the rest.
- **5 new threats added to `kb/playbooks/agent.yaml`** (memory poisoning, intent breaking, rogue agent in MAS, cascading hallucinations, overwhelming HITL) and **2 new threats in `mcp_server.yaml`** (insecure inter-agent protocol abuse, compromised agent registry). Existing threats in `agent`, `tool`, `mcp_server`, `llm_inference` playbooks were enriched with `owasp_agentic` and `maestro` mappings.
- **`engines/maestro.py`** — pure-Python keyword-and-component-aware enrichment that adds MAESTRO + OWASP-Agentic IDs to every threat.
- **Mitigation roll-up** now pulls OWASP Agentic AI mitigations alongside ATLAS and OWASP LLM mitigations; framework_refs use the prefixes `OWASP-LLM:`, `OWASP-AGT:`, `ATLAS:`.
- **`/maestro`** and **`/agentic`** web UI pages browse the full frameworks. KB search now filterable by `owasp_llm`, `owasp_agentic`, `maestro`, `atlas`, or `nist`.
- **STIX 2.1 export** carries `owasp_agentic`, `maestro_layers`, `maestro_threats` as custom properties and adds external_references for both new frameworks.
- **CSV risk register** adds columns for `owasp_agentic`, `maestro_layers`, `maestro_threats`.
- **5 new tests** for OWASP Agentic / MAESTRO loading and enrichment; total 48 tests (was 36).

### Coverage

- Agentic sample (`agentic_system.yaml`) now lights up **16/17 OWASP Agentic threats**, **all 7 MAESTRO layers**, **39 MAESTRO threat IDs**, and **9/10 OWASP LLM Top 10**.

## [0.1.0] — 2026-05-09

### Added

- **Knowledge base** with OWASP LLM Top 10 (2025), MITRE ATLAS (15 tactics, 41 techniques, 25 mitigations curated for AI), NIST AI RMF / AI 600-1 GenAI Profile entries, and STRIDE-AI matrix.
- **15 component playbooks** for: llm_inference, rag_vector_store, agent, tool, mcp_server, training_pipeline, fine_tuning_pipeline, embedding_service, prompt_template_store, model_registry, guardrails, output_filter, data_source, external_api, user.
- **Engines**: STRIDE-AI threat enumeration, ATLAS keyword enrichment, DREAD-AI risk scoring, NetworkX-based attack-path generation, ATLAS+OWASP+inline mitigation roll-up.
- **CLI** (`atms analyze`, `atms web`, `atms kb-search`, `atms list-playbooks`, `atms validate`, `atms selftest`).
- **Web UI** (FastAPI + Jinja2): paste-or-load YAML, run analysis, view threats/paths/mitigations, download all formats.
- **Reports**: Markdown, self-contained dark-mode HTML, STIX 2.1 bundle, ATLAS Navigator JSON layer, CSV (risk register + mitigations).
- **4 sample AI systems** ready to analyze: marketing chatbot, customer-support RAG, autonomous DevOps agent, fine-tune pipeline.
- **Optional vision module** for converting architecture-diagram images into draft YAML via the Anthropic vision API (opt-in via `ANTHROPIC_API_KEY`).
- **36 unit + integration tests** (pytest) covering KB, engines, reporting, and the web UI.
- **Self-threat-model** in `THREAT_MODEL.md`.

### Status

- All 4 bundled samples pass selftest.
- 100% of OWASP LLM Top 10 categories covered by the RAG sample analysis.
- 30+ ATLAS techniques referenced in the RAG sample analysis.
