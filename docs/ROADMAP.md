# ATMS — 6-month roadmap (post-v0.18.43 audit)

> **Status as of v0.18.56:** All V1 phases (0-6) and all V2/V3
> follow-up phases (A-H, with F=already-shipped) **complete**.
> ~1,100 tests passing (1,387 defined); ~80% line coverage;
> 4 real-world corpus benchmarks pinned. See CHANGELOG.md for
> the version-by-version breakdown.


> **Premise.** v0.18.43 is functionally complete and feature-rich.
> The 43-cycle development pace from v0.17 → v0.18.43 means the
> codebase has accreted scope faster than it has been pruned. The
> goal of the next 6 months is **honest consolidation**, not new
> feature surface — every phase pays back technical debt before
> any new capability lands.
>
> **Acceptance bar for every phase**: the full test suite passes
> twice consecutively (sequential **and** parallel), the
> architecture drift guard stays green, the selftest exercises
> every bundled sample without exception, and `git diff` is reviewed
> commit-by-commit before merge.

## Phase 0 — Audit (this phase, in-progress)

Deliverables — **done when this section is committed**:
- `docs/ARCHITECTURE.mmd` — comprehensive mermaid diagram of all 14
  subsystems (12 input formats / 12 ingest modules / 24 engines /
  17 KB modules / 14 reporting modules / 6 evidence parsers / 3
  feeds / 5 delivery surfaces).
- `docs/ROADMAP.md` — this file.

Baseline numbers (recorded 2026-05-16):

| Metric                            | Value                              |
|-----------------------------------|------------------------------------|
| `src/` LOC                        | 19,838                             |
| `tests/` LOC                      | 14,241                             |
| Tests collected / passed (-n 4)   | 928 / 924 (4 deselected `slow`)    |
| Suite wall-clock                  | ~18 s parallel, ~30 s sequential   |
| Tags shipped                      | 32                                 |
| Engines                           | 24 modules                         |
| Ingest modules                    | 12                                 |
| Reporting modules                 | 14                                 |
| KB YAML files                     | 166                                |
| Playbooks                         | 121 (100% ComponentType coverage)  |
| Compliance controls / frameworks  | 117 / 15                           |
| Architectural rules               | 25                                 |
| Web routes                        | 32                                 |
| CLI commands                      | 28                                 |
| MCP tools                         | 5                                  |
| REST endpoints                    | 4                                  |
| Static export formats             | 14 (md/html/exec/stix/navigator/csv/json/sarif/otm/compliance/jira/roadmap/sbom + mermaid) |

Identified debt (concrete, file-level):

| Smell                              | Location                                                  | Resolution phase |
|------------------------------------|-----------------------------------------------------------|------------------|
| Unconditional `pytest.skip()`      | `tests/test_v016_features.py:266` — "no threats emitted"  | Phase 2          |
| Conditional `pytest.skip()` (×4)   | jira_export · roadmap_export · v14 · vision_optional      | Phase 2          |
| 29 source modules without dedicated `test_<mod>.py` | engines/ · reporting/ · ingest/         | Phase 2          |
| 5 TODO/FIXME markers in `src/`     | `models.py`, `architecture.html`, vendored `mermaid.min.js` | Phase 1        |
| `_RESOURCE_MAP` duplicates         | `pulumi_yaml.py` has dup `gcp:storage:Bucket` key entries | Phase 1          |
| Companion docs in installed dir    | `CHANGELOG.md` etc. lag the bundled .exe by ~5 days       | Phase 6          |
| GitHub Release publication         | Blocked by sandbox; tags are on remote, releases aren't   | Phase 6          |
| Coverage measurement               | Not wired                                                 | Phase 2          |
| CI/CD                              | No GitHub Actions workflow                                | Phase 6          |

## Phase 1 (month 1) — Dead-code + unused-feature removal

**Goal**: prove every line of code earns its keep.

Deliverables:
1. Run `vulture` or equivalent to enumerate genuinely unused
   functions/classes. Hand-audit the report (vulture has FPs).
   Remove or document.
2. Sweep web routes / CLI commands / MCP tools / export formats
   for ones that overlap. Consolidate. Examples to investigate:
   - `atms ingest-iac` vs the specific `ingest-cfn` / `ingest-k8s` /
     `ingest-azure` / `ingest-pulumi` commands — one cohesive
     `atms ingest <path>` super-command may suffice now that
     `atms scan` auto-detects.
   - `csv_export.py` exports `risk_register` + `mitigations`; only
     `risk_register` is wired into the web download. Either expose
     `mitigations` or delete it.
   - `engines/reference_patterns.py` only has 4 referencing files —
     verify it's actually firing on canonical samples.
3. Audit every `kb/*/*.yaml` for files referenced by no engine.
4. Resolve the 5 TODO/FIXME markers (close or convert to issues).
5. De-duplicate `pulumi_yaml._RESOURCE_MAP`.

Acceptance:
- LOC delta: net **negative** (or zero — never positive).
- Test count delta: **zero or positive** (no test losses).
- All 924 tests pass twice.
- `atms selftest` exercises every bundled sample cleanly.
- Drift guard green; `/architecture` page still loads.

System-wide-impact checks: re-run all benchmark corpus tests
(currently OWASP Threat Dragon demo) — coverage numbers must
match v0.18.43 floors exactly.

## Phase 2 (month 2) — Test-suite honesty

**Goal**: every passing test guards a real invariant.

Deliverables:
1. Address the unconditional `pytest.skip` in
   `tests/test_v016_features.py:266` — either fix the playbook gap
   or delete the test.
2. Convert each conditional skip into an explicit expectation
   (and assert the precondition, instead of silently skipping).
3. Add `coverage.py` (already a transitive dep) configuration;
   wire `pytest --cov` into `pyproject.toml` `addopts`. Establish a
   coverage floor — pick 80% line + 70% branch for the first cut.
4. Profile the 4 `slow` tests; either trim them or move them into
   `tests/slow/` with a separate pytest target.
5. Add property-based tests (Hypothesis) for the 5 schema-validation
   surfaces: System YAML round-trip, OTM round-trip, ARM JSON
   parse, drawio parse, Pulumi YAML parse. Catches edge cases the
   author didn't think of.
6. Stabilise parallel runs — investigate any test that occasionally
   reorders output or modifies shared state.

Acceptance:
- Coverage report committed under `docs/COVERAGE.md` with floors.
- Zero `pytest.skip` calls (or each remaining one is documented
  with the precondition asserted).
- Parallel + sequential runs produce identical results in 5
  consecutive invocations.
- Suite wall-clock under 20 s parallel **after** the property-based
  tests land.

System-wide-impact checks: confirm every public API surface
(workflow.analyze, every ingest function, every render_*
exporter) has at least one direct test, not just integration
coverage.

## Phase 3 (month 3) — Performance + stability

**Goal**: meaningful speedups + memory budget audit.

Deliverables:
1. Profile cold-start: import-time, KB load, first `analyze()`.
   Identify any single module that costs >100 ms to load and
   defer it (`importlib.import_module` inside the function that
   needs it).
2. KB loader currently re-parses every YAML on each cold start;
   build a pickle cache invalidated by mtime. Confirm load time
   drops by ≥50%.
3. `analyze()` hot path: profile on the largest bundled sample
   (`bank_with_llm_fraud.yaml`); identify the top 5 hotspots; fix
   the worst one (likely the architectural-rule fire loop or the
   framework-mapping keyword scan).
4. Web server: confirm no memory leak across 1000 sequential
   `/analyze` requests. `_RUNS` is already capped at 32 — verify
   eviction works.
5. Test-suite parallel run goal: <15 s.

Acceptance:
- Before/after numbers in every commit message.
- Memory peak per `analyze()` call documented under
  `docs/PERFORMANCE.md`.
- No regression in any benchmark output.

System-wide-impact checks: re-run the Threat Dragon corpus
benchmark; ALE estimate, threat count, attack path count must
match v0.18.43 floors exactly. Re-run on all 12 input formats.

## Phase 4 (month 4) — Real-world corpus expansion

**Goal**: prove ATMS works on diverse externally-authored threat
models, not just contrived fixtures.

Deliverables — add ≥5 corpus entries under `samples/corpus/`, each
with provenance + pinned regression test:

1. AWS Solutions Library reference architecture (e.g. SaaS Boost
   or AWS Landing Zone Accelerator) — CFN ingest path.
2. Azure quickstart template (e.g. `azure-quickstart-templates`
   AKS reference) — Bicep ingest path.
3. Kubernetes Istio sample architecture — K8s ingest path.
4. AWS Threat Composer sample (if Amazon's `threat-composer` ships
   any public sample threat models) — JSON adapter.
5. Pulumi Examples repo entry (a multi-cloud sample) — Pulumi YAML
   path.

Each lands under `samples/corpus/<source>_<name>/` with:
- The source artefact, verbatim, with a `_provenance.yaml`
  recording URL, fetch date, upstream license.
- The ATMS-translated YAML.
- A regression test in `tests/corpus/test_<source>.py` pinning the
  threat / attack-path / compliance counts.

`docs/BENCHMARKS.md` grows to a side-by-side table of every corpus
entry.

Acceptance:
- Every corpus regression test passes.
- `docs/BENCHMARKS.md` is consistent with the suite (no drift).
- LOC delta in `src/` is small (these are mostly data + test files).

System-wide-impact checks: confirm the new corpora don't slow the
suite past Phase 3's 15 s floor — they may need the `slow`
marker.

## Phase 5 (month 5) — Documentation pass

**Goal**: a new user can be productive in under 15 minutes
without reading source.

Deliverables:
1. `docs/GETTING-STARTED.md` — 5-minute walkthrough from install
   to first report.
2. `docs/CLI.md` — every CLI command with example invocations.
3. `docs/REST-API.md` — every endpoint with `curl` examples.
4. `docs/MCP.md` — already exists; audit + expand.
5. `docs/ARCHITECTURE.md` — companion narrative to
   `ARCHITECTURE.mmd`.
6. `docs/WRITING-A-PLAYBOOK.md` — how to author a new
   ComponentType playbook.
7. `docs/CONTRIBUTING.md` — dev setup, test conventions, commit
   style, drift guard explained.
8. Audit every docstring in `src/atms/engines/*.py` and
   `src/atms/reporting/*.py` — every public function gets a
   one-line summary + Args + Returns + Raises if applicable.
9. README rewrite — currently descriptive but uneven; aim for
   tight + opinionated.

Acceptance:
- Markdown lint passes on every `docs/*.md`.
- Every CLI command in `docs/CLI.md` is reachable via `atms <cmd>
  --help`.
- Every link in every doc resolves (link-checker pass).
- Manual "new developer" walkthrough: a colleague (or a future
  self) clones the repo, follows `docs/GETTING-STARTED.md`, and
  ships a fix in under an hour.

System-wide-impact checks: docs cycles can't introduce code
regressions, but make sure all doc-referenced commands / paths
still exist.

## Phase 6 (month 6) — Release engineering

**Goal**: automated, reproducible, signed releases.

Deliverables:
1. GitHub Actions workflow:
   - `.github/workflows/ci.yml` — run on every push: test suite +
     drift guard + ruff lint + mypy.
   - `.github/workflows/release.yml` — on `v*` tag push: build
     `dist/atms.exe`, attach to a GitHub release with auto-generated
     notes from `CHANGELOG.md`.
2. Wheel build verified — `pip install atms` works from a fresh
   venv on Python 3.11/3.12/3.13.
3. Winget manifest under `winget/` (so Windows users can
   `winget install atms`).
4. Code signing for the .exe — explore Azure Trusted Signing or a
   personal EV cert.
5. Version bump v0.18.43 → **v0.19.0** to mark the consolidation
   release.
6. Tag the v0.19.0 release with comprehensive notes covering
   every phase's deliverables.

Acceptance:
- One `git push origin v0.19.0` triggers a full pipeline run that
  publishes a signed installer + a wheel.
- Documentation page documenting the release process.
- No human in the loop required (except the EV-cert handshake).

System-wide-impact checks: install the wheel into a clean venv,
run `atms selftest`, confirm 11/11.

## Cross-cutting principles

These apply to every phase:

- **No external dependencies beyond what's already in
  `pyproject.toml`** — keep the offline-first contract intact.
- **No paid runtime APIs** — ATMS runs fully offline with no
  per-analysis cost; the engine itself shouldn't introduce per-call costs.
- **Stay in `<repo-root>`** — no cloning external
  repos for inspection, only WebFetch / WebSearch for public docs.
- **Validate twice** — every phase's acceptance section includes
  running the suite twice (parallel + sequential).
- **System-wide impact analysis** — every commit message includes
  a "Blast radius" line: what other components touch this code,
  and what tests cover them.
- **No revert-by-commit** — if a change breaks something, fix
  forward in a new commit. Don't litter the history with reverts.

## Out of scope (explicit)

These are NOT going to be tackled in the next 6 months unless
specifically requested:

- Multi-user / RBAC / authentication — offline-first design choice.
- Cloud-account auto-discovery — needs new SDK deps, paid API costs.
- WeasyPrint PDF rendering — kept as opt-in dep; the `@media print`
  CSS shipped in Cycle OO covers 90% of the need.
- A new methodology (PASTA / VAST / Trike) — STRIDE for AI is the
  established take.
- A GUI authoring tool beyond `/editor` — Threat Dragon and
  drawio are the right tools for free-hand diagramming; ATMS is
  the analysis engine.

---

_This roadmap is intentionally conservative. v0.18.43 is the
end of the feature-breadth phase; the next 6 months are about
depth, polish, and trustworthiness._
