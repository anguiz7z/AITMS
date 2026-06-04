"""Phase Q — CI security + drift-guard surface (v0.18.65).

Roadmap V4 Phase Q. After J/K/L lifted parser coverage to ~97-100%
and M-P shipped corpus + DX improvements, the remaining honest gap
was supply-chain security: pyproject.toml pins ~10 runtime deps and
~6 dev deps, none of which were being scanned for known CVEs in CI.
Phase Q adds:

  * `security` GitHub Actions job running `pip-audit` against the
    installed dependency set. Non-blocking initially so a fresh CVE
    in a transitive doesn't stop unrelated PRs — but still surfaces
    in the CI summary.
  * `schema-check` step in the existing test job — the Phase O JSON
    Schema is now drift-guarded the same way the palette JSON is.

This file pins the CI yaml structure so a future "cleanup" can't
silently drop those guards.

Why test the CI file at all? Because GitHub Actions config drift is
the easiest thing to miss in code review. A small typo in a step
name silently disables a security check; that's exactly the failure
mode we want to catch locally.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI_FILE = ROOT / ".github" / "workflows" / "ci.yml"


def _load_ci() -> dict:
    assert CI_FILE.exists(), f"CI workflow missing: {CI_FILE}"
    # PyYAML loads `on:` as True (Python boolean) — that's the YAML
    # reserved-word coercion bug. Force string keys by re-parsing the
    # raw text into a dict via safe_load and accepting the True key.
    raw = CI_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    return data


def test_ci_yaml_parses():
    """Sanity: the file is valid YAML."""
    data = _load_ci()
    assert data is not None
    assert "jobs" in data


def test_ci_has_security_job():
    """v0.18.65 Phase Q — there must be a `security` job that runs
    pip-audit on the installed dependency set."""
    data = _load_ci()
    jobs = data.get("jobs", {})
    assert "security" in jobs, (
        f"Missing `security` job in CI. Current jobs: {list(jobs)}. "
        f"Phase Q (v0.18.65) added this — it should not be removed without "
        f"replacement coverage (e.g. dependabot config that actually runs)."
    )
    # The job must invoke pip-audit somewhere.
    raw = CI_FILE.read_text(encoding="utf-8")
    assert "pip-audit" in raw, (
        "The `security` job exists but doesn't reference pip-audit. "
        "Either restore pip-audit or update this test to match the "
        "replacement scanner."
    )


def test_ci_schema_drift_guard_present():
    """v0.18.63 Phase O — `gen_schema.py --check` must run in CI to
    catch the case where someone edits atms.models but doesn't run
    `make schema`."""
    raw = CI_FILE.read_text(encoding="utf-8")
    assert "gen_schema.py --check" in raw, (
        "Missing the JSON Schema drift-guard step. Phase O introduced "
        "this; without it, VSCode users pinning the canonical URL get "
        "an outdated schema after a Pydantic model change."
    )


def test_ci_palette_drift_guard_still_present():
    """Sanity: Phase 1 palette guard didn't get dropped along the way."""
    raw = CI_FILE.read_text(encoding="utf-8")
    assert "gen_palette.py --check" in raw, (
        "Lost the palette drift-guard step. This was added in v0.16.10 "
        "and is the regression net for the ComponentType -> editor "
        "palette JSON drift."
    )


def test_ci_architecture_drift_guard_still_present():
    """Sanity: Phase 0 architecture-diagram guard didn't get dropped."""
    raw = CI_FILE.read_text(encoding="utf-8")
    assert "check_architecture_drift.py" in raw, (
        "Lost the architecture-diagram drift-guard step. This was added "
        "in v0.17.2 and forces a diagram update alongside every new "
        "engine module."
    )


def test_ci_coverage_floor_unchanged():
    """The 86% floor is the Phase E contract; loosening it without a
    plan is a regression."""
    raw = CI_FILE.read_text(encoding="utf-8")
    assert "--cov-fail-under=86" in raw, (
        "Coverage floor changed from --cov-fail-under=86. "
        "Phase E set this; only raise it (never lower)."
    )


def test_ci_matrix_covers_three_python_versions():
    """We support Python 3.11-3.13 per pyproject.toml. CI must match."""
    data = _load_ci()
    test_job = data["jobs"].get("test", {})
    matrix = test_job.get("strategy", {}).get("matrix", {})
    py_versions = set(str(v) for v in matrix.get("python-version", []))
    expected = {"3.11", "3.12", "3.13"}
    assert py_versions == expected, (
        f"Python matrix drift: CI runs {py_versions}, pyproject pins "
        f"{expected}. Either widen pyproject (>=3.x) or update CI to match."
    )


def test_ci_matrix_covers_ubuntu_and_windows():
    """ATMS ships a Windows .exe; we MUST keep Windows in the test
    matrix or risk breaking the installer build path."""
    data = _load_ci()
    test_job = data["jobs"].get("test", {})
    matrix = test_job.get("strategy", {}).get("matrix", {})
    oses = set(matrix.get("os", []))
    assert "ubuntu-latest" in oses
    assert "windows-latest" in oses, (
        "Lost windows-latest from the test matrix. The build-exe job "
        "still runs Windows-only, but a parser bug that only manifests "
        "on Windows would now slip past `pytest` runs and only get "
        "caught at PyInstaller time."
    )


def test_ci_build_exe_job_hard_gated_by_repo_var():
    """v0.18.72 Hibernation Phase 7 — `build-exe` is hibernated. The
    job exists for one-flag re-enablement, but its `if:` condition
    REQUIRES `vars.BUILD_EXE_ENABLED == 'true'` so a routine tag push
    does NOT build the .exe.

    This test catches the case where someone removes the gate
    intending to "just rebuild for this tag" but forgets to restore
    it after."""
    data = _load_ci()
    build_exe = data["jobs"].get("build-exe", {})
    if_condition = str(build_exe.get("if", ""))
    assert "BUILD_EXE_ENABLED" in if_condition, (
        "build-exe job is no longer gated by BUILD_EXE_ENABLED. If the "
        ".exe distribution is being un-hibernated, also remove the "
        "FEATURE_BUILD_EXE default = False in src/atms/features.py "
        "and update the hibernation table in README."
    )


def test_ci_build_installer_job_hard_gated_by_repo_var():
    """v0.18.72 Hibernation Phase 7 — installer hibernated alongside
    the .exe."""
    data = _load_ci()
    build_inst = data["jobs"].get("build-installer", {})
    if_condition = str(build_inst.get("if", ""))
    assert "BUILD_INSTALLER_ENABLED" in if_condition, (
        "build-installer job is no longer gated. Update this test or "
        "restore the gate."
    )


def test_ci_pip_audit_step_continues_on_error_for_now():
    """pip-audit is non-blocking right now (continue-on-error: true).
    Document this is intentional — when deps stabilise and the team
    is confident no zero-days are open, this flag should be removed.

    Test verifies the flag IS present (so dropping the flag silently
    without a deliberate decision fails)."""
    data = _load_ci()
    sec = data["jobs"].get("security", {})
    assert sec.get("continue-on-error") is True, (
        "The security job's continue-on-error is now `false`/missing. "
        "If this is intentional, GOOD — it means the team is enforcing "
        "the dep-CVE scan as a hard gate. Update this test to assert "
        "False (or remove this test) to lock in the new policy."
    )
