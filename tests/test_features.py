"""Hibernation Phase 1 — feature-flag module contract tests.

The hibernation roadmap (see CHANGELOG v0.18.68) narrows ATMS to the
core promise by defaulting every non-essential capability OFF. This
test pins the flag contract:

  * Every KEEP flag defaults True.
  * Every HIBERNATE flag defaults False.
  * Env-var override pattern works (ATMS_FEATURE_<NAME>=1).
  * `enabled_features()` round-trips the contract.
  * `is_enabled()` matches the constant lookup.
  * `FeatureDisabledError` carries the canonical re-enable hint.

This test file is the regression net for the narrowing. If a flag's
default gets flipped accidentally (e.g. via a merge), this test
catches it before behaviour drifts.
"""

from __future__ import annotations

import os

import pytest

import atms.features as features_mod
from atms.features import FeatureDisabledError, enabled_features, is_enabled

# ─── Default-state contract ─────────────────────────────────────────

# v1.0.1 (2026-05-31) un-hibernation: every FREE + OFFLINE capability is
# enabled by default. KEEP_FLAGS = "default ON". Only two cases stay OFF:
#   * vision  — needs a local Ollama vision model pulled first (opt-in)
#   * nav_*   — top-bar PLACEMENT flags; the tools WORK + are reachable
#               from /docs, these only control whether each gets a tab.
KEEP_FLAGS = {
    # core
    "analyze", "editor", "samples", "docs",
    "web_ui", "report_html", "report_md",
    # input parsers (free, offline)
    "ingest_yaml", "ingest_drawio", "ingest_mermaid", "ingest_vsdx",
    "ingest_tm7", "ingest_otm", "ingest_terraform", "ingest_pulumi",
    "ingest_cfn", "ingest_azure", "ingest_k8s", "ingest_compose",
    # evidence / red-team
    "evidence", "redteam", "cve_lookup", "feeds_refresh",
    # analysis-tool surfaces (functional flags; nav placement is separate)
    "iac", "compliance", "devices", "diff",
    # exporters
    "export_sbom", "export_stix", "export_sarif", "export_navigator",
    "export_jira", "export_roadmap", "export_otm", "export_csv",
    "export_compliance_matrix", "export_csa_table", "export_csa_risk",
    # delivery surfaces
    "rest_api", "mcp_server", "build_exe", "build_installer",
    # framework engines
    "framework_linddun", "framework_nist_ai_100_2",
    "framework_nist_ai_rmf", "framework_owasp_ml",
    # extra CLI
    "cli_watch", "cli_review", "cli_diff", "cli_kb_browsers",
}

# Default-OFF: opt-in vision + the top-bar placement flags.
HIBERNATE_FLAGS = {
    "vision",
    "nav_iac", "nav_compliance", "nav_devices", "nav_diff",
}


def _defaults_snapshot(monkeypatch) -> dict[str, bool]:
    """Take a snapshot of feature flags AS IF no env var was set —
    i.e. the compiled-default contract.

    Uses monkeypatch.delenv so vars are restored at fixture teardown.
    No module reload needed: ``enabled_features()`` reads env at call
    time (Phase 7 refactor)."""
    for k in list(os.environ):
        if k.startswith("ATMS_FEATURE_"):
            monkeypatch.delenv(k, raising=False)
    return features_mod.enabled_features()


def test_keep_flags_all_default_true(monkeypatch):
    """The core promise stays on by default.

    Tests the COMPILED defaults (env-var-free), not whatever the runner
    has set in the current process. This is the regression net against
    someone accidentally flipping a KEEP flag to default False."""
    snap = _defaults_snapshot(monkeypatch)
    missing = KEEP_FLAGS - set(snap.keys())
    assert not missing, f"KEEP flag names missing from module: {missing}"
    for flag in KEEP_FLAGS:
        assert snap[flag] is True, (
            f"KEEP flag `{flag}` defaulted to False — core promise broke. "
            f"Check src/atms/features.py."
        )


def test_hibernate_flags_all_default_false(monkeypatch):
    """Every non-core capability defaults OFF.

    Tests the COMPILED defaults (env-var-free); see `_defaults_snapshot`."""
    snap = _defaults_snapshot(monkeypatch)
    missing = HIBERNATE_FLAGS - set(snap.keys())
    assert not missing, f"HIBERNATE flag names missing: {missing}"
    for flag in HIBERNATE_FLAGS:
        assert snap[flag] is False, (
            f"HIBERNATE flag `{flag}` defaulted to True — "
            f"non-core capability is live. Check src/atms/features.py."
        )


def test_keep_and_hibernate_sets_are_disjoint():
    """A flag is exactly one of KEEP / HIBERNATE — no overlap."""
    overlap = KEEP_FLAGS & HIBERNATE_FLAGS
    assert not overlap, f"flags in both KEEP and HIBERNATE: {overlap}"


def test_enabled_features_covers_every_module_constant():
    """`enabled_features()` snapshot includes every FEATURE_* constant
    in the module — so adding a new flag without listing it here will
    surface immediately."""
    snap = enabled_features()
    module_consts = {
        k.removeprefix("FEATURE_").lower()
        for k in dir(features_mod)
        if k.startswith("FEATURE_") and isinstance(
            getattr(features_mod, k), bool
        )
    }
    assert module_consts == set(snap.keys())


def test_every_module_flag_is_in_keep_or_hibernate():
    """Every flag in features.py is categorised — catches the case where
    a new flag gets added without the test acknowledging which side
    of the rule it belongs to."""
    snap_keys = set(enabled_features().keys())
    uncategorised = snap_keys - KEEP_FLAGS - HIBERNATE_FLAGS
    assert not uncategorised, (
        f"flags not categorised in this test: {sorted(uncategorised)}. "
        f"Decide KEEP or HIBERNATE and add to the appropriate set."
    )


# ─── Env-var override contract ──────────────────────────────────────


@pytest.mark.parametrize("env_val,expected", [
    ("1", True),
    ("true", True),
    ("TRUE", True),
    ("yes", True),
    ("on", True),
    ("0", False),
    ("false", False),
    ("no", False),
    ("off", False),
    ("", False),
    ("garbage", False),
])
def test_env_var_override_parses_truthy_strings(monkeypatch, env_val, expected):
    """ATMS_FEATURE_<NAME> env var → bool with the expected truthy set.

    Uses ``is_enabled`` (env-aware at call time) so no module reload
    is needed."""
    monkeypatch.setenv("ATMS_FEATURE_EVIDENCE", env_val)
    assert features_mod.is_enabled("evidence") is expected


def test_env_var_override_can_disable_a_keep_flag(monkeypatch):
    """The override pattern works for OFF as well as ON — useful for
    a "minimal-mode" deployment that drops even the Samples page."""
    monkeypatch.setenv("ATMS_FEATURE_SAMPLES", "0")
    assert features_mod.is_enabled("samples") is False


def test_env_var_unset_returns_compiled_default(monkeypatch):
    """No env var → compiled default. monkeypatch restores env vars
    at teardown, and ``is_enabled`` reads env at call time (Phase 7
    refactor) so no module reload is needed."""
    for k in list(os.environ):
        if k.startswith("ATMS_FEATURE_"):
            monkeypatch.delenv(k, raising=False)
    assert features_mod.is_enabled("analyze") is True
    # vision is the canonical default-OFF feature (opt-in local Ollama).
    assert features_mod.is_enabled("vision") is False


# ─── is_enabled() helper contract ───────────────────────────────────


def test_is_enabled_matches_constants():
    """`is_enabled(name)` returns the same value as the FEATURE_NAME
    constant."""
    for name, value in enabled_features().items():
        assert is_enabled(name) is value, (
            f"is_enabled({name!r}) drift vs. FEATURE_{name.upper()}"
        )


def test_is_enabled_unknown_returns_false():
    """Unknown feature names return False rather than raising — keeps
    callers simple (no try/except, just check)."""
    assert is_enabled("nonexistent_xyz_feature") is False


def test_is_enabled_case_insensitive(monkeypatch):
    """`is_enabled` accepts any case. Strips ATMS_FEATURE_* env vars so
    the result reflects compiled defaults regardless of conftest /
    runner state."""
    for k in list(os.environ):
        if k.startswith("ATMS_FEATURE_"):
            monkeypatch.delenv(k, raising=False)
    assert is_enabled("VISION") is is_enabled("vision") is False
    assert is_enabled("ANALYZE") is is_enabled("analyze") is True


# ─── FeatureDisabledError exception contract ─────────────────────────────


def test_feature_disabled_carries_feature_name():
    """The exception exposes the feature name as an attribute."""
    exc = FeatureDisabledError("evidence")
    assert exc.feature == "evidence"


def test_feature_disabled_message_includes_re_enable_hint():
    """The error message itself tells the caller how to flip it —
    no need to grep docs."""
    msg = str(FeatureDisabledError("vision"))
    assert "ATMS_FEATURE_VISION=1" in msg
    assert "src/atms/features.py" in msg
    assert "Re-enabling hibernated features" in msg


def test_feature_disabled_is_a_runtime_error():
    """Hibernated path → RuntimeError subclass; lets callers
    `except RuntimeError` if they want a generic catch."""
    assert issubclass(FeatureDisabledError, RuntimeError)


# ─── Snapshot stability ─────────────────────────────────────────────


def test_enabled_features_returns_a_new_dict_each_call():
    """The snapshot is a fresh dict, not a shared mutable reference."""
    a = enabled_features()
    b = enabled_features()
    a["analyze"] = False
    assert b["analyze"] is True  # not mutated by the change to `a`


def test_module_exports_explicit_all():
    """`__all__` is set so star-imports stay deliberate."""
    assert hasattr(features_mod, "__all__")
    assert "FEATURE_ANALYZE" in features_mod.__all__
    assert "FeatureDisabledError" in features_mod.__all__
    assert "is_enabled" in features_mod.__all__
    assert "enabled_features" in features_mod.__all__
