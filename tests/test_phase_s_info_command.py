"""Phase S — `atms info` diagnostic command (v0.18.67).

Bug-report friction: when a user opens an issue, the maintainer's
first question is always "what's your Python, your ATMS version, are
you running the .exe or pip install, is your KB intact?". Until v0.18.67,
the user had to run 4 separate commands to gather that info.

Phase S adds `atms info` (and `atms info --json` for scripting) which
prints all of it in one shot. Modelled after the well-known
`pip --version`, `kubectl version`, `docker info` pattern.

This file pins:
  * The command is registered and listed in `atms --help`.
  * Human-readable output mentions all five KB counts + version +
    platform.
  * `--json` output is valid JSON, all fields present, types right.
  * Counts match the bundle's actual content (121 playbooks, 121
    component types, 117 controls, 15 frameworks, 25 arch rules).
    These are load-bearing — if any drops, something silently broke
    in the KB load path.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from atms import __version__ as atms_version
from atms.cli import cli


def test_info_command_listed_in_help():
    """`atms --help` mentions the new command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "info" in result.output


def test_info_human_form_includes_version():
    """Human-readable output mentions the current ATMS version."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info"])
    assert result.exit_code == 0, f"failed: {result.output}"
    assert f"ATMS v{atms_version}" in result.output


def test_info_human_form_mentions_kb_sections():
    """Human form lists all the KB count headings — guards against the
    output silently losing a section."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info"])
    for label in (
        "Playbooks",
        "Frameworks",
        "Compliance controls",
        "Architecture rules",
        "Component types",
    ):
        assert label in result.output, (
            f"`atms info` output missing label `{label}`: {result.output}"
        )


def test_info_human_form_includes_python_and_platform():
    """The Python version + platform string should appear — they're the
    most-asked bug-report data points after the ATMS version."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info"])
    # Python version line.
    assert "Python" in result.output
    # Platform string (Linux / Windows / Darwin).
    assert "Platform" in result.output
    # Frozen-exe indicator (yes/no).
    assert "Frozen exe" in result.output


def test_info_json_form_is_valid_json():
    """`atms info --json` output parses as JSON."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, dict)


def test_info_json_form_has_all_top_level_fields():
    """JSON output declares the contract:
    {atms_version, python_version, python_implementation, platform,
     frozen, kb: {...}, features: {...}}

    v0.18.72 Hibernation Phase 6 adds the `features` block.
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--json"])
    data = json.loads(result.output)
    for key in (
        "atms_version",
        "python_version",
        "python_implementation",
        "platform",
        "frozen",
        "kb",
        "features",  # Phase 6
    ):
        assert key in data, f"info --json missing top-level key {key!r}"
    kb = data["kb"]
    for key in (
        "playbooks",
        "frameworks",
        "controls",
        "architecture_rules",
        "component_types",
    ):
        assert key in kb, f"info --json missing kb.{key!r}"
    # Phase 6 — features block contract.
    feats = data["features"]
    for key in ("enabled_count", "disabled_count", "enabled", "disabled"):
        assert key in feats, f"info --json missing features.{key!r}"
    assert isinstance(feats["enabled"], list)
    assert isinstance(feats["disabled"], list)
    assert feats["enabled_count"] == len(feats["enabled"])
    assert feats["disabled_count"] == len(feats["disabled"])


def test_info_json_features_block_lists_keep_flags_as_enabled():
    """The 9 KEEP flags must always show up in the `enabled` list
    (analyze, editor, samples, docs, ingest_yaml, ingest_drawio,
    web_ui, report_html, report_md)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--json"])
    data = json.loads(result.output)
    enabled = set(data["features"]["enabled"])
    keep = {
        "analyze", "editor", "samples", "docs",
        "ingest_yaml", "ingest_drawio",
        "web_ui", "report_html", "report_md",
    }
    missing = keep - enabled
    assert not missing, (
        f"KEEP flag(s) missing from info --json enabled list: {missing}. "
        f"Either features.py drifted or info command dropped fields."
    )


def test_info_json_features_block_reflects_enabled_by_default():
    """v1.0.1 un-hibernation: free/offline features are ON by default;
    only vision + the nav-placement flags are OFF. Formerly-hibernated
    functional features now appear in `enabled`."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--json"])
    data = json.loads(result.output)
    enabled = set(data["features"]["enabled"])
    disabled = set(data["features"]["disabled"])
    for flag in ("evidence", "redteam", "rest_api", "mcp_server", "ingest_vsdx"):
        assert flag in enabled, (
            f"`{flag}` should be enabled by default now, got: {disabled}"
        )
    for flag in ("vision", "nav_iac", "nav_compliance", "nav_devices", "nav_diff"):
        assert flag in disabled, (
            f"`{flag}` should be default-OFF, got enabled set: {enabled}"
        )


def test_info_human_form_mentions_feature_section():
    """The human-readable form has a `Features:` section that the JSON
    block also contains."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info"])
    assert "Features:" in result.output
    assert "Hibernated:" in result.output
    assert "Re-enable a hibernated feature:" in result.output
    assert "ATMS_FEATURE_" in result.output


def test_info_json_counts_match_bundle_reality():
    """The KB counts are load-bearing — if any drops below floor, the
    KB loaded with a missing file (which would silently degrade
    threat coverage on every analysis from then on)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--json"])
    data = json.loads(result.output)
    kb = data["kb"]

    # Floors locked to the v0.18.67 baseline. Use ≥ so adding more is fine.
    assert kb["playbooks"] >= 121, (
        f"Playbook count {kb['playbooks']} below the v0.18.67 floor of 121. "
        f"Probably means kb/playbooks/ failed to load some files."
    )
    assert kb["frameworks"] >= 15, kb["frameworks"]
    assert kb["controls"] >= 117, kb["controls"]
    assert kb["architecture_rules"] >= 25, kb["architecture_rules"]
    assert kb["component_types"] >= 121, kb["component_types"]


def test_info_json_version_matches_atms_version():
    """The version reported by `atms info` matches `atms.__version__`."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--json"])
    data = json.loads(result.output)
    assert data["atms_version"] == atms_version


def test_info_json_frozen_field_is_boolean():
    """`frozen` field should always be a real bool — guards against a
    refactor that returns the truthy `getattr(sys, 'frozen', False)`
    sentinel object instead of `True`/`False`."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info", "--json"])
    data = json.loads(result.output)
    assert isinstance(data["frozen"], bool)
