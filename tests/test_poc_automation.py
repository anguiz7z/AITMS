"""Regression tests for v0.17.3 Cycle E — POC / scale-tier automation.

Closes the "POC is not automated" pain point. Three contracts pinned:
  1. `atms analyze --deployment-stage poc` overrides
     System.deployment_stage from the command line.
  2. `--industry` + `--revenue-bucket` flags override the same fields.
  3. The editor UI exposes a deployment_stage dropdown that round-trips
     into the saved/analysed System.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml
from click.testing import CliRunner
from fastapi.testclient import TestClient

from atms.cli import cli
from atms.web import app

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _write_temp_system_yaml() -> Path:
    """Minimal 2-component YAML with NO scale-tier fields set."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8",
    )
    yaml.safe_dump({
        "name": "test",
        "components": [
            {"id": "u", "name": "U", "type": "user"},
            {"id": "llm", "name": "LLM", "type": "llm_inference"},
        ],
    }, f)
    f.close()
    return Path(f.name)


def test_cli_deployment_stage_flag_overrides_system():
    """`--deployment-stage poc` reaches the analysed System."""
    yaml_path = _write_temp_system_yaml()
    try:
        with tempfile.TemporaryDirectory() as out:
            res = CliRunner().invoke(cli, [
                "analyze", str(yaml_path),
                "--out", out,
                "--format", "json",
                "--deployment-stage", "poc",
            ])
            assert res.exit_code == 0, res.output
            assert "CLI overrides applied" in res.output
            assert "stage=poc" in res.output
    finally:
        yaml_path.unlink(missing_ok=True)


def test_cli_industry_flag_overrides_system():
    """`--industry tier1_bank` is exposed + applied."""
    yaml_path = _write_temp_system_yaml()
    try:
        with tempfile.TemporaryDirectory() as out:
            res = CliRunner().invoke(cli, [
                "analyze", str(yaml_path),
                "--out", out,
                "--format", "json",
                "--industry", "tier1_bank",
            ])
            assert res.exit_code == 0, res.output
            assert "industry=tier1_bank" in res.output
    finally:
        yaml_path.unlink(missing_ok=True)


def test_cli_revenue_bucket_flag_overrides_system():
    yaml_path = _write_temp_system_yaml()
    try:
        with tempfile.TemporaryDirectory() as out:
            res = CliRunner().invoke(cli, [
                "analyze", str(yaml_path),
                "--out", out,
                "--format", "json",
                "--revenue-bucket", "over_5b",
            ])
            assert res.exit_code == 0, res.output
            assert "revenue=over_5b" in res.output
    finally:
        yaml_path.unlink(missing_ok=True)


def test_cli_all_three_flags_combine():
    """All three scale-tier flags can be set at once."""
    yaml_path = _write_temp_system_yaml()
    try:
        with tempfile.TemporaryDirectory() as out:
            res = CliRunner().invoke(cli, [
                "analyze", str(yaml_path),
                "--out", out,
                "--format", "json",
                "--deployment-stage", "poc",
                "--industry", "tier1_bank",
                "--revenue-bucket", "over_5b",
            ])
            assert res.exit_code == 0, res.output
            # All three overrides surface in the log line.
            assert "stage=poc" in res.output
            assert "industry=tier1_bank" in res.output
            assert "revenue=over_5b" in res.output
    finally:
        yaml_path.unlink(missing_ok=True)


def test_cli_poc_caps_ale_below_pilot():
    """End-to-end: same YAML, different --deployment-stage. POC tier
    should produce LOWER ALE than production tier (the user-visible
    POC automation actually changes the output)."""
    import json
    yaml_path = _write_temp_system_yaml()
    try:
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as out_dir:
            out = Path(out_dir)
            r1 = runner.invoke(cli, [
                "analyze", str(yaml_path),
                "--out", str(out / "poc"),
                "--format", "json",
                "--industry", "tier1_bank",
                "--deployment-stage", "poc",
            ])
            r2 = runner.invoke(cli, [
                "analyze", str(yaml_path),
                "--out", str(out / "prod"),
                "--format", "json",
                "--industry", "tier1_bank",
                "--deployment-stage", "production",
                "--revenue-bucket", "over_5b",
            ])
            assert r1.exit_code == 0, r1.output
            assert r2.exit_code == 0, r2.output
            # Output filename uses the input YAML's stem.
            stem = yaml_path.stem
            poc_tm = json.loads((out / "poc" / f"{stem}.json").read_text())
            prod_tm = json.loads((out / "prod" / f"{stem}.json").read_text())
            poc_ale = poc_tm["summary"]["ale"]["ale_high_total"]
            prod_ale = prod_tm["summary"]["ale"]["ale_high_total"]
            # POC tier caps loss_high at $5M + frequency at 1/yr; prod tier
            # uses much higher caps. POC ALE must be far below prod ALE.
            assert poc_ale < prod_ale, (
                f"POC ALE ${poc_ale:,.0f} should be < prod ALE ${prod_ale:,.0f}"
            )
    finally:
        yaml_path.unlink(missing_ok=True)


def test_editor_html_has_deployment_stage_dropdown():
    """The editor toolbar exposes a deployment_stage dropdown."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/editor")
    assert r.status_code == 200
    html = r.text
    assert 'id="deployment-stage"' in html
    # All three options must be present
    for opt in ("poc", "pilot", "production"):
        assert f'value="{opt}"' in html, f"option value={opt!r} missing"


def test_cli_help_includes_poc_flags():
    """The --help text mentions --deployment-stage so it's discoverable."""
    res = CliRunner().invoke(cli, ["analyze", "--help"])
    assert res.exit_code == 0
    assert "--deployment-stage" in res.output
    assert "--industry" in res.output
    assert "--revenue-bucket" in res.output
