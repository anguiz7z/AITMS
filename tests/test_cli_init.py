"""Regression tests for v0.17.3 Cycle I — `atms init` scaffold.

Pins three contracts:
  1. Each of the 4 templates (basic / rag / agentic / chatbot)
     produces a syntactically-valid System YAML that round-trips
     through Pydantic.
  2. The scaffold defaults to deployment_stage=poc so users get the
     conservative FAIR-priors tier out of the box.
  3. Idempotency: re-running over an existing file refuses without
     --force.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from atms.cli import cli
from atms.models import System


@pytest.mark.parametrize("template", ["basic", "rag", "agentic", "chatbot"])
def test_init_produces_valid_system_yaml(template):
    """Every template scaffold parses + validates as a real System."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / f"test_{template}.yaml"
        res = runner.invoke(cli, [
            "init", f"test-{template}",
            "--template", template,
            "--out", str(out),
        ])
        assert res.exit_code == 0, res.output
        assert out.exists()
        raw = yaml.safe_load(out.read_text(encoding="utf-8"))
        # The scaffold MUST be valid against the System schema.
        sys_obj = System.model_validate(raw)
        assert sys_obj.name == f"test-{template}"
        assert len(sys_obj.components) >= 2


@pytest.mark.parametrize("template", ["basic", "rag", "agentic", "chatbot"])
def test_init_defaults_to_poc_deployment_stage(template):
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "x.yaml"
        runner.invoke(cli, [
            "init", "x", "--template", template, "--out", str(out),
        ])
        raw = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert raw.get("deployment_stage") == "poc", (
            f"{template} scaffold should default to deployment_stage=poc"
        )


def test_init_refuses_to_overwrite_without_force():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "exists.yaml"
        out.write_text("placeholder", encoding="utf-8")
        res = runner.invoke(cli, ["init", "x", "--out", str(out)])
        assert res.exit_code != 0, "should refuse to overwrite"
        assert "already exists" in res.output.lower()
        # Original content untouched
        assert out.read_text() == "placeholder"


def test_init_force_overwrites():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "exists.yaml"
        out.write_text("placeholder", encoding="utf-8")
        res = runner.invoke(cli, ["init", "x", "--out", str(out), "--force"])
        assert res.exit_code == 0, res.output
        # Now it's a real System YAML
        raw = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert raw["name"] == "x"


def test_init_default_path_is_name_yaml():
    """No --out → writes <name>.yaml in cwd."""
    runner = CliRunner()
    with runner.isolated_filesystem() as td:
        res = runner.invoke(cli, ["init", "my-sample"])
        assert res.exit_code == 0, res.output
        assert (Path(td) / "my-sample.yaml").exists()


def test_init_help_lists_all_four_templates():
    res = CliRunner().invoke(cli, ["init", "--help"])
    assert res.exit_code == 0
    out = res.output
    for tpl in ("basic", "rag", "agentic", "chatbot"):
        assert tpl in out, f"template {tpl!r} not in --help"


def test_init_scaffolds_pass_validate_subcommand():
    """End-to-end: a scaffolded system passes `atms validate` (the
    Cycle H CI-grade tool). Confirms the scaffolds aren't subtly
    broken."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        scaffold = Path(td) / "x.yaml"
        r1 = runner.invoke(cli, ["init", "x", "--out", str(scaffold)])
        assert r1.exit_code == 0
        r2 = runner.invoke(cli, ["validate", str(scaffold)])
        assert r2.exit_code == 0, r2.output
