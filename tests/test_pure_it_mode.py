"""Regression tests for v0.17.4 Cycle K — pure-IT mode.

Pins the contract that lifting the AI-scope gate (via
`analyze(system, require_ai_components=False)` or
`atms analyze --allow-pure-it`) enables pure-IT and pure-OT systems
to be analyzed without raising NoAIComponentsError.

The default behaviour is UNCHANGED: pure-IT systems still raise
NoAIComponentsError unless the user explicitly opts into the new mode.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from atms.cli import cli
from atms.engines.ai_scope import NoAIComponentsError
from atms.models import Component, System
from atms.workflow import analyze


def _pure_it_system() -> System:
    """An IT-only system — firewall + database + web app. Zero AI."""
    return System(name="it-only", components=[
        Component(id="fw", name="Edge firewall", type="firewall"),
        Component(id="web", name="Web app", type="web_application"),
        Component(id="db", name="Customer DB", type="database"),
    ])


def _pure_ot_system() -> System:
    """An OT-only system — PLC + SCADA + HMI. Zero AI."""
    return System(name="ot-only", components=[
        Component(id="plc", name="PLC", type="plc"),
        Component(id="scada", name="SCADA master", type="scada"),
        Component(id="hmi", name="HMI", type="hmi"),
    ])


# ─── Default behaviour unchanged ────────────────────────────────────
def test_default_behaviour_rejects_pure_it():
    """Without the new flag, pure-IT systems still raise — the v0.15+
    AI-anchored contract is preserved for existing callers."""
    with pytest.raises(NoAIComponentsError):
        analyze(_pure_it_system())


def test_default_behaviour_rejects_pure_ot():
    with pytest.raises(NoAIComponentsError):
        analyze(_pure_ot_system())


# ─── Opt-in pure-IT mode ────────────────────────────────────────────
def test_pure_it_mode_accepts_pure_it_system():
    """require_ai_components=False analyses a pure-IT system without raising."""
    tm = analyze(_pure_it_system(), require_ai_components=False)
    assert tm.threats, "expected playbook threats to fire in pure-IT mode"
    # Each component should have at least one threat.
    ids_with_threats = {t.component_id for t in tm.threats}
    assert {"fw", "web", "db"}.issubset(ids_with_threats), (
        f"every component should produce threats; got {ids_with_threats}"
    )


def test_pure_it_mode_accepts_pure_ot_system():
    tm = analyze(_pure_ot_system(), require_ai_components=False)
    assert tm.threats
    ids_with_threats = {t.component_id for t in tm.threats}
    assert {"plc", "scada", "hmi"}.issubset(ids_with_threats)


def test_pure_it_mode_preserves_ai_behaviour_when_ai_present():
    """A mixed system (AI + IT) under `require_ai_components=False`
    behaves the same as default mode — AI provenance still flows
    through to the threats."""
    sys_obj = System(name="hybrid", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(id="db", name="DB", type="database"),
    ])
    tm_default = analyze(sys_obj)
    tm_pure_it = analyze(sys_obj, require_ai_components=False)
    # Same threat IDs in both runs (since the system has AI, the
    # blast-radius logic kicks in either way).
    assert {t.id for t in tm_default.threats} == {t.id for t in tm_pure_it.threats}


def test_pure_it_mode_summary_has_expected_keys():
    """Pure-IT analyses still produce the standard summary shape."""
    tm = analyze(_pure_it_system(), require_ai_components=False)
    for key in ("severity_breakdown", "risk_matrix", "ale",
                "threats_active", "threats_closed"):
        assert key in tm.summary, f"missing summary key: {key}"


# ─── CLI: --allow-pure-it flag ──────────────────────────────────────
def test_cli_allow_pure_it_flag_works_on_it_only_system():
    yaml_path = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8",
    )
    yaml.safe_dump({
        "name": "no-ai",
        "components": [
            {"id": "fw", "name": "Firewall", "type": "firewall"},
            {"id": "db", "name": "DB", "type": "database"},
        ],
    }, yaml_path)
    yaml_path.close()
    try:
        with tempfile.TemporaryDirectory() as out:
            res = CliRunner().invoke(cli, [
                "analyze", yaml_path.name,
                "--out", out,
                "--format", "json",
                "--allow-pure-it",
            ])
            assert res.exit_code == 0, res.output
            assert "Analysis complete" in res.output or "threats=" in res.output
    finally:
        Path(yaml_path.name).unlink(missing_ok=True)


def test_cli_without_allow_pure_it_still_rejects_pure_it():
    """The CLI default keeps the AI-anchored contract: pure-IT YAML
    must surface the NoAIComponentsError message."""
    yaml_path = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8",
    )
    yaml.safe_dump({
        "name": "no-ai",
        "components": [
            {"id": "fw", "name": "Firewall", "type": "firewall"},
        ],
    }, yaml_path)
    yaml_path.close()
    try:
        with tempfile.TemporaryDirectory() as out:
            res = CliRunner().invoke(cli, [
                "analyze", yaml_path.name,
                "--out", out,
                "--format", "json",
            ])
            # Existing CLI catches NoAIComponentsError as a friendly
            # warning + non-zero exit.
            assert res.exit_code != 0 or "AI" in res.output
    finally:
        Path(yaml_path.name).unlink(missing_ok=True)


def test_cli_help_documents_allow_pure_it():
    res = CliRunner().invoke(cli, ["analyze", "--help"])
    assert res.exit_code == 0
    assert "--allow-pure-it" in res.output
    assert "AI-anchored" in res.output or "general-purpose" in res.output.lower()
