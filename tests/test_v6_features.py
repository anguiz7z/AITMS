"""Tests for v0.6.0 additions: Mermaid DFD, mitigation prioritisation, atms diff,
realistic enterprise sample.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from atms.engines.mitigations import prioritise_mitigations
from atms.models import Component, Mitigation, System, Threat
from atms.reporting import render_mermaid
from atms.workflow import analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ─────────────────────────────────────────── Mermaid DFD
def test_mermaid_basic_structure():
    s = System(
        name="t",
        components=[
            Component(id="u", name="user", type="user", trust_zone="internet"),
            Component(id="a", name="agent", type="agent", trust_zone="corp"),
        ],
        dataflows=[],
    )
    out = render_mermaid(s)
    assert out.startswith("flowchart")
    assert "subgraph zone_internet" in out
    assert "subgraph zone_corp" in out
    # Stadium for user, hexagon for agent
    assert 'u(["user' in out
    assert 'a{{"agent' in out


def test_mermaid_edges_and_boundary_crossings():
    s = System(
        name="t",
        components=[
            Component(id="u", name="u", type="user", trust_zone="internet"),
            Component(id="a", name="a", type="agent", trust_zone="corp"),
        ],
        dataflows=[],
    )
    from atms.models import Dataflow

    s.dataflows = [
        Dataflow(source="u", target="a", label="msg", crosses_boundary=False),
        Dataflow(source="a", target="u", label="reply", crosses_boundary=True),
    ]
    out = render_mermaid(s)
    assert "u -->|" in out  # normal arrow
    assert "a ==>|" in out  # thick boundary-crossing arrow


def test_mermaid_safe_ids():
    s = System(
        name="t",
        components=[
            Component(id="weird-id.with#chars", name="X", type="user"),
        ],
    )
    out = render_mermaid(s)
    # Sanitised id
    assert "weird_id_with_chars" in out


def test_mermaid_in_full_workflow():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    out = render_mermaid(tm.system)
    # Every component id should appear at least once
    for c in tm.system.components:
        assert c.id.replace("-", "_").replace(".", "_") in out, f"missing {c.id}"


# ─────────────────────────────────────────── Mitigation prioritisation
def test_prioritise_returns_top_n():
    threats = [
        Threat(id="t1", component_id="c", title="t1", description="x", likelihood=5, impact=5, severity="critical"),
        Threat(id="t2", component_id="c", title="t2", description="x", likelihood=2, impact=2, severity="low"),
    ]
    mits = [
        Mitigation(id="m1", title="big-bang", description="x", addresses_threat_ids=["t1"], effort="low", risk_reduction=5),
        Mitigation(id="m2", title="small", description="x", addresses_threat_ids=["t2"], effort="high", risk_reduction=2),
    ]
    ranked = prioritise_mitigations(mits, threats, top_n=10)
    assert ranked[0].id == "m1"
    assert ranked[-1].id == "m2"


def test_prioritise_truncates_to_top_n():
    mits = [
        Mitigation(id=f"m{i}", title=f"m{i}", description="x", addresses_threat_ids=[], effort="medium", risk_reduction=3)
        for i in range(20)
    ]
    ranked = prioritise_mitigations(mits, [], top_n=5)
    assert len(ranked) == 5


def test_workflow_exposes_priority_ids():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    pids = tm.summary.get("priority_mitigation_ids", [])
    assert len(pids) >= 1
    assert len(pids) <= 10
    # Every priority id must be present in the mitigation list
    all_ids = {m.id for m in tm.mitigations}
    for pid in pids:
        assert pid in all_ids


# ─────────────────────────────────────────── Enterprise sample
def test_enterprise_sample_loads_and_analyses():
    raw = yaml.safe_load((SAMPLES / "enterprise_rag_agent.yaml").read_text(encoding="utf-8"))
    s = System.model_validate(raw)
    assert len(s.components) >= 18
    tm = analyze(s)
    # A 20-component system should produce a substantial threat surface
    assert len(tm.threats) >= 50
    # Should hit all 7 MAESTRO layers
    assert len(tm.summary["maestro_layers"]) == 7
    # Should hit at least 12 OWASP Agentic threats
    assert len(tm.summary["owasp_agentic_coverage"]) >= 12


# ─────────────────────────────────────────── atms diff
@pytest.mark.hibernated  # Phase 4
def test_diff_command_detects_added_and_removed(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli

    # Build two slightly different threat-model JSONs
    base = {
        "system": {"name": "x", "components": [], "dataflows": [], "trust_boundaries": []},
        "threats": [
            {"id": "T_A", "component_id": "c", "component_name": "c", "title": "alpha",
             "description": "", "likelihood": 3, "impact": 3, "severity": "medium",
             "risk_score": 50.0,
             "stride_ai": [], "owasp_llm": [], "owasp_agentic": [], "atlas_techniques": [],
             "nist_ai_rmf": [], "maestro_layers": [], "maestro_threats": [],
             "confidence": 0.9, "mitigation_ids": [], "references": []},
            {"id": "T_B", "component_id": "c", "component_name": "c", "title": "beta",
             "description": "", "likelihood": 4, "impact": 4, "severity": "high",
             "risk_score": 75.0,
             "stride_ai": [], "owasp_llm": [], "owasp_agentic": [], "atlas_techniques": [],
             "nist_ai_rmf": [], "maestro_layers": [], "maestro_threats": [],
             "confidence": 0.9, "mitigation_ids": [], "references": []},
        ],
        "attack_paths": [], "mitigations": [], "summary": {"threats": 2, "mitigations": 0},
        "generated_at": "2026-05-09T00:00:00+00:00", "tool_version": "0.6.0",
    }
    new = json.loads(json.dumps(base))
    # Remove T_B, add T_C, escalate T_A from medium to critical
    new["threats"] = [
        {**base["threats"][0], "severity": "critical", "risk_score": 95.0},
        {"id": "T_C", "component_id": "c", "component_name": "c", "title": "gamma",
         "description": "", "likelihood": 5, "impact": 5, "severity": "critical",
         "risk_score": 100.0,
         "stride_ai": [], "owasp_llm": [], "owasp_agentic": [], "atlas_techniques": [],
         "nist_ai_rmf": [], "maestro_layers": [], "maestro_threats": [],
         "confidence": 0.9, "mitigation_ids": [], "references": []},
    ]
    new["summary"] = {"threats": 2, "mitigations": 0}

    old_p = tmp_path / "old.json"
    new_p = tmp_path / "new.json"
    old_p.write_text(json.dumps(base), encoding="utf-8")
    new_p.write_text(json.dumps(new), encoding="utf-8")

    res = CliRunner().invoke(cli, ["diff", str(old_p), str(new_p), "--format", "json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    added = [t["id"] for t in payload["added_threats"]]
    removed = [t["id"] for t in payload["removed_threats"]]
    assert "T_C" in added
    assert "T_B" in removed
    sev_changed = {x["threat_id"] for x in payload["severity_changed"]}
    assert "T_A" in sev_changed


def test_kb_search_cli_accepts_all_framework_choices():
    """Regression: CLI must accept owasp_llm / owasp_agentic / maestro filters
    (was stale in v0.2-v0.7.0 and only allowed atlas|owasp|nist|all)."""
    from click.testing import CliRunner

    from atms.cli import cli

    for fw in ["all", "atlas", "owasp", "owasp_llm", "owasp_agentic", "maestro", "nist"]:
        res = CliRunner().invoke(cli, ["kb-search", "prompt", "--framework", fw, "--limit", "1"])
        assert res.exit_code == 0, f"--framework {fw} crashed: {res.output}"


@pytest.mark.hibernated  # Phase 4


def test_diff_command_markdown_format(tmp_path):
    """Markdown rendering should produce headings and not crash."""
    from click.testing import CliRunner

    from atms.cli import cli

    doc = {
        "system": {"name": "x", "components": [], "dataflows": [], "trust_boundaries": []},
        "threats": [],
        "attack_paths": [], "mitigations": [], "summary": {"threats": 0, "mitigations": 0},
        "generated_at": "2026-05-09T00:00:00+00:00", "tool_version": "0.6.0",
    }
    p1 = tmp_path / "a.json"; p1.write_text(json.dumps(doc), encoding="utf-8")
    p2 = tmp_path / "b.json"; p2.write_text(json.dumps(doc), encoding="utf-8")
    res = CliRunner().invoke(cli, ["diff", str(p1), str(p2), "--format", "markdown"])
    assert res.exit_code == 0
    assert "# Diff:" in res.output
