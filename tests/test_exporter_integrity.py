"""Exporter integrity regressions (audit F015/F016/F017/F018/F047)."""

from __future__ import annotations

import json

import pytest

from atms.models import Component, Dataflow, System
from atms.reporting.csv_export import csv_safe, write_csv
from atms.reporting.jira_export import render_jira_csv
from atms.reporting.navigator import render_navigator
from atms.reporting.stix import render_stix
from atms.workflow import analyze

pytestmark = pytest.mark.hibernated  # these exporters are hibernated surfaces


def _hybrid():
    s = System(name="H", components=[
        Component(id="u", name="User", type="user", trust_zone="internet"),
        Component(id="llm", name="L", type="llm_inference"),
        Component(id="vm", name="VM", type="cloud_compute"),
    ], dataflows=[Dataflow(source="u", target="llm"), Dataflow(source="vm", target="llm")])
    return analyze(s)


def test_jira_risk_score_is_over_100_not_25():
    """F015: risk_score is a 0-100 scale; the label must read /100."""
    out = render_jira_csv(_hybrid())
    assert "/25" not in out
    assert "/100" in out


def test_navigator_hybrid_emits_both_layers():
    """F016: a hybrid AI+cloud system emits BOTH the ATLAS and the ATT&CK
    Enterprise/Cloud layers, not just ATLAS."""
    nav = json.loads(render_navigator(_hybrid()))
    assert isinstance(nav, list), "hybrid system should produce a multi-layer array"
    domains = {layer["domain"] for layer in nav}
    assert "atlas" in domains and "enterprise-attack" in domains


def test_stix_has_no_empty_external_references():
    """F018: STIX 2.1 forbids an empty external_references array; the key must
    be omitted when a threat has no framework refs."""
    bundle = json.loads(render_stix(_hybrid()))
    for obj in bundle["objects"]:
        assert obj.get("external_references") != [], (
            f"{obj.get('id')} emits invalid empty external_references[]"
        )


def test_csv_safe_neutralises_formula_injection():
    """F047: a cell beginning with = + - @ is prefixed so spreadsheets don't
    execute it; a component named '=cmd|calc' must not stay a live formula."""
    assert csv_safe("=cmd|'/c calc'!A1").startswith("'=")
    assert csv_safe("+1").startswith("'+")
    assert csv_safe("@SUM(A1)").startswith("'@")
    assert csv_safe("normal text") == "normal text"
    tm = analyze(System(name="X", components=[Component(id="c", name="=cmd|calc", type="llm_inference")]))
    rr = write_csv(tm, "risk_register")
    assert "'=cmd|calc" in rr  # neutralised in the rendered CSV


def test_roadmap_renders_after_most_severe_change():
    """F017: the roadmap (now labelling by most-severe addressed severity)
    still renders end-to-end."""
    from atms.reporting.roadmap_export import render_roadmap_md
    assert render_roadmap_md(_hybrid())
