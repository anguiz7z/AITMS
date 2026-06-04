"""Regression tests for v0.18.23 Cycle MM — mitigation roadmap export."""

from __future__ import annotations

# v0.18.70 Hibernation Phase 3 — entire file exercises a
# hibernated surface. Skipped by default; run with:
#     pytest -m hibernated tests/test_roadmap_export.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import json

import pytest
from fastapi.testclient import TestClient

from atms.models import Component, System
from atms.reporting.roadmap_export import render_roadmap_json, render_roadmap_md
from atms.web import app
from atms.workflow import analyze


@pytest.fixture(scope="module")
def model():
    s = System(name="roadmap-test", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    return analyze(s)


# ─── Markdown renderer ─────────────────────────────────────────────
def test_md_starts_with_h1():
    s = System(name="hello", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    m = analyze(s)
    md = render_roadmap_md(m, top_n=3)
    assert md.startswith("# Mitigation roadmap — hello")


def test_md_includes_checkbox_per_task(model):
    md = render_roadmap_md(model, top_n=5)
    # Every task line has an unchecked `- [ ]` checkbox.
    boxes = md.count("- [ ]")
    assert boxes >= 1


def test_md_groups_by_family(model):
    md = render_roadmap_md(model, top_n=10)
    # At least one `## ` family heading appears.
    family_headings = [line for line in md.splitlines() if line.startswith("## ")]
    assert family_headings


def test_md_includes_validation_test_when_present():
    """Synthesise a mitigation with a validation_test field to ensure
    the renderer surfaces it."""
    s = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    m = analyze(s)
    if m.mitigations:
        m.mitigations[0].validation_test = "Run scanner X to confirm"
        # Force this mitigation to the top of priority by editing summary.
        m.summary["priority_mitigation_ids"] = [m.mitigations[0].id]
        md = render_roadmap_md(m, top_n=1)
        assert "Run scanner X to confirm" in md


def test_md_top_n_caps_output(model):
    md3 = render_roadmap_md(model, top_n=3)
    md10 = render_roadmap_md(model, top_n=10)
    boxes3 = md3.count("- [ ]")
    boxes10 = md10.count("- [ ]")
    assert boxes3 <= 3
    assert boxes10 >= boxes3


# ─── JSON renderer ─────────────────────────────────────────────────
def test_json_returns_valid_structure(model):
    data = json.loads(render_roadmap_json(model, top_n=5))
    assert "system" in data
    assert "tasks" in data
    assert data["system"] == "roadmap-test"
    assert isinstance(data["tasks"], list)
    assert len(data["tasks"]) <= 5


def test_json_task_fields_present(model):
    """Phase 2: dead skip replaced with an explicit precondition.
    Default fixture produces 108 mitigations — if zero ever come
    back, the workflow's mitigations engine has regressed."""
    data = json.loads(render_roadmap_json(model, top_n=5))
    assert data["tasks"], (
        "Default fixture should produce at least one task — "
        "mitigations engine regression?"
    )
    t = data["tasks"][0]
    for field in ("rank", "mitigation_id", "title", "family", "effort",
                  "risk_reduction", "automatable", "d3fend",
                  "validation_test", "addresses_threats", "frameworks"):
        assert field in t, f"missing task field: {field}"


def test_json_ranks_are_sequential(model):
    data = json.loads(render_roadmap_json(model, top_n=10))
    ranks = [t["rank"] for t in data["tasks"]]
    assert ranks == list(range(1, len(ranks) + 1))


# ─── Web download routes ───────────────────────────────────────────
def _run_and_get_run_id(c: TestClient) -> str:
    import re
    yaml_str = ("name: t\ncomponents:\n  - id: u\n    name: User\n    type: user\n"
                "  - id: llm\n    name: LLM\n    type: llm_inference\n")
    r = c.post("/analyze", data={"yaml": yaml_str})
    assert r.status_code == 200, r.text[:300]
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    assert m
    return m.group(1)


def test_report_advertises_roadmap_buttons():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": "name: t\ncomponents:\n  - id: u\n    name: u\n    type: user\n  - id: llm\n    name: LLM\n    type: llm_inference\n"})
    assert r.status_code == 200
    assert "Roadmap .md" in r.text
    assert "Roadmap .json" in r.text


def test_roadmap_md_download_returns_markdown():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _run_and_get_run_id(c)
    r = c.get(f"/download/{run_id}/roadmap_md")
    assert r.status_code == 200
    assert r.text.startswith("# Mitigation roadmap")
    assert r.headers["content-type"].startswith("text/markdown")
    assert "roadmap.md" in r.headers.get("content-disposition", "")


def test_roadmap_json_download_returns_json():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _run_and_get_run_id(c)
    r = c.get(f"/download/{run_id}/roadmap_json")
    assert r.status_code == 200
    data = json.loads(r.text)
    assert "system" in data
    assert "tasks" in data
    assert r.headers["content-type"].startswith("application/json")
    assert "roadmap.json" in r.headers.get("content-disposition", "")
