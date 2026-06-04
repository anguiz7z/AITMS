"""Regression tests for v0.18.27 Cycle QQ — dedicated /attack-paths page."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from atms.web import app

_SAMPLE_YAML = """
name: ap-test
components:
  - id: u
    name: User
    type: user
  - id: api
    name: API
    type: api_gateway
  - id: llm
    name: LLM
    type: llm_inference
  - id: db
    name: DB
    type: database
dataflows:
  - source: u
    target: api
  - source: api
    target: llm
  - source: llm
    target: db
"""


def _analyze_and_run_id(c: TestClient) -> str:
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    assert r.status_code == 200, r.text[:200]
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    assert m
    return m.group(1)


def test_attack_paths_route_returns_200():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _analyze_and_run_id(c)
    r = c.get(f"/attack-paths/{run_id}")
    assert r.status_code == 200


def test_attack_paths_route_404_on_unknown_run():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/attack-paths/abcdef000000")
    assert r.status_code == 404


def test_attack_paths_page_extends_base():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _analyze_and_run_id(c)
    r = c.get(f"/attack-paths/{run_id}")
    # Inherits from base.html → contains the nav.
    assert "AI Threat Modeling Studio" in r.text
    # Has the page heading.
    assert "Attack paths" in r.text


def test_attack_paths_page_renders_empty_state_when_no_paths():
    """A trivial 2-component system may produce no multi-step paths;
    the page should render an empty-state message rather than 500."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={
        "yaml": "name: t\ncomponents:\n  - id: u\n    name: User\n    type: user\n  - id: llm\n    name: LLM\n    type: llm_inference\n",
    })
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    run_id = m.group(1)
    r2 = c.get(f"/attack-paths/{run_id}")
    assert r2.status_code == 200
    # Either there are paths, or the empty-state copy appears.
    assert ("No multi-step attack paths" in r2.text) or (".ap-card" in r2.text)


def test_attack_paths_page_shows_business_impact_chips():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _analyze_and_run_id(c)
    r = c.get(f"/attack-paths/{run_id}")
    # The Impact / Difficulty chip headings render.
    assert "Impact" in r.text
    assert "Difficulty" in r.text


def test_report_page_links_to_attack_paths_view():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    assert r.status_code == 200
    assert "/attack-paths/" in r.text
    # The button text.
    assert "Attack paths" in r.text


def test_attack_paths_page_renders_kill_chain_flow():
    """When at least one path exists, its tactics should render as a flow."""
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _analyze_and_run_id(c)
    r = c.get(f"/attack-paths/{run_id}")
    # Either an empty state or at least one .ap-flow div with → arrows.
    if "ap-flow" in r.text:
        assert "→" in r.text
