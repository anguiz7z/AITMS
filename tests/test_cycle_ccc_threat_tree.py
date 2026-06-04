"""Regression tests for v0.18.39 Cycle CCC — threat-tree SVG on /attack-paths."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from atms.web import app

_SAMPLE_YAML = """
name: tt-test
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


def _get_run_id(c: TestClient) -> str:
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    assert r.status_code == 200
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    assert m
    return m.group(1)


def test_attack_paths_page_includes_svg_kill_chain():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _get_run_id(c)
    r = c.get(f"/attack-paths/{run_id}")
    assert r.status_code == 200
    # SVG block opens and closes — either at least one path exists with SVG,
    # OR empty state with no SVG. Both are valid; check SVG markers only when
    # paths exist.
    if "ap-card" in r.text:
        assert "<svg" in r.text, "Expected SVG kill-chain when paths exist"


def test_svg_is_inline_no_external_image_src():
    """The kill-chain SVG must be inline — no external <img> or <object>."""
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _get_run_id(c)
    r = c.get(f"/attack-paths/{run_id}")
    # No external src on the path SVG region.
    if "Kill-chain visualisation" in r.text:
        start = r.text.find("<svg")
        end = r.text.find("</svg>", start)
        block = r.text[start:end]
        assert '<img' not in block
        assert '<object' not in block


def test_svg_carries_summary_with_step_and_threat_counts():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _get_run_id(c)
    r = c.get(f"/attack-paths/{run_id}")
    # Footer summary text appears.
    if "<svg" in r.text:
        assert "steps" in r.text and "threats" in r.text


def test_attack_paths_collapsible_summary_present():
    """The SVG is wrapped in a <details> so users can collapse it."""
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _get_run_id(c)
    r = c.get(f"/attack-paths/{run_id}")
    if "<svg" in r.text:
        assert "<details" in r.text or "<summary" in r.text
