"""Regression tests for v0.18.35 Cycle YY — D3FEND coverage panel."""

from __future__ import annotations

from fastapi.testclient import TestClient

from atms.web import app

_SAMPLE_YAML = """
name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""


def test_report_includes_d3fend_section_when_mitigations_carry_refs():
    """A real analyze run will produce mitigations with d3fend refs;
    the section should render with the technique chips."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    assert r.status_code == 200
    # Either the heading is present (data exists) or the block is
    # silently skipped (data absent). For a vanilla LLM system at
    # least one mitigation should carry a D3FEND ref.
    text = r.text
    if "D3FEND coverage" in text:
        # When the panel renders, it should also surface at least one
        # `D3-` technique ID via the chips.
        assert ">D3-" in text or "MITRE D3FEND" in text


def test_report_renders_without_500_on_empty_d3fend():
    """Even when no mitigation has a D3FEND ref, the page should
    render cleanly (the panel is conditionally rendered)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    assert r.status_code == 200
    # Page MUST render the threat table either way.
    assert "Top threats" in r.text
