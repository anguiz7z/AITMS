"""Regression tests for v0.18.13 Cycle CC — risk heatmap on /report.

The web report renders a 5x5 likelihood × impact heatmap above the
DFD. It's pure HTML+CSS, no JS, no extra deps. The heatmap section
only renders when `threats` is non-empty.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from atms.web import app

_AI_SAMPLE_YAML = """
name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""


def test_heatmap_section_present_on_normal_report():
    """A non-trivial analysis produces threats → heatmap section renders."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    assert r.status_code == 200
    html = r.text
    assert "Risk heatmap" in html
    assert "atms-heatmap" in html
    # 25 data cells + 5 column-axis labels + 5 row-axis labels = 35
    # (+1 corner spacer). At minimum, every L value 1..5 appears.
    for L in range(1, 6):
        assert f"L={L}" in html
    for I in range(1, 6):
        assert f"I={I}" in html


def test_heatmap_uses_no_external_js():
    """Heatmap should be pure HTML+CSS so it survives an offline export."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    assert r.status_code == 200
    # Extract the heatmap block.
    html = r.text
    start = html.find("Risk heatmap")
    end = html.find("Architecture (data flow diagram)", start)
    assert start != -1 and end != -1
    block = html[start:end]
    # No <script> inside the heatmap section.
    assert "<script" not in block


def test_heatmap_zones_present():
    """The 4 risk zones (low/medium/high/critical) should all appear at
    least once in the class list — proves all 4 colour buckets render."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    html = r.text
    for zone in ("hm-zone-low", "hm-zone-medium", "hm-zone-high", "hm-zone-critical"):
        assert zone in html, f"Missing risk-zone class: {zone}"


def test_heatmap_tooltip_carries_threat_ids():
    """Hovering a populated cell should surface threat IDs in the tooltip
    (rendered as `title=` attribute content)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    html = r.text
    # The simplest probe: at least one cell carries a per-threat bullet.
    assert "&#10;• " in html, "Expected a cell tooltip with at least one threat bullet"
