"""Regression tests for v0.18.3 Cycle S — classification-confidence
pills surfaced in the HTML report.

When a system is ingested from a diagram (drawio / mermaid), each
component carries `metadata.source` indicating HOW it was classified
(style / shape / label / fallback). The HTML report's component
headers must surface this as a coloured pill so reviewers can see
at a glance which components are high-confidence vs. need review.
"""

from __future__ import annotations

import pytest

from atms.ingest.drawio import drawio_to_system
from atms.ingest.mermaid import mermaid_to_system
from atms.models import Component, System
from atms.reporting.html import render_html
from atms.workflow import analyze


def test_stencil_classified_component_gets_green_pill():
    """A draw.io component matched by an AWS stencil prefix should
    render a green 'classified: stencil' pill in the report."""
    src = """<?xml version="1.0"?>
<mxfile><diagram><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="lam" value="Lambda" style="shape=mxgraph.aws4.lambda" vertex="1" parent="1"/>
  <mxCell id="user" value="User" style="shape=actor" vertex="1" parent="1"/>
  <mxCell id="e" edge="1" source="user" target="lam" parent="1"/>
</root></mxGraphModel></diagram></mxfile>"""
    import pathlib
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".drawio", delete=False, encoding="utf-8"
    ) as f:
        f.write(src)
        path = pathlib.Path(f.name)
    try:
        system = drawio_to_system(path)
        tm = analyze(system, require_ai_components=False)
        html = render_html(tm)
        assert "classified: stencil" in html
    finally:
        path.unlink(missing_ok=True)


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_label_classified_component_gets_yellow_pill():
    """A mermaid component matched by label regex (no shape hint)
    should render an amber 'classified: label' pill."""
    src = """flowchart LR
    user[Customer] --> api[AWS Lambda]
    """
    system = mermaid_to_system(src)
    tm = analyze(system, require_ai_components=False)
    html = render_html(tm)
    assert "classified: label" in html


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_shape_classified_component_gets_green_pill():
    """A mermaid component matched by strong shape (cylinder/circle)
    should render a green 'classified: shape' pill."""
    src = """flowchart LR
    user[User] --> db[(Customer DB)]
    """
    system = mermaid_to_system(src)
    tm = analyze(system, require_ai_components=False)
    html = render_html(tm)
    assert "classified: shape" in html


def test_hand_written_yaml_has_no_pills():
    """A System constructed in code (no ingest source) should NOT
    show any classification pills — they're only for auto-ingested
    components."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    tm = analyze(sys_obj)
    html = render_html(tm)
    assert "classified:" not in html


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_fallback_classified_component_gets_red_warning_pill():
    """A component that fell through both style and label
    classification (got the 'other' fallback) should render a red
    warning pill so reviewers spot it immediately."""
    src = """flowchart LR
    weird{{Mystery thing}}
    """
    system = mermaid_to_system(src)
    # The `weird` cell has shape=hexagon → maps to "agent". Override
    # to test the fallback path explicitly.
    system.components[0].metadata = {"source": "drawio:fallback", "raw_style": "unknown"}
    system.components[0].type = "other"
    tm = analyze(system, require_ai_components=False)
    html = render_html(tm)
    assert "classified: fallback" in html
    # Warning emoji + critical color
    assert "⚠" in html
