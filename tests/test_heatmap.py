"""Regression tests for v0.16.12 interactive risk-heatmap.

The matrix cells + threat blocks must carry `data-l` / `data-i`
attributes for the JS click-to-filter to work. These tests don't
execute JS — they pin the DOM contract in the rendered HTML.
"""

from __future__ import annotations

import re

from atms.models import Component, System
from atms.reporting.html import render_html
from atms.workflow import analyze


def _render_sample_html() -> str:
    sys_obj = System(name="t", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    tm = analyze(sys_obj)
    return render_html(tm)


def test_matrix_cells_carry_l_i_data_attrs():
    """All 25 matrix cells must have data-l + data-i so the JS click
    handler can identify which (L, I) bucket the cell represents."""
    html = _render_sample_html()
    # Count matrix-cell occurrences of `data-l=` (the 5x5 grid).
    cells_with_data = re.findall(
        r'<div class="cell[^"]*"\s+data-l="(\d)"\s+data-i="(\d)"', html
    )
    assert len(cells_with_data) == 25, (
        f"expected 25 matrix cells with data-l/i, got {len(cells_with_data)}"
    )
    # Coordinates should be (1..5, 1..5).
    coords = {(int(l), int(i)) for l, i in cells_with_data}
    assert coords == {(l, i) for l in range(1, 6) for i in range(1, 6)}


def test_threat_blocks_carry_l_i_data_attrs():
    """Every threat-block must carry data-l + data-i for click-filter."""
    html = _render_sample_html()
    threat_blocks = re.findall(
        r'<div class="threat-block"\s+data-l="(\d)"\s+data-i="(\d)"', html
    )
    assert threat_blocks, "no threat blocks with data-l/i found"
    # All values in 1..5
    for l, i in threat_blocks:
        assert 1 <= int(l) <= 5
        assert 1 <= int(i) <= 5


def test_report_includes_filter_bar_and_clear_script():
    """The interactive scaffolding must be present in the rendered HTML."""
    html = _render_sample_html()
    assert 'id="matrix-filter-bar"' in html, "filter-bar div missing"
    assert "matrix-clear" in html, "clear-button JS missing"
    assert "selectedL = null" in html, "filter-state JS missing"
