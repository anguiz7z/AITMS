"""Regression tests for v0.18.25 Cycle OO — print-friendly @media print CSS.

Browser "File → Print → Save as PDF" should produce a clean, light-
themed, chrome-free PDF without requiring any server-side PDF dep.
The CSS sits in `base.html` so every page benefits.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from atms.web import app

_SAMPLE_YAML = """
name: t
components:
  - id: u
    name: u
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""


def test_print_media_query_present_in_base():
    """Every rendered page must include the `@media print` block."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/")
    assert r.status_code == 200
    assert "@media print" in r.text


def test_print_css_hides_navigation_and_actions():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    assert r.status_code == 200
    # The print stylesheet should hide header / footer / actions / filter.
    # Concrete checks: each token appears within the @media print block.
    pmark = r.text.find("@media print")
    end = r.text.find("}\n</style>", pmark)
    if end == -1:
        end = r.text.find("</style>", pmark)
    print_block = r.text[pmark:end]
    for selector in ("header", ".actions", ".threat-filter"):
        assert selector in print_block, f"print CSS missing {selector!r}"


def test_print_css_forces_light_theme():
    """The :root override inside @media print should set a white bg."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/")
    pmark = r.text.find("@media print")
    print_block = r.text[pmark:pmark + 4000]
    assert "--bg: #ffffff" in print_block
    assert "color: #0e1116" in print_block


def test_print_css_outlines_severity_chips():
    """Coloured severity badges become outlined (B&W-printer-safe)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/")
    pmark = r.text.find("@media print")
    print_block = r.text[pmark:pmark + 4000]
    assert ".severity" in print_block
    assert "border: 1px solid #000" in print_block


def test_print_css_includes_heatmap_styles():
    """The L×I heatmap (Cycle CC) needs print-mode tweaks."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/")
    pmark = r.text.find("@media print")
    print_block = r.text[pmark:pmark + 4000]
    assert "atms-heatmap" in print_block


def test_print_css_prevents_row_breaks_in_tables():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/")
    pmark = r.text.find("@media print")
    print_block = r.text[pmark:pmark + 4000]
    assert "page-break-inside" in print_block
