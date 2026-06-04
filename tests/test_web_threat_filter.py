"""Regression tests for v0.18.20 Cycle JJ — filterable threat table."""

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


def test_report_includes_filter_input():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    assert r.status_code == 200
    assert 'id="threat-filter-input"' in r.text
    assert 'placeholder="Filter threats' in r.text


def test_report_includes_severity_chips():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    for sev in ("critical", "high", "medium", "low"):
        assert f'data-severity="{sev}"' in r.text


def test_report_threats_table_has_data_severity_attr():
    """Every threat row needs `data-severity` for the severity-chip
    filter to work."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    # At least one row with data-severity.
    assert 'data-severity="medium"' in r.text or \
           'data-severity="high"' in r.text or \
           'data-severity="low"' in r.text or \
           'data-severity="critical"' in r.text


def test_report_filter_js_present_and_inline():
    """The filter JS must be inline (no external script src) so the
    behaviour survives offline exports of the report."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    # The IIFE wraps the filter logic.
    assert "Live filter for the threats table" in r.text
    assert "threat-filter-input" in r.text
    # Esc key handler.
    assert "Escape" in r.text


def test_report_filter_has_no_external_scripts():
    """Cycle JJ promised the filter is pure inline JS — confirm no new
    `<script src=...>` for the filter region."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _SAMPLE_YAML})
    # Find the script that contains our filter IIFE; ensure no `src=`.
    start = r.text.find("Live filter for the threats table")
    end = r.text.find("</script>", start)
    assert start != -1 and end != -1
    block = r.text[start:end]
    assert "<script src" not in block
