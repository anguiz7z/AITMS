"""Regression tests for v0.18.11 Cycle AA — web /download/{run_id}/exec.

The CLI exec-summary feature (Cycle Z) is also reachable from the
web report page. Every analyse run caches an exec.html and the
report page surfaces a download button.
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


def test_analyze_run_caches_exec_summary():
    """Running an analyse via /analyze should make /download/{id}/exec
    return the exec-summary HTML."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    assert r.status_code == 200, r.text[:400]
    # The report page contains the run-id download links.
    html = r.text
    assert "/exec" in html, "Report page must link to the exec-summary download"


def test_exec_download_returns_html_attachment():
    """POST /analyze → get run_id → GET /download/{run_id}/exec returns HTML."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    assert r.status_code == 200
    # Extract run_id from the report's download links.
    import re
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    assert m, "Expected /download/{run_id}/md link in report"
    run_id = m.group(1)
    # Fetch the exec summary.
    r2 = c.get(f"/download/{run_id}/exec")
    assert r2.status_code == 200
    assert r2.text.startswith("<!doctype html>")
    assert "executive summary" in r2.text.lower()
    # Attachment Content-Disposition
    cd = r2.headers.get("content-disposition", "")
    assert "exec.html" in cd


def test_exec_download_works_for_ingest_auto_analyze():
    """The auto-analyze flow (Cycle Q) also caches an exec.html."""
    drawio = b"""<mxfile><diagram><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="u" value="User" style="shape=actor" vertex="1" parent="1"/>
  <mxCell id="api" value="API" style="shape=mxgraph.aws4.api_gateway" vertex="1" parent="1"/>
  <mxCell id="bedrock" value="Bedrock" style="shape=mxgraph.aws4.bedrock" vertex="1" parent="1"/>
  <mxCell id="e1" edge="1" source="u" target="api" parent="1"/>
  <mxCell id="e2" edge="1" source="api" target="bedrock" parent="1"/>
</root></mxGraphModel></diagram></mxfile>"""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("x.drawio", drawio, "application/xml")},
        data={"auto_analyze": "true"},
    )
    assert r.status_code == 200, r.text[:400]
    import re
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    assert m
    r2 = c.get(f"/download/{m.group(1)}/exec")
    assert r2.status_code == 200
    assert r2.text.startswith("<!doctype html>")


def test_report_page_advertises_exec_button():
    """The report.html template must have a visible 'Exec summary' button."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    assert "Exec summary" in r.text
