"""Regression tests for v0.18.2 Cycle Q — auto-analyze on upload.

Pins the user-asked-for flow: "Once I upload the diagram - system
should automatically identify boundaries, device types, assets,
connections etc. It should be comprehensive threat model."

When the upload form is submitted with `auto_analyze=true`, /ingest
parses the diagram AND runs the analysis pipeline AND renders the
full threat report — no manual review step.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from atms.web import app

_DRAWIO_AI_RAG = b"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile><diagram><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="user" value="Customer" style="shape=actor" vertex="1" parent="1"/>
  <mxCell id="apigw" value="API Gateway" style="shape=mxgraph.aws4.api_gateway" vertex="1" parent="1"/>
  <mxCell id="bedrock" value="Bedrock" style="shape=mxgraph.aws4.bedrock" vertex="1" parent="1"/>
  <mxCell id="kendra" value="Kendra" style="shape=mxgraph.aws4.kendra" vertex="1" parent="1"/>
  <mxCell id="e1" edge="1" source="user" target="apigw" parent="1"/>
  <mxCell id="e2" edge="1" source="apigw" target="bedrock" parent="1"/>
  <mxCell id="e3" edge="1" source="bedrock" target="kendra" parent="1"/>
</root></mxGraphModel></diagram></mxfile>
"""

_DRAWIO_PURE_IT = b"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile><diagram><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="fw" value="Edge firewall" style="shape=mxgraph.azure.firewall" vertex="1" parent="1"/>
  <mxCell id="web" value="Web App" style="rounded=1" vertex="1" parent="1"/>
  <mxCell id="db" value="Postgres DB" style="rounded=1" vertex="1" parent="1"/>
  <mxCell id="e1" edge="1" source="fw" target="web" parent="1"/>
  <mxCell id="e2" edge="1" source="web" target="db" parent="1"/>
</root></mxGraphModel></diagram></mxfile>
"""


def test_default_ingest_renders_yaml_review_page():
    """Without auto_analyze, /ingest behaves like pre-v0.18.2 — shows
    the YAML for review on the home page."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.drawio", _DRAWIO_AI_RAG, "application/xml")},
    )
    assert r.status_code == 200
    # The home/index page has the YAML preview textarea.
    assert "Edit YAML" in r.text or 'name="yaml"' in r.text


def test_auto_analyze_renders_report_directly():
    """With auto_analyze=true, /ingest jumps straight to the report."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.drawio", _DRAWIO_AI_RAG, "application/xml")},
        data={"auto_analyze": "true"},
    )
    assert r.status_code == 200
    # Report page has the metrics div + the Risk matrix section.
    assert "Risk matrix" in r.text or "metrics" in r.text
    # Threat blocks present.
    assert "threat-block" in r.text or "Threats" in r.text


def test_auto_analyze_handles_pure_it_diagram():
    """A pure-IT diagram with auto_analyze MUST still render — the
    new --allow-pure-it path kicks in automatically."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.drawio", _DRAWIO_PURE_IT, "application/xml")},
        data={"auto_analyze": "true"},
    )
    assert r.status_code == 200, r.text[:400]
    # The notice should indicate general-purpose mode.
    assert "general-purpose" in r.text or "Auto-analysed" in r.text


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_auto_analyze_with_mermaid():
    """Mermaid + auto_analyze: same flow, different parser."""
    mermaid_src = b"""flowchart LR
    user[Customer] --> apigw[API Gateway]
    apigw --> bedrock[Bedrock LLM]
    bedrock --> kendra[(Kendra)]
"""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.mmd", mermaid_src, "text/plain")},
        data={"auto_analyze": "true"},
    )
    assert r.status_code == 200
    assert "Risk matrix" in r.text or "metrics" in r.text


def test_home_page_has_parse_and_analyse_button():
    """The new combined button must be in the upload form."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/")
    assert r.status_code == 200
    assert "Parse &amp; analyse" in r.text or "Parse & analyse" in r.text
    assert 'name="auto_analyze"' in r.text


def test_auto_analyze_pure_it_drawio_has_real_threats():
    """End-to-end value check: an uploaded pure-IT diagram with
    auto_analyze produces actual threats in the rendered report."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.drawio", _DRAWIO_PURE_IT, "application/xml")},
        data={"auto_analyze": "true"},
    )
    assert r.status_code == 200
    # The report's severity-breakdown line should show non-zero counts
    # somewhere — either critical/high/medium/low.
    severities_present = sum(
        1 for sev in ("critical", "high", "medium", "low")
        if f"sev-{sev}" in r.text
    )
    assert severities_present >= 1, "expected at least one severity pill in report"
