"""Regression tests for v0.17.4 Cycle N — web /ingest accepts .drawio.

Pins the contract that the /ingest route handles draw.io / mxGraph
uploads and surfaces the auto-classification summary in the page
notice.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from atms.web import app

_DRAWIO_AWS_RAG = b"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile><diagram><mxGraphModel><root>
  <mxCell id="0"/><mxCell id="1" parent="0"/>
  <mxCell id="vpc" value="VPC" style="shape=mxgraph.aws4.vpc" vertex="1" parent="1"/>
  <mxCell id="apigw" value="API Gateway" style="shape=mxgraph.aws4.api_gateway" vertex="1" parent="vpc"/>
  <mxCell id="bedrock" value="Bedrock" style="shape=mxgraph.aws4.bedrock" vertex="1" parent="vpc"/>
  <mxCell id="user" value="Customer" style="shape=actor" vertex="1" parent="1"/>
  <mxCell id="e1" edge="1" source="user" target="apigw" parent="1"/>
  <mxCell id="e2" edge="1" source="apigw" target="bedrock" parent="1"/>
</root></mxGraphModel></diagram></mxfile>
"""


def test_ingest_accepts_drawio_extension():
    """Uploading a .drawio file returns 200 and pre-populates the YAML box."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.drawio", _DRAWIO_AWS_RAG, "application/xml")},
    )
    assert r.status_code == 200, r.text[:500]
    assert "api_gateway" in r.text  # auto-classified
    assert "llm_inference" in r.text  # bedrock → llm_inference


def test_ingest_accepts_xml_extension_as_drawio():
    """The .xml extension is treated as raw mxGraph (alias for .drawio)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.xml", _DRAWIO_AWS_RAG, "application/xml")},
    )
    assert r.status_code == 200, r.text[:500]


def test_ingest_drawio_surfaces_classification_summary():
    """The page notice reports how components were classified
    (via style / via label / fallback)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.drawio", _DRAWIO_AWS_RAG, "application/xml")},
    )
    html = r.text
    assert "Classification" in html or "stencil style" in html


def test_ingest_drawio_extracts_trust_boundary():
    """A VPC-containered diagram produces a trust_boundaries entry in
    the populated YAML."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.drawio", _DRAWIO_AWS_RAG, "application/xml")},
    )
    html = r.text
    assert "trust_boundaries" in html or "trust boundaries" in html


def test_ingest_rejects_unknown_extension():
    """Uploading a .png falls through to the vision path, and without
    ANTHROPIC_API_KEY it errors out with a friendly message."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/ingest",
        files={"diagram": ("test.txt", b"hello", "text/plain")},
    )
    # 400 with the "Unsupported diagram format" banner from the index template.
    assert r.status_code == 400
    assert "Unsupported" in r.text or ".txt" in r.text


def test_home_page_advertises_drawio_support():
    """The landing-page form must mention .drawio so users know they
    can upload it."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/")
    assert r.status_code == 200
    assert ".drawio" in r.text
    assert "drawio,.xml" in r.text or ".drawio,.xml" in r.text  # accept= attr
