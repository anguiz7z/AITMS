"""Regression tests for v0.17.4 Cycle L — draw.io XML ingest.

Pins the contract that uploaded .drawio diagrams become structured
System YAML via the 3-layer classification: style-prefix dict →
label regex → 'other' fallback.

Uses inline draw.io XML strings so the tests don't depend on any
external file. The XML fragments mirror real mxGraph output produced
by draw.io / diagrams.net 24.x.
"""

from __future__ import annotations

import pytest

from atms.ingest.drawio import (
    STYLE_PREFIX_MAP,
    _classify_cell,
    _classify_label,
    _classify_style,
    classification_summary,
    drawio_to_system,
)


# ─── Unit: classifier layers ────────────────────────────────────────
def test_style_prefix_aws_lambda_classifies_as_serverless():
    assert _classify_style("shape=mxgraph.aws4.lambda;fillColor=#ED7100") == "serverless_function"


def test_style_prefix_azure_openai_classifies_as_llm():
    assert _classify_style("shape=mxgraph.azure.openai;fillColor=#0078D4") == "llm_inference"


def test_style_prefix_gcp_vertex_classifies_as_ml_endpoint():
    assert _classify_style("shape=mxgraph.gcp2.vertex_ai") == "ml_inference_endpoint"


def test_label_regex_lambda_classifies_as_serverless():
    assert _classify_label("AWS Lambda — order processor") == "serverless_function"


def test_label_regex_user_classifies_as_user():
    assert _classify_label("Customer browser") == "user"


def test_label_regex_plc_classifies_as_plc():
    assert _classify_label("PLC #3 — packaging line") == "plc"


def test_classify_cell_prefers_style_over_label():
    """A cloud-stencil shape with a misleading label still classifies
    by style (high-confidence signal beats heuristic)."""
    style = "shape=mxgraph.aws4.s3"
    label = "Customer DB"  # would label-regex to `database`
    ctype, src = _classify_cell(style, label)
    assert ctype == "object_storage"
    assert src == "style"


def test_classify_cell_falls_back_to_other_when_unknown():
    ctype, src = _classify_cell(
        "shape=somethingNobodyUses",
        "Mystery box of joy",
    )
    assert ctype == "other"
    assert src == "fallback"


def test_style_prefix_map_keys_are_lowercase():
    """Lookup is case-folded — keys must be too."""
    for prefix, _ in STYLE_PREFIX_MAP:
        assert prefix == prefix.lower(), (
            f"Style prefix {prefix!r} must be lowercase for the lookup to hit."
        )


# ─── End-to-end: parse a real-shaped .drawio file ───────────────────
_MINIMAL_DRAWIO = """<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net">
  <diagram name="Page-1" id="abc">
    <mxGraphModel dx="800" dy="600" grid="1" gridSize="10" guides="1" tooltips="1" connect="1">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
        <mxCell id="user1" value="Customer" style="shape=actor;whiteSpace=wrap;html=1;" vertex="1" parent="1">
          <mxGeometry x="40" y="40" width="60" height="60" as="geometry" />
        </mxCell>
        <mxCell id="apigw" value="API Gateway" style="shape=mxgraph.aws4.api_gateway;sketch=0;fillColor=#FF4F8B" vertex="1" parent="1">
          <mxGeometry x="200" y="40" width="80" height="80" as="geometry" />
        </mxCell>
        <mxCell id="bedrock" value="Bedrock LLM" style="shape=mxgraph.aws4.bedrock" vertex="1" parent="1">
          <mxGeometry x="400" y="40" width="80" height="80" as="geometry" />
        </mxCell>
        <mxCell id="kendra" value="Kendra index" style="shape=mxgraph.aws4.kendra" vertex="1" parent="1">
          <mxGeometry x="400" y="200" width="80" height="80" as="geometry" />
        </mxCell>
        <mxCell id="db" value="Customer DB (postgres)" style="rounded=1" vertex="1" parent="1">
          <mxGeometry x="600" y="40" width="120" height="60" as="geometry" />
        </mxCell>
        <mxCell id="e1" value="HTTPS" style="endArrow=classic" edge="1" parent="1" source="user1" target="apigw">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
        <mxCell id="e2" value="invokeModel" style="endArrow=classic" edge="1" parent="1" source="apigw" target="bedrock">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
        <mxCell id="e3" value="retrieve" style="endArrow=classic" edge="1" parent="1" source="bedrock" target="kendra">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
        <mxCell id="e4" value="SQL" style="endArrow=classic" edge="1" parent="1" source="bedrock" target="db">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
"""


@pytest.fixture
def minimal_drawio_path(tmp_path):
    p = tmp_path / "minimal.drawio"
    p.write_text(_MINIMAL_DRAWIO, encoding="utf-8")
    return p


def test_drawio_ingest_extracts_5_components(minimal_drawio_path):
    system = drawio_to_system(minimal_drawio_path)
    assert len(system.components) == 5
    names = {c.name for c in system.components}
    assert "Customer" in names
    assert "Bedrock LLM" in names
    assert "Kendra index" in names


def test_drawio_ingest_extracts_4_dataflows(minimal_drawio_path):
    system = drawio_to_system(minimal_drawio_path)
    assert len(system.dataflows) == 4
    labels = {d.label for d in system.dataflows}
    assert "HTTPS" in labels
    assert "invokeModel" in labels


def test_drawio_ingest_classifies_aws_stencils_correctly(minimal_drawio_path):
    system = drawio_to_system(minimal_drawio_path)
    by_name = {c.name: c.type for c in system.components}
    assert by_name["Customer"] == "user"  # via style=actor
    assert by_name["API Gateway"] == "api_gateway"  # via mxgraph.aws4.api_gateway
    assert by_name["Bedrock LLM"] == "llm_inference"  # via mxgraph.aws4.bedrock
    assert by_name["Kendra index"] == "rag_vector_store"  # via mxgraph.aws4.kendra


def test_drawio_ingest_classifies_label_regex_when_no_style(minimal_drawio_path):
    """The DB has style=rounded=1 only — must fall back to label regex
    on 'postgres' → 'database'."""
    system = drawio_to_system(minimal_drawio_path)
    by_name = {c.name: c.type for c in system.components}
    assert by_name["Customer DB (postgres)"] == "database"


def test_drawio_ingest_records_classification_source_in_metadata(minimal_drawio_path):
    system = drawio_to_system(minimal_drawio_path)
    sources = [
        (c.name, (c.metadata or {}).get("source", ""))
        for c in system.components
    ]
    # 4 of 5 components should classify via style; 1 via label (the DB).
    style_classified = sum(1 for _, s in sources if s == "drawio:style")
    label_classified = sum(1 for _, s in sources if s == "drawio:label")
    assert style_classified >= 4
    assert label_classified >= 1


def test_classification_summary_counts_correctly(minimal_drawio_path):
    system = drawio_to_system(minimal_drawio_path)
    summary = classification_summary(system)
    assert sum(summary.values()) == len(system.components)
    assert summary["style"] >= 4
    assert summary["label"] >= 1


def test_drawio_dangling_edges_are_dropped(tmp_path):
    """Edges pointing to non-existent cells must not crash + must not
    appear in the output."""
    p = tmp_path / "dangling.drawio"
    p.write_text("""<mxfile><diagram><mxGraphModel><root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
        <mxCell id="a" value="A" style="shape=mxgraph.aws4.lambda" vertex="1" parent="1"/>
        <mxCell id="e" edge="1" source="a" target="ghost"/>
    </root></mxGraphModel></diagram></mxfile>""", encoding="utf-8")
    system = drawio_to_system(p)
    assert len(system.components) == 1
    assert len(system.dataflows) == 0


def test_drawio_system_is_analysable_end_to_end(minimal_drawio_path):
    """The system we parse must be valid enough to analyse via the
    workflow.analyze() entry point. End-to-end confidence check."""
    from atms.workflow import analyze
    system = drawio_to_system(minimal_drawio_path)
    tm = analyze(system)  # has AI components, no --allow-pure-it needed
    assert tm.threats, "analyse should produce threats"


def test_drawio_pure_it_diagram_works_with_allow_pure_it(tmp_path):
    """A non-AI draw.io diagram must analyse in pure-IT mode."""
    from atms.workflow import analyze

    p = tmp_path / "pure_it.drawio"
    p.write_text("""<mxfile><diagram><mxGraphModel><root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
        <mxCell id="fw" value="Firewall" style="shape=mxgraph.azure.firewall" vertex="1" parent="1"/>
        <mxCell id="db" value="Postgres DB" style="rounded=1" vertex="1" parent="1"/>
        <mxCell id="e1" edge="1" source="fw" target="db" value="filtered"/>
    </root></mxGraphModel></diagram></mxfile>""", encoding="utf-8")
    system = drawio_to_system(p)
    assert len(system.components) == 2
    tm = analyze(system, require_ai_components=False)
    assert tm.threats
