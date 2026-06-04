"""Regression tests for v0.17.4 Cycle M — trust-boundary inference
from draw.io container hierarchy.

Pins the contract that draw.io VPC / subnet / DMZ containers become
TrustBoundary objects on the resulting System, components inherit
the boundary's label as their trust_zone, and dataflows crossing
boundaries are flagged with crosses_boundary=True.

Per the v0.17.4 research pass, trust boundaries are CONTAINERS
(VPC / subnet / DMZ / cluster / namespace / zone) — devices like
firewalls / routers stay as components.
"""

from __future__ import annotations

import pytest

from atms.ingest.drawio import _is_boundary_cell, drawio_to_system


# ─── Unit: boundary cell detection ──────────────────────────────────
@pytest.mark.parametrize("style,label", [
    ("", "VPC: production"),
    ("", "Subnet 10.0.1.0/24"),
    ("", "DMZ"),
    ("", "kube-system namespace"),
    ("", "Tenant A"),
    ("shape=mxgraph.aws4.virtual_private_cloud", ""),
    ("shape=mxgraph.aws4.vpc", ""),
    ("shape=mxgraph.azure.virtual_network", "ANY label"),
    ("shape=mxgraph.gcp2.vpc", ""),
    ("swimlane;rounded=0", "Production zone"),
])
def test_is_boundary_cell_recognises_zones(style, label):
    assert _is_boundary_cell(style, label), (
        f"({style!r}, {label!r}) should be a boundary"
    )


@pytest.mark.parametrize("style,label", [
    ("shape=mxgraph.aws4.lambda", "OrderProcessor"),
    ("shape=mxgraph.azure.firewall", "Edge Firewall"),
    ("rounded=1", "Customer DB (postgres)"),
    ("shape=actor", "Customer"),
    # Importantly: a router or firewall is a DEVICE, not a boundary.
    ("", "Router #1"),
    ("", "Edge Firewall"),
])
def test_is_boundary_cell_rejects_devices(style, label):
    assert not _is_boundary_cell(style, label), (
        f"({style!r}, {label!r}) is a device, not a boundary"
    )


# ─── End-to-end: container hierarchy → trust boundaries ─────────────
_DRAWIO_WITH_VPC = """<?xml version="1.0" encoding="UTF-8"?>
<mxfile><diagram><mxGraphModel><root>
  <mxCell id="0"/>
  <mxCell id="1" parent="0"/>
  <mxCell id="vpc1" value="VPC: production" style="shape=mxgraph.aws4.vpc" vertex="1" parent="1">
    <mxGeometry x="40" y="40" width="600" height="400" as="geometry"/>
  </mxCell>
  <mxCell id="dmz" value="DMZ subnet" style="rounded=0;dashed=1" vertex="1" parent="vpc1">
    <mxGeometry x="60" y="80" width="200" height="200" as="geometry"/>
  </mxCell>
  <mxCell id="apigw" value="API Gateway" style="shape=mxgraph.aws4.api_gateway" vertex="1" parent="dmz">
    <mxGeometry x="80" y="120" width="80" height="80" as="geometry"/>
  </mxCell>
  <mxCell id="internal" value="Internal subnet" style="rounded=0;dashed=1" vertex="1" parent="vpc1">
    <mxGeometry x="300" y="80" width="200" height="200" as="geometry"/>
  </mxCell>
  <mxCell id="lambda" value="Order Lambda" style="shape=mxgraph.aws4.lambda" vertex="1" parent="internal">
    <mxGeometry x="320" y="120" width="80" height="80" as="geometry"/>
  </mxCell>
  <mxCell id="db" value="Postgres DB" style="rounded=1" vertex="1" parent="internal">
    <mxGeometry x="420" y="120" width="80" height="80" as="geometry"/>
  </mxCell>
  <mxCell id="user" value="Customer" style="shape=actor" vertex="1" parent="1">
    <mxGeometry x="700" y="40" width="60" height="60" as="geometry"/>
  </mxCell>
  <mxCell id="e1" edge="1" source="user" target="apigw" value="HTTPS" parent="1"/>
  <mxCell id="e2" edge="1" source="apigw" target="lambda" value="invoke" parent="1"/>
  <mxCell id="e3" edge="1" source="lambda" target="db" value="SQL" parent="1"/>
</root></mxGraphModel></diagram></mxfile>
"""


@pytest.fixture
def drawio_with_vpc(tmp_path):
    p = tmp_path / "vpc.drawio"
    p.write_text(_DRAWIO_WITH_VPC, encoding="utf-8")
    return p


def test_vpc_container_becomes_trust_boundary(drawio_with_vpc):
    system = drawio_to_system(drawio_with_vpc)
    # The VPC and the two subnets are all boundaries, each containing components.
    # But the VPC contains no DIRECT components (only subnets) — so it may or
    # may not surface. Subnets contain the components, so they're the relevant
    # boundaries.
    assert len(system.trust_boundaries) >= 2, (
        f"expected ≥2 boundaries (subnets), got {len(system.trust_boundaries)}"
    )
    boundary_descriptions = {b.description for b in system.trust_boundaries}
    assert any("DMZ" in d for d in boundary_descriptions)
    assert any("Internal" in d for d in boundary_descriptions)


def test_components_get_trust_zone_from_enclosing_boundary(drawio_with_vpc):
    system = drawio_to_system(drawio_with_vpc)
    by_name = {c.name: c for c in system.components}
    assert "API Gateway" in by_name
    assert "Order Lambda" in by_name
    assert "Postgres DB" in by_name
    # API Gateway is in the DMZ subnet; the other two are in Internal.
    apigw_zone = by_name["API Gateway"].trust_zone
    lambda_zone = by_name["Order Lambda"].trust_zone
    db_zone = by_name["Postgres DB"].trust_zone
    assert "dmz" in apigw_zone.lower()
    assert "internal" in lambda_zone.lower()
    assert lambda_zone == db_zone, (
        "Lambda and DB are both in Internal subnet → same zone"
    )
    # Customer is outside any boundary → "default".
    assert by_name["Customer"].trust_zone == "default"


def test_dataflow_marks_crosses_boundary_when_zones_differ(drawio_with_vpc):
    system = drawio_to_system(drawio_with_vpc)
    flows_by_src = {(d.source, d.target): d for d in system.dataflows}
    # Find the user→apigw flow by component IDs (which were sanitised
    # from the raw cell ids).
    name_to_id = {c.name: c.id for c in system.components}
    user_id = name_to_id["Customer"]
    apigw_id = name_to_id["API Gateway"]
    lambda_id = name_to_id["Order Lambda"]
    db_id = name_to_id["Postgres DB"]
    # user (default zone) → apigw (DMZ) crosses a boundary
    assert flows_by_src[(user_id, apigw_id)].crosses_boundary
    # apigw (DMZ) → lambda (Internal) crosses a boundary
    assert flows_by_src[(apigw_id, lambda_id)].crosses_boundary
    # lambda (Internal) → db (Internal) does NOT cross — same zone
    assert not flows_by_src[(lambda_id, db_id)].crosses_boundary


def test_boundary_classification_picks_network_for_vpc_subnet(drawio_with_vpc):
    system = drawio_to_system(drawio_with_vpc)
    types = {b.type for b in system.trust_boundaries}
    # VPC + subnet boundaries default to 'network' classification.
    assert "network" in types


def test_boundary_with_tenant_label_classifies_as_tenancy(tmp_path):
    p = tmp_path / "tenant.drawio"
    p.write_text("""<mxfile><diagram><mxGraphModel><root>
        <mxCell id="0"/><mxCell id="1" parent="0"/>
        <mxCell id="t" value="Tenant A namespace" style="rounded=0;dashed=1" vertex="1" parent="1"/>
        <mxCell id="app" value="App" style="shape=mxgraph.aws4.lambda" vertex="1" parent="t"/>
    </root></mxGraphModel></diagram></mxfile>""", encoding="utf-8")
    system = drawio_to_system(p)
    assert len(system.trust_boundaries) == 1
    assert system.trust_boundaries[0].type == "tenancy"


def test_diagram_without_containers_still_works(tmp_path):
    """A flat diagram with no boundary containers must still parse +
    produce zero trust boundaries (not crash)."""
    p = tmp_path / "flat.drawio"
    p.write_text("""<mxfile><diagram><mxGraphModel><root>
        <mxCell id="0"/><mxCell id="1" parent="0"/>
        <mxCell id="a" value="Lambda" style="shape=mxgraph.aws4.lambda" vertex="1" parent="1"/>
        <mxCell id="b" value="Bedrock" style="shape=mxgraph.aws4.bedrock" vertex="1" parent="1"/>
        <mxCell id="e" edge="1" source="a" target="b" parent="1"/>
    </root></mxGraphModel></diagram></mxfile>""", encoding="utf-8")
    system = drawio_to_system(p)
    assert system.trust_boundaries == []
    assert len(system.components) == 2
    assert all(c.trust_zone == "default" for c in system.components)
    # No boundaries means dataflows don't cross any.
    assert not system.dataflows[0].crosses_boundary
