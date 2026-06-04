"""Regression tests for v0.18.29 Cycle SS — CycloneDX SBOM export."""

from __future__ import annotations

# v0.18.70 Hibernation Phase 3 — entire file exercises a
# hibernated surface. Skipped by default; run with:
#     pytest -m hibernated tests/test_sbom_export.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import json
import re

import pytest
from fastapi.testclient import TestClient

from atms.models import Component, ComponentType, Dataflow, System
from atms.reporting.sbom_export import _TYPE_MAP, render_sbom_cdx
from atms.web import app
from atms.workflow import analyze

# CycloneDX 1.5 allowed values for component.type.
_VALID_CDX_TYPES = {
    "application", "framework", "library", "container", "platform",
    "device", "firmware", "file", "machine-learning-model",
    "data", "cryptographic-asset",
}


def test_sbom_type_map_covers_every_component_type():
    """Phase 1 invariant: every ATMS ComponentType has an explicit
    CycloneDX type mapping — no silent default-to-application."""
    import typing
    all_types = set(typing.get_args(ComponentType))
    mapped = set(_TYPE_MAP.keys())
    missing = all_types - mapped
    extra = mapped - all_types
    assert not missing, (
        f"{len(missing)} ATMS ComponentTypes have no SBOM mapping: "
        f"{sorted(missing)}"
    )
    assert not extra, (
        f"{len(extra)} SBOM mappings reference unknown ComponentTypes "
        f"(probably stale): {sorted(extra)}"
    )


def test_sbom_type_map_values_are_valid_cdx_types():
    """Every mapped value must be a CycloneDX 1.5 spec enum value."""
    invalid = {ct: cdx for ct, cdx in _TYPE_MAP.items()
               if cdx not in _VALID_CDX_TYPES}
    assert not invalid, (
        f"Non-spec CycloneDX type values in _TYPE_MAP: {invalid}"
    )


@pytest.fixture(scope="module")
def model():
    s = System(name="sbom-test", components=[
        Component(id="u", name="User", type="user"),
        Component(id="waf", name="WAF", type="waf"),
        Component(id="llm", name="LLM", type="llm_inference",
                   metadata={"vendor": "Anthropic", "product": "Claude Sonnet 4.5",
                             "version": "2025-09",
                             "cpe": "cpe:2.3:a:anthropic:claude:4.5:*:*:*:*:*:*:*",
                             "hostname": "claude.api.anthropic.com"}),
        Component(id="kv", name="Vault", type="secrets_vault"),
        Component(id="db", name="DB", type="database"),
    ], dataflows=[
        Dataflow(source="u", target="waf"),
        Dataflow(source="waf", target="llm"),
        Dataflow(source="llm", target="kv"),
        Dataflow(source="llm", target="db"),
    ])
    return analyze(s)


# ─── Pure renderer ────────────────────────────────────────────────
def test_sbom_returns_valid_json(model):
    sbom_text = render_sbom_cdx(model)
    data = json.loads(sbom_text)
    assert isinstance(data, dict)


def test_sbom_has_required_top_level_fields(model):
    data = json.loads(render_sbom_cdx(model))
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"
    assert data["version"] == 1
    assert "serialNumber" in data
    assert data["serialNumber"].startswith("urn:uuid:")
    assert "metadata" in data
    assert "components" in data


def test_sbom_metadata_has_timestamp_and_tool(model):
    data = json.loads(render_sbom_cdx(model))
    md = data["metadata"]
    assert "timestamp" in md
    # ISO-8601 with timezone.
    assert "T" in md["timestamp"]
    tools = md.get("tools", [])
    assert tools
    assert tools[0]["name"] == "atms"


def test_sbom_components_have_bom_ref_per_component(model):
    data = json.loads(render_sbom_cdx(model))
    refs = {c["bom-ref"] for c in data["components"]}
    assert refs == {c.id for c in model.system.components}


def test_sbom_component_type_maps_correctly(model):
    data = json.loads(render_sbom_cdx(model))
    by_ref = {c["bom-ref"]: c for c in data["components"]}
    assert by_ref["llm"]["type"] == "machine-learning-model"
    assert by_ref["db"]["type"] == "data"
    assert by_ref["kv"]["type"] == "cryptographic-asset"


def test_sbom_carries_vendor_product_version(model):
    data = json.loads(render_sbom_cdx(model))
    by_ref = {c["bom-ref"]: c for c in data["components"]}
    llm = by_ref["llm"]
    assert llm["supplier"]["name"] == "Anthropic"
    assert llm["name"] == "Claude Sonnet 4.5"
    assert llm["version"] == "2025-09"
    assert llm["cpe"].startswith("cpe:2.3:a:anthropic:claude")


def test_sbom_includes_atms_metadata_properties(model):
    data = json.loads(render_sbom_cdx(model))
    by_ref = {c["bom-ref"]: c for c in data["components"]}
    llm_props = {p["name"]: p["value"] for p in by_ref["llm"]["properties"]}
    assert llm_props["atms:component_type"] == "llm_inference"
    assert "atms:trust_zone" in llm_props
    assert llm_props["atms:hostname"] == "claude.api.anthropic.com"


def test_sbom_dependencies_mirror_dataflows(model):
    data = json.loads(render_sbom_cdx(model))
    deps = data.get("dependencies", [])
    by_ref = {d["ref"]: d["dependsOn"] for d in deps}
    # llm depends on kv and db.
    assert "llm" in by_ref
    assert set(by_ref["llm"]) == {"kv", "db"}


def test_sbom_handles_empty_dataflows():
    s = System(name="lonely", components=[
        Component(id="x", name="x", type="user"),
    ])
    m = analyze(s, require_ai_components=False)
    data = json.loads(render_sbom_cdx(m))
    # Either no "dependencies" key, or an empty list — both valid CDX.
    assert data.get("dependencies", []) == [] or "dependencies" not in data


# ─── Web download route ───────────────────────────────────────────
def _analyze_get_run_id(c: TestClient) -> str:
    r = c.post("/analyze", data={"yaml": (
        "name: t\ncomponents:\n  - id: u\n    name: u\n    type: user\n"
        "  - id: llm\n    name: LLM\n    type: llm_inference\n")})
    assert r.status_code == 200
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    return m.group(1)


def test_report_advertises_sbom_button():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": (
        "name: t\ncomponents:\n  - id: u\n    name: u\n    type: user\n"
        "  - id: llm\n    name: LLM\n    type: llm_inference\n")})
    assert r.status_code == 200
    assert "SBOM (CDX)" in r.text
    assert "/download/" in r.text


def test_sbom_download_returns_cdx_json():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _analyze_get_run_id(c)
    r = c.get(f"/download/{run_id}/sbom")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    data = json.loads(r.text)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"
    cd = r.headers.get("content-disposition", "")
    assert "sbom.cdx.json" in cd
