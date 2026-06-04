"""Feature-availability + reversibility contract (web routes).

v1.0.1 (2026-05-31) UN-HIBERNATION: the aggressive v0.18.68 hibernation
broke the real product — the upload form advertised .vsdx / IaC formats
while their parsers errored, and Evidence / Red-team / IaC / Compliance /
Devices / Diff routes 404'd. Per the owner, every FREE + OFFLINE
capability is now ENABLED by default.

This file pins the NEW contract:
  * The formerly-hibernated routes now SERVE (200), not 404.
  * Every export format downloads (no hibernation gate).
  * The hibernation MECHANISM still works in reverse: setting
    ATMS_FEATURE_<NAME>=0 turns a route back off (404 + re-enable hint),
    so the capability is still toggleable, just on-by-default.
  * Swagger / ReDoc / OpenAPI stay disabled (app config, independent of
    the feature flags).

Only `vision` (image→YAML via local Ollama) remains off-by-default.
"""

from __future__ import annotations

import importlib
import os

import pytest
from fastapi.testclient import TestClient

import atms.features as features_mod
import atms.web as web_mod

# Default-mode contract (features on by default; routes serve). Under
# `-m hibernated` conftest force-enables every flag, so the one
# disable-reversibility test below can't toggle a route off cleanly.
# Skip that single test in all-forced mode; the rest still hold.
_ALL_FORCED = os.environ.get("ATMS_FEATURE_NAV_IAC") == "1"


@pytest.fixture
def client(monkeypatch):
    # Isolate from cross-file env leakage: test the COMPILED defaults.
    import os
    for k in list(os.environ):
        if k.startswith("ATMS_FEATURE_"):
            monkeypatch.delenv(k, raising=False)
    importlib.reload(features_mod)
    importlib.reload(web_mod)
    return TestClient(web_mod.app, raise_server_exceptions=False)


# ─── Formerly-hibernated HTML routes now SERVE ──────────────────────


@pytest.mark.parametrize("route", [
    "/evidence",
    "/redteam",
    "/iac",
    "/compliance",
    "/devices",
    "/diff",
])
def test_feature_html_route_serves(client, route):
    """Enabled by default → 200, and the body is NOT the hibernation
    stub."""
    r = client.get(route)
    assert r.status_code == 200, (
        f"Route {route} returned {r.status_code}; expected 200 "
        f"(feature enabled by default)."
    )
    assert "hibernated" not in r.text.lower()


# ─── Formerly-hibernated POST ingest routes accept requests ─────────


@pytest.mark.parametrize("route", [
    "/evidence/ingest",
    "/redteam/ingest",
    "/iac/ingest",
])
def test_feature_post_route_not_gated(client, route):
    """POST on an ingest route is no longer blocked by the hibernation
    gate (it may 200 or validation-error, but never the 404 stub)."""
    r = client.post(route, files={"file": ("x.csv", b"", "text/plain")})
    assert not (r.status_code == 404 and "hibernated" in r.text.lower()), (
        f"POST {route} still hibernation-gated: {r.status_code}"
    )


# ─── REST API serves ────────────────────────────────────────────────


def test_rest_api_metrics_serves(client):
    r = client.get("/api/v1/metrics")
    assert r.status_code == 200
    assert "hibernated" not in r.text.lower()


def test_rest_api_analyze_not_gated(client):
    r = client.post("/api/v1/analyze", json={})
    assert not (r.status_code == 404 and "hibernated" in r.text.lower())


def test_rest_api_scan_not_gated(client):
    r = client.post("/api/v1/scan", files={"file": ("x.yaml", b"name: t\n", "text/plain")})
    assert not (r.status_code == 404 and "hibernated" in r.text.lower())


def test_api_compliance_serves(client):
    r = client.get("/api/compliance")
    assert r.status_code == 200


def test_api_devices_serves(client):
    r = client.get("/api/devices")
    assert r.status_code == 200


# ─── Swagger / ReDoc / OpenAPI stay disabled (app config) ───────────


def test_swagger_ui_disabled(client):
    """ATMS owns /docs for its own index; FastAPI's Swagger UI is off."""
    r = client.get("/docs")
    assert r.status_code == 200
    assert "SwaggerUIBundle" not in r.text
    assert "Knowledge base" in r.text or "OWASP Agentic" in r.text


def test_redoc_returns_404(client):
    assert client.get("/redoc").status_code == 404


def test_openapi_json_returns_404(client):
    assert client.get("/openapi.json").status_code == 404


# ─── KEEP routes still serve ────────────────────────────────────────


@pytest.mark.parametrize("route", [
    "/",
    "/editor",
    "/samples",
    "/docs",
    "/healthz",
])
def test_keep_route_returns_200(client, route):
    r = client.get(route)
    assert r.status_code == 200, (
        f"Core route {route} returned {r.status_code}; expected 200."
    )


@pytest.mark.parametrize("route", [
    "/kb", "/playbooks", "/maestro", "/agentic",
    "/methodology", "/architecture", "/capabilities", "/about",
])
def test_reference_routes_still_serve(client, route):
    r = client.get(route)
    assert r.status_code == 200


# ─── Every export format downloads (no hibernation gate) ───────────


def test_download_route_md_format_passes_gate(client):
    """md with a bogus run id → 'run not found' (404), NOT hibernated."""
    r = client.get("/download/bogus_run_id/md")
    assert r.status_code == 404
    assert "hibernated" not in r.text.lower()


@pytest.mark.parametrize("fmt", [
    "stix", "navigator", "csv", "compliance", "compliance_csv",
    "jira_csv", "jira_json", "roadmap_md", "roadmap_json", "sbom",
])
def test_download_route_format_not_hibernation_gated(client, fmt):
    """Export formats are enabled → a bogus run id 404s on RUN LOOKUP,
    not on a hibernation gate."""
    r = client.get(f"/download/any_run_id/{fmt}")
    assert "hibernated" not in r.text.lower(), (
        f"Format `{fmt}` is still hibernation-gated: {r.text[:160]}"
    )


# ─── Reversibility: the mechanism still toggles OFF ────────────────


@pytest.mark.skipif(_ALL_FORCED, reason="can't toggle off under all-flags-forced run")
def test_env_override_can_disable_a_route(monkeypatch):
    """The hibernation mechanism is intact, just inverted: features are
    ON by default but ATMS_FEATURE_<NAME>=0 turns one back OFF, proving
    deployments can still trim the surface."""
    monkeypatch.setenv("ATMS_FEATURE_EVIDENCE", "0")
    c = TestClient(web_mod.app, raise_server_exceptions=False)
    r = c.get("/evidence")
    assert r.status_code == 404
    assert "hibernated" in r.text.lower() or "ATMS_FEATURE_" in r.text


def test_env_override_keeps_route_on_by_default(monkeypatch):
    """With no override, the route serves (the default-on contract)."""
    monkeypatch.delenv("ATMS_FEATURE_EVIDENCE", raising=False)
    c = TestClient(web_mod.app, raise_server_exceptions=False)
    r = c.get("/evidence")
    assert r.status_code == 200
