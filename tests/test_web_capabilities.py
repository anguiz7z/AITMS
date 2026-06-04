"""Regression tests for v0.18.31 Cycle UU — /capabilities discovery page."""

from __future__ import annotations

from fastapi.testclient import TestClient

from atms.web import app


def test_capabilities_route_returns_200():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/capabilities")
    assert r.status_code == 200


def test_capabilities_lists_input_formats():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/capabilities")
    text = r.text
    # Major formats should appear by name.
    for token in (".drawio", ".bicep", "Pulumi YAML", "CloudFormation",
                  "Kubernetes manifests", ".vsdx", "Mermaid"):
        assert token in text, f"missing format mention: {token}"


def test_capabilities_lists_compliance_frameworks():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/capabilities")
    text = r.text
    # All 11 frameworks should render as pills.
    for fw in ("DORA", "GDPR", "ISO27001", "NIST_800_53", "NIST_CSF",
                "PCI_DSS", "HIPAA", "SOC2", "EU_AI_Act", "NIS2", "SEC_CYBER"):
        assert fw in text, f"missing framework: {fw}"


def test_capabilities_lists_arch_rules():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/capabilities")
    text = r.text
    # Spot-check rules from each major batch.
    for rule in ("missing_waf", "missing_centralized_logging",
                  "missing_prompt_injection_guard",
                  "unbounded_agent_tool_access"):
        assert rule in text, f"missing arch rule: {rule}"


def test_capabilities_lists_export_formats():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/capabilities")
    text = r.text
    for token in ("Markdown report", "HTML report", "Executive summary",
                  "STIX 2.1", "Navigator layer", "SARIF",
                  "Compliance matrix", "JIRA", "CycloneDX"):
        assert token in text, f"missing export format: {token}"


def test_capabilities_lists_rest_endpoints():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/capabilities")
    text = r.text
    for ep in ("/api/v1/analyze", "/api/v1/scan",
                "/api/v1/metrics", "/healthz"):
        assert ep in text, f"missing REST endpoint mention: {ep}"


def test_capabilities_nav_link_absent_when_hibernated():
    """v0.18.69 Hibernation Phase 2 — Capabilities was collapsed into
    /docs; its top-level nav entry is gone unless the env var
    ATMS_FEATURE_NAV_COMPLIANCE=1 (or a future capabilities-specific
    flag) is set. The page itself still serves; it just lost the nav."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/")
    # Look only in the <nav>...</nav> block — the body of /docs etc.
    # may legitimately link to /capabilities.
    nav_start = r.text.find("<nav>")
    nav_end = r.text.find("</nav>", nav_start)
    nav_block = r.text[nav_start:nav_end]
    assert '/capabilities' not in nav_block, (
        "Capabilities is hibernated; should not be in top-level nav."
    )
    # Cross-check the underlying route still serves.
    r2 = c.get("/capabilities")
    assert r2.status_code == 200
