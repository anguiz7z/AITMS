"""Regression tests for v0.18.30 Cycle TT — /healthz + /api/v1/metrics."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from atms import __version__
from atms.web import app


def test_healthz_returns_200_with_version():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["version"] == __version__


def test_healthz_response_is_small_and_stable():
    """Probes can be called many times per second — body should be small."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/healthz")
    # Pin keys so a future change has to update this test.
    assert set(r.json().keys()) == {"ok", "version"}
    assert len(r.text) < 200


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_metrics_returns_kb_inventory():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/api/v1/metrics")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["version"] == __version__
    kb = body["kb"]
    # Sanity: known floor counts (these only grow; if they shrink something broke).
    assert kb["playbooks"] >= 120
    assert kb["compliance_controls"] >= 85
    assert kb["compliance_frameworks"] >= 11
    assert kb["atlas_techniques"] >= 30
    assert kb["device_catalog"] >= 200


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_metrics_includes_arch_rule_count():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/api/v1/metrics")
    body = r.json()
    assert body["arch_rules"] >= 25


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_metrics_frameworks_list_matches_count():
    c = TestClient(app, raise_server_exceptions=False)
    body = c.get("/api/v1/metrics").json()
    kb = body["kb"]
    assert len(kb["frameworks"]) == kb["compliance_frameworks"]
    # SOC2 was added in NN.
    assert "SOC2" in kb["frameworks"]


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_metrics_runs_cached_starts_at_zero():
    """In a fresh TestClient process, no runs are stored."""
    c = TestClient(app, raise_server_exceptions=False)
    body = c.get("/api/v1/metrics").json()
    # Don't pin to 0 (other tests may have populated the in-process
    # singleton); just confirm the field is an int in range.
    assert isinstance(body["runs_cached"], int)
    assert 0 <= body["runs_cached"] <= body["runs_capacity"]


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_metrics_increments_runs_cached_after_analyze():
    c = TestClient(app, raise_server_exceptions=False)
    before = c.get("/api/v1/metrics").json()["runs_cached"]
    r = c.post("/analyze", data={"yaml": (
        "name: t\ncomponents:\n  - id: u\n    name: u\n    type: user\n"
        "  - id: llm\n    name: LLM\n    type: llm_inference\n")})
    assert r.status_code == 200
    after = c.get("/api/v1/metrics").json()["runs_cached"]
    assert after >= before + 1


def test_healthz_does_not_require_authentication():
    """Confirm there's no auth gate that breaks LBs."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/healthz")
    assert r.status_code == 200
    # No WWW-Authenticate header / 401 / 403.
    assert "WWW-Authenticate" not in r.headers
