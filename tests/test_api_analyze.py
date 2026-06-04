"""Regression tests for v0.18.21 Cycle KK — REST API for analyse.

`/api/v1/analyze` is the programmatic endpoint for CI/CD pipelines.
POST JSON, GET back JSON. Goal: a `curl | jq` flow that doesn't
require parsing HTML.
"""

from __future__ import annotations

# v0.18.70 Hibernation Phase 3 — entire file exercises a
# hibernated surface. Skipped by default; run with:
#     pytest -m hibernated tests/test_api_analyze.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


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

_PURE_IT_YAML = """
name: pure-it
components:
  - id: u
    name: User
    type: user
  - id: web
    name: Web
    type: web_application
  - id: db
    name: DB
    type: database
"""


def _post(c: TestClient, body: dict):
    return c.post("/api/v1/analyze", json=body)


def test_api_analyze_happy_path_returns_model():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": _SAMPLE_YAML})
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["ok"] is True
    assert "version" in body
    assert "summary" in body
    assert "model" in body
    assert len(body["model"]["threats"]) > 0
    # Summary is the same dict the workflow exposes.
    assert "severity_breakdown" in body["summary"]


def test_api_analyze_returns_model_in_threatmodel_shape():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": _SAMPLE_YAML})
    body = r.json()
    model = body["model"]
    # Every top-level ThreatModel field present.
    for key in ("system", "threats", "attack_paths", "mitigations", "summary"):
        assert key in model, f"missing model.{key}"
    # Threats have required fields.
    t = model["threats"][0]
    for field in ("id", "title", "severity", "likelihood", "impact",
                  "component_id"):
        assert field in t, f"missing threat.{field}"


def test_api_analyze_missing_yaml_returns_400():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {})
    assert r.status_code == 400
    assert "yaml" in r.json().get("detail", "").lower()


def test_api_analyze_empty_yaml_returns_400():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": "   "})
    assert r.status_code == 400


def test_api_analyze_invalid_yaml_returns_400():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": "not: : valid yaml: ["})
    assert r.status_code == 400
    assert "parse" in r.json().get("detail", "").lower()


def test_api_analyze_invalid_system_returns_400():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": "components:\n  - id: x\n    name: x\n    type: nope\n"})
    assert r.status_code == 400


def test_api_analyze_unknown_methodology_returns_400():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": _SAMPLE_YAML, "methodology": "foo"})
    assert r.status_code == 400
    assert "methodology" in r.json().get("detail", "").lower()


def test_api_analyze_supports_linddun_methodology():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": _SAMPLE_YAML, "methodology": "linddun"})
    assert r.status_code == 200


def test_api_analyze_allow_pure_it_default_true():
    """Default behaviour: pure-IT YAML still produces threats."""
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": _PURE_IT_YAML})
    assert r.status_code == 200
    assert len(r.json()["model"]["threats"]) > 0


def test_api_analyze_compliance_matrix_optional():
    """Default: no compliance_matrix key. Opt-in via flag."""
    c = TestClient(app, raise_server_exceptions=False)
    r1 = _post(c, {"yaml": _SAMPLE_YAML})
    assert "compliance_matrix" not in r1.json()
    r2 = _post(c, {"yaml": _SAMPLE_YAML, "include_compliance_matrix": True})
    body = r2.json()
    assert "compliance_matrix" in body
    assert isinstance(body["compliance_matrix"], list)


def test_api_analyze_jira_payload_optional():
    """Default: no jira key. Opt-in via flag."""
    c = TestClient(app, raise_server_exceptions=False)
    r1 = _post(c, {"yaml": _SAMPLE_YAML})
    assert "jira" not in r1.json()
    r2 = _post(c, {"yaml": _SAMPLE_YAML, "include_jira_payload": True})
    body = r2.json()
    assert "jira" in body
    assert "issueUpdates" in body["jira"]


def test_api_analyze_round_trip_json_is_lossless():
    """The returned model JSON should be re-loadable via Pydantic."""
    from atms.models import ThreatModel
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": _SAMPLE_YAML})
    body = r.json()
    # Reconstruct via Pydantic — proves the JSON shape is faithful.
    reconstructed = ThreatModel.model_validate(body["model"])
    assert len(reconstructed.threats) == len(body["model"]["threats"])


def test_api_analyze_root_must_be_mapping():
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, {"yaml": "- item1\n- item2\n"})
    assert r.status_code == 400
    assert "mapping" in r.json().get("detail", "").lower()
