"""Web-UI smoke tests via FastAPI TestClient."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atms.web import app

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_home(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "ATMS" in r.text
    assert "Analyze" in r.text


def test_healthz(client):
    """v0.18.30 Cycle TT: /healthz now returns JSON {ok, version}
    instead of plaintext 'ok' — the new shape is friendlier for
    load balancers + k8s probes that prefer a typed payload."""
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "version" in body


def test_samples_page(client):
    r = client.get("/samples")
    assert r.status_code == 200
    assert "rag_system.yaml" in r.text or "Customer Support" in r.text


def test_kb_page(client):
    r = client.get("/kb")
    assert r.status_code == 200
    r2 = client.get("/kb", params={"q": "prompt injection"})
    assert r2.status_code == 200
    assert "LLM01" in r2.text


def test_playbooks_page(client):
    r = client.get("/playbooks")
    assert r.status_code == 200
    assert "llm_inference" in r.text


def test_about(client):
    r = client.get("/about")
    assert r.status_code == 200
    assert "ATMS" in r.text


def test_analyze_post(client):
    yaml_text = (SAMPLES_DIR / "chatbot.yaml").read_text(encoding="utf-8")
    r = client.post("/analyze", data={"yaml": yaml_text})
    assert r.status_code == 200
    assert "Threats" in r.text
    assert "Marketing" in r.text


def test_analyze_invalid(client):
    r = client.post("/analyze", data={"yaml": "this: is: not: valid: yaml"})
    assert r.status_code == 400
    # The page must echo the actual parser error inside the .alert-error
    # banner — NOT just match "error" inside the CSS class name (which
    # appears on every render). Look for the explicit `<strong>Error:`
    # the index template renders only when `{% if error %}` fires.
    assert "<strong>Error:</strong>" in r.text


def test_load_sample_via_query(client):
    r = client.get("/?sample=chatbot.yaml")
    assert r.status_code == 200
    assert "Marketing" in r.text


def test_maestro_page(client):
    r = client.get("/maestro")
    assert r.status_code == 200
    assert "MAESTRO" in r.text
    assert "Foundation Models" in r.text
    assert "Agent Ecosystem" in r.text


def test_agentic_page(client):
    r = client.get("/agentic")
    assert r.status_code == 200
    assert "Agentic" in r.text
    assert "Memory Poisoning" in r.text
    assert "AGT01" in r.text


def test_kb_search_agentic_via_web(client):
    r = client.get("/kb", params={"q": "memory poisoning", "framework": "owasp_agentic"})
    assert r.status_code == 200
    assert "AGT01" in r.text


def test_kb_search_maestro_via_web(client):
    r = client.get("/kb", params={"q": "agent ecosystem", "framework": "maestro"})
    assert r.status_code == 200
    assert "M.L7" in r.text


def test_load_sample_path_traversal_blocked(client):
    """v0.14.4: assert the SPECIFIC defence — the route must return the
    fixed `Sample not found.` error, not silently 200 with an empty
    YAML pre-populated. The previous assertion `/etc/passwd not in
    r.text` could not fail: even a successful traversal that dumped
    `root:x:0:0:` doesn't contain the literal string `/etc/passwd`."""
    r = client.get("/?sample=../../etc/passwd")
    assert r.status_code == 200
    # Defence-message present
    assert "Sample not found." in r.text
    # Defence-in-depth: no shell-style `root:x:` content
    assert "root:x:" not in r.text
    assert "PRIVATE KEY" not in r.text
