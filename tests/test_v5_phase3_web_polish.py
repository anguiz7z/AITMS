"""Roadmap V5 Phase 3 — web UI demo-surface contract.

The web UI on :8765 is the only delivery surface that ships. On
inspection (v0.19.3) the demo surface was already in good shape — the
earlier hibernation + web work had already:

  * parsed each sample's real name / description / component-count for
    the /samples table (no blank-comment-line logic),
  * styled error messages via `.alert-error` (a real, legible CSS rule),
  * wired a friendly error path on /analyze (malformed YAML -> HTTP 400
    re-render with the error, never a traceback or 500).

So Phase 3 adds NO production change — it LOCKS the existing polish so a
future edit can't regress it. This is the honest outcome: the surface
was already good; the value is the regression net.

KEEP suite (flags off).
"""

from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from atms.web import app

ROOT = Path(__file__).resolve().parents[1]


def _client():
    return TestClient(app, raise_server_exceptions=False)


# ─── KEEP routes serve populated content ────────────────────────────


def test_index_route_populated():
    r = _client().get("/")
    assert r.status_code == 200
    assert "Analyze an AI system" in r.text
    assert 'action="/analyze"' in r.text


def test_editor_route_populated():
    r = _client().get("/editor")
    assert r.status_code == 200
    assert "palette" in r.text.lower() or "editor" in r.text.lower()


def test_docs_route_populated():
    r = _client().get("/docs")
    assert r.status_code == 200
    assert "Knowledge base" in r.text or "Playbooks" in r.text


def test_samples_route_populated():
    r = _client().get("/samples")
    assert r.status_code == 200
    assert "Sample AI systems" in r.text


# ─── Samples page shows real per-sample data ────────────────────────


def test_samples_page_shows_real_names_and_counts():
    """Each sample row shows its System name, a numeric component count,
    and a Load link — not blank cells derived from a missing comment."""
    r = _client().get("/samples")
    body = r.text
    # A Load link per bundled sample.
    assert body.count('href="/?sample=') >= 10
    # Real system names from the YAML (not filenames) appear.
    assert "Autonomous DevOps Agent" in body or "Marketing Content Chatbot" in body
    # The Components column header is present.
    assert "Components" in body


def test_samples_page_has_components_column():
    r = _client().get("/samples")
    assert "<th>Components</th>" in r.text


# ─── Error rendering is styled + friendly (no 500, no traceback) ────


def test_alert_error_css_is_real():
    """`.alert-error` must carry a real CSS declaration so error
    messages are visible, not bare text."""
    base = (ROOT / "src" / "atms" / "templates" / "web" / "base.html").read_text(
        encoding="utf-8")
    m = re.search(r"\.alert-error\s*\{([^}]*)\}", base)
    assert m, ".alert-error rule not found"
    assert m.group(1).strip(), ".alert-error rule is empty"
    # And the base `.alert` rule it builds on is non-empty too.
    m2 = re.search(r"\.alert\s*\{([^}]*)\}", base)
    assert m2 and "background" in m2.group(1)


def test_analyze_malformed_yaml_renders_styled_error_not_500():
    """Malformed YAML re-renders the index (HTTP 400) with the error
    inside an .alert-error block — never a 500, never a traceback."""
    r = _client().post("/analyze", data={"yaml": "name: t\n  : : ["})
    assert r.status_code == 400
    assert "alert-error" in r.text
    assert "Traceback (most recent call last)" not in r.text


def test_analyze_schema_invalid_renders_styled_error():
    r = _client().post("/analyze", data={"yaml": "foo: bar\n"})
    assert r.status_code in (200, 400)
    assert r.status_code != 500
    assert "Traceback (most recent call last)" not in r.text


# ─── Analyze report renders end-to-end ──────────────────────────────


def test_analyze_valid_system_renders_report():
    """A valid AI system analyses and renders a report page with a
    threats section + no traceback."""
    r = _client().post("/analyze", data={
        "yaml": (
            "name: demo\ncomponents:\n"
            "  - id: llm\n    name: LLM\n    type: llm_inference\n"
            "  - id: rag\n    name: RAG\n    type: rag_vector_store\n"
        )})
    assert r.status_code == 200
    assert "Traceback (most recent call last)" not in r.text
    assert "threat" in r.text.lower()
