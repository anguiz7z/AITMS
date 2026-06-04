"""Regression tests for v0.18.16 Cycle FF — web compliance-matrix download.

Mirrors the v0.18.11 Cycle AA test pattern for exec-summary: every
analyse run should auto-cache a compliance matrix (HTML + CSV) and
the report page should surface the download buttons.
"""

from __future__ import annotations

# v0.18.70 Hibernation Phase 3 — entire file exercises a
# hibernated surface. Skipped by default; run with:
#     pytest -m hibernated tests/test_web_compliance.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import re

from fastapi.testclient import TestClient

from atms.web import app

_AI_SAMPLE_YAML = """
name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""


def _run_and_get_run_id(c: TestClient) -> str:
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    assert r.status_code == 200, r.text[:400]
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    assert m, "Expected /download/{run_id}/md link in report"
    return m.group(1)


def test_report_page_advertises_compliance_buttons():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": _AI_SAMPLE_YAML})
    assert r.status_code == 200
    assert "Compliance matrix" in r.text
    assert "Compliance CSV" in r.text
    assert "/compliance" in r.text


def test_compliance_html_download_returns_self_contained_doc():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _run_and_get_run_id(c)
    r2 = c.get(f"/download/{run_id}/compliance")
    assert r2.status_code == 200
    assert r2.text.startswith("<!doctype html>")
    # Smoke checks for the matrix structure.
    for word in ("Compliance coverage", "Covered", "Uncovered"):
        assert word in r2.text
    # Attachment filename.
    cd = r2.headers.get("content-disposition", "")
    assert "compliance.html" in cd


def test_compliance_csv_download_returns_csv():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _run_and_get_run_id(c)
    r2 = c.get(f"/download/{run_id}/compliance_csv")
    assert r2.status_code == 200
    # CSV header check.
    first_line = r2.text.splitlines()[0]
    assert first_line.startswith("control_id,framework,title,status")
    cd = r2.headers.get("content-disposition", "")
    assert "compliance.csv" in cd
    assert r2.headers["content-type"].startswith("text/csv")


def test_compliance_download_404_on_unknown_run():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/download/abcdef000000/compliance")
    assert r.status_code == 404
