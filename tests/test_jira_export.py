"""Regression tests for v0.18.17 Cycle GG — JIRA backlog export.

Covers both the CLI render path and the web download path.
"""

from __future__ import annotations

# v0.18.70 Hibernation Phase 3 — entire file exercises a
# hibernated surface. Skipped by default; run with:
#     pytest -m hibernated tests/test_jira_export.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import csv
import io
import json
import re

import pytest
from fastapi.testclient import TestClient

from atms.models import System
from atms.reporting.jira_export import (
    _PRIORITY_MAP,
    _build_labels,
    render_jira_csv,
    render_jira_json,
)
from atms.web import app
from atms.workflow import analyze

_SAMPLE_YAML = """
name: jira-demo
components:
  - id: u
    name: User
    type: user
  - id: app
    name: WebApp
    type: web_application
  - id: db
    name: DB
    type: database
dataflows:
  - source: u
    target: app
    label: HTTPS
  - source: app
    target: db
    label: TLS SQL
"""


@pytest.fixture(scope="module")
def model():
    """Build a model with enough threats for meaningful export."""
    import yaml
    s = System.model_validate(yaml.safe_load(_SAMPLE_YAML))
    return analyze(s, require_ai_components=False)


# ─── Renderer-level tests ─────────────────────────────────────────
def test_jira_csv_header_in_expected_order(model):
    csv_text = render_jira_csv(model)
    header = csv_text.splitlines()[0]
    assert header == ("Summary,Description,Issue Type,Priority,Status,"
                       "Component/s,Labels,External ID")


def test_jira_csv_one_row_per_threat(model):
    csv_text = render_jira_csv(model)
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 1 + len(model.threats)  # header + threats


def test_jira_csv_priority_maps_correctly(model):
    """Every CSV row's Priority value must be a JIRA-valid one."""
    csv_text = render_jira_csv(model)
    reader = csv.DictReader(io.StringIO(csv_text))
    seen = set()
    for row in reader:
        seen.add(row["Priority"])
    assert seen.issubset(set(_PRIORITY_MAP.values()))
    assert seen, "Expected at least one priority in output"


def test_jira_csv_issue_type_is_risk(model):
    csv_text = render_jira_csv(model)
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        assert row["Issue Type"] == "Risk"


def test_jira_csv_external_id_matches_threat_id(model):
    csv_text = render_jira_csv(model)
    reader = csv.DictReader(io.StringIO(csv_text))
    ext_ids = [row["External ID"] for row in reader]
    threat_ids = [t.id for t in model.threats]
    assert ext_ids == threat_ids


def test_jira_csv_labels_include_atms_marker(model):
    """Every threat must be discoverable in JIRA by `labels = atms-threat`."""
    csv_text = render_jira_csv(model)
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        assert "atms-threat" in row["Labels"]


def test_jira_csv_severity_label_present(model):
    csv_text = render_jira_csv(model)
    reader = csv.DictReader(io.StringIO(csv_text))
    severities = set()
    for row in reader:
        # Labels are `;`-separated; each starts with the field name.
        labels = row["Labels"].split(";")
        sev_labels = [l for l in labels if l.startswith("severity:")]
        assert sev_labels, f"No severity label on row {row['External ID']}"
        severities.add(sev_labels[0].split(":", 1)[1])
    # At least one valid severity value.
    assert severities.issubset({"critical", "high", "medium", "low", "info"})


def test_jira_csv_summary_truncated_to_250_chars(model):
    """JIRA's Summary cap is 255 chars; we truncate at 250."""
    # Inject a long-titled threat.
    long_threat = model.threats[0].model_copy(update={"title": "x" * 500})
    model2 = model.model_copy(update={"threats": [long_threat] + model.threats[1:]})
    csv_text = render_jira_csv(model2)
    reader = csv.DictReader(io.StringIO(csv_text))
    first = next(reader)
    assert len(first["Summary"]) <= 250


def test_jira_json_valid_bulk_payload(model):
    data = json.loads(render_jira_json(model))
    assert "issueUpdates" in data
    assert isinstance(data["issueUpdates"], list)
    assert len(data["issueUpdates"]) == len(model.threats)
    for issue in data["issueUpdates"]:
        assert "fields" in issue
        assert "project" in issue["fields"]
        assert issue["fields"]["project"]["key"] == "SEC"  # default
        assert "summary" in issue["fields"]
        assert issue["fields"]["issuetype"]["name"] == "Risk"


def test_jira_json_honours_custom_project_key(model):
    data = json.loads(render_jira_json(model, project_key="MYPROJ"))
    for issue in data["issueUpdates"]:
        assert issue["fields"]["project"]["key"] == "MYPROJ"


def test_jira_json_label_list_is_array(model):
    """JIRA REST expects `labels` as a JSON array (not a string)."""
    data = json.loads(render_jira_json(model))
    for issue in data["issueUpdates"]:
        assert isinstance(issue["fields"]["labels"], list)


# ─── Helper tests ─────────────────────────────────────────────────
def test_build_labels_includes_framework_refs(model):
    """Phase 2: dead skip replaced with an explicit precondition.
    The default user+llm fixture produces 14 threats, all with
    framework refs — if that ever stops being true, this test
    catches it rather than silently skipping."""
    threats_with_refs = [t for t in model.threats if t.references]
    assert threats_with_refs, (
        "Default fixture should produce at least one threat with "
        "framework references — playbook regression?"
    )
    t = threats_with_refs[0]
    labels = _build_labels(t)
    framework_labels = [l for l in labels if l.startswith("framework:")]
    assert framework_labels


def test_build_labels_no_whitespace():
    """JIRA labels cannot contain whitespace."""
    class FakeThreat:
        severity = "high"
        references = ["NIST SP 800-53 AC-3"]  # has spaces
        stride_ai = ["Spoofing"]
        kill_chain_phase = "delivery"
    labels = _build_labels(FakeThreat())
    for lab in labels:
        assert " " not in lab, f"label has whitespace: {lab}"


# ─── Web-route tests ──────────────────────────────────────────────
def _run_and_get_run_id(c: TestClient) -> str:
    yaml_minimal = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""
    r = c.post("/analyze", data={"yaml": yaml_minimal})
    assert r.status_code == 200, r.text[:400]
    m = re.search(r"/download/([a-f0-9]+)/md", r.text)
    assert m
    return m.group(1)


def test_report_page_advertises_jira_buttons():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/analyze", data={"yaml": "name: t\ncomponents:\n  - id: u\n    name: u\n    type: user\n  - id: llm\n    name: LLM\n    type: llm_inference\n"})
    assert r.status_code == 200
    assert "JIRA CSV" in r.text
    assert "JIRA JSON" in r.text


def test_jira_csv_download_returns_csv():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _run_and_get_run_id(c)
    r = c.get(f"/download/{run_id}/jira_csv")
    assert r.status_code == 200
    assert r.text.splitlines()[0].startswith("Summary,Description,Issue Type")
    assert r.headers["content-type"].startswith("text/csv")
    assert "jira.csv" in r.headers.get("content-disposition", "")


def test_jira_json_download_returns_json():
    c = TestClient(app, raise_server_exceptions=False)
    run_id = _run_and_get_run_id(c)
    r = c.get(f"/download/{run_id}/jira_json")
    assert r.status_code == 200
    data = json.loads(r.text)
    assert "issueUpdates" in data
    assert r.headers["content-type"].startswith("application/json")
    assert "jira.json" in r.headers.get("content-disposition", "")
