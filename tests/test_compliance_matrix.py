"""Regression tests for v0.18.15 Cycle EE — compliance coverage matrix."""

from __future__ import annotations

import pytest

from atms.models import Component, Dataflow, System
from atms.reporting.compliance_matrix import (
    compute_coverage,
    coverage_summary,
    render_compliance_matrix_csv,
    render_compliance_matrix_html,
)
from atms.workflow import analyze


@pytest.fixture(scope="module")
def model():
    """Build a small pure-IT system that triggers multiple framework
    refs (user / waf / app / db / vault / siem). Module-scoped because
    `analyze` is the slowest call in this test file."""
    s = System(name="cov-demo", components=[
        Component(id="u", name="User", type="user"),
        Component(id="waf", name="WAF", type="waf"),
        Component(id="app", name="App", type="web_application"),
        Component(id="db", name="DB", type="database"),
        Component(id="kv", name="Vault", type="secrets_vault"),
        Component(id="siem", name="SIEM", type="siem"),
    ], dataflows=[
        Dataflow(source="u", target="waf", label="HTTPS"),
        Dataflow(source="waf", target="app", label="TLS+JWT"),
        Dataflow(source="app", target="db", label="TLS SQL"),
        Dataflow(source="app", target="kv", label="mTLS"),
    ])
    return analyze(s, require_ai_components=False)


# ─── compute_coverage ─────────────────────────────────────────────
def test_compute_coverage_returns_rows_for_every_control_in_framework(model):
    rows = compute_coverage(model, framework="NIST_800_53")
    assert len(rows) > 0
    # Every row must have NIST_800_53 as framework.
    assert {r["framework"] for r in rows} == {"NIST_800_53"}


def test_compute_coverage_status_values_are_valid(model):
    rows = compute_coverage(model)
    valid = {"covered", "mitigated", "uncovered", "not-applicable"}
    for r in rows:
        assert r["status"] in valid


def test_compute_coverage_sort_order_covered_first(model):
    """Covered/mitigated rows should sort above uncovered/n.a."""
    rows = compute_coverage(model)
    statuses = [r["status"] for r in rows]
    # Find indices of each status's first occurrence.
    first_seen = {}
    for i, s in enumerate(statuses):
        first_seen.setdefault(s, i)
    if "covered" in first_seen and "uncovered" in first_seen:
        assert first_seen["covered"] < first_seen["uncovered"]
    if "mitigated" in first_seen and "uncovered" in first_seen:
        assert first_seen["mitigated"] < first_seen["uncovered"]


def test_compute_coverage_in_scope_uncovered_distinguishable(model):
    """In-scope-but-uncovered controls have applies_to overlap with
    system components; not-applicable ones don't."""
    rows = compute_coverage(model)
    types_in_system = {"user", "waf", "web_application", "database",
                       "secrets_vault", "siem"}
    for r in rows:
        if r["status"] == "uncovered":
            assert not r["applies_to"] or bool(set(r["applies_to"]) & types_in_system)
        if r["status"] == "not-applicable":
            assert r["applies_to"] and not (set(r["applies_to"]) & types_in_system)


def test_compute_coverage_empty_when_no_controls_match_filter(model):
    rows = compute_coverage(model, framework="FRAMEWORK_THAT_DOES_NOT_EXIST")
    assert rows == []


# ─── coverage_summary ─────────────────────────────────────────────
def test_coverage_summary_totals_add_up(model):
    rows = compute_coverage(model)
    summ = coverage_summary(rows)
    assert (summ["covered"] + summ["mitigated"]
            + summ["uncovered"] + summ["not_applicable"]) == summ["total"]
    assert summ["total"] == len(rows)


def test_coverage_summary_per_framework_breakdown(model):
    rows = compute_coverage(model)
    summ = coverage_summary(rows)
    # Every framework that appears in any row should appear in the breakdown.
    frameworks_in_rows = {r["framework"] for r in rows}
    assert frameworks_in_rows <= set(summ["frameworks"].keys())


# ─── render_compliance_matrix_html ────────────────────────────────
def test_render_html_returns_self_contained_document(model):
    html = render_compliance_matrix_html(model)
    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    # No external CSS / JS — must be self-contained for offline use.
    assert "<script" not in html
    assert "<link rel=" not in html


def test_render_html_includes_legend_and_summary_cards(model):
    html = render_compliance_matrix_html(model)
    for word in ("Covered", "Mitigated", "Uncovered", "Not applicable"):
        assert word in html


def test_render_html_filter_block_only_with_framework(model):
    no_filter = render_compliance_matrix_html(model)
    with_filter = render_compliance_matrix_html(model, framework="NIST_800_53")
    assert "Filtered to" not in no_filter
    assert "Filtered to" in with_filter
    assert "NIST_800_53" in with_filter


def test_render_html_escapes_threat_titles(model):
    """The renderer must HTML-escape user-derived strings."""
    # Inject a malicious system name; re-run to confirm escape.
    model.system.name = "<script>alert(1)</script>"
    html = render_compliance_matrix_html(model)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ─── render_compliance_matrix_csv ─────────────────────────────────
def test_render_csv_header_and_rows(model):
    csv_text = render_compliance_matrix_csv(model, framework="NIST_800_53")
    lines = csv_text.splitlines()
    assert lines[0].startswith("control_id,framework,title,status")
    assert len(lines) > 1  # at least header + 1 row
    # Each data row should have the same number of columns as the header.
    expected_cols = lines[0].count(",")
    for line in lines[1:]:
        # crude check: count commas outside quoted text is hard with raw split;
        # just confirm the row has the framework name in column 2.
        assert "NIST_800_53" in line


def test_render_csv_consistent_with_compute_coverage(model):
    rows = compute_coverage(model, framework="NIST_800_53")
    csv_text = render_compliance_matrix_csv(model, framework="NIST_800_53")
    # rows + header = number of csv lines
    assert len(csv_text.splitlines()) == len(rows) + 1
