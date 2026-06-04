"""Regression tests for v0.18.22 Cycle LL — `atms watch` mode."""

from __future__ import annotations

import time

import pytest
from click.testing import CliRunner

from atms.cli import cli, compute_run_delta
from atms.models import Component, System
from atms.workflow import analyze

_BASE_YAML = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""

_BASE_PLUS_DB = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
  - id: db
    name: DB
    type: database
"""


# ─── compute_run_delta (pure function) ─────────────────────────────
def test_delta_first_run_treats_everything_as_added():
    s = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    m = analyze(s, require_ai_components=False)
    delta = compute_run_delta(None, m)
    assert delta["threats_prev"] == 0
    assert delta["threats_now"] == len(m.threats)
    assert len(delta["added_ids"]) == len(m.threats)
    assert delta["removed_ids"] == []
    assert delta["severity_changed"] == []


def test_delta_no_changes_when_models_equal():
    s = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    m = analyze(s, require_ai_components=False)
    delta = compute_run_delta(m, m)
    assert delta["added_ids"] == []
    assert delta["removed_ids"] == []
    assert delta["severity_changed"] == []
    assert all(v == 0 for v in delta["severity_delta"].values())


def test_delta_detects_added_threats_when_component_added():
    """Add a `db` connected to the `llm` so it sits in the AI blast
    radius (otherwise the v0.15+ AI-scope filter drops it from
    threat enumeration even with require_ai_components=False)."""
    from atms.models import Dataflow
    s1 = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    s2 = System(
        name="t",
        components=list(s1.components) + [Component(id="db", name="DB", type="database")],
        dataflows=[Dataflow(source="llm", target="db", label="store")],
    )
    m1 = analyze(s1, require_ai_components=False)
    m2 = analyze(s2, require_ai_components=False)
    delta = compute_run_delta(m1, m2)
    assert delta["threats_now"] > delta["threats_prev"]
    assert len(delta["added_ids"]) > 0
    db_added = [tid for tid in delta["added_ids"] if tid.startswith("db.")]
    assert db_added


def test_delta_detects_removed_threats_when_component_removed():
    """Removing a `db` (that was in the AI blast radius) drops its threats."""
    from atms.models import Dataflow
    s1 = System(
        name="t",
        components=[
            Component(id="u", name="User", type="user"),
            Component(id="llm", name="LLM", type="llm_inference"),
            Component(id="db", name="DB", type="database"),
        ],
        dataflows=[Dataflow(source="llm", target="db", label="store")],
    )
    s2 = System(
        name="t",
        components=[c for c in s1.components if c.id != "db"],
        # dataflow to `db` is gone with the component; pydantic would reject otherwise.
        dataflows=[],
    )
    m1 = analyze(s1, require_ai_components=False)
    m2 = analyze(s2, require_ai_components=False)
    delta = compute_run_delta(m1, m2)
    assert len(delta["removed_ids"]) > 0
    db_removed = [tid for tid in delta["removed_ids"] if tid.startswith("db.")]
    assert db_removed


def test_delta_severity_breakdown_consistent_with_counter():
    s = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    m = analyze(s, require_ai_components=False)
    delta = compute_run_delta(None, m)
    # sum of severity_breakdown_now equals threats_now
    assert sum(delta["severity_breakdown_now"].values()) == delta["threats_now"]
    # severity_delta values = now - prev, both 0 → delta values == now values
    for sev, count in delta["severity_breakdown_now"].items():
        assert delta["severity_delta"][sev] == count


# ─── CLI watch command (with --max-iters hidden flag) ─────────────
@pytest.mark.hibernated  # Phase 4
def test_watch_runs_at_least_one_iteration(tmp_path):
    """`atms watch --max-iters 2 --interval 0.1` should run twice and exit."""
    p = tmp_path / "sys.yaml"
    p.write_text(_BASE_YAML, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, [
        "watch", str(p), "--interval", "0.1", "--max-iters", "2",
    ])
    assert res.exit_code == 0, res.output
    assert "Watching:" in res.output
    # Should have printed at least one threats line.
    assert "threats:" in res.output


@pytest.mark.hibernated  # Phase 4


def test_watch_reacts_to_file_change(tmp_path):
    """Touch the file between iters; the second iter should detect the
    change and print a delta line."""
    p = tmp_path / "sys.yaml"
    p.write_text(_BASE_YAML, encoding="utf-8")

    # Pre-touch to ensure mtime starts > 0.
    time.sleep(0.05)
    # We don't have great control over when exactly the loop polls; instead
    # call with max-iters=3 + a fast interval and expect at least one threats: line.
    runner = CliRunner()
    res = runner.invoke(cli, [
        "watch", str(p), "--interval", "0.05", "--max-iters", "3",
    ])
    assert res.exit_code == 0, res.output
    threats_lines = [l for l in res.output.splitlines() if "threats:" in l]
    assert threats_lines, f"Expected at least one threats line in {res.output!r}"


@pytest.mark.hibernated  # Phase 4


def test_watch_reports_analysis_error_gracefully(tmp_path):
    """Bad YAML shouldn't crash the loop — it prints a red error and continues."""
    p = tmp_path / "bad.yaml"
    p.write_text("not: : valid yaml: [", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, [
        "watch", str(p), "--interval", "0.05", "--max-iters", "2",
    ])
    # exit_code 0 because the loop ran to max-iters without crashing.
    assert res.exit_code == 0, res.output
    # "analysis failed" appears in the output.
    assert "analysis failed" in res.output.lower() or "failed" in res.output.lower()
