"""Regression tests for v0.18.10 Cycle Z — executive summary report.

Pins the contract that `render_exec_summary` produces a self-contained
HTML one-pager suitable for leadership consumption, and that the
analyze/scan CLI exposes `--format exec` to write it.
"""

from __future__ import annotations

import pytest
import yaml
from click.testing import CliRunner

from atms.cli import cli
from atms.models import Component, System
from atms.reporting.exec_summary import render_exec_summary
from atms.workflow import analyze


def _build_model():
    sys_obj = System(name="ACME-Bedrock-RAG", components=[
        Component(id="u", name="Customer", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(id="rag", name="RAG", type="rag_vector_store"),
    ])
    return analyze(sys_obj)


# ─── Render contract ────────────────────────────────────────────────
def test_exec_summary_is_self_contained_html():
    """Output is a complete HTML document — no external CSS/JS."""
    html = render_exec_summary(_build_model())
    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    # No external references.
    assert "https://" not in html
    assert 'src="' not in html and 'href="' not in html


def test_exec_summary_includes_system_name():
    html = render_exec_summary(_build_model())
    assert "ACME-Bedrock-RAG" in html


def test_exec_summary_renders_top_5_threats():
    """The 'Top 5 threats by risk' table should have 5 rows max."""
    html = render_exec_summary(_build_model())
    assert "Top 5 threats" in html
    # Severity pills are present.
    assert "severity sev-" in html


def test_exec_summary_renders_top_5_mitigations():
    html = render_exec_summary(_build_model())
    assert "Top 5 mitigation priorities" in html


def test_exec_summary_includes_headline_metrics():
    html = render_exec_summary(_build_model())
    assert "Headline metrics" in html
    for label in ("Components", "Threats", "Critical", "High"):
        assert label in html


def test_exec_summary_includes_narrative():
    """One-paragraph executive narrative based on stats."""
    html = render_exec_summary(_build_model())
    # Posture banner has one of three labels.
    posture_present = any(
        f"Posture: {p}" in html for p in ("ELEVATED", "ATTENTION", "HEALTHY")
    )
    assert posture_present, f"Missing posture banner in: {html[:1000]}"


def test_exec_summary_escapes_user_input():
    """A system name with HTML chars must be escaped (no injection)."""
    sys_obj = System(name="<script>evil</script>", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="L", type="llm_inference"),
    ])
    tm = analyze(sys_obj)
    html = render_exec_summary(tm)
    assert "<script>evil" not in html
    assert "&lt;script&gt;" in html


def test_exec_summary_works_on_pure_it_system():
    """The summary must render on a pure-IT (zero-AI) system too."""
    sys_obj = System(name="pure-it", components=[
        Component(id="u", name="User", type="user"),
        Component(id="db", name="DB", type="database"),
    ])
    tm = analyze(sys_obj, require_ai_components=False)
    html = render_exec_summary(tm)
    assert html.startswith("<!doctype html>")


# ─── CLI integration ────────────────────────────────────────────────
def test_cli_analyze_format_exec_writes_exec_html(tmp_path):
    """Output filename uses the input YAML's stem (`sys` here)."""
    p = tmp_path / "sys.yaml"
    yaml.safe_dump({
        "name": "x",
        "components": [
            {"id": "u", "name": "U", "type": "user"},
            {"id": "llm", "name": "L", "type": "llm_inference"},
        ],
    }, p.open("w", encoding="utf-8"))
    out = tmp_path / "out"
    res = CliRunner().invoke(cli, [
        "analyze", str(p), "--out", str(out), "--format", "exec",
    ])
    assert res.exit_code == 0, res.output
    summary_file = out / "sys.exec.html"
    assert summary_file.exists()
    assert summary_file.read_text(encoding="utf-8").startswith("<!doctype html>")


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_cli_scan_format_exec_works(tmp_path):
    p = tmp_path / "stack.yaml"
    yaml.safe_dump({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Lam": {"Type": "AWS::Lambda::Function", "Properties": {}},
        },
    }, p.open("w", encoding="utf-8"))
    out = tmp_path / "out"
    res = CliRunner().invoke(cli, [
        "scan", str(p), "--out", str(out), "--format", "exec",
    ])
    assert res.exit_code == 0, res.output
    summary = out / "stack.exec.html"
    assert summary.exists()


def test_cli_analyze_format_all_includes_exec(tmp_path):
    """--format all should produce an exec.html alongside other outputs."""
    p = tmp_path / "sys.yaml"
    yaml.safe_dump({
        "name": "x",
        "components": [
            {"id": "u", "name": "U", "type": "user"},
            {"id": "llm", "name": "L", "type": "llm_inference"},
        ],
    }, p.open("w", encoding="utf-8"))
    out = tmp_path / "out"
    res = CliRunner().invoke(cli, [
        "analyze", str(p), "--out", str(out), "--format", "all",
    ])
    assert res.exit_code == 0, res.output
    # Stem is "sys" (from sys.yaml), not "x" (system.name).
    assert (out / "sys.exec.html").exists()
    assert (out / "sys.md").exists()
    assert (out / "sys.html").exists()
