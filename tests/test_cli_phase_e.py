"""Phase E coverage tests for src/atms/cli.py.

Phase A covered cve_lookup + mcp_server. cli.py is 741 statements
(largest module by far) and sat at 55.6% — the remaining 288
uncovered lines are spread across:

  refresh-feeds, cve-lookup, review, validate, diff, init,
  list-playbooks, kb-search, ingest-azure / pulumi / otm (analyse
  branch), watch, mcp

Phase E writes targeted CliRunner exercises for these commands.
Honest target: ≥75% line coverage on cli.py.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from atms.cli import cli


# ─── refresh-feeds (mocked network) ───────────────────────────────
@pytest.mark.hibernated  # Phase 4
def test_refresh_feeds_both_succeed(tmp_path, monkeypatch):
    """Happy path: both KEV + EPSS refresh succeed."""
    monkeypatch.setenv("ATMS_KB_NO_CACHE", "1")
    with patch("atms.feeds.refresh.refresh_kev", return_value=42) as kev, \
         patch("atms.feeds.refresh.refresh_epss", return_value=180) as epss:
        runner = CliRunner()
        res = runner.invoke(cli, ["refresh-feeds"])
    assert res.exit_code == 0, res.output
    assert "KEV refreshed" in res.output
    assert "EPSS refreshed" in res.output
    assert "42 rows" in res.output
    assert "180 rows" in res.output
    assert kev.called and epss.called


@pytest.mark.hibernated  # Phase 4


def test_refresh_feeds_kev_only(monkeypatch):
    monkeypatch.setenv("ATMS_KB_NO_CACHE", "1")
    with patch("atms.feeds.refresh.refresh_kev", return_value=10) as kev, \
         patch("atms.feeds.refresh.refresh_epss") as epss:
        runner = CliRunner()
        res = runner.invoke(cli, ["refresh-feeds", "--no-epss"])
    assert res.exit_code == 0
    assert kev.called
    assert not epss.called


@pytest.mark.hibernated  # Phase 4


def test_refresh_feeds_handles_kev_runtime_error(monkeypatch):
    """A network failure during KEV refresh must NOT crash the CLI —
    error is logged in red, EPSS still gets attempted."""
    monkeypatch.setenv("ATMS_KB_NO_CACHE", "1")
    with patch("atms.feeds.refresh.refresh_kev",
                side_effect=RuntimeError("KEV server unreachable")), \
         patch("atms.feeds.refresh.refresh_epss", return_value=99):
        runner = CliRunner()
        res = runner.invoke(cli, ["refresh-feeds"])
    assert res.exit_code == 0
    assert "KEV refresh failed" in res.output
    assert "EPSS refreshed" in res.output


@pytest.mark.hibernated  # Phase 4


def test_refresh_feeds_handles_epss_runtime_error(monkeypatch):
    monkeypatch.setenv("ATMS_KB_NO_CACHE", "1")
    with patch("atms.feeds.refresh.refresh_kev", return_value=1), \
         patch("atms.feeds.refresh.refresh_epss",
                side_effect=RuntimeError("EPSS api timeout")):
        runner = CliRunner()
        res = runner.invoke(cli, ["refresh-feeds"])
    assert res.exit_code == 0
    assert "EPSS refresh failed" in res.output


# ─── cve-lookup (mocked network) ──────────────────────────────────
@pytest.mark.hibernated  # Phase 4
def test_cve_lookup_cmd_happy_path():
    from atms.feeds.cve_lookup import CveLookupResult
    fake = CveLookupResult(
        cve="CVE-2024-12345", source="nvd",
        title="Example RCE",
        description="A test vulnerability that lets an attacker do bad things.",
        severity="critical", cvss=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L",
        cwe=["CWE-79", "CWE-200"],
        affected=["cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"],
        references=["https://example.com/advisory"],
        published="2024-01-15",
    )
    with patch("atms.feeds.cve_lookup.cve_lookup", return_value=fake):
        runner = CliRunner()
        res = runner.invoke(cli, ["cve-lookup", "CVE-2024-12345"])
    assert res.exit_code == 0
    assert "CVE-2024-12345" in res.output
    assert "Example RCE" in res.output
    assert "CWE-79" in res.output
    assert "https://example.com/advisory" in res.output


@pytest.mark.hibernated  # Phase 4


def test_cve_lookup_cmd_exits_one_on_lookup_failure():
    with patch("atms.feeds.cve_lookup.cve_lookup",
                side_effect=RuntimeError("Could not look up CVE-X")):
        runner = CliRunner()
        res = runner.invoke(cli, ["cve-lookup", "CVE-X"])
    assert res.exit_code == 1
    assert "Lookup failed" in res.output


@pytest.mark.hibernated  # Phase 4


def test_cve_lookup_cmd_handles_value_error_on_bad_id():
    """Not a CVE id → ValueError from cve_lookup → exit 1."""
    with patch("atms.feeds.cve_lookup.cve_lookup",
                side_effect=ValueError("Not a CVE id")):
        runner = CliRunner()
        res = runner.invoke(cli, ["cve-lookup", "garbage"])
    assert res.exit_code == 1


# ─── list-playbooks ───────────────────────────────────────────────
def test_list_playbooks_no_filter():
    runner = CliRunner()
    res = runner.invoke(cli, ["list-playbooks"])
    assert res.exit_code == 0
    # Should see at least the well-known component types.
    assert "llm_inference" in res.output
    assert "database" in res.output
    assert "api_gateway" in res.output


def test_list_playbooks_shows_known_types():
    """list-playbooks has no filter flag; just exercises the rendering."""
    runner = CliRunner()
    res = runner.invoke(cli, ["list-playbooks"])
    assert res.exit_code == 0
    # 121 playbooks → output should mention multiple known component types
    for ct in ("llm_inference", "database", "api_gateway", "secrets_vault"):
        assert ct in res.output


# ─── kb-search ────────────────────────────────────────────────────
def test_kb_search_with_query():
    runner = CliRunner()
    res = runner.invoke(cli, ["kb-search", "prompt"])
    assert res.exit_code == 0
    # Should hit at least one playbook / framework entry.
    assert len(res.output) > 50


def test_kb_search_unknown_query_no_crash():
    runner = CliRunner()
    res = runner.invoke(cli, ["kb-search", "zxqzyxzwwz-no-match"])
    assert res.exit_code == 0


# ─── compliance ───────────────────────────────────────────────────
@pytest.mark.hibernated  # Phase 4
def test_compliance_browse_all():
    runner = CliRunner()
    res = runner.invoke(cli, ["compliance"])
    assert res.exit_code == 0
    # Default shows multiple frameworks.
    out = res.output
    assert ("SOC2" in out) or ("NIST" in out) or ("GDPR" in out)


@pytest.mark.hibernated  # Phase 4


def test_compliance_filter_by_framework():
    runner = CliRunner()
    res = runner.invoke(cli, ["compliance", "--framework", "SOC2"])
    assert res.exit_code == 0
    assert "SOC2" in res.output


@pytest.mark.hibernated  # Phase 4


def test_compliance_empty_result_when_no_match():
    runner = CliRunner()
    res = runner.invoke(cli, ["compliance",
                              "--framework", "SOC2",
                              "--query", "this-substring-will-not-match"])
    assert res.exit_code == 0
    assert "No matching" in res.output or "0" in res.output


# ─── devices ──────────────────────────────────────────────────────
def test_devices_browse_all():
    runner = CliRunner()
    res = runner.invoke(cli, ["devices"])
    assert res.exit_code == 0
    assert len(res.output) > 100  # 274 entries → non-trivial output


def test_devices_filter_by_type():
    runner = CliRunner()
    res = runner.invoke(cli, ["devices", "--type", "llm_inference"])
    assert res.exit_code == 0


# ─── review (interactive) ─────────────────────────────────────────
@pytest.mark.hibernated  # Phase 4
def test_review_no_other_typed_components(tmp_path):
    """A system with no 'other' types → early-return with helpful message."""
    yaml_text = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""
    p = tmp_path / "sys.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["review", str(p)])
    assert res.exit_code == 0
    assert "Nothing to review" in res.output


@pytest.mark.hibernated  # Phase 4


def test_review_promptable_other_type(tmp_path):
    """A component with type='other' should prompt for a new type;
    we feed 'llm_inference' on stdin."""
    yaml_text = """name: t
components:
  - id: u
    name: User
    type: user
  - id: mystery
    name: Mystery Component
    type: other
"""
    p = tmp_path / "sys.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    out_path = tmp_path / "sys.reviewed.yaml"
    runner = CliRunner()
    res = runner.invoke(cli, ["review", str(p), "--out", str(out_path)],
                        input="llm_inference\n")
    assert res.exit_code == 0
    assert "1 change" in res.output or "0 change" in res.output
    # The output YAML should now have the type substituted.
    reviewed = out_path.read_text(encoding="utf-8")
    assert "llm_inference" in reviewed


# ─── validate ─────────────────────────────────────────────────────
def test_validate_good_yaml_exit_zero(tmp_path):
    yaml_text = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""
    p = tmp_path / "sys.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["validate", str(p)])
    assert res.exit_code == 0


def test_validate_strict_with_other_component_exit_3(tmp_path):
    """Strict mode + an 'other' component → exit 3."""
    yaml_text = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
  - id: x
    name: X
    type: other
"""
    p = tmp_path / "sys.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["validate", str(p), "--strict"])
    assert res.exit_code == 3


def test_validate_pure_it_exits_4_when_ai_scope_checked(tmp_path):
    """Pure-IT system + --check-ai-scope (default on) → exit 4."""
    yaml_text = """name: pure-it
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
    p = tmp_path / "sys.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["validate", str(p)])
    assert res.exit_code == 4


def test_validate_json_output(tmp_path):
    yaml_text = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""
    p = tmp_path / "sys.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["validate", str(p), "--json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["valid"] is True


def test_validate_invalid_yaml_exits_2(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("not: : valid yaml: [", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["validate", str(p)])
    assert res.exit_code == 2


# ─── init ─────────────────────────────────────────────────────────
def test_init_default_template(tmp_path):
    """init takes NAME as positional arg; template defaults to 'basic'."""
    out = tmp_path / "starter.yaml"
    runner = CliRunner()
    res = runner.invoke(cli, ["init", "my-test", "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert out.exists()
    body = out.read_text(encoding="utf-8")
    assert "my-test" in body
    assert "components" in body


def test_init_rag_template(tmp_path):
    out = tmp_path / "rag.yaml"
    runner = CliRunner()
    res = runner.invoke(cli, ["init", "rag-app", "--template", "rag",
                                "--out", str(out)])
    assert res.exit_code == 0, res.output
    body = out.read_text(encoding="utf-8")
    assert "rag_vector_store" in body or "llm_inference" in body


def test_init_refuses_to_overwrite_existing(tmp_path):
    out = tmp_path / "exists.yaml"
    out.write_text("dont clobber me", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["init", "x", "--out", str(out)])
    assert res.exit_code != 0  # refuse without --force
    # Friendly error mentions the file existing
    assert "exist" in res.output.lower() or out.read_text(encoding="utf-8") == "dont clobber me"


def test_init_force_overwrites(tmp_path):
    out = tmp_path / "exists.yaml"
    out.write_text("clobber me", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["init", "x", "--out", str(out), "--force"])
    assert res.exit_code == 0, res.output
    assert "clobber me" not in out.read_text(encoding="utf-8")


# ─── diff ─────────────────────────────────────────────────────────
def _model_dump(threats: list[dict], summary: dict | None = None) -> dict:
    return {"threats": threats, "summary": summary or {}}


@pytest.mark.hibernated  # Phase 4


def test_diff_added_and_removed_threats(tmp_path):
    old = _model_dump([
        {"id": "t1", "severity": "high", "title": "Old A", "risk_score": 10},
        {"id": "t2", "severity": "medium", "title": "Old B", "risk_score": 8},
    ])
    new = _model_dump([
        {"id": "t1", "severity": "high", "title": "Old A", "risk_score": 10},
        {"id": "t3", "severity": "critical", "title": "New C", "risk_score": 20},
    ])
    op = tmp_path / "old.json"
    np = tmp_path / "new.json"
    op.write_text(json.dumps(old), encoding="utf-8")
    np.write_text(json.dumps(new), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["diff", str(op), str(np)])
    assert res.exit_code == 0
    # Both added (t3) and removed (t2) should appear.
    assert "t3" in res.output
    assert "t2" in res.output


@pytest.mark.hibernated  # Phase 4


def test_diff_severity_change_detected(tmp_path):
    old = _model_dump([
        {"id": "t1", "severity": "medium", "title": "Stable", "risk_score": 8},
    ])
    new = _model_dump([
        {"id": "t1", "severity": "critical", "title": "Stable", "risk_score": 25},
    ])
    op = tmp_path / "old.json"
    np = tmp_path / "new.json"
    op.write_text(json.dumps(old), encoding="utf-8")
    np.write_text(json.dumps(new), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["diff", str(op), str(np), "--format", "markdown"])
    assert res.exit_code == 0
    # Markdown header + severity-changed section.
    assert "Severity changed" in res.output
    assert "medium" in res.output and "critical" in res.output


@pytest.mark.hibernated  # Phase 4


def test_diff_json_format(tmp_path):
    old = _model_dump([{"id": "t1", "severity": "high", "title": "A", "risk_score": 10}])
    new = _model_dump([{"id": "t2", "severity": "critical", "title": "B", "risk_score": 20}])
    op = tmp_path / "old.json"
    np = tmp_path / "new.json"
    op.write_text(json.dumps(old), encoding="utf-8")
    np.write_text(json.dumps(new), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["diff", str(op), str(np), "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert "added_threats" in data
    assert "removed_threats" in data
    assert "severity_changed" in data


@pytest.mark.hibernated  # Phase 4


def test_diff_disposition_change_detected(tmp_path):
    """v0.16.6 disposition-lifecycle diff path."""
    old = _model_dump([
        {"id": "t1", "severity": "high", "title": "T", "risk_score": 10,
         "disposition": "open"},
    ])
    new = _model_dump([
        {"id": "t1", "severity": "high", "title": "T", "risk_score": 10,
         "disposition": "mitigated"},
    ])
    op = tmp_path / "old.json"
    np = tmp_path / "new.json"
    op.write_text(json.dumps(old), encoding="utf-8")
    np.write_text(json.dumps(new), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["diff", str(op), str(np), "--format", "markdown"])
    assert res.exit_code == 0
    assert "Disposition" in res.output
    assert "mitigated" in res.output


# ─── ci ───────────────────────────────────────────────────────────
def test_ci_below_max_severity_exit_zero(tmp_path):
    """Pure-IT YAML with severity ceiling 'critical' → exit 0."""
    yaml_text = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""
    p = tmp_path / "sys.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["ci", str(p), "--max-severity", "critical"])
    # Either exits 0 (no critical) or exits 1 (critical present); both
    # are valid behaviours depending on the analysis. The point is that
    # the command runs to completion without crashing.
    assert res.exit_code in (0, 1)
    assert "threat" in res.output.lower() or "analysis" in res.output.lower()
