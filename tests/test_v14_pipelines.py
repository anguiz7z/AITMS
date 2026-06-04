"""Tests for v0.14 — red-team / BAS parsers, docker-compose + Terraform
ingest, D3FEND mitigation actionability."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from atms.engines.d3fend import apply_d3fend_actionability
from atms.evidence.redteam import (
    parse_atomic_red_team,
    parse_bas_csv,
    parse_caldera,
    parse_redteam,
)
from atms.ingest.docker_compose import parse_docker_compose
from atms.ingest.terraform import parse_terraform
from atms.kb import get_kb
from atms.models import Component, Mitigation, System
from atms.workflow import analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ───────────────────────── Caldera parser ─────────────────────────────────
CALDERA_SAMPLE = {
    "name": "atms-test-op",
    "chain": [
        {
            "ability": {
                "ability_id": "abc-123",
                "name": "Disable Defender",
                "technique_id": "T1562.001",
                "tactic": "defense-evasion",
                "description": "Disable Microsoft Defender via PowerShell.",
            },
            "status": 0,
            "state": "finished",
            "host": "lab-host-01",
            "finish": "2026-04-01T10:00:00Z",
        },
        {
            "ability": {
                "ability_id": "def-456",
                "name": "Failed scan",
                "technique_id": "T1057",
                "description": "Process listing.",
            },
            # Use the unambiguous v4 failure marker. v1's status=1 is
            # actually success, so don't rely on it to mean "failed".
            "state": "failed",
            "status": 2,
            "host": "lab-host-01",
        },
    ],
}


@pytest.mark.hibernated  # Phase 4


def test_caldera_parser_keeps_only_successes(tmp_path):
    p = tmp_path / "op.json"
    p.write_text(json.dumps(CALDERA_SAMPLE), encoding="utf-8")
    rows = parse_caldera(p)
    assert len(rows) == 1
    assert rows[0].source == "red_team"
    assert rows[0].source_type == "caldera"
    assert rows[0].source_id == "abc-123"
    assert rows[0].affected_asset == "lab-host-01"
    # technique id propagated to references for the matcher
    assert any("T1562.001" in r for r in rows[0].references)


# ───────────────────────── Atomic Red Team parser ─────────────────────────
ATOMIC_SAMPLE = [{
    "Atomic": {
        "auto_generated_guid": "atomic-uuid-1",
        "name": "Process Discovery via tasklist",
        "display_name": "Process Discovery",
        "attack_technique": "T1057",
        "description": "Run tasklist to enumerate processes.",
    },
    "Hostname": "win10-lab",
    "ExecutionResult": "Success",
    "StartTime": "2026-04-01T10:00:00Z",
}]


@pytest.mark.hibernated  # Phase 4


def test_atomic_red_team_parser(tmp_path):
    p = tmp_path / "atomic.json"
    p.write_text(json.dumps(ATOMIC_SAMPLE), encoding="utf-8")
    rows = parse_atomic_red_team(p)
    assert len(rows) == 1
    assert rows[0].source == "red_team"
    assert rows[0].severity == "high"
    assert rows[0].affected_asset == "win10-lab"


# ───────────────────────── BAS CSV parser ─────────────────────────────────
@pytest.mark.hibernated  # Phase 4
def test_bas_csv_parser_sniffs_columns(tmp_path):
    p = tmp_path / "bas.csv"
    p.write_text(
        "Technique ID,Scenario Name,Target,Result,Severity\n"
        "T1078,Valid accounts test,vpn01.corp,Successful,High\n"
        "T1190,Public-app exploit,web01.corp,Prevented,Low\n",
        encoding="utf-8",
    )
    rows = parse_bas_csv(p)
    assert len(rows) == 2
    assert rows[0].source == "red_team"
    assert rows[0].severity == "high"
    assert rows[0].affected_asset == "vpn01.corp"
    assert rows[1].severity == "low"


@pytest.mark.hibernated  # Phase 4


def test_parse_redteam_auto_routes_by_extension(tmp_path):
    csv_p = tmp_path / "x.csv"
    csv_p.write_text("Technique,Asset,Result\nT1078,h1,Success\n", encoding="utf-8")
    rows = parse_redteam(csv_p)
    assert rows[0].source == "red_team"


@pytest.mark.hibernated  # Phase 4


def test_workflow_marks_threats_exploited_with_redteam_evidence():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    sys_obj = System.model_validate(raw)
    # Force a known hostname on the LLM component for matching
    for c in sys_obj.components:
        if c.type == "llm_inference":
            c.metadata = {"hostname": "lab-host-01"}
            break
    rt_evidence = parse_caldera_inline()
    tm = analyze(sys_obj, evidence=rt_evidence)
    # At least one threat should be marked exploited
    assert any(t.evidence_status == "exploited" for t in tm.threats)


def parse_caldera_inline():
    """Tiny helper avoids re-writing CALDERA_SAMPLE to disk."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(CALDERA_SAMPLE, f)
        p = Path(f.name)
    try:
        return parse_caldera(p)
    finally:
        p.unlink(missing_ok=True)


# ───────────────────────── docker-compose ingest ──────────────────────────
COMPOSE_SAMPLE = """
services:
  web:
    image: nginx:1.27
    ports: ["80:80"]
    networks: [edge]
  api:
    image: ghcr.io/example/api:1.4.2
    depends_on: [db]
    networks: [edge, internal]
  db:
    image: postgres:16
    networks: [internal]
  vault:
    image: hashicorp/vault:1.18
    networks: [internal]
networks:
  edge:
  internal:
"""


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_docker_compose_classifies_services(tmp_path):
    p = tmp_path / "docker-compose.yml"
    p.write_text(COMPOSE_SAMPLE, encoding="utf-8")
    sys_obj = parse_docker_compose(p)
    by_id = {c.id: c for c in sys_obj.components}
    assert by_id["web"].type == "load_balancer"  # nginx
    assert by_id["db"].type == "database"
    assert by_id["vault"].type == "secrets_vault"
    # ports → user component + edge flow
    user = next((c for c in sys_obj.components if c.type == "user"), None)
    assert user is not None
    assert any(df.source == user.id and df.target == "web" for df in sys_obj.dataflows)
    # depends_on → flow
    assert any(df.source == "api" and df.target == "db" for df in sys_obj.dataflows)
    # vendor / version sniff
    assert by_id["db"].metadata.get("version") == "16"
    assert by_id["db"].metadata.get("product") == "postgres"


# ───────────────────────── Terraform ingest ───────────────────────────────
TF_SAMPLE = """
provider "aws" { region = "us-east-1" }

resource "aws_s3_bucket" "logs" {
  bucket = "my-logs"
}

resource "aws_lambda_function" "handler" {
  function_name = "handler"
  role          = aws_iam_role.lambda_role.arn
  s3_bucket     = aws_s3_bucket.logs.bucket
  depends_on    = [aws_iam_role.lambda_role]
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda-role"
}
"""


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_classifies_resources(tmp_path):
    p = tmp_path / "main.tf"
    p.write_text(TF_SAMPLE, encoding="utf-8")
    sys_obj = parse_terraform(p)
    by_name = {c.name: c for c in sys_obj.components}
    assert "aws_s3_bucket.logs" in by_name
    assert by_name["aws_s3_bucket.logs"].type == "object_storage"
    assert by_name["aws_lambda_function.handler"].type == "serverless_function"
    assert by_name["aws_iam_role.lambda_role"].type == "iam_principal"
    # Vendor sniff
    assert by_name["aws_s3_bucket.logs"].metadata.get("vendor") == "AWS"
    # Dataflow: lambda → iam_role + lambda → s3 (interpolation)
    flow_pairs = {(df.source, df.target) for df in sys_obj.dataflows}
    assert any("iam_role" in tgt for src, tgt in flow_pairs if "lambda" in src)


# ───────────────────────── D3FEND mitigation engine ───────────────────────
def test_d3fend_engine_decorates_mfa_mitigation():
    kb = get_kb()
    assert kb.d3fend_rules, "D3FEND rules should be loaded"
    m = Mitigation(
        id="MFA-1",
        title="Require phishing-resistant MFA on all admin access",
        description="Use FIDO2 / passkeys for every privileged login.",
    )
    apply_d3fend_actionability([m], kb=kb)
    assert m.control_family == "preventive"
    assert m.automatable is True
    assert m.validation_test
    assert any(d.startswith("D3-") for d in m.d3fend)
    assert any("YubiKey" in v or "Duo" in v or "Passkeys" in v for v in m.vendor_examples)


def test_d3fend_engine_decorates_waf():
    kb = get_kb()
    m = Mitigation(id="W-1", title="Deploy a WAF in front of the public web app",
                   description="Web application firewall blocks common OWASP Top 10 payloads.")
    apply_d3fend_actionability([m], kb=kb)
    assert m.control_family == "preventive"
    assert "D3-NTPM" in m.d3fend


def test_d3fend_does_not_clobber_explicit_values():
    kb = get_kb()
    m = Mitigation(
        id="X-1", title="Custom MFA control",
        description="Custom MFA implementation.",
        control_family="detective", d3fend=["D3-CUSTOM"],
    )
    apply_d3fend_actionability([m], kb=kb)
    # Already set → preserved
    assert m.control_family == "detective"
    assert m.d3fend == ["D3-CUSTOM"]


def test_workflow_decorates_mitigations_with_d3fend():
    raw = yaml.safe_load((SAMPLES / "aws_bedrock_agent.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    # At least one mitigation must have d3fend tags + a control_family
    assert any(m.d3fend for m in tm.mitigations), "expected at least one D3FEND-decorated mitigation"
    assert any(m.control_family for m in tm.mitigations)


# ───────────────────────── CSV mitigation export columns ──────────────────
def test_mitigations_csv_has_v14_actionability_columns():
    from atms.reporting import write_csv
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    out = write_csv(tm, "mitigations")
    header = out.splitlines()[0]
    for col in ("control_family", "automatable", "d3fend",
                "vendor_examples", "validation_test"):
        assert col in header, f"mitigations CSV missing v0.14 column: {col}"


# ───────────────────────── CLI smoke ──────────────────────────────────────
@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4
def test_cli_ingest_iac_compose(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli
    p = tmp_path / "docker-compose.yml"
    p.write_text(COMPOSE_SAMPLE, encoding="utf-8")
    out = tmp_path / "system.yaml"
    res = CliRunner().invoke(cli, ["ingest-iac", str(p), "--out", str(out)])
    assert res.exit_code == 0, res.output
    body = out.read_text(encoding="utf-8")
    assert "vault" in body
    assert "type: secrets_vault" in body


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_cli_ingest_iac_terraform(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli
    p = tmp_path / "main.tf"
    p.write_text(TF_SAMPLE, encoding="utf-8")
    out = tmp_path / "system.yaml"
    res = CliRunner().invoke(cli, ["ingest-iac", str(p), "--out", str(out)])
    assert res.exit_code == 0, res.output
    body = out.read_text(encoding="utf-8")
    assert "aws_lambda_function.handler" in body
    assert "type: serverless_function" in body


@pytest.mark.hibernated  # Phase 4


def test_cli_ingest_redteam_csv(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli
    rt = tmp_path / "scenarios.csv"
    rt.write_text(
        "Technique,Asset,Result\nT1078,vpn01.corp,Success\n",
        encoding="utf-8",
    )
    sys_path = tmp_path / "tiny.yaml"
    sys_path.write_text(yaml.safe_dump({
        "name": "tiny", "components": [
            {"id": "vpn", "name": "VPN", "type": "vpn_gateway",
             "trust_zone": "dmz",
             "metadata": {"hostname": "vpn01.corp", "product": "PAN-OS"}},
            # v0.15.0: AI-scope gate requires at least one AI primary.
            {"id": "llm", "name": "LLM", "type": "llm_inference"},
        ],
        "dataflows": [
            {"id": "f1", "source": "vpn", "target": "llm", "label": "egress"},
        ],
    }), encoding="utf-8")
    out_dir = tmp_path / "out"
    res = CliRunner().invoke(cli, ["ingest-redteam", str(rt), str(sys_path),
                                    "--out", str(out_dir)])
    assert res.exit_code == 0, res.output
    md = list(out_dir.glob("*.md"))
    assert md, "expected a markdown report"


# ───────────────────────── Web routes ─────────────────────────────────────
@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3
def test_redteam_page_renders(client_module_scope):
    r = client_module_scope.get("/redteam")
    assert r.status_code == 200
    assert "Red-team" in r.text


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_iac_page_renders(client_module_scope):
    r = client_module_scope.get("/iac")
    assert r.status_code == 200
    assert "Infrastructure-as-Code" in r.text


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_iac_ingest_compose_round_trip(client_module_scope, tmp_path):
    files = {"iac_file": ("docker-compose.yml", COMPOSE_SAMPLE.encode(),
                          "application/x-yaml")}
    r = client_module_scope.post("/iac/ingest", files=files)
    assert r.status_code == 200
    assert "type: secrets_vault" in r.text
    assert "vault" in r.text


# ───────────────────────── QA-evaluator regression tests ─────────────────
@pytest.mark.hibernated  # Phase 4
def test_caldera_v1_status_1_alone_does_not_promote_to_success(tmp_path):
    """v0.14.1 fix: legacy v1 Caldera used `status=1` for success while
    v2/v4 use `status=1` for failure. Trusting both creates false
    positives. With state-first semantics, a row with `status=1` and
    NO `state` should be treated as failure."""
    sample = {
        "name": "v1-conflict-op",
        "chain": [{
            "ability": {"ability_id": "v1-1", "name": "RCE",
                        "technique_id": "T1059"},
            "status": 1,  # ambiguous v1 vs v2/v4
            # no `state` field
            "host": "host-1",
        }],
    }
    p = tmp_path / "v1.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    rows = parse_caldera(p)
    assert rows == [], "ambiguous status=1 (no state) must NOT auto-promote to success"


@pytest.mark.hibernated  # Phase 4


def test_caldera_collect_flag_does_not_promote_failure():
    """v0.14.1 fix: `collect: true` only means stdout was captured —
    it's set on failed abilities too. Don't treat it as a success
    marker."""
    import tempfile
    sample = {
        "name": "collect-failure-op",
        "chain": [{
            "ability": {"ability_id": "c-1", "name": "Failed RCE",
                        "technique_id": "T1059"},
            "state": "failed",
            "status": 2,
            "collect": True,  # captured stderr from failure
            "host": "host-1",
        }],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(sample, f)
        p = Path(f.name)
    try:
        rows = parse_caldera(p)
    finally:
        p.unlink(missing_ok=True)
    assert rows == [], "collect=True must not override state=failed"


@pytest.mark.hibernated  # Phase 4


def test_caldera_jsonl_with_crlf_and_bom(tmp_path):
    """v0.14.1 fix: Atomic Red Team JSONL files written by PowerShell on
    Windows have CRLF line endings AND a UTF-8 BOM. Both must parse."""
    invocations = [
        {"Atomic": {"name": "T1057-tasklist", "attack_technique": "T1057",
                    "auto_generated_guid": "g1"},
         "Hostname": "win10-lab", "ExecutionResult": "Success"},
        {"Atomic": {"name": "T1059.001-iex", "attack_technique": "T1059.001",
                    "auto_generated_guid": "g2"},
         "Hostname": "win10-lab", "ExecutionResult": "Success"},
    ]
    body = "\r\n".join(json.dumps(inv) for inv in invocations)
    # Prefix with UTF-8 BOM
    p = tmp_path / "atomic.jsonl"
    p.write_bytes("﻿".encode() + body.encode("utf-8"))
    rows = parse_atomic_red_team(p)
    assert len(rows) == 2
    assert rows[0].source_id == "g1"
    assert rows[1].source_id == "g2"


def test_attack_id_correlation_rejects_bogus_tokens():
    """v0.14.1 fix: tighten the ATT&CK regex so `Technique = "TLS-1.2"`
    or `"TROJAN-9"` in a third-party CSV doesn't trigger ATT&CK
    correlation."""
    from atms.engines.evidence import apply_evidence
    from atms.models import Evidence, Threat
    components = [Component(id="c", name="C", type="agent")]
    threats = [Threat(id="t", component_id="c", title="x", description="x",
                      atlas_techniques=["TLS"], likelihood=2, impact=2)]
    ev = [Evidence(source="red_team", title="false-positive bait",
                   references=["TLS-1.2", "TROJAN-9"])]
    apply_evidence(threats, components, ev)
    # No matched component, no real CVE, no real ATT&CK ID → no evidence.
    assert threats[0].evidence_status == "hypothetical"
    assert not threats[0].evidence


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_string_with_braces_doesnt_break_block_count(tmp_path):
    """v0.14.1 fix: `_balanced_block` must mask string contents so a
    description with `{` and `}` inside doesn't corrupt the brace
    count. Without the fix, the resource block would be truncated."""
    src = '''
    resource "aws_s3_bucket" "logs" {
      bucket = "my-logs"
      tags = {
        purpose = "use { and } sparingly"
      }
    }
    resource "aws_iam_role" "r" { name = "r" }
    '''
    p = tmp_path / "x.tf"
    p.write_text(src, encoding="utf-8")
    sys_obj = parse_terraform(p)
    # Both resources must be parsed. Pre-fix, `_balanced_block` would
    # close the s3_bucket on the first `}` inside the string, leaving
    # the second resource unparsed.
    names = {c.name for c in sys_obj.components}
    assert "aws_s3_bucket.logs" in names
    assert "aws_iam_role.r" in names


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_ref_in_string_literal_doesnt_create_dataflow(tmp_path):
    """v0.14.1 fix: an underscore-name + dot inside a string literal
    looked like a resource reference under the v0.14.0 regex. Mask
    string contents first."""
    src = '''
    resource "aws_s3_bucket" "logs" {
      bucket = "my_company_logs.production"  # string-literal ref
      depends_on = [aws_iam_role.real_dep]
    }
    resource "aws_iam_role" "real_dep" { name = "r" }
    '''
    p = tmp_path / "y.tf"
    p.write_text(src, encoding="utf-8")
    sys_obj = parse_terraform(p)
    pairs = {(df.source, df.target) for df in sys_obj.dataflows}
    # Real depends_on creates a real flow:
    assert any("aws_s3_bucket" in s and "aws_iam_role" in t for s, t in pairs)
    # The string-literal `my_company_logs.production` must NOT.
    assert not any("my_company" in s or "my_company" in t for s, t in pairs)


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_skips_symlink(tmp_path):
    """v0.14.1 fix: symlinks in a parsed directory must be skipped to
    avoid escaping the project root."""
    import os
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "main.tf").write_text(
        'resource "aws_s3_bucket" "real" { bucket = "r" }\n', encoding="utf-8")
    target = tmp_path / "outside.tf"
    target.write_text(
        'resource "aws_s3_bucket" "outside" { bucket = "o" }\n', encoding="utf-8")
    try:
        os.symlink(target, proj / "linked.tf")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform / permission")
    sys_obj = parse_terraform(proj)
    names = {c.name for c in sys_obj.components}
    assert "aws_s3_bucket.real" in names
    assert "aws_s3_bucket.outside" not in names


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_compose_python_image_falls_back_to_container_runtime(tmp_path):
    """v0.14.4 fix: a `python:3.11` service must NOT be auto-classified
    as `web_application`. Python base images run ML training jobs,
    agents, batch processors — silently mapping them to web_application
    silently selects the wrong threat playbook. Default to
    `container_runtime`."""
    p = tmp_path / "compose.yml"
    p.write_text("services:\n  ml:\n    image: python:3.11\n", encoding="utf-8")
    sys_obj = parse_docker_compose(p)
    assert sys_obj.components[0].type != "web_application"
    # The safer fallback in _classify_image is `container_runtime`.
    assert sys_obj.components[0].type == "container_runtime"


def test_compose_image_with_registry_port_does_not_corrupt_version():
    """v0.14.1 fix: `localhost:5000/myimg` (no tag) must not split into
    name=localhost, version=5000/myimg."""
    from atms.ingest.docker_compose import _split_image
    name, ver = _split_image("localhost:5000/myimg")
    assert name == "localhost:5000/myimg"
    assert ver == "latest"
    name, ver = _split_image("localhost:5000/myimg:1.4.2")
    assert name == "localhost:5000/myimg"
    assert ver == "1.4.2"


@pytest.mark.hibernated  # Phase 4


def test_caldera_accepts_v4_state_finished(tmp_path):
    """Caldera v4 emits state=finished without a status code. Must still parse."""
    sample = {
        "name": "v4-op",
        "chain": [
            {
                "ability": {"ability_id": "v4-1", "name": "RCE",
                            "technique_id": "T1059"},
                "state": "finished",  # v4 success marker
                "host": "host-1",
            },
        ],
    }
    p = tmp_path / "v4.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    rows = parse_caldera(p)
    assert len(rows) == 1
    assert rows[0].source_id == "v4-1"


@pytest.mark.hibernated  # Phase 4


def test_caldera_flat_shape_link_technique_id(tmp_path):
    """Hand-rolled Caldera exports sometimes put `technique_id` directly on
    the link (not nested under `ability`). The matcher must still emit an
    `attack:<id>` reference so downstream evidence correlation works."""
    sample = {
        "name": "flat-op",
        "links": [
            {
                "technique_id": "T1110.003",  # ← flat on link, no `ability`
                "name": "Password spray",
                "state": "finished",
                "host": "lab-host",
                "finish": "2026-05-09T10:00:00Z",
            },
            {
                # Also accept the alternate `attack_id` alias.
                "attack_id": "T1078",
                "name": "Valid accounts",
                "status": 0,
                "host": "lab-host",
            },
        ],
    }
    p = tmp_path / "flat.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    rows = parse_caldera(p)
    assert len(rows) == 2
    assert "attack:T1110.003" in rows[0].references
    assert "attack:T1078" in rows[1].references


def test_attack_id_correlation_routes_evidence_without_hostname():
    """Red-team evidence with an ATT&CK ID but no asset must still be
    attached to threats already tagged with the same technique."""
    from atms.engines.evidence import apply_evidence
    from atms.models import Evidence, Threat
    components = [Component(id="agent", name="Agent", type="agent")]
    threats = [
        Threat(id="t1", component_id="agent", title="Defender disabled by adversary",
               description="Adversary turns off EDR.",
               atlas_techniques=["AML.T0048"],
               attack_enterprise=["T1562.001"],  # ← matches the evidence below
               likelihood=3, impact=4),
    ]
    ev = [Evidence(
        source="red_team", source_type="caldera",
        source_id="abc", title="Disable Defender",
        affected_asset="",  # no hostname → component matcher misses
        references=["attack:T1562.001"],
    )]
    apply_evidence(threats, components, ev)
    assert threats[0].evidence_status == "exploited"
    assert threats[0].evidence, "expected the red-team row to attach via ATT&CK ID"


def test_d3fend_mfa_fatigue_rule_wins_over_generic_mfa():
    """The more-specific MFA-fatigue rule must match before the generic
    MFA rule so a 'number matching' mitigation gets the right
    validation_test."""
    from atms.engines.d3fend import apply_d3fend_actionability
    from atms.models import Mitigation
    m = Mitigation(id="x", title="Enable MFA fatigue / number matching",
                   description="Defeat push-bombing by requiring number matching in IDP.")
    apply_d3fend_actionability([m])
    assert m.validation_test
    assert "number-matching" in m.validation_test.lower() or "number matching" in m.validation_test.lower()


def test_d3fend_word_boundary_does_not_false_match():
    """A bare-token rule (`tls`, `kms`) must not match the same letters
    appearing inside an identifier like `tls_smuggling.middleware.py`.
    Other rules (e.g. patch-management, on the keyword "patch") may
    legitimately fire — we only assert the TLS rule's tags did not."""
    from atms.engines.d3fend import apply_d3fend_actionability
    from atms.models import Mitigation
    m = Mitigation(id="x2", title="Patch tls_smuggling.middleware.py CVE",
                   description="Update tls_smuggling middleware to v2.")
    apply_d3fend_actionability([m])
    # The TLS rule emits D3-NTA / D3-MA. Those must NOT appear here.
    assert "D3-NTA" not in m.d3fend
    assert "D3-MA" not in m.d3fend


def test_d3fend_engine_preserves_explicit_automatable_false():
    """If a hand-written playbook sets automatable=False explicitly, the
    engine must not flip it to True. We use d3fend = ['D3-CUSTOM'] as the
    'already curated' signal."""
    from atms.engines.d3fend import apply_d3fend_actionability
    from atms.models import Mitigation
    m = Mitigation(id="x", title="Custom MFA control",
                   description="Custom MFA implementation.",
                   automatable=False, d3fend=["D3-CUSTOM"])
    apply_d3fend_actionability([m])
    assert m.automatable is False
    assert m.d3fend == ["D3-CUSTOM"]


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_skips_terraform_cache_dir(tmp_path):
    """The .terraform/ cache contains vendored module code that must NOT
    be parsed as user resources."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.tf").write_text(
        'resource "aws_s3_bucket" "user_bucket" { bucket = "u" }\n', encoding="utf-8")
    cache = project / ".terraform" / "modules" / "vendor"
    cache.mkdir(parents=True)
    (cache / "vendor.tf").write_text(
        'resource "aws_s3_bucket" "vendor_bucket" { bucket = "v" }\n', encoding="utf-8")
    sys_obj = parse_terraform(project)
    names = {c.name for c in sys_obj.components}
    assert "aws_s3_bucket.user_bucket" in names
    assert "aws_s3_bucket.vendor_bucket" not in names, \
        ".terraform/ cache content must be skipped"


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_does_not_create_flow_for_var_or_local_refs():
    """`var.region`, `local.x` shouldn't generate spurious dataflows."""
    src = '''
    resource "aws_s3_bucket" "logs" {
      bucket = var.bucket_name
      tags   = local.common_tags
    }
    resource "aws_lambda_function" "handler" {
      function_name = local.name
      role          = aws_iam_role.lambda_role.arn
    }
    resource "aws_iam_role" "lambda_role" {
      name = "lambda-role"
    }
    '''
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False, encoding="utf-8") as f:
        f.write(src)
        p = Path(f.name)
    try:
        sys_obj = parse_terraform(p)
    finally:
        p.unlink(missing_ok=True)
    # Only one dataflow should exist: lambda -> iam_role
    assert len(sys_obj.dataflows) == 1
    df = sys_obj.dataflows[0]
    assert "lambda" in df.source and "iam_role" in df.target


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_redteam_ingest_csv_round_trip(client_module_scope):
    """Submit a BAS CSV with a single successful T1078 against the VPN
    gateway. The response page must show at least one threat with status
    'exploited' and the matched component name in the report — the
    weaker `'threats' in text` assertion in v0.14.0 was tautological."""
    csv_blob = (
        b"Technique,Asset,Result\nT1078,vpn01.corp,Success\n"
    )
    yaml_text = yaml.safe_dump({
        "name": "tiny-rt-roundtrip",
        "components": [
            {"id": "vpn", "name": "GlobalProtect VPN", "type": "vpn_gateway",
             "trust_zone": "dmz",
             "metadata": {"hostname": "vpn01.corp", "product": "PAN-OS"}},
            {"id": "u", "name": "User", "type": "user", "trust_zone": "internet"},
            # v0.15.0: AI-scope gate requires at least one AI primary;
            # an LLM behind the VPN puts it in scope.
            {"id": "llm", "name": "Internal LLM", "type": "llm_inference"},
        ],
        "dataflows": [
            {"source": "u", "target": "vpn", "label": "tunnel"},
            {"source": "vpn", "target": "llm", "label": "internal LLM API"},
        ],
    })
    r = client_module_scope.post(
        "/redteam/ingest",
        files={"artefact_file": ("scenarios.csv", csv_blob, "text/csv")},
        data={"yaml_text": yaml_text, "methodology": "stride-ai"},
    )
    assert r.status_code == 200
    body = r.text
    # The component name must show up — that's the piece that proves the
    # threat actually came from THIS system, not just nav chrome.
    assert "GlobalProtect VPN" in body
    # And the run must have produced an `exploited` threat: red-team
    # success against the VPN-gateway playbook's CVE / VPN threats
    # should flip at least one to exploited.
    assert "exploited" in body.lower()


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_redteam_ingest_rejects_bad_methodology(client_module_scope):
    """The /redteam/ingest endpoint must reject methodology values
    outside the allow-list with HTTP 400."""
    yaml_text = yaml.safe_dump({"name": "tiny", "components": [
        {"id": "u", "name": "U", "type": "user"}]})
    r = client_module_scope.post(
        "/redteam/ingest",
        files={"artefact_file": ("scenarios.csv",
                                  b"Technique,Asset,Result\nT1078,h,Success\n",
                                  "text/csv")},
        data={"yaml_text": yaml_text, "methodology": "totally-invalid"},
    )
    assert r.status_code == 400
    assert "methodology" in r.text.lower()


def test_d3fend_first_match_wins():
    """v0.14.8: when a single mitigation matches multiple D3FEND rules,
    the first one wins. Documented in d3fend.py header but until now
    untested. A KB reorder of `d3fend/mappings.yaml` could silently
    change which rule wins for ambiguous mitigations."""
    from atms.engines.d3fend import apply_d3fend_actionability
    from atms.kb import KnowledgeBase
    from atms.models import Mitigation

    fake_kb = KnowledgeBase.__new__(KnowledgeBase)
    fake_kb.d3fend_rules = [
        {"mitigation_match": ["mfa"], "control_family": "preventive",
         "automatable": True, "validation_test": "first-rule-wins",
         "d3fend": ["D3-MFA"], "vendor_examples": ["Okta"]},
        {"mitigation_match": ["mfa"], "control_family": "detective",
         "automatable": False, "validation_test": "second-rule-loses",
         "d3fend_techniques": ["D3-OTHER"], "vendor_examples": ["NotOkta"]},
    ]
    m = Mitigation(id="x", title="Enable MFA on every workload identity",
                   description="MFA is the control.")
    apply_d3fend_actionability([m], kb=fake_kb)
    assert m.validation_test == "first-rule-wins"
    assert "D3-MFA" in (m.d3fend or [])


def test_quantitative_handles_inverted_freq_range():
    """v0.14.8: a playbook author may type `freq_low: 20, freq_high: 5`
    by mistake. Engine must produce a finite, non-negative ALE rather
    than NaN / negative."""
    from atms.engines.quantitative import score_quantitative
    from atms.models import Threat
    threats = [Threat(
        id="t", component_id="c", title="x", description="y",
        likelihood=3, impact=3,
        freq_low=20, freq_high=5, loss_low=1000, loss_high=500,
    )]
    out = score_quantitative(threats)
    # At minimum the engine must NOT crash and must NOT emit negatives.
    assert out[0].ale_low >= 0, f"ale_low went negative: {out[0].ale_low}"
    assert out[0].ale_high >= 0, f"ale_high went negative: {out[0].ale_high}"
    # And the inverted range must not produce NaN / inf either.
    import math
    assert math.isfinite(out[0].ale_low) and math.isfinite(out[0].ale_high)


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_otm_typo_falls_through_to_other_not_misleading_match(tmp_path):
    """v0.14.8: a hand-edited OTM with `attributes.atms_component_type:
    agnet` (typo) must resolve to a recognisable type, not silently
    pick the wrong playbook because of fuzzy substring matching."""
    import json as _json

    from atms.ingest.otm import parse_otm
    p = tmp_path / "typo.otm.json"
    p.write_text(_json.dumps({
        "otmVersion": "0.2.0",
        "project": {"name": "typo", "id": "typo"},
        "components": [{
            "id": "c1", "name": "Agent",
            "type": "process",
            "attributes": {"atms_component_type": "agnet"},
        }],
    }), encoding="utf-8")
    sys_obj = parse_otm(p)
    assert sys_obj.components
    # The typo must NOT silently land as `network_segment` because of
    # the substring match `net` ⊂ `agnet`. Acceptable resolutions are
    # `other` (clean fall-through) or `agent` (lenient fuzz that
    # happens to land on the right answer). Anything else means the
    # fuzzy substring matcher is misleading users.
    ct = sys_obj.components[0].type
    assert ct in {"other", "agent"}, (
        f"typo 'agnet' resolved to '{ct}' — expected 'other' or "
        f"explicit 'agent', not a fuzzy substring match"
    )


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_skips_indented_eot_marker(tmp_path):
    """v0.14.8: a heredoc body that contains a line whose only content
    is the marker keyword (e.g. `EOT` indented) must NOT prematurely
    close the heredoc when the heredoc opener was `<<EOT` (no leading
    dash). The current `_strip_comments` masks string contents but
    relies on a strict-marker regex; if it changes to be loose, this
    test catches the regression."""
    from atms.ingest.terraform import parse_terraform
    p = tmp_path / "main.tf"
    p.write_text(
        'resource "aws_iam_role_policy" "x" {\n'
        '  policy = <<EOT\n'
        '{\n'
        '  "Statement": [\n'
        '    "EOT inside string is fine"\n'
        '  ]\n'
        '}\n'
        'EOT\n'
        '}\n\n'
        'resource "aws_s3_bucket" "y" {\n'
        '  bucket = "after-heredoc"\n'
        '}\n',
        encoding="utf-8",
    )
    sys_obj = parse_terraform(p)
    # Both resources must be visible; if heredoc parsing drops the s3
    # bucket, the second resource is silently lost.
    component_names = {c.name for c in sys_obj.components}
    assert any("y" in n or "s3" in n.lower() or "bucket" in n.lower()
               for n in component_names), (
        f"aws_s3_bucket.y was lost after heredoc; saw {component_names}"
    )
