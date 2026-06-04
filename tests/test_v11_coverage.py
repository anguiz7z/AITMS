"""Tests for v0.11 — device catalog + NIST AI 100-2 + Cyber Kill Chain +
PASTA methodology + PNG ingestion path."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
import yaml

from atms.engines.kill_chain import PHASES, assign_kill_chain_phases
from atms.engines.nist_ai_100_2 import enrich_with_nist_ai_100_2
from atms.kb import get_kb
from atms.models import Component, System, Threat
from atms.workflow import SUPPORTED_METHODOLOGIES, analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ────────────────────────────── Device catalog ────────────────────────────
def test_device_catalog_loaded():
    kb = get_kb()
    assert isinstance(kb.devices, list)
    # 200+ entries spanning multiple component types
    assert len(kb.devices) >= 200
    cats = {d.get("category") for d in kb.devices}
    # Spot-check the 40 component types appear
    for ct in [
        "llm_inference", "rag_vector_store", "iam_principal", "secrets_vault",
        "database", "firewall", "directory_service", "endpoint",
        "legacy_mainframe", "plc", "scada", "industrial_protocol",
        "iot_device", "load_balancer", "vpn_gateway", "network_switch",
        "email_server", "mfa_service",
    ]:
        assert ct in cats, f"no device-catalog entries for {ct}"


def test_device_catalog_has_well_known_products():
    kb = get_kb()
    products = {(d.get("vendor"), d.get("product")) for d in kb.devices}
    # Basic sanity: a few headline products MUST be present
    assert ("Anthropic", "Claude (API)") in products
    assert ("Microsoft", "Active Directory Domain Services") in products
    assert ("Siemens", "SIMATIC S7-1500") in products
    assert ("Palo Alto Networks", "PAN-OS Firewall (PA-Series / VM-Series)") in products


def test_devices_for_filters_by_category():
    kb = get_kb()
    plcs = kb.devices_for("plc")
    assert plcs, "no plc devices loaded"
    assert all(d.get("category") == "plc" for d in plcs)


# ────────────────────────────── NIST AI 100-2 ─────────────────────────────
def test_nist_ai_100_2_loaded():
    kb = get_kb()
    assert len(kb.nist_ai_100_2) >= 12
    # Spot-check canonical IDs
    for k in ["NIST_PAI_EVASION", "NIST_PAI_POISONING_DATA",
              "NIST_PAI_PRIVACY_MEMBERSHIP",
              "NIST_GAI_PROMPT_INJECTION_DIRECT",
              "NIST_GAI_PROMPT_INJECTION_INDIRECT",
              "NIST_GAI_DATA_EXTRACTION"]:
        assert k in kb.nist_ai_100_2, f"missing {k}"


def test_nist_ai_100_2_engine_tags_prompt_injection():
    sys_obj = System(
        name="x",
        components=[Component(id="llm", name="LLM", type="llm_inference")],
    )
    threats = [
        Threat(
            id="t1", component_id="llm",
            title="Direct prompt injection bypasses guardrails",
            description="User input contains instructions that override the system prompt.",
            stride_ai=["Tampering"],
            likelihood=4, impact=4,
        ),
    ]
    enriched = enrich_with_nist_ai_100_2(threats, sys_obj.components)
    assert "NIST_GAI_PROMPT_INJECTION_DIRECT" in enriched[0].nist_ai_100_2


def test_nist_ai_100_2_engine_tags_membership_inference():
    sys_obj = System(
        name="x",
        components=[Component(id="r", name="vec", type="rag_vector_store")],
    )
    threats = [
        Threat(
            id="t1", component_id="r",
            title="Membership inference reidentifies training records",
            description="Adversary can determine whether a record was in training data.",
            stride_ai=["Information_Disclosure"],
            likelihood=3, impact=4,
        ),
    ]
    enriched = enrich_with_nist_ai_100_2(threats, sys_obj.components)
    assert any(tag.startswith("NIST_PAI_PRIVACY") for tag in enriched[0].nist_ai_100_2)


# ────────────────────────────── Kill chain ────────────────────────────────
def test_kill_chain_assigns_a_phase_to_every_threat():
    threats = [
        Threat(id="t1", component_id="c", title="Phishing email lures user",
               description="Spearphishing attachment", stride_ai=["Spoofing"],
               likelihood=4, impact=4),
        Threat(id="t2", component_id="c", title="C2 beacon over HTTPS",
               description="Agent calls back to attacker C2", stride_ai=["Tampering"],
               likelihood=3, impact=5),
        Threat(id="t3", component_id="c", title="Data exfiltration over Dropbox",
               description="Attacker exfiltrates sensitive data via cloud storage",
               stride_ai=["Information_Disclosure"], likelihood=3, impact=5),
    ]
    out = assign_kill_chain_phases(threats)
    for t in out:
        assert t.kill_chain_phase in PHASES, f"{t.id}: unexpected phase {t.kill_chain_phase!r}"
    # Phishing → Delivery; C2 → Command_and_Control; exfil → Actions_on_Objectives
    assert out[0].kill_chain_phase == "Delivery"
    assert out[1].kill_chain_phase == "Command_and_Control"
    assert out[2].kill_chain_phase == "Actions_on_Objectives"


# ────────────────────────────── PASTA methodology ────────────────────────
def test_supported_methodologies_includes_pasta():
    assert "pasta" in SUPPORTED_METHODOLOGIES


def test_pasta_methodology_filters_to_attacker_priorities():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    sys_obj = System.model_validate(raw)
    full = analyze(sys_obj)
    pasta = analyze(sys_obj, methodology="pasta")
    # PASTA is a strict (or equal) subset of full results.
    assert len(pasta.threats) <= len(full.threats)
    # Every retained threat is either in an attack path, has likelihood >= 4,
    # or is high/critical severity.
    in_paths = {tid for p in pasta.attack_paths for tid in p.threat_ids}
    for t in pasta.threats:
        ok = (t.id in in_paths) or t.likelihood >= 4 or t.severity in ("high", "critical")
        assert ok, f"{t.id} should not have survived PASTA filter"
    assert pasta.summary["methodology"] == "pasta"


def test_summary_exposes_v11_keys(aws_bedrock_tm_readonly):
    # v0.17.3: uses cached session-scoped analysis.
    tm = aws_bedrock_tm_readonly
    assert "nist_ai_100_2_coverage" in tm.summary
    assert "kill_chain_breakdown" in tm.summary
    assert isinstance(tm.summary["kill_chain_breakdown"], dict)


# ────────────────────────────── Web — /devices + /api/devices ─────────────
@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3
def test_devices_browse_page(client_module_scope):
    r = client_module_scope.get("/devices")
    assert r.status_code == 200
    assert "Device & product catalog" in r.text
    assert "Anthropic" in r.text  # at least one well-known vendor visible


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_devices_api_default_returns_all(client_module_scope):
    r = client_module_scope.get("/api/devices")
    assert r.status_code == 200
    j = r.json()
    assert "devices" in j and "count" in j
    assert j["count"] >= 200


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_devices_api_filters_by_category(client_module_scope):
    r = client_module_scope.get("/api/devices", params={"category": "directory_service"})
    assert r.status_code == 200
    j = r.json()
    assert j["count"] >= 1
    assert all(d.get("category") == "directory_service" for d in j["devices"])


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_devices_api_filters_by_query(client_module_scope):
    r = client_module_scope.get("/api/devices", params={"q": "fortigate"})
    assert r.status_code == 200
    j = r.json()
    assert j["count"] >= 1
    # At least one Fortinet entry returned
    assert any("Fortinet" in d.get("vendor", "") for d in j["devices"])


# ────────────────────────────── Web — PNG ingestion (vision module mock) ──
def test_png_upload_without_anthropic_returns_clear_error(client_module_scope, monkeypatch):
    """If the user uploads a PNG without ANTHROPIC_API_KEY, the response must
    explain the situation rather than crash."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64  # minimal magic header
    r = client_module_scope.post(
        "/ingest",
        files={"diagram": ("test.png", fake_png, "image/png")},
    )
    assert r.status_code == 400
    assert "vision" in r.text.lower()
    assert "ANTHROPIC_API_KEY" in r.text or "anthropic" in r.text.lower()


def test_png_upload_with_mocked_vision_module(client_module_scope):
    """When the vision module returns valid YAML, the route should accept it."""
    fake_yaml = yaml.safe_dump({
        "name": "Vision-extracted system",
        "components": [
            {"id": "u", "name": "User", "type": "user", "trust_zone": "internet"},
            {"id": "llm", "name": "Claude", "type": "llm_inference", "trust_zone": "prod"},
        ],
        "dataflows": [{"source": "u", "target": "llm", "label": "prompt"}],
    })
    fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    with mock.patch(
        "atms.vision.analyzer.diagram_to_system_yaml", return_value=fake_yaml
    ):
        r = client_module_scope.post(
            "/ingest",
            files={"diagram": ("arch.png", fake_png, "image/png")},
        )
    assert r.status_code == 200
    assert "Vision-extracted system" in r.text


# ────────────────────────────── CLI ───────────────────────────────────────
def test_devices_cli_command_runs():
    from click.testing import CliRunner

    from atms.cli import cli
    runner = CliRunner()
    res = runner.invoke(cli, ["devices", "--type", "plc"])
    assert res.exit_code == 0, res.output
    assert "Siemens" in res.output or "Allen-Bradley" in res.output


def test_kb_search_cli_accepts_v11_frameworks():
    from click.testing import CliRunner

    from atms.cli import cli
    res = CliRunner().invoke(
        cli, ["kb-search", "prompt injection", "--framework", "nist_ai_100_2", "--limit", "1"],
    )
    assert res.exit_code == 0, res.output


def test_analyze_cli_accepts_pasta_methodology():
    from click.testing import CliRunner

    from atms.cli import cli
    sample = SAMPLES / "rag_system.yaml"
    runner = CliRunner()
    with runner.isolated_filesystem() as td:
        out_dir = Path(td) / "out"
        res = runner.invoke(
            cli,
            ["analyze", str(sample), "--out", str(out_dir),
             "--format", "md", "--methodology", "pasta"],
        )
        assert res.exit_code == 0, res.output


# ────────────────────────────── Reports ───────────────────────────────────
def test_html_report_has_v11_columns(aws_bedrock_tm_readonly):
    from atms.reporting import render_html
    # v0.17.3: uses cached session-scoped analysis.
    tm = aws_bedrock_tm_readonly
    html = render_html(tm)
    assert "NIST AI 100-2" in html
    assert "Kill Chain" in html or "Cyber Kill Chain" in html


def test_markdown_report_has_v11_sections(aws_bedrock_tm_readonly):
    from atms.reporting import render_markdown
    # v0.17.3: uses cached session-scoped analysis.
    tm = aws_bedrock_tm_readonly
    md = render_markdown(tm)
    assert "NIST AI 100-2" in md
    assert "Kill Chain" in md


def test_csv_register_has_v11_columns():
    from atms.reporting import write_csv
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    csv = write_csv(tm, "risk_register")
    header = csv.splitlines()[0]
    assert "nist_ai_100_2" in header
    assert "kill_chain_phase" in header
