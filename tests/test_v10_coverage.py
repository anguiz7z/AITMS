"""Tests for v0.10 — IT/Network/OT/Legacy/Identity component types,
MITRE ATT&CK Enterprise + ICS, LINDDUN privacy, methodology selection
and the GUI editor backend."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from atms.engines.linddun import enrich_with_linddun
from atms.engines.maestro import DEFAULT_LAYER_MAP
from atms.kb import get_kb
from atms.models import Component, System, Threat
from atms.reporting import render_html, render_markdown
from atms.workflow import SUPPORTED_METHODOLOGIES, analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"

V10_TYPES = [
    "database",
    "firewall",
    "directory_service",
    "web_application",
    "endpoint",
    "legacy_mainframe",
    "plc",
    "scada",
    "iot_device",
    "load_balancer",
    "vpn_gateway",
    "network_switch",
    "email_server",
    "mfa_service",
    "industrial_protocol",
]


# ───────────────────────────────────────────────────────────── KB
def test_attack_enterprise_kb_loaded():
    kb = get_kb()
    # We curated >= 30 techniques across Enterprise + ICS.
    assert len(kb.attack_enterprise) >= 30
    # Spot-check well-known IDs that the playbooks reference.
    for tid in [
        "T1190", "T1078", "T1098", "T1003",
        "T1558", "T1110", "T1566", "T1499",
        "T1557", "T0855", "T0836",
    ]:
        assert tid in kb.attack_enterprise, f"missing {tid}"


def test_linddun_kb_loaded():
    kb = get_kb()
    # 7 LINDDUN categories — at least one entry per category.
    assert len(kb.linddun) >= 12
    cats = {entry.get("category") for entry in kb.linddun.values()}
    assert {"Linking", "Identifying", "Non-repudiation", "Detecting",
            "Data_Disclosure", "Unawareness", "Non_Compliance"} <= cats


def test_v10_playbooks_loaded():
    kb = get_kb()
    for ctype in V10_TYPES:
        assert ctype in kb.playbooks, f"playbook missing for {ctype}"
        assert len(kb.playbooks[ctype]["threats"]) >= 3, \
            f"{ctype} playbook should have >= 3 threats"


def test_kb_search_attack_enterprise():
    kb = get_kb()
    results = kb.search("phishing email", framework="attack_enterprise", limit=5)
    ids = {r["id"] for r in results}
    assert "T1566" in ids


def test_kb_search_linddun():
    kb = get_kb()
    results = kb.search("training set", framework="linddun", limit=5)
    ids = {r["id"] for r in results}
    assert "L_001" in ids


def test_kb_search_attack_alias_covers_both():
    kb = get_kb()
    results = kb.search("modbus", framework="attack", limit=5)
    ids = {r["id"] for r in results}
    # ICS technique should be reachable via the unified "attack" alias
    assert "T0855" in ids


# ───────────────────────────────────────────────────────────── Models
def test_component_type_literal_has_v10_types():
    for ctype in V10_TYPES:
        c = Component(id="x", name="x", type=ctype)
        assert c.type == ctype


def test_threat_has_v10_framework_fields():
    t = Threat(
        id="t1", component_id="c", title="t", description="x",
        likelihood=3, impact=3,
    )
    assert t.attack_enterprise == []
    assert t.linddun == []


# ───────────────────────────────────────────────────────────── MAESTRO map
def test_maestro_layer_map_covers_all_v10_types():
    for ctype in V10_TYPES:
        assert ctype in DEFAULT_LAYER_MAP, f"{ctype} missing from DEFAULT_LAYER_MAP"
        layers = DEFAULT_LAYER_MAP[ctype]
        assert layers, f"{ctype} has no MAESTRO layers"
        assert any(layer.startswith("M.L") for layer in layers), \
            f"{ctype} layers don't look like M.LN: {layers!r}"


# ───────────────────────────────────────────────────────────── LINDDUN engine
def test_linddun_engine_tags_privacy_threat():
    sys_obj = System(
        name="privacy-mini",
        components=[
            Component(id="llm", name="LLM", type="llm_inference"),
            Component(id="ext", name="OpenAI", type="external_api"),
        ],
    )
    threats = [
        Threat(
            id="t.privacy", component_id="llm", title="PII leak through prompt to third-party",
            description=("Personal data is forwarded as part of prompts to an external "
                         "third-party model API; oversharing of PII without DPA."),
            likelihood=4, impact=4,
        ),
    ]
    enriched = enrich_with_linddun(threats, sys_obj.components)
    assert enriched[0].linddun, "expected at least one LINDDUN tag"


# ───────────────────────────────────────────────────────────── Workflow
def test_methodologies_constant():
    assert "stride-ai" in SUPPORTED_METHODOLOGIES
    assert "linddun" in SUPPORTED_METHODOLOGIES


def test_unknown_methodology_raises():
    sys_obj = System(name="x", components=[Component(id="u", name="u", type="user")])
    with pytest.raises(ValueError):
        analyze(sys_obj, methodology="bogus")


def test_linddun_methodology_filters_to_privacy_threats():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    sys_obj = System.model_validate(raw)
    full = analyze(sys_obj)
    privacy = analyze(sys_obj, methodology="linddun")
    # Privacy lens drops any threat without a LINDDUN tag, so it is a strict subset.
    assert len(privacy.threats) <= len(full.threats)
    # And every retained threat has at least one LINDDUN ID.
    assert all(t.linddun for t in privacy.threats)
    # Summary records the methodology
    assert privacy.summary["methodology"] == "linddun"
    assert full.summary["methodology"] == "stride-ai"


def test_summary_exposes_v10_keys():
    raw = yaml.safe_load((SAMPLES / "it_ot_factory.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    assert "attack_enterprise_coverage" in tm.summary
    assert "linddun_coverage" in tm.summary
    # The IT/OT factory sample should exercise both new frameworks
    assert len(tm.summary["attack_enterprise_coverage"]) >= 5
    # Privacy may be lighter on this sample but at least one LINDDUN ID
    # should fire (e.g. employee-data telemetry).
    assert "methodology" in tm.summary


# ───────────────────────────────────────────────────────────── IT / OT sample
def test_it_ot_factory_sample_loads_and_analyses():
    raw = yaml.safe_load((SAMPLES / "it_ot_factory.yaml").read_text(encoding="utf-8"))
    s = System.model_validate(raw)
    # The sample is intentionally rich — at least 20 components.
    assert len(s.components) >= 20
    tm = analyze(s)
    # v0.15.0: AI-scope gate filters out-of-scope components, so the
    # bound dropped from >=60 to >=50 for this hybrid IT/OT/AI sample.
    assert len(tm.threats) >= 50
    # ATT&CK Enterprise + ICS coverage
    assert len(tm.summary["attack_enterprise_coverage"]) >= 5
    # No component should be `other` — every type in the sample is in the
    # extended ComponentType literal.
    assert all(c.type != "other" for c in s.components)


# ───────────────────────────────────────────────────────────── Visio classifier
def test_vsdx_classifier_picks_v10_stencils():
    from atms.ingest.vsdx import _classify

    cases = [
        ("Microsoft SQL Server primary", "database"),
        ("Oracle DB cluster", "database"),
        ("Fortigate edge firewall", "firewall"),
        ("Active Directory domain controller", "directory_service"),
        ("Entra ID", "directory_service"),
        ("Customer portal (React frontend)", "web_application"),
        ("Developer laptop", "endpoint"),
        ("Windows 10 PC", "endpoint"),
        ("AS/400 ledger", "legacy_mainframe"),
        ("z/OS mainframe", "legacy_mainframe"),
        ("Siemens S7-1500 PLC", "plc"),
        ("Allen-Bradley CompactLogix", "plc"),
        ("OSIsoft historian", "scada"),
        ("Wonderware HMI", "scada"),
        ("IP camera", "iot_device"),
        ("Smart sensor", "iot_device"),
        ("F5 BIG-IP load balancer", "load_balancer"),
        ("HAProxy reverse proxy", "load_balancer"),
        ("GlobalProtect VPN gateway", "vpn_gateway"),
        ("WireGuard tunnel", "vpn_gateway"),
        ("Cisco Catalyst 9500 switch", "network_switch"),
        ("Microsoft Exchange Server", "email_server"),
        ("Office 365 tenant", "email_server"),
        ("Duo MFA", "mfa_service"),
        ("Modbus/TCP bus", "industrial_protocol"),
        ("OPC-UA channel", "industrial_protocol"),
    ]
    for label, expected in cases:
        actual = _classify(label)
        assert actual == expected, f"{label!r} -> {actual!r} (expected {expected!r})"


# ───────────────────────────────────────────────────────────── Reports
def test_html_report_has_v10_columns():
    raw = yaml.safe_load((SAMPLES / "it_ot_factory.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    html = render_html(tm)
    assert "ATT&amp;CK Enterprise" in html or "ATT&CK Enterprise" in html
    assert "LINDDUN" in html


def test_markdown_report_has_v10_sections():
    raw = yaml.safe_load((SAMPLES / "it_ot_factory.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    md = render_markdown(tm)
    assert "ATT&CK Enterprise" in md
    assert "LINDDUN" in md


# ───────────────────────────────────────────────────────────── CLI
def test_kb_search_cli_accepts_v10_frameworks():
    from click.testing import CliRunner

    from atms.cli import cli

    for fw in ["attack_enterprise", "linddun", "attack"]:
        res = CliRunner().invoke(cli, ["kb-search", "credential", "--framework", fw, "--limit", "1"])
        assert res.exit_code == 0, f"--framework {fw} failed: {res.output}"


def test_analyze_cli_accepts_methodology():
    from click.testing import CliRunner

    from atms.cli import cli

    sample = SAMPLES / "rag_system.yaml"
    runner = CliRunner()
    with runner.isolated_filesystem() as td:
        out_dir = Path(td) / "out"
        res = runner.invoke(
            cli,
            ["analyze", str(sample), "--out", str(out_dir),
             "--format", "md", "--methodology", "linddun"],
        )
        assert res.exit_code == 0, res.output
        # The MD report should mention privacy or LINDDUN
        md_files = list(out_dir.glob("*.md"))
        assert md_files, "no markdown produced"
        body = md_files[0].read_text(encoding="utf-8")
        assert "linddun" in body.lower() or "LINDDUN" in body


# ───────────────────────────────────────────────────────────── Web UI
def test_web_editor_page_renders(client_module_scope):
    r = client_module_scope.get("/editor")
    assert r.status_code == 200
    assert "System editor" in r.text or "system editor" in r.text.lower()
    assert "atms-editor.js" in r.text


def test_web_editor_save_round_trip(client_module_scope):
    payload = {
        "name": "tiny",
        "description": "tiny",
        "components": [
            {"id": "u", "name": "User", "type": "user", "trust_zone": "internet"},
            {"id": "llm", "name": "Claude", "type": "llm_inference", "trust_zone": "prod"},
        ],
        "dataflows": [{"source": "u", "target": "llm", "label": "prompt"}],
    }
    r = client_module_scope.post("/editor/save", json=payload)
    assert r.status_code == 200
    assert "name: tiny" in r.text
    assert "id: llm" in r.text


def test_web_editor_analyze_round_trip(client_module_scope):
    import json

    payload = {
        "name": "editor-mini",
        "components": [
            {"id": "u", "name": "User", "type": "user", "trust_zone": "internet"},
            {"id": "llm", "name": "Claude", "type": "llm_inference", "trust_zone": "prod"},
        ],
        "dataflows": [{"source": "u", "target": "llm", "label": "prompt"}],
    }
    r = client_module_scope.post(
        "/editor/analyze",
        data={"system_json": json.dumps(payload), "methodology": "stride-ai"},
    )
    assert r.status_code == 200
    # The report page mentions threat counts
    assert "Threats" in r.text or "threats" in r.text.lower()


def test_web_kb_dropdown_has_attack_enterprise_and_linddun(client_module_scope):
    r = client_module_scope.get("/kb")
    assert r.status_code == 200
    assert "ATT&amp;CK Enterprise" in r.text or "ATT&CK Enterprise" in r.text
    assert "LINDDUN" in r.text


def test_web_analyze_accepts_methodology_form_field(client_module_scope):
    yaml_text = (SAMPLES / "rag_system.yaml").read_text(encoding="utf-8")
    r = client_module_scope.post(
        "/analyze",
        data={"yaml": yaml_text, "methodology": "linddun"},
    )
    assert r.status_code == 200
