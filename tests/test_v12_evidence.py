"""Tests for v0.12 — VAPT / SARIF / STIX / CSV ingestion + CISA KEV + EPSS."""

from __future__ import annotations

# v0.18.70 Hibernation Phase 3 — entire file exercises a
# hibernated surface. Skipped by default; run with:
#     pytest -m hibernated tests/test_v12_evidence.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import json
from pathlib import Path

import yaml

from atms.engines.evidence import apply_evidence
from atms.evidence import (
    parse_any,
    parse_csv,
    parse_nessus,
    parse_sarif,
    parse_stix,
)
from atms.evidence.matcher import match_evidence
from atms.kb import get_kb
from atms.models import Component, Evidence, System, Threat
from atms.workflow import analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ────────────────────────────── KEV / EPSS bundled snapshots ─────────────
def test_kev_catalog_bundled():
    kb = get_kb()
    assert isinstance(kb.kev_cves, list)
    assert len(kb.kev_cves) >= 50, "expected the bundled KEV snapshot to ship at least 50 rows"
    # Every row should be a CVE-XXXX-NNN string
    for cve in kb.kev_cves:
        assert cve.startswith("CVE-")


def test_kev_contains_well_known_cves():
    kb = get_kb()
    # ProxyLogon, ProxyShell, Log4Shell, PAN-OS, Fortigate, Citrix Bleed
    for required in [
        "CVE-2021-26855", "CVE-2021-34473", "CVE-2021-44228",
        "CVE-2024-3400", "CVE-2024-21762", "CVE-2023-4966",
    ]:
        assert required in kb.kev_cves, f"KEV bundle missing {required}"


def test_epss_snapshot_bundled():
    kb = get_kb()
    assert isinstance(kb.epss_scores, list)
    assert len(kb.epss_scores) >= 50
    for row in kb.epss_scores[:3]:
        assert "cve" in row and "epss" in row
        assert 0 <= row["epss"] <= 1


# ────────────────────────────── Evidence model ───────────────────────────
def test_evidence_model_defaults():
    e = Evidence(source="vapt", title="x")
    assert e.cve == [] and e.cvss is None and e.epss is None
    assert e.kev is False and e.observed_at == ""


# ────────────────────────────── CSV parser ────────────────────────────────
def test_csv_parser_sniffs_columns(tmp_path):
    p = tmp_path / "findings.csv"
    p.write_text(
        "cve,Severity,Asset,Title,Description\n"
        "CVE-2024-3400,Critical,vpn01.corp,PAN-OS RCE,GlobalProtect command injection\n"
        "CVE-2021-44228,High,app01.corp,Log4Shell,Log4j JNDI RCE\n"
        ",low,laptop42,Outdated TLS,TLS 1.0 still enabled\n",
        encoding="utf-8",
    )
    rows = parse_csv(p)
    assert len(rows) == 3
    assert rows[0].source == "vapt"
    assert rows[0].cve == ["CVE-2024-3400"]
    assert rows[0].severity == "critical"
    assert rows[1].cve == ["CVE-2021-44228"]
    assert rows[2].severity == "low"


def test_csv_parser_handles_cvss_severity(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text(
        "CVE,Risk,CVSS,Asset\n"
        "CVE-2024-1,9.8,9.8,host1\n"
        "CVE-2024-2,4.0,4.0,host2\n",
        encoding="utf-8",
    )
    rows = parse_csv(p)
    assert rows[0].severity == "critical"
    assert rows[0].cvss == 9.8
    assert rows[1].severity == "medium"


# ────────────────────────────── Nessus parser ─────────────────────────────
NESSUS_SNIPPET = """\
<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Test scan">
    <ReportHost name="webapp01.corp">
      <ReportItem severity="4" pluginID="98765" pluginName="Apache Log4j RCE (Log4Shell)">
        <description>Remote attackers can execute arbitrary code via crafted JNDI strings.</description>
        <cve>CVE-2021-44228</cve>
        <cvss3_base_score>10.0</cvss3_base_score>
        <see_also>https://logging.apache.org/log4j/2.x/security.html</see_also>
      </ReportItem>
      <ReportItem severity="2" pluginID="11219" pluginName="Open ssh port">
        <description>SSH service is reachable.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def test_nessus_parser_extracts_findings(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(NESSUS_SNIPPET, encoding="utf-8")
    rows = parse_nessus(p)
    assert len(rows) == 2
    assert rows[0].source == "vapt"
    assert rows[0].source_type == "nessus"
    assert rows[0].severity == "critical"
    assert rows[0].cve == ["CVE-2021-44228"]
    assert rows[0].cvss == 10.0
    assert rows[0].affected_asset == "webapp01.corp"
    assert rows[1].severity == "medium"


# ────────────────────────────── SARIF parser ─────────────────────────────
SARIF_SNIPPET = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": [
            {"id": "python.lang.security.audit.dangerous-yaml-load",
             "shortDescription": {"text": "Use yaml.safe_load"},
             "defaultConfiguration": {"level": "error"},
             "properties": {"tags": ["CVE-2017-18342", "security"]}},
        ]}},
        "results": [
            {"ruleId": "python.lang.security.audit.dangerous-yaml-load",
             "level": "error",
             "message": {"text": "Use yaml.safe_load instead of yaml.load."},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/loader.py"}}}]},
        ],
    }],
}


def test_sarif_parser_extracts_findings(tmp_path):
    p = tmp_path / "f.sarif"
    p.write_text(json.dumps(SARIF_SNIPPET), encoding="utf-8")
    rows = parse_sarif(p)
    assert len(rows) == 1
    assert rows[0].source == "vapt"
    assert "sarif:semgrep" in rows[0].source_type
    assert rows[0].severity == "high"
    assert rows[0].cve == ["CVE-2017-18342"]
    assert rows[0].affected_asset == "src/loader.py"


# ────────────────────────────── STIX parser ──────────────────────────────
STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--12345678-1234-1234-1234-123456789abc",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "name": "PAN-OS RCE indicator",
            "description": "Active exploitation of CVE-2024-3400 by APT41",
            "confidence": 95,
            "labels": ["malicious-activity"],
            "external_references": [
                {"source_name": "cve", "external_id": "CVE-2024-3400",
                 "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"},
            ],
            "created": "2024-04-12T00:00:00Z",
        },
    ],
}


def test_stix_parser_extracts_indicators(tmp_path):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps(STIX_BUNDLE), encoding="utf-8")
    rows = parse_stix(p)
    assert len(rows) == 1
    assert rows[0].source == "ti"
    assert rows[0].cve == ["CVE-2024-3400"]
    assert rows[0].severity == "critical"


def test_parse_any_picks_format(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(NESSUS_SNIPPET, encoding="utf-8")
    rows = parse_any(p)
    assert rows and rows[0].source_type == "nessus"


# ────────────────────────────── Matcher ─────────────────────────────────
def test_matcher_by_hostname():
    components = [
        Component(id="c1", name="web", type="web_application",
                  metadata={"hostname": "webapp01.corp"}),
        Component(id="c2", name="db", type="database",
                  metadata={"hostname": "db01.corp"}),
    ]
    ev = Evidence(source="vapt", title="Log4Shell", affected_asset="webapp01.corp",
                  cve=["CVE-2021-44228"])
    pairs = match_evidence([ev], components)
    assert len(pairs) == 1
    matched_ids = [c.id for c in pairs[0][1]]
    assert matched_ids == ["c1"]


def test_matcher_by_product_when_no_hostname():
    components = [
        Component(id="vpn", name="VPN gateway", type="vpn_gateway",
                  metadata={"product": "PAN-OS"}),
        Component(id="db", name="db", type="database",
                  metadata={"product": "Oracle Database"}),
    ]
    ev = Evidence(source="vapt", title="PAN-OS GlobalProtect RCE", affected_asset="")
    pairs = match_evidence([ev], components)
    assert any(c.id == "vpn" for c in pairs[0][1])


def test_matcher_falls_back_to_name():
    components = [Component(id="ad", name="Active Directory", type="directory_service")]
    ev = Evidence(source="vapt", title="Active Directory LDAP RCE")
    pairs = match_evidence([ev], components)
    assert pairs[0][1][0].id == "ad"


def test_matcher_returns_empty_list_when_no_match():
    components = [Component(id="x", name="something", type="other")]
    ev = Evidence(source="vapt", title="totally unrelated")
    pairs = match_evidence([ev], components)
    assert pairs[0][1] == []


# ────────────────────────────── Engine ──────────────────────────────────
def _toy_system_threats():
    components = [
        Component(id="vpn", name="GlobalProtect", type="vpn_gateway",
                  metadata={"hostname": "vpn01.corp", "product": "PAN-OS"}),
    ]
    threats = [
        Threat(id="vpn.t1", component_id="vpn",
               title="Internet-facing VPN with vendor-CVE chain",
               description="Exploitable PAN-OS CVE on the perimeter VPN.",
               likelihood=3, impact=4, severity="medium"),
    ]
    return components, threats


def test_engine_kev_forces_critical():
    components, threats = _toy_system_threats()
    ev = Evidence(source="vapt", source_type="nessus", source_id="98765",
                  title="PAN-OS GlobalProtect RCE",
                  affected_asset="vpn01.corp", cve=["CVE-2024-3400"], severity="high")
    apply_evidence(threats, components, [ev])
    t = threats[0]
    assert t.evidence
    assert t.evidence[0].kev is True
    assert t.severity == "critical"
    assert t.likelihood == 5
    assert t.evidence_status == "exploited"


def test_engine_high_scanner_finding_promotes_status():
    components, threats = _toy_system_threats()
    ev = Evidence(source="vapt", source_type="nessus",
                  title="OOB write in some component",
                  affected_asset="vpn01.corp", severity="high",
                  cve=["CVE-2099-9999"])  # not on KEV
    apply_evidence(threats, components, [ev])
    t = threats[0]
    assert t.evidence_status == "observed"
    assert t.likelihood >= 4


def test_engine_red_team_marks_exploited():
    components, threats = _toy_system_threats()
    ev = Evidence(source="red_team", source_type="caldera",
                  title="Caldera ability succeeded against VPN",
                  affected_asset="vpn01.corp", severity="medium")
    apply_evidence(threats, components, [ev])
    t = threats[0]
    assert t.evidence_status == "exploited"
    assert t.likelihood == 5


def test_engine_ti_only_marks_likely():
    components, threats = _toy_system_threats()
    ev = Evidence(source="ti", source_type="stix:indicator",
                  title="Active campaign targeting PAN-OS",
                  affected_asset="vpn01.corp", severity="high",
                  cve=["CVE-2099-9999"])  # non-KEV
    apply_evidence(threats, components, [ev])
    t = threats[0]
    assert t.evidence_status == "likely"


def test_engine_decorates_with_epss_score():
    components, threats = _toy_system_threats()
    ev = Evidence(source="vapt", source_type="csv",
                  title="Log4Shell finding",
                  affected_asset="vpn01.corp",
                  cve=["CVE-2021-44228"])
    apply_evidence(threats, components, [ev])
    # CVE-2021-44228 is in our bundled EPSS top-N
    assert threats[0].evidence[0].epss is not None
    assert threats[0].evidence[0].epss > 0.5


# ────────────────────────────── Workflow integration ─────────────────────
def test_analyze_accepts_evidence_kwarg():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    sys_obj = System.model_validate(raw)
    # Force-set hostname on the LLM component so the matcher fires
    for c in sys_obj.components:
        if c.type == "llm_inference":
            c.metadata = {"hostname": "llm01.corp"}
            break
    # Non-KEV / non-EPSS CVE to verify the baseline path
    ev = [Evidence(source="vapt", source_type="nessus",
                   title="Hypothetical placeholder finding",
                   affected_asset="llm01.corp",
                   cve=["CVE-2099-99999"], severity="critical")]
    full = analyze(sys_obj)
    enriched = analyze(sys_obj, evidence=ev)
    # Total threat count is unchanged but the model must record evidence.
    assert len(full.threats) == len(enriched.threats)
    assert enriched.summary["evidence_total"] >= 1
    assert enriched.summary["evidence_kev_hits"] == 0
    # KEV-listed CVE
    ev[0].cve = ["CVE-2024-3400"]
    enriched2 = analyze(sys_obj, evidence=ev)
    assert enriched2.summary["evidence_kev_hits"] >= 1


def test_workflow_summary_keys_v12_present():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    for k in ("evidence_status_breakdown", "evidence_total", "evidence_kev_hits"):
        assert k in tm.summary, f"missing summary key: {k}"


# ────────────────────────────── Web routes ───────────────────────────────
def test_web_evidence_page_renders(client_module_scope):
    r = client_module_scope.get("/evidence")
    assert r.status_code == 200
    assert "Evidence-driven analysis" in r.text


def test_web_evidence_ingest_csv(client_module_scope):
    csv_blob = (
        b"CVE,Severity,Asset,Title\n"
        b"CVE-2024-3400,Critical,vpn01.corp,PAN-OS RCE\n"
    )
    yaml_text = yaml.safe_dump({
        "name": "tiny",
        "components": [
            {"id": "vpn", "name": "VPN gw", "type": "vpn_gateway",
             "trust_zone": "dmz", "metadata": {"hostname": "vpn01.corp"}},
            {"id": "u", "name": "User", "type": "user", "trust_zone": "internet"},
            # v0.15.0: AI-scope gate requires at least one AI primary.
            {"id": "llm", "name": "Internal LLM", "type": "llm_inference"},
        ],
        "dataflows": [
            {"source": "u", "target": "vpn", "label": "tunnel"},
            {"source": "vpn", "target": "llm", "label": "LLM API"},
        ],
    })
    r = client_module_scope.post(
        "/evidence/ingest",
        files={"evidence_file": ("findings.csv", csv_blob, "text/csv")},
        data={"yaml_text": yaml_text, "methodology": "stride-ai"},
    )
    assert r.status_code == 200
    # The report must surface the KEV hit as critical somewhere
    assert "KEV" in r.text or "kev" in r.text.lower()


def test_web_evidence_rejects_unknown_extension(client_module_scope):
    yaml_text = yaml.safe_dump({"name": "x", "components": [
        {"id": "u", "name": "U", "type": "user"}]})
    r = client_module_scope.post(
        "/evidence/ingest",
        files={"evidence_file": ("foo.bin", b"\x00\x01\x02", "application/octet-stream")},
        data={"yaml_text": yaml_text},
    )
    assert r.status_code == 400


# ────────────────────────────── CLI ──────────────────────────────────────
def test_ingest_evidence_cli(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli

    csv_path = tmp_path / "findings.csv"
    csv_path.write_text(
        "CVE,Severity,Asset,Title\n"
        "CVE-2024-3400,Critical,vpn01.corp,PAN-OS RCE\n",
        encoding="utf-8",
    )
    sys_path = tmp_path / "tiny.yaml"
    sys_path.write_text(yaml.safe_dump({
        "name": "tiny",
        "components": [
            {"id": "vpn", "name": "VPN", "type": "vpn_gateway",
             "trust_zone": "dmz", "metadata": {"hostname": "vpn01.corp"}},
            # v0.15.0: AI-scope gate requires at least one AI primary.
            {"id": "llm", "name": "LLM", "type": "llm_inference"},
        ],
        "dataflows": [
            {"id": "f1", "source": "vpn", "target": "llm", "label": "egress"},
        ],
    }), encoding="utf-8")
    out_dir = tmp_path / "out"
    runner = CliRunner()
    res = runner.invoke(
        cli,
        ["ingest-evidence", str(csv_path), str(sys_path), "--out", str(out_dir)],
    )
    assert res.exit_code == 0, res.output
    md_files = list(out_dir.glob("*.md"))
    assert md_files, "expected markdown output"
    body = md_files[0].read_text(encoding="utf-8")
    assert "Evidence" in body
    assert "evidence_kev_hits" in str(out_dir.read_text) or "KEV" in body or "exploited" in body.lower()


# ────────────────────────────── CSV export ───────────────────────────────
def test_csv_register_includes_v12_columns():
    from atms.reporting import write_csv
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    out = write_csv(tm, "risk_register")
    header = out.splitlines()[0]
    for col in ("evidence_status", "evidence_count", "evidence_kev"):
        assert col in header, f"missing CSV column {col}"
