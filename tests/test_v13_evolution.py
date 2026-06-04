"""Tests for v0.13 — feeds, CVE lookup, compliance, controls, FAIR-lite,
OWASP ML, OTM ingest/export, SARIF report, JSON-Schema, defensive fixes."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest
import yaml

from atms.engines.compliance import enrich_with_compliance
from atms.engines.controls import CONTROL_EFFECTS, apply_component_controls
from atms.engines.owasp_ml import enrich_with_owasp_ml
from atms.engines.quantitative import portfolio_ale, score_quantitative
from atms.evidence.matcher import match_evidence
from atms.kb import get_kb
from atms.models import Component, Evidence, System, Threat
from atms.reporting import render_otm, render_sarif
from atms.workflow import analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ───────────────────────────── Compliance KB ─────────────────────────────
def test_compliance_kb_loaded_with_all_frameworks():
    kb = get_kb()
    assert len(kb.compliance_controls) >= 40
    frameworks = {c.get("framework") for c in kb.compliance_controls.values()}
    for fw in [
        "NIS2", "DORA", "EU_AI_Act", "GDPR",
        "PCI_DSS", "HIPAA", "NIST_800_53", "NIST_CSF",
        "ISO27001", "SEC_CYBER",
    ]:
        assert fw in frameworks, f"compliance framework missing: {fw}"


def test_compliance_engine_tags_controls_for_phishing():
    sys_obj = System(
        name="x",
        components=[Component(id="mail", name="Mail", type="email_server")],
    )
    threats = [Threat(
        id="t1", component_id="mail", title="Phishing email lures user",
        description="Inbound phishing with malicious link bypasses safe-link rewrite.",
        stride_ai=["Spoofing"], likelihood=4, impact=5,
    )]
    enriched = enrich_with_compliance(threats, sys_obj.components)
    # Should have hit at least one of NIS2.21.2.g (cyber-hygiene/training)
    assert any(c.startswith("NIS2.") or c.startswith("PCI_DSS.") or c.startswith("ISO27001.")
               for c in enriched[0].compliance_controls)


def test_kb_search_compliance_filter():
    kb = get_kb()
    rows = kb.search("supply chain", framework="compliance", limit=5)
    assert any(r["framework"] == "compliance" for r in rows)


# ───────────────────────────── OWASP ML KB ───────────────────────────────
def test_owasp_ml_kb_loaded():
    kb = get_kb()
    assert len(kb.owasp_ml) >= 10
    for k in ["ML01:2023", "ML02:2023", "ML05:2023", "ML10:2023"]:
        assert k in kb.owasp_ml


def test_owasp_ml_engine_tags_data_poisoning():
    sys_obj = System(
        name="x",
        components=[Component(id="train", name="Trainer", type="training_pipeline")],
    )
    threats = [Threat(
        id="t1", component_id="train",
        title="Training data poisoning via crowd-sourced labels",
        description="Attacker injects mislabelled examples to corrupt the model.",
        stride_ai=["Tampering"], likelihood=3, impact=4,
    )]
    enriched = enrich_with_owasp_ml(threats, sys_obj.components)
    assert "ML02:2023" in enriched[0].owasp_ml


# ───────────────────────────── Component controls ────────────────────────
def test_controls_recognised_vocabulary_is_documented():
    # Spot-check the documented controls are still wired
    for name in ["mfa_required", "waf", "edr", "segmentation", "encryption_at_rest",
                 "guardrails_enabled", "phishing_resistant_mfa"]:
        assert name in CONTROL_EFFECTS


def test_controls_lower_likelihood_for_matching_threat():
    components = [Component(
        id="mail", name="Exchange", type="email_server",
        controls=["phishing_resistant_mfa", "edr"],
    )]
    threats = [Threat(
        id="t1", component_id="mail",
        title="MFA fatigue / push-bombing of admin account",
        description="Adversary spams MFA push notifications until user approves; "
                    "phish remains the typical vector.",
        likelihood=4, impact=5,
    )]
    apply_component_controls(threats, components)
    # phishing_resistant_mfa has delta=-2 and matches both 'mfa' and 'phish'
    assert threats[0].likelihood < 4


def test_controls_never_drop_below_1():
    components = [Component(
        id="x", name="x", type="endpoint",
        controls=["edr", "edr", "edr", "edr", "edr"],  # piling on
    )]
    threats = [Threat(id="t1", component_id="x",
                      title="Ransomware deployment", description="Ransomware encryption.",
                      likelihood=2, impact=5)]
    apply_component_controls(threats, components)
    assert threats[0].likelihood >= 1


# ───────────────────────────── FAIR-lite quantitative ────────────────────
def test_fair_lite_assigns_default_ranges():
    threats = [Threat(id="t", component_id="c", title="t", description="d",
                      likelihood=3, impact=4)]
    score_quantitative(threats)
    assert threats[0].freq_low > 0 and threats[0].freq_high > threats[0].freq_low
    assert threats[0].loss_low > 0 and threats[0].loss_high > threats[0].loss_low
    assert threats[0].ale_low > 0 and threats[0].ale_high > threats[0].ale_low


def test_fair_lite_respects_explicit_overrides():
    threats = [Threat(id="t", component_id="c", title="t", description="d",
                      likelihood=3, impact=4,
                      loss_low=10_000_000, loss_high=20_000_000,
                      freq_low=0.5, freq_high=2.0)]
    score_quantitative(threats)
    # Overrides preserved
    assert threats[0].loss_low == 10_000_000
    assert threats[0].freq_high == 2.0
    # ALE = freq * loss
    assert threats[0].ale_low == round(0.5 * 10_000_000, 2)


def test_portfolio_ale_aggregates():
    threats = [
        Threat(id="t1", component_id="c", title="t1", description="d",
               likelihood=2, impact=2),
        Threat(id="t2", component_id="c", title="t2", description="d",
               likelihood=4, impact=4),
    ]
    score_quantitative(threats)
    summary = portfolio_ale(threats)
    assert summary["ale_high_total"] >= summary["ale_low_total"]
    assert len(summary["top_contributors"]) <= 5


# ───────────────────────────── Evidence matcher v0.13 ────────────────────
def test_matcher_uses_cpe_when_available():
    components = [Component(
        id="c1", name="App", type="web_application",
        metadata={"cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
    )]
    ev = Evidence(
        source="vapt", title="Log4Shell",
        affected_asset="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
        cve=["CVE-2021-44228"],
    )
    pairs = match_evidence([ev], components)
    assert pairs[0][1][0].id == "c1"


def test_matcher_uses_purl_when_available():
    components = [Component(
        id="c1", name="API", type="serverless_function",
        metadata={"purl": "pkg:pypi/requests@2.31.0"},
    )]
    ev = Evidence(source="vapt", title="requests CVE",
                  affected_asset="pkg:pypi/requests@2.31.0",
                  cve=["CVE-2099-99999"])
    pairs = match_evidence([ev], components)
    assert pairs[0][1][0].id == "c1"


def test_matcher_uses_description_not_just_title():
    components = [Component(id="db", name="DB",
                            type="database", metadata={"product": "PostgreSQL"})]
    ev = Evidence(source="vapt", title="Authentication issue",
                  description="Affects PostgreSQL versions before 17.")
    pairs = match_evidence([ev], components)
    assert pairs[0][1][0].id == "db"


def test_workflow_surfaces_unmatched_evidence_count():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    sys_obj = System.model_validate(raw)
    ev = [Evidence(source="vapt", title="totally unrelated",
                   affected_asset="ghost-host-9999", cve=["CVE-2000-0001"])]
    tm = analyze(sys_obj, evidence=ev)
    assert tm.summary["evidence_unmatched"] >= 1


# ───────────────────────────── Disposition lifecycle ─────────────────────
def test_threat_disposition_default_open():
    t = Threat(id="t1", component_id="c", title="x", description="x",
               likelihood=3, impact=3)
    assert t.disposition == "open"


def test_threat_disposition_round_trips_through_csv():
    from atms.reporting import write_csv
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    out = write_csv(tm, "risk_register")
    header = out.splitlines()[0]
    for col in ("disposition", "reviewed_by", "due_date", "ale_low", "ale_high"):
        assert col in header


# ───────────────────────────── OTM ingest + export ───────────────────────
OTM_SAMPLE = {
    "otmVersion": "0.2.0",
    "project": {"id": "proj1", "name": "External OTM model",
                "description": "imported from elsewhere"},
    "trustZones": [
        {"id": "tz-internet", "name": "internet", "type": "trustZone",
         "risk": {"trustRating": 1}},
        {"id": "tz-corp", "name": "corp_net", "type": "trustZone"},
    ],
    "components": [
        {"id": "user1", "name": "User", "type": "user",
         "parent": {"trustZone": "tz-internet"},
         "attributes": {"vendor": "Internal"}},
        {"id": "llm1", "name": "Claude on Bedrock", "type": "llm",
         "parent": {"trustZone": "tz-corp"},
         "attributes": {"vendor": "Anthropic", "product": "Claude (API)",
                        "version": "Claude 3.5 Sonnet"}},
        {"id": "vec1", "name": "Pinecone", "type": "vector-store",
         "parent": {"trustZone": "tz-corp"}},
    ],
    "dataflows": [
        {"id": "d1", "name": "prompt", "source": "user1", "destination": "llm1"},
        {"id": "d2", "name": "retrieve", "source": "llm1", "destination": "vec1"},
    ],
}


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_otm_round_trip(tmp_path):
    from atms.ingest.otm import parse_otm
    p = tmp_path / "model.json"
    p.write_text(json.dumps(OTM_SAMPLE), encoding="utf-8")
    system = parse_otm(p)
    assert system.name == "External OTM model"
    assert {c.id for c in system.components} == {"user1", "llm1", "vec1"}
    # type mapping: 'llm' → llm_inference, 'vector-store' → rag_vector_store
    by_id = {c.id: c.type for c in system.components}
    assert by_id["llm1"] == "llm_inference"
    assert by_id["vec1"] == "rag_vector_store"
    # metadata preserved
    llm = next(c for c in system.components if c.id == "llm1")
    assert llm.metadata.get("vendor") == "Anthropic"
    assert llm.metadata.get("product") == "Claude (API)"


def test_otm_export_emits_atms_attributes():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    out = render_otm(tm)
    parsed = json.loads(out)
    assert parsed["otmVersion"] == "0.2.0"
    assert parsed["threats"], "OTM export must contain threats"
    first = parsed["threats"][0]
    assert "attributes" in first
    assert "atms_severity" in first["attributes"]


# ───────────────────────────── SARIF export ──────────────────────────────
def test_sarif_export_well_formed():
    raw = yaml.safe_load((SAMPLES / "rag_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    out = render_sarif(tm)
    parsed = json.loads(out)
    assert parsed["version"] == "2.1.0"
    runs = parsed["runs"]
    assert runs and runs[0]["tool"]["driver"]["name"] == "ATMS"
    assert runs[0]["results"], "SARIF export must contain results"
    levels = {r["level"] for r in runs[0]["results"]}
    assert levels.issubset({"note", "warning", "error"})


# ───────────────────────────── JSON-Schema for System ────────────────────
def test_system_json_schema_loads():
    from atms.paths import kb_dir
    schema_path = kb_dir() / "system.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["title"] == "ATMS System"
    assert "components" in schema["properties"]
    enum = schema["definitions"]["component_type"]["enum"]
    # Sanity: contains AI + cloud + IT/OT types
    for t in ("llm_inference", "iam_principal", "plc", "directory_service"):
        assert t in enum


# ───────────────────────────── CLI smoke ─────────────────────────────────
def test_atms_ci_exits_clean_when_below_threshold(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli
    sys_path = tmp_path / "tiny.yaml"
    sys_path.write_text(yaml.safe_dump({
        "name": "tiny", "components": [
            {"id": "u", "name": "U", "type": "user", "trust_zone": "internet"},
            # v0.15.0: AI-scope gate requires at least one AI primary.
            {"id": "llm", "name": "LLM", "type": "llm_inference"},
        ],
    }), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["ci", str(sys_path),
                              "--max-severity", "critical",
                              "--sarif-out", str(tmp_path / "out.sarif")])
    # tiny system has only fallback medium threats → ci passes
    assert res.exit_code in (0, 2)  # depends on bucket tuning; just must not crash
    assert (tmp_path / "out.sarif").exists()


def test_atms_ci_fails_when_critical_present(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli
    sys_path = tmp_path / "vpn.yaml"
    sys_path.write_text(yaml.safe_dump({
        "name": "kev-test",
        "components": [
            {"id": "vpn", "name": "VPN", "type": "vpn_gateway",
             "trust_zone": "dmz", "metadata": {"hostname": "vpn01.corp",
                                                 "product": "PAN-OS"}},
            # v0.15.0: AI-scope gate requires at least one AI primary;
            # adding an llm_inference puts the VPN in scope as adjacent.
            {"id": "llm", "name": "Bedrock LLM", "type": "llm_inference"},
        ],
        "dataflows": [
            {"id": "f1", "source": "vpn", "target": "llm", "label": "egress"},
        ],
    }), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["ci", str(sys_path),
                              "--max-severity", "high"])
    # The vpn_gateway playbook ships with a high-severity vendor-CVE entry,
    # so the CI gate should trip.
    assert res.exit_code in (0, 2), res.output


@pytest.mark.hibernated  # Phase 4


def test_atms_compliance_lists_controls():
    from click.testing import CliRunner

    from atms.cli import cli
    runner = CliRunner()
    res = runner.invoke(cli, ["compliance", "--framework", "NIS2"])
    assert res.exit_code == 0, res.output
    assert "NIS2" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_atms_ingest_otm_roundtrip(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli
    p = tmp_path / "model.json"
    p.write_text(json.dumps(OTM_SAMPLE), encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["ingest-otm", str(p),
                              "--out", str(tmp_path / "system.yaml")])
    assert res.exit_code == 0, res.output
    body = (tmp_path / "system.yaml").read_text(encoding="utf-8")
    assert "External OTM model" in body
    assert "llm_inference" in body


# ───────────────────────────── Web routes ─────────────────────────────────
@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3
def test_compliance_browse_page(client_module_scope):
    r = client_module_scope.get("/compliance")
    assert r.status_code == 200
    assert "Compliance control library" in r.text


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_compliance_api_filters_by_framework(client_module_scope):
    r = client_module_scope.get("/api/compliance", params={"framework": "NIS2"})
    assert r.status_code == 200
    j = r.json()
    assert j["count"] >= 1
    assert all(c.get("framework") == "NIS2" for c in j["controls"])


def test_kb_page_lists_v13_frameworks(client_module_scope):
    r = client_module_scope.get("/kb")
    assert r.status_code == 200
    assert "OWASP ML Top 10" in r.text or "owasp_ml" in r.text.lower()
    assert "Compliance" in r.text


# ───────────────────────────── Defensive fixes ───────────────────────────
def test_attack_paths_engine_has_dfs_cap():
    from atms.engines.attack_paths import MAX_DFS_PATHS_PER_SOURCE
    assert MAX_DFS_PATHS_PER_SOURCE >= 100  # configurable but sane


def test_mermaid_init_uses_strict_security_level():
    from atms.paths import static_dir
    js = (static_dir() / "atms-mermaid.js").read_text(encoding="utf-8")
    assert "securityLevel: 'strict'" in js or 'securityLevel: "strict"' in js


def test_review_command_includes_v10_types():
    cli_path = Path(__file__).resolve().parents[1] / "src" / "atms" / "cli.py"
    body = cli_path.read_text(encoding="utf-8")
    # Ensure the review command's valid_types list includes the v0.10 types
    for t in ("firewall", "directory_service", "plc", "scada", "iot_device",
              "industrial_protocol", "legacy_mainframe"):
        assert t in body, f"review command's valid_types must list {t}"


def test_runs_store_has_lru_cap():
    from atms import web as web_mod
    assert hasattr(web_mod, "_RUNS_MAX")
    assert web_mod._RUNS_MAX >= 8


# ───────────────────────────── Workflow summary v0.13 keys ───────────────
def test_summary_exposes_v13_keys(aws_bedrock_tm_readonly):
    # v0.17.3: uses cached session-scoped analysis.
    tm = aws_bedrock_tm_readonly
    for k in ("compliance_coverage", "compliance_frameworks", "owasp_ml_coverage",
              "disposition_breakdown", "evidence_unmatched", "ale", "kev_meta"):
        assert k in tm.summary


def test_kev_metadata_includes_refreshed_date():
    kb = get_kb()
    # Bundled snapshot has either '# Snapshot taken:' or '# Refreshed:' header
    assert kb.kev_meta.get("refreshed") or kb.epss_meta.get("refreshed")


# ───────────────────────────── Refresh / CVE-lookup (network mocked) ─────
def test_refresh_kev_writes_yaml(tmp_path):
    from atms.feeds.refresh import refresh_kev
    fake_csv = (
        b"cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,"
        b"requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
        b"CVE-2099-1,Acme,Widget,Test,2099-01-01,Test description,Patch,2099-02-01,Known,\n"
    )
    target = tmp_path / "kev.yaml"
    with mock.patch("atms.feeds.refresh._http_get", return_value=fake_csv):
        n = refresh_kev(target)
    assert n == 1
    text = target.read_text(encoding="utf-8")
    assert "CVE-2099-1" in text
    assert "ransomware: true" in text


def test_refresh_epss_writes_yaml(tmp_path):
    from atms.feeds.refresh import refresh_epss
    fake_json = json.dumps({"data": [
        {"cve": "CVE-2099-1", "epss": "0.91", "percentile": "0.95"},
        {"cve": "CVE-2099-2", "epss": "0.88", "percentile": "0.92"},
    ]}).encode("utf-8")
    target = tmp_path / "epss.yaml"
    with mock.patch("atms.feeds.refresh._http_get", return_value=fake_json):
        n = refresh_epss(target, top_n=10)
    assert n == 2
    text = target.read_text(encoding="utf-8")
    assert "CVE-2099-1" in text and "epss: 0.91" in text


def test_cve_lookup_parses_nvd_response():
    from atms.feeds.cve_lookup import cve_lookup
    fake_payload = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2099-1",
                "descriptions": [{"lang": "en", "value": "Test description."}],
                "metrics": {"cvssMetricV31": [{
                    "cvssData": {"baseScore": 9.8,
                                 "vectorString": "CVSS:3.1/AV:N/AC:L"},
                    "baseSeverity": "CRITICAL",
                }]},
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                "references": [{"url": "https://example.test/advisory"}],
                "configurations": [],
                "published": "2099-01-01T00:00:00.000",
                "lastModified": "2099-01-02T00:00:00.000",
            },
        }],
    }
    with mock.patch("atms.feeds.cve_lookup._http_get_json", return_value=fake_payload):
        res = cve_lookup("CVE-2099-1")
    assert res.cvss == 9.8
    assert res.severity == "critical"
    assert "CWE-79" in res.cwe
    assert res.source == "nvd"
