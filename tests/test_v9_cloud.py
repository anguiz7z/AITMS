"""Tests for v0.9 — cloud component types + OWASP API Top 10 + MITRE ATT&CK Cloud."""

from __future__ import annotations

from pathlib import Path

import pytest

from atms.engines.maestro import DEFAULT_LAYER_MAP
from atms.kb import get_kb
from atms.models import Component, Dataflow, System, Threat
from atms.workflow import analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"

CLOUD_TYPES = [
    "iam_principal",
    "secrets_vault",
    "object_storage",
    "network_segment",
    "serverless_function",
    "api_gateway",
    "container_runtime",
    "kms_key",
    "message_queue",
    "observability_stack",
]


# ───────────────────────────────────────────────────────────── KB
def test_owasp_api_kb_loaded():
    kb = get_kb()
    assert len(kb.owasp_api) == 10
    for n in range(1, 11):
        assert f"API{n}:2023" in kb.owasp_api
    # Spot-check a couple
    assert kb.owasp_api["API1:2023"]["title"] == "Broken Object Level Authorization"
    assert kb.owasp_api["API4:2023"]["short"] == "resource_consumption"


def test_attack_cloud_kb_loaded():
    kb = get_kb()
    # >= 25 techniques in the curated subset
    assert len(kb.attack_cloud) >= 25
    # Well-known cloud-specific IDs must be present
    for tid in ["T1078.004", "T1530", "T1552.005", "T1496", "T1098.001"]:
        assert tid in kb.attack_cloud, f"missing canonical technique {tid}"


def test_cloud_playbooks_loaded():
    kb = get_kb()
    for ctype in CLOUD_TYPES:
        assert ctype in kb.playbooks, f"playbook missing for {ctype}"
        assert len(kb.playbooks[ctype]["threats"]) >= 3


def test_kb_search_owasp_api(kb_obj=None):
    kb = kb_obj or get_kb()
    results = kb.search("broken object", framework="owasp_api", limit=5)
    assert any(r["id"] == "API1:2023" for r in results)


def test_kb_search_attack_cloud():
    kb = get_kb()
    results = kb.search("instance metadata", framework="attack_cloud", limit=5)
    ids = {r["id"] for r in results}
    assert "T1552.005" in ids


# ───────────────────────────────────────────────────────────── Models
def test_component_type_literal_extended():
    """The Pydantic literal must accept all 10 new cloud component types."""
    for ctype in CLOUD_TYPES:
        # If literal didn't accept the value, model_validate would raise.
        c = Component(id="x", name="x", type=ctype)
        assert c.type == ctype


def test_threat_has_new_framework_fields():
    t = Threat(
        id="t1", component_id="c", title="t", description="x",
        likelihood=3, impact=3,
    )
    # New v0.9 fields default to empty list (no validation crash).
    assert t.owasp_api == []
    assert t.attack_cloud == []


# ───────────────────────────────────────────────────────────── MAESTRO mapping
def test_maestro_layer_map_covers_all_cloud_types():
    """Every cloud component type must have at least one MAESTRO layer."""
    for ctype in CLOUD_TYPES:
        assert ctype in DEFAULT_LAYER_MAP, f"{ctype} not in DEFAULT_LAYER_MAP"
        layers = DEFAULT_LAYER_MAP[ctype]
        assert len(layers) >= 1, f"{ctype} has no MAESTRO layers"
        # Most cloud components live in L4; observability lives in L5 + L6.
        # We just require A layer; specific layer choice depends on the type.
        assert any(layer.startswith("M.L") for layer in layers), \
            f"{ctype} layers must look like M.LN: {layers!r}"


# ───────────────────────────────────────────────────────────── Enrichment engine
@pytest.fixture
def cloud_only_system() -> System:
    """A small all-cloud system to exercise the enrichment engine.

    v0.15.0: now includes an `llm_inference` so the AI-scope gate
    accepts it. The cloud components remain AI-adjacent and exercise
    the cloud enricher unchanged.
    """
    return System(
        name="cloud-mini",
        components=[
            Component(id="llm", name="Bedrock LLM", type="llm_inference", trust_zone="aws_internal"),
            Component(id="gw", name="API gateway", type="api_gateway", trust_zone="internet"),
            Component(id="lam", name="Lambda", type="serverless_function", trust_zone="aws_dmz"),
            Component(id="s3", name="S3 bucket", type="object_storage", trust_zone="aws_internal"),
            Component(id="iam", name="IAM role", type="iam_principal", trust_zone="aws_internal"),
            Component(id="kms", name="KMS key", type="kms_key", trust_zone="aws_internal"),
        ],
        dataflows=[
            Dataflow(id="1", source="gw", target="lam", label="invoke"),
            Dataflow(id="2", source="lam", target="llm", label="prompt"),
            Dataflow(id="3", source="llm", target="s3", label="write log"),
            Dataflow(id="4", source="iam", target="lam", label="assume role"),
            Dataflow(id="5", source="lam", target="kms", label="decrypt"),
        ],
    )


def test_cloud_engine_enriches_threats(cloud_only_system):
    tm = analyze(cloud_only_system)
    # API-gateway threats should pick up at least a few OWASP API IDs
    api_threats = [t for t in tm.threats if t.component_id == "gw"]
    assert any(t.owasp_api for t in api_threats), \
        "expected at least one api_gateway threat to be tagged with an OWASP API ID"
    # Some threat across the system should have an ATT&CK Cloud technique
    assert any(t.attack_cloud for t in tm.threats), \
        "expected at least one threat to be tagged with an ATT&CK Cloud technique"


def test_summary_exposes_new_coverage_keys(aws_bedrock_tm_readonly):
    # v0.17.3: uses cached session-scoped analysis (was: 0.78 s call).
    tm = aws_bedrock_tm_readonly
    assert "owasp_api_coverage" in tm.summary
    assert "attack_cloud_coverage" in tm.summary
    # The AWS sample should hit a healthy slice of both
    assert len(tm.summary["owasp_api_coverage"]) >= 5
    assert len(tm.summary["attack_cloud_coverage"]) >= 5


# ───────────────────────────────────────────────────────────── Cloud samples
def test_aws_bedrock_sample_loads_and_analyses(aws_bedrock_tm_readonly):
    # v0.17.3: uses cached session-scoped analysis.
    tm = aws_bedrock_tm_readonly
    assert len(tm.system.components) >= 18
    # Big system → big threat surface
    assert len(tm.threats) >= 80
    # Cloud-specific frameworks lit up
    assert len(tm.summary["owasp_api_coverage"]) >= 7
    assert len(tm.summary["attack_cloud_coverage"]) >= 10


def test_azure_openai_rag_sample_loads_and_analyses(azure_openai_rag_tm_readonly):
    # v0.17.3: uses cached session-scoped analysis.
    tm = azure_openai_rag_tm_readonly
    assert len(tm.system.components) >= 18
    assert len(tm.threats) >= 70
    assert len(tm.summary["owasp_api_coverage"]) >= 5
    assert len(tm.summary["attack_cloud_coverage"]) >= 8


# ───────────────────────────────────────────────────────────── Visio classifier
def test_vsdx_classifier_picks_cloud_stencils():
    """Sanity test that cloud-stencil regexes resolve to cloud component types."""
    from atms.ingest.vsdx import _classify

    cases = [
        ("AWS Lambda", "serverless_function"),
        ("Azure Functions", "serverless_function"),
        ("Cloud Run", "serverless_function"),
        ("S3 bucket", "object_storage"),
        ("Azure Blob Storage", "object_storage"),
        ("API Gateway", "api_gateway"),
        ("Azure API Management", "api_gateway"),
        ("AWS Secrets Manager", "secrets_vault"),
        ("Azure Key Vault", "secrets_vault"),
        ("VPC private subnet", "network_segment"),
        ("EKS cluster", "container_runtime"),
        ("AKS cluster", "container_runtime"),
        ("AWS KMS", "kms_key"),
        ("SQS queue", "message_queue"),
        ("Azure Service Bus", "message_queue"),
        ("CloudWatch logs", "observability_stack"),
        ("Application Insights", "observability_stack"),
        ("IAM role for orchestrator", "iam_principal"),
        ("Service principal", "iam_principal"),
    ]
    for label, expected in cases:
        actual = _classify(label)
        assert actual == expected, f"{label!r} → {actual!r} (expected {expected!r})"


# ───────────────────────────────────────────────────────────── CLI
def test_kb_search_cli_accepts_v9_frameworks():
    """The CLI choice list must include owasp_api and attack_cloud."""
    from click.testing import CliRunner

    from atms.cli import cli

    for fw in ["owasp_api", "attack_cloud"]:
        res = CliRunner().invoke(cli, ["kb-search", "credential", "--framework", fw, "--limit", "1"])
        assert res.exit_code == 0, f"--framework {fw} failed: {res.output}"


# ───────────────────────────────────────────────────────────── Reports
def test_html_report_has_v9_columns(aws_bedrock_tm_readonly):
    """The standalone HTML report must include OWASP API + ATT&CK Cloud metric tiles."""
    from atms.reporting import render_html

    # v0.17.3: uses cached session-scoped analysis.
    tm = aws_bedrock_tm_readonly
    html = render_html(tm)
    assert "OWASP API" in html
    assert "ATT&amp;CK Cloud" in html or "ATT&CK Cloud" in html
    # At least one OWASP API ID and one ATT&CK technique should appear as a pill
    assert "API1:2023" in html or "API2:2023" in html or "API4:2023" in html
    # ATT&CK technique IDs follow Txxxx pattern
    import re
    assert re.search(r"\bT\d{4}\b", html), "no ATT&CK Cloud technique id in HTML"


def test_markdown_report_has_v9_sections(aws_bedrock_tm_readonly):
    from atms.reporting import render_markdown

    # v0.17.3: uses cached session-scoped analysis.
    tm = aws_bedrock_tm_readonly
    md = render_markdown(tm)
    assert "OWASP API Security Top 10" in md
    assert "ATT&CK Cloud" in md


# ───────────────────────────────────────────────────────────── Web UI
def test_web_kb_dropdown_has_owasp_api(client_module_scope):
    r = client_module_scope.get("/kb")
    assert r.status_code == 200
    assert "OWASP API Security Top 10" in r.text
    assert "MITRE ATT&CK Cloud" in r.text or "ATT&amp;CK Cloud" in r.text


def test_web_kb_search_owasp_api_via_query(client_module_scope):
    r = client_module_scope.get("/kb", params={"q": "broken object", "framework": "owasp_api"})
    assert r.status_code == 200
    assert "API1:2023" in r.text


def test_web_analyze_cloud_sample(client_module_scope):
    """Posting an AWS-Bedrock sample to /analyze produces the inline report with v0.9 metrics."""
    yaml_text = (SAMPLES / "aws_bedrock_agent.yaml").read_text(encoding="utf-8")
    r = client_module_scope.post("/analyze", data={"yaml": yaml_text})
    assert r.status_code == 200
    assert "OWASP API" in r.text
    assert "ATT&amp;CK Cloud" in r.text or "ATT&CK Cloud" in r.text
