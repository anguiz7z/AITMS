"""Regression tests for v0.18.41 Cycle EEE — Microsoft Threat Modeling Tool (.tm7) ingest."""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_cycle_eee_tm7_ingest.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


from pathlib import Path

import pytest
from click.testing import CliRunner

from atms.cli import cli
from atms.ingest.tm7 import tm7_to_system

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLE = FIXTURES / "sample.tm7"


def test_tm7_fixture_exists():
    """Sanity: the bundled synthetic TM7 fixture is present."""
    assert SAMPLE.exists(), f"missing fixture: {SAMPLE}"


def test_tm7_parses_into_system():
    s = tm7_to_system(path=SAMPLE)
    assert len(s.components) == 7
    assert len(s.dataflows) == 6
    assert len(s.trust_boundaries) == 1


def test_tm7_stencil_shape_maps_to_component_type():
    """StencilRectangle → user, StencilEllipse → web/process default,
    StencilParallelLines → data store default."""
    s = tm7_to_system(path=SAMPLE)
    types = {c.id: c.type for c in s.components}
    assert types["customer_browser"] == "user"            # rectangle
    assert types["waf"] == "waf"                          # ellipse + 'WAF' keyword
    assert types["api_gateway"] == "api_gateway"          # ellipse + 'API Gateway'
    assert types["order_service_lambda"] == "serverless_function"  # 'Lambda'
    assert types["rds_sql_database"] == "database"        # parallel lines, SQL
    assert types["s3_uploads_bucket"] == "object_storage" # parallel lines, S3
    assert types["aws_secrets_manager_vault"] == "secrets_vault"  # vault


def test_tm7_connectors_become_dataflows():
    s = tm7_to_system(path=SAMPLE)
    edges = {(df.source, df.target) for df in s.dataflows}
    assert ("customer_browser", "waf") in edges
    assert ("waf", "api_gateway") in edges
    assert ("api_gateway", "order_service_lambda") in edges
    assert ("order_service_lambda", "rds_sql_database") in edges


def test_tm7_dataflow_label_extracted_from_properties():
    s = tm7_to_system(path=SAMPLE)
    by_pair = {(df.source, df.target): df.label for df in s.dataflows}
    # The first connector has a HeaderDisplayAttribute "HTTPS request"
    assert by_pair[("customer_browser", "waf")] == "HTTPS request"


def test_tm7_boundary_emitted():
    s = tm7_to_system(path=SAMPLE)
    assert s.trust_boundaries[0].id == "internet_boundary"
    assert s.trust_boundaries[0].type == "network"


def test_tm7_component_metadata_carries_guid_and_shape():
    s = tm7_to_system(path=SAMPLE)
    by_id = {c.id: c for c in s.components}
    md = by_id["waf"].metadata
    assert md["source"] == "tm7"
    assert md["tm7_shape"] == "StencilEllipse"
    assert md["tm7_guid"].startswith("00000000-")


def test_tm7_rejects_non_tm7_xml():
    with pytest.raises(ValueError, match="ThreatModel"):
        tm7_to_system(text="<NotAThreatModel/>")


def test_tm7_rejects_malformed_xml():
    with pytest.raises(ValueError, match="parse error"):
        tm7_to_system(text="<not-xml<<")


def test_tm7_full_pipeline_emits_threats():
    """End-to-end: parsed TM7 → analyze() produces threats."""
    from atms.workflow import analyze
    s = tm7_to_system(path=SAMPLE)
    m = analyze(s, require_ai_components=False)
    assert len(m.threats) >= 20  # 7 typed components should generate plenty


def test_scan_detects_tm7_extension(tmp_path):
    """`atms scan foo.tm7` auto-routes to the TM7 parser."""
    target = tmp_path / "sample.tm7"
    target.write_bytes(SAMPLE.read_bytes())
    runner = CliRunner()
    res = runner.invoke(cli, ["scan", str(target), "--format", "md"])
    assert res.exit_code == 0, res.output
    assert "tm7" in res.output.lower()


def test_ingest_tm7_cli_command_renders_yaml(tmp_path):
    """`atms ingest-tm7 sample.tm7 --out sys.yaml` round-trips cleanly."""
    target = tmp_path / "out.yaml"
    runner = CliRunner()
    res = runner.invoke(cli, ["ingest-tm7", str(SAMPLE), "--out", str(target)])
    assert res.exit_code == 0, res.output
    assert target.exists()
    text = target.read_text(encoding="utf-8")
    assert "components:" in text
    assert "customer_browser" in text
