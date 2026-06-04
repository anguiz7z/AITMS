"""Tests for the .vsdx → System ingestion path."""

from __future__ import annotations

import html
import re
import zipfile
from pathlib import Path

import pytest
import yaml

from atms.ingest.vsdx import vsdx_to_system, vsdx_to_system_yaml
from atms.models import System
from atms.workflow import analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
VSDX = SAMPLES / "test_diagram.vsdx"


def test_test_diagram_present():
    assert VSDX.exists(), "samples/test_diagram.vsdx is missing — run scripts to regenerate"


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_vsdx_to_system_basic():
    s = vsdx_to_system(VSDX)
    assert isinstance(s, System)
    assert len(s.components) >= 3
    types = {c.type for c in s.components}
    # Heuristic-based classification should pick out user/agent/vector store
    assert "user" in types
    assert "agent" in types
    assert "rag_vector_store" in types


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_vsdx_dataflows_extracted():
    s = vsdx_to_system(VSDX)
    assert len(s.dataflows) >= 1
    # Every dataflow source/target must reference a real component id
    ids = {c.id for c in s.components}
    for d in s.dataflows:
        assert d.source in ids
        assert d.target in ids


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_vsdx_to_yaml_roundtrip():
    yaml_str = vsdx_to_system_yaml(VSDX)
    parsed = yaml.safe_load(yaml_str)
    s = System.model_validate(parsed)
    assert len(s.components) >= 3


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_vsdx_pipeline_full_analysis():
    """The whole point of this feature: VSDX → System → ThreatModel."""
    s = vsdx_to_system(VSDX)
    tm = analyze(s)
    assert len(tm.threats) >= 5
    # The vector store + agent components should produce OWASP LLM hits
    assert len(tm.summary["owasp_coverage"]) >= 3
    assert len(tm.summary["maestro_layers"]) >= 1


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_vsdx_rejects_vsd():
    with pytest.raises(ValueError, match="Legacy"):
        vsdx_to_system("foo.vsd")


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_vsdx_rejects_unknown_format():
    with pytest.raises(ValueError, match="Unsupported"):
        vsdx_to_system("foo.png")


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_vsdx_rejects_missing_file():
    with pytest.raises(FileNotFoundError):
        vsdx_to_system("/no/such/file.vsdx")


def test_vsdx_rejects_malformed_zip(tmp_path):
    """A .vsdx that's a zip but not a Visio doc should error, not crash."""
    bad = tmp_path / "fake.vsdx"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("hello.txt", "not a visio")
    with pytest.raises(Exception):
        vsdx_to_system(bad)


# ─────────────────────────────────────────────────────────── Web upload flow
def _extract_yaml_from_html(html_text: str) -> str:
    m = re.search(r'<textarea[^>]*name="yaml"[^>]*>(.*?)</textarea>', html_text, re.DOTALL)
    assert m, "no yaml textarea in response"
    return html.unescape(m.group(1))


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_web_ingest_then_analyze(client_module_scope):
    c = client_module_scope
    with VSDX.open("rb") as f:
        r = c.post("/ingest", files={"diagram": ("test_diagram.vsdx", f)})
    assert r.status_code == 200
    yaml_text = _extract_yaml_from_html(r.text)
    assert "support_agent_langgraph" in yaml_text or "agent" in yaml_text

    r2 = c.post("/analyze", data={"yaml": yaml_text})
    assert r2.status_code == 200
    assert "Threats" in r2.text


def test_web_ingest_rejects_vsd(client_module_scope):
    r = client_module_scope.post("/ingest", files={"diagram": ("foo.vsd", b"")})
    assert r.status_code == 400


def test_web_ingest_rejects_other_extensions(client_module_scope):
    r = client_module_scope.post("/ingest", files={"diagram": ("foo.txt", b"")})
    assert r.status_code == 400


def test_web_ingest_oversize(client_module_scope):
    big = b"x" * (11 * 1024 * 1024)
    r = client_module_scope.post("/ingest", files={"diagram": ("big.vsdx", big)})
    assert r.status_code == 413


# ─────────────────────────────────────────────────────────── CLI
@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4
def test_cli_ingest_writes_yaml(tmp_path):
    from click.testing import CliRunner

    from atms.cli import cli

    out = tmp_path / "out.yaml"
    result = CliRunner().invoke(
        cli, ["ingest", str(VSDX), "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
    s = System.model_validate(parsed)
    assert len(s.components) >= 3


def test_cli_ingest_rejects_vsd():
    from click.testing import CliRunner

    from atms.cli import cli

    # Build a fake .vsd file (just touch a path with that suffix)
    with CliRunner().isolated_filesystem() as tmp:
        p = Path(tmp) / "foo.vsd"
        p.write_bytes(b"")
        result = CliRunner().invoke(cli, ["ingest", str(p)])
        assert result.exit_code == 2
        assert "Legacy .vsd" in result.output


# ─────────────────────────────────────────── Risk #3: data classification + vague labels
def test_data_classification_sensitive_keywords():
    from atms.ingest.vsdx import _classify_data

    assert _classify_data("api key") == "restricted"
    assert _classify_data("password reset") == "restricted"
    assert _classify_data("PII lookup") == "confidential"
    assert _classify_data("customer data") == "confidential"
    assert _classify_data("public docs") == "public"
    assert _classify_data("user prompt") == "internal"
    assert _classify_data("") == "internal"


def test_vague_label_detection():
    from atms.ingest.vsdx import is_vague_label

    assert is_vague_label("")
    assert is_vague_label("->")
    assert is_vague_label("→")
    assert is_vague_label("connector")
    assert is_vague_label("LINE")
    assert not is_vague_label("user prompt")
    assert not is_vague_label("PII lookup")


def test_vague_dataflows_helper():
    from atms.ingest.vsdx import vague_dataflows
    from atms.models import Component, Dataflow, System

    s = System(
        name="t",
        components=[
            Component(id="a", name="a", type="user"),
            Component(id="b", name="b", type="agent"),
        ],
        dataflows=[
            Dataflow(source="a", target="b", label="user prompt"),
            Dataflow(source="a", target="b", label="->"),
            Dataflow(source="a", target="b", label=""),
        ],
    )
    flows = vague_dataflows(s)
    assert len(flows) == 2  # the meaningful "user prompt" excluded


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_cli_ingest_classification_in_yaml(tmp_path):
    """End-to-end: parsed YAML carries the inferred data_classification."""
    from click.testing import CliRunner

    from atms.cli import cli

    out = tmp_path / "out.yaml"
    result = CliRunner().invoke(cli, ["ingest", str(VSDX), "--out", str(out)])
    assert result.exit_code == 0
    parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
    classifications = {df["data_classification"] for df in parsed.get("dataflows", [])}
    # At least 'internal' should be present for the test diagram (user prompt / retrieval query)
    assert classifications  # non-empty
