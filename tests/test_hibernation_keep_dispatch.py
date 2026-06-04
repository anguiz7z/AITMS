"""Bug-fix regression (v0.18.73) — KEEP auto-detect surfaces must refuse
hibernated formats GRACEFULLY, not crash.

The hibernation work (v0.18.68-72) gated every parser entry point with
``@gated`` so it raises ``FeatureDisabledError`` when its flag is off.
Three KEEP surfaces auto-detect the input format and dispatch directly
to the matching parser:

  * ``atms scan <file>``    (CLI, KEEP) — suffix dispatch in scan_cmd
  * ``atms ingest <file>``  (CLI, KEEP) — suffix dispatch in ingest
  * web ``POST /ingest``    (KEEP)      — suffix dispatch in ingest_diagram

Audit found:
  - CLI scan/ingest on a hibernated format (Terraform, mermaid, vsdx, …)
    let ``FeatureDisabledError`` escape as a raw Python traceback.
  - The web route was ALREADY graceful: its broad ``except Exception``
    renders a friendly 400 "Could not parse diagram: …" page whose
    message includes the re-enable hint. This test LOCKS that so it
    can't regress to a 500.

Fix: ``features.graceful_hibernation`` decorator wraps the two KEEP CLI
commands → ``FeatureDisabledError`` becomes a clean ``click.UsageError``
(exit 2, the re-enable hint, no traceback).

KEEP formats (System YAML + drawio) must keep working end-to-end. Runs
in the DEFAULT suite (flags off) — the contract a shipping user sees.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from fastapi.testclient import TestClient

from atms.cli import cli
from atms.web import app

_DRAWIO = (
    b'<mxfile><diagram><mxGraphModel><root>'
    b'<mxCell id="0"/><mxCell id="1" parent="0"/>'
    b'<mxCell id="2" value="LLM" vertex="1" parent="1"><mxGeometry/></mxCell>'
    b'</root></mxGraphModel></diagram></mxfile>'
)
_MERMAID = b"graph TD\n  A[User] --> B[LLM]\n"
_TERRAFORM = b'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'


# ─── CLI scan ───────────────────────────────────────────────────────


def test_cli_scan_terraform_now_parses(tmp_path):
    """v1.0.1: Terraform ingest is ENABLED by default — `atms scan x.tf`
    parses + analyses cleanly, no hibernation hint, no traceback."""
    f = tmp_path / "x.tf"
    f.write_bytes(_TERRAFORM)
    r = CliRunner().invoke(cli, ["scan", str(f), "--out", str(tmp_path / "o")])
    assert r.exit_code == 0, f"terraform scan failed: {r.output}"
    assert "hibernated" not in r.output.lower()
    assert "Traceback (most recent call last)" not in r.output


def test_cli_scan_terraform_off_refuses_cleanly(tmp_path, monkeypatch):
    """Reversibility: ATMS_FEATURE_INGEST_TERRAFORM=0 → clean UsageError
    with the re-enable hint, not a traceback."""
    monkeypatch.setenv("ATMS_FEATURE_INGEST_TERRAFORM", "0")
    f = tmp_path / "x.tf"
    f.write_bytes(_TERRAFORM)
    r = CliRunner().invoke(cli, ["scan", str(f), "--out", str(tmp_path / "o")])
    assert r.exit_code != 0
    assert "hibernated" in r.output.lower()
    assert "ATMS_FEATURE_INGEST_TERRAFORM" in r.output
    assert "Traceback (most recent call last)" not in r.output


def test_cli_scan_keep_system_yaml_still_works(tmp_path):
    """KEEP System YAML still scans + analyses."""
    sample = Path(__file__).resolve().parents[1] / "samples" / "rag_system.yaml"
    r = CliRunner().invoke(cli, ["scan", str(sample), "--out", str(tmp_path / "o")])
    assert r.exit_code == 0, f"KEEP YAML scan failed: {r.output}"
    assert "system-yaml" in r.output.lower()


def test_cli_scan_keep_drawio_still_works(tmp_path):
    """KEEP drawio still scans + analyses."""
    f = tmp_path / "d.drawio"
    f.write_bytes(_DRAWIO)
    r = CliRunner().invoke(cli, ["scan", str(f), "--out", str(tmp_path / "o")])
    assert r.exit_code == 0, f"KEEP drawio scan failed: {r.output}"
    assert "drawio" in r.output.lower()


# ─── CLI ingest ─────────────────────────────────────────────────────


def test_cli_ingest_mermaid_now_parses(tmp_path):
    """v1.0.1: Mermaid ingest is ENABLED by default — `atms ingest x.mmd`
    emits a System YAML, no hibernation hint, no traceback."""
    f = tmp_path / "x.mmd"
    f.write_bytes(_MERMAID)
    out = tmp_path / "o.yaml"
    r = CliRunner().invoke(cli, ["ingest", str(f), "--out", str(out)])
    assert r.exit_code == 0, f"mermaid ingest failed: {r.output}"
    assert "hibernated" not in r.output.lower()
    assert "Traceback (most recent call last)" not in r.output


def test_cli_ingest_keep_drawio_still_works(tmp_path):
    """KEEP drawio ingest emits a System YAML file."""
    f = tmp_path / "d.drawio"
    f.write_bytes(_DRAWIO)
    out = tmp_path / "out.yaml"
    r = CliRunner().invoke(cli, ["ingest", str(f), "--out", str(out)])
    assert r.exit_code == 0, f"KEEP drawio ingest failed: {r.output}"
    assert out.exists()


# ─── Web /ingest (field name is `diagram`; route already degrades) ──


def test_web_ingest_mermaid_now_renders_editor():
    """v1.0.1: mermaid upload is ENABLED — the route parses it and renders
    the editor (200), never a 500, no hibernation message."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/ingest", files={"diagram": ("d.mmd", _MERMAID, "text/plain")})
    assert r.status_code == 200, f"mermaid upload returned {r.status_code}"
    assert "hibernated" not in r.text.lower()


def test_web_ingest_keep_drawio_still_200():
    """KEEP drawio upload still renders the editor (200)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/ingest", files={"diagram": ("d.drawio", _DRAWIO, "application/xml")})
    assert r.status_code == 200


# ─── Re-enable restores the format end-to-end ───────────────────────


def test_env_override_restores_scan_terraform(tmp_path, monkeypatch):
    """ATMS_FEATURE_INGEST_TERRAFORM=1 makes the same scan succeed —
    proving the refusal is purely the flag, not a broken parser."""
    monkeypatch.setenv("ATMS_FEATURE_INGEST_TERRAFORM", "1")
    f = tmp_path / "x.tf"
    f.write_bytes(_TERRAFORM)
    r = CliRunner().invoke(cli, ["scan", str(f), "--out", str(tmp_path / "o")])
    assert r.exit_code == 0, f"re-enabled terraform scan failed: {r.output}"
    assert "terraform" in r.output.lower()
