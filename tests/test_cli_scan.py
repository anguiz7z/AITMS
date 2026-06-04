"""Regression tests for v0.18.8 Cycle X — `atms scan` super-command.

Pins the contract that `atms scan FILE` auto-detects the format and
runs the ingest + analyze pipeline in one step.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from atms.cli import cli


def _run_scan(input_path: str, extra_args: list[str] | None = None):
    """Helper: invoke `atms scan` with default formats=json, isolated out dir."""
    args = ["scan", input_path, "--format", "json"]
    if extra_args:
        args.extend(extra_args)
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as out:
        args.extend(["--out", out])
        result = runner.invoke(cli, args)
        # Read the JSON report if the run succeeded.
        report = None
        for p in Path(out).glob("*.json"):
            try:
                report = json.loads(p.read_text(encoding="utf-8"))
                break
            except Exception:  # noqa: BLE001
                pass
        return result, report


# ─── Auto-detect each format ────────────────────────────────────────
def test_scan_detects_drawio(tmp_path):
    p = tmp_path / "x.drawio"
    p.write_text("""<mxfile><diagram><mxGraphModel><root>
        <mxCell id="0"/><mxCell id="1" parent="0"/>
        <mxCell id="u" value="User" style="shape=actor" vertex="1" parent="1"/>
        <mxCell id="lam" value="Lambda" style="shape=mxgraph.aws4.lambda" vertex="1" parent="1"/>
        <mxCell id="e" edge="1" source="u" target="lam" parent="1"/>
    </root></mxGraphModel></diagram></mxfile>""", encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "format=" in res.output
    assert "drawio" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_mermaid(tmp_path):
    p = tmp_path / "x.mmd"
    p.write_text("flowchart LR\n  user[User] --> lam[Lambda]\n", encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "mermaid" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_markdown_with_mermaid_fence(tmp_path):
    p = tmp_path / "README.md"
    p.write_text("""# Arch
```mermaid
flowchart LR
  u[User] --> api[Lambda]
```
""", encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "mermaid" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_cloudformation(tmp_path):
    p = tmp_path / "stack.yaml"
    yaml.safe_dump({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Lam": {"Type": "AWS::Lambda::Function", "Properties": {}},
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
        },
    }, p.open("w", encoding="utf-8"))
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "cloudformation" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_kubernetes(tmp_path):
    p = tmp_path / "manifest.yaml"
    p.write_text("""apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
spec:
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.27
""", encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "kubernetes" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_pulumi_yaml(tmp_path):
    """A `.yaml` file with `runtime: yaml` AND Pulumi-style types
    auto-routes to the Pulumi parser."""
    p = tmp_path / "Pulumi.yaml"
    p.write_text("""name: stack
runtime: yaml
resources:
  bucket:
    type: aws:s3:Bucket
  fn:
    type: aws:lambda:Function
""", encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "pulumi-yaml" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_bicep(tmp_path):
    """`.bicep` files should auto-route to the Bicep parser."""
    p = tmp_path / "infra.bicep"
    p.write_text("""
resource kv 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: 'mykv'
}
resource sql 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: 'mysql'
}
""", encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "bicep" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_arm_template_json(tmp_path):
    """A JSON file with `$schema=deploymentTemplate.json` auto-routes
    to the ARM template parser."""
    import json
    p = tmp_path / "deploy.json"
    p.write_text(json.dumps({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [{
            "type": "Microsoft.KeyVault/vaults",
            "name": "kv1",
            "apiVersion": "2022-07-01",
        }],
    }), encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "arm-template" in res.output


def test_scan_detects_system_yaml(tmp_path):
    """A regular ATMS System YAML falls through to system-yaml."""
    p = tmp_path / "sys.yaml"
    yaml.safe_dump({
        "name": "x",
        "components": [
            {"id": "u", "name": "U", "type": "user"},
            {"id": "llm", "name": "L", "type": "llm_inference"},
        ],
    }, p.open("w", encoding="utf-8"))
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "system-yaml" in res.output


# ─── Auto pure-IT mode ──────────────────────────────────────────────
def test_scan_auto_routes_pure_it_systems():
    """A pure-IT YAML (no AI components) doesn't hit NoAIComponentsError."""
    p = Path(tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ).name)
    yaml.safe_dump({
        "name": "no-ai",
        "components": [
            {"id": "fw", "name": "FW", "type": "firewall"},
            {"id": "db", "name": "DB", "type": "database"},
        ],
    }, p.open("w", encoding="utf-8"))
    try:
        res, report = _run_scan(str(p))
        assert res.exit_code == 0, res.output
        assert "pure-IT mode" in res.output
        assert report is not None
        assert report["threats"], "expected non-empty threats from pure-IT scan"
    finally:
        p.unlink(missing_ok=True)


# ─── Outputs ────────────────────────────────────────────────────────
@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4
def test_scan_writes_full_report_with_default_formats(tmp_path):
    p = tmp_path / "x.mmd"
    p.write_text("flowchart LR\n  user[Customer] --> llm[Bedrock]\n", encoding="utf-8")
    out = tmp_path / "out"
    res = CliRunner().invoke(cli, [
        "scan", str(p), "--out", str(out),
    ])
    assert res.exit_code == 0, res.output
    # All-formats default → expect at least md / html / json / stix.
    assert (out / "x.md").exists()
    assert (out / "x.html").exists()
    assert (out / "x.json").exists()


def test_scan_help_documents_supported_formats():
    res = CliRunner().invoke(cli, ["scan", "--help"])
    assert res.exit_code == 0
    for ext in (".drawio", ".mermaid", ".vsdx", ".tf", ".yaml"):
        assert ext in res.output, f"--help should mention {ext}"


def test_scan_rejects_unsupported_extension(tmp_path):
    p = tmp_path / "weird.bin"
    p.write_bytes(b"\x00\x01\x02")
    res, _ = _run_scan(str(p))
    assert res.exit_code != 0
    assert "Unsupported" in res.output
