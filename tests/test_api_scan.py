"""Regression tests for v0.18.26 Cycle PP — REST `/api/v1/scan` endpoint.

Pairs with `/api/v1/analyze` (Cycle KK). Same goal — JSON in, JSON
out — but accepts multipart file uploads in any of the 11 input
formats ATMS supports.
"""

from __future__ import annotations

# v0.18.70 Hibernation Phase 3 — entire file exercises a
# hibernated surface. Skipped by default; run with:
#     pytest -m hibernated tests/test_api_scan.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


from fastapi.testclient import TestClient

from atms.web import app

_DRAWIO = b"""<mxfile><diagram><mxGraphModel><root>
<mxCell id="0"/><mxCell id="1" parent="0"/>
<mxCell id="u" value="User" style="shape=actor" vertex="1" parent="1"/>
<mxCell id="api" value="API" style="shape=mxgraph.aws4.api_gateway" vertex="1" parent="1"/>
<mxCell id="bedrock" value="Bedrock" style="shape=mxgraph.aws4.bedrock" vertex="1" parent="1"/>
<mxCell id="e1" edge="1" source="u" target="api" parent="1"/>
<mxCell id="e2" edge="1" source="api" target="bedrock" parent="1"/>
</root></mxGraphModel></diagram></mxfile>"""

_MERMAID = b"""flowchart LR
  user((Customer)) --> api[API Gateway]
  api --> llm[Anthropic Claude API]
"""

_BICEP = b"""
resource kv 'Microsoft.KeyVault/vaults@2022-07-01' = { name: 'mykv' }
resource sql 'Microsoft.Sql/servers@2022-05-01-preview' = { name: 'mysql' }
resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2022-08-15' = { name: 'mycosmos' }
"""

_PULUMI = b"""name: stk
runtime: yaml
resources:
  bucket:
    type: aws:s3:Bucket
  fn:
    type: aws:lambda:Function
  role:
    type: aws:iam:Role
"""

_CFN = b"""AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Lam:
    Type: AWS::Lambda::Function
    Properties: {}
  Bucket:
    Type: AWS::S3::Bucket
    Properties: {}
  Tab:
    Type: AWS::DynamoDB::Table
    Properties: {}
"""

_K8S = b"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
spec:
  template:
    metadata:
      labels: { app: web }
    spec:
      containers:
        - name: web
          image: nginx:1.27
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: app
spec:
  selector: { app: web }
"""

_SYSTEM_YAML = b"""name: sys-yaml-test
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""


# ─── Auto-detect ──────────────────────────────────────────────────
def test_scan_drawio_autodetect():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan", files={"file": ("x.drawio", _DRAWIO, "application/xml")})
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["detected_format"] == "drawio"
    assert len(body["model"]["threats"]) > 0


def test_scan_mermaid_autodetect():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan", files={"file": ("x.mmd", _MERMAID, "text/plain")})
    assert r.status_code == 200, r.text[:300]
    assert r.json()["detected_format"] == "mermaid"


def test_scan_bicep_autodetect():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan", files={"file": ("infra.bicep", _BICEP, "text/plain")})
    assert r.status_code == 200, r.text[:300]
    assert r.json()["detected_format"] == "bicep"


def test_scan_pulumi_autodetect():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan", files={"file": ("Pulumi.yaml", _PULUMI, "text/yaml")})
    assert r.status_code == 200, r.text[:300]
    assert r.json()["detected_format"] == "pulumi"


def test_scan_cloudformation_autodetect():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan", files={"file": ("cfn.yaml", _CFN, "text/yaml")})
    assert r.status_code == 200, r.text[:300]
    assert r.json()["detected_format"] == "cloudformation"


def test_scan_kubernetes_autodetect():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan", files={"file": ("k8s.yaml", _K8S, "text/yaml")})
    assert r.status_code == 200, r.text[:300]
    assert r.json()["detected_format"] == "kubernetes"


def test_scan_system_yaml_autodetect():
    """A `.yaml` with `name:` + `components:` falls through to system-yaml."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan", files={"file": ("sys.yaml", _SYSTEM_YAML, "text/yaml")})
    assert r.status_code == 200
    assert r.json()["detected_format"] == "system-yaml"


# ─── Manual format override ───────────────────────────────────────
def test_scan_explicit_format_override():
    """Caller specifies format; auto-detect is bypassed."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan",
               files={"file": ("untitled", _PULUMI, "text/plain")},
               data={"format": "pulumi"})
    assert r.status_code == 200, r.text[:300]
    assert r.json()["detected_format"] == "pulumi"


def test_scan_unsupported_explicit_format_400():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan",
               files={"file": ("x.bin", b"binary", "application/octet-stream")},
               data={"format": "no-such-format"})
    assert r.status_code == 400


# ─── Errors ───────────────────────────────────────────────────────
def test_scan_unknown_suffix_no_autodetect_400():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan",
               files={"file": ("x.zzz", b"random", "application/octet-stream")})
    assert r.status_code == 400


def test_scan_invalid_methodology_400():
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan",
               files={"file": ("x.drawio", _DRAWIO, "application/xml")},
               data={"methodology": "nonsense"})
    assert r.status_code == 400


def test_scan_response_shape_matches_analyze():
    """The response keys mirror /api/v1/analyze, plus `detected_format`."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/scan", files={"file": ("x.drawio", _DRAWIO, "application/xml")})
    body = r.json()
    for key in ("ok", "version", "summary", "model", "detected_format"):
        assert key in body
    assert body["ok"] is True
    # Model can be re-validated via Pydantic.
    from atms.models import ThreatModel
    ThreatModel.model_validate(body["model"])
