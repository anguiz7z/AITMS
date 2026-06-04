"""Regression tests for v0.18.18 Cycle HH — Pulumi YAML ingest."""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_pulumi_yaml_ingest.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import pytest

from atms.ingest.pulumi_yaml import pulumi_to_system

_AWS_SAMPLE = """
name: aws-demo
runtime: yaml
resources:
  bucket:
    type: aws:s3:Bucket
    properties:
      acl: private
  func:
    type: aws:lambda:Function
    properties:
      role: ${role.arn}
      environment:
        BUCKET: ${bucket.id}
  role:
    type: aws:iam:Role
  vpc:
    type: aws:ec2:Vpc
    properties:
      cidrBlock: 10.0.0.0/16
  kms:
    type: aws:kms:Key
  rds:
    type: aws:rds:Instance
    properties:
      kmsKeyId: ${kms.arn}
  bedrock:
    type: aws:bedrock:Model
  waf:
    type: aws:wafv2:WebAcl
"""

_AZURE_SAMPLE = """
name: azure-demo
runtime: yaml
resources:
  stg:
    type: azure-native:storage:StorageAccount
  app:
    type: azure-native:web:WebApp
    properties:
      serverFarmId: ${plan.id}
  plan:
    type: azure-native:web:AppServicePlan
  kv:
    type: azure-native:keyvault:Vault
  aoai:
    type: azure-native:cognitiveservices:Account
"""

_GCP_SAMPLE = """
name: gcp-demo
runtime: yaml
resources:
  bucket:
    type: gcp:storage:Bucket
  fn:
    type: gcp:cloudfunctions:Function
    properties:
      bucket: ${bucket.name}
  bq:
    type: gcp:bigquery:Dataset
  vertex_model:
    type: gcp:aiplatform:Model
"""

_K8S_SAMPLE = """
name: k8s-demo
runtime: yaml
resources:
  web_dep:
    type: kubernetes:apps/v1:Deployment
  web_svc:
    type: kubernetes:core/v1:Service
  cron:
    type: kubernetes:batch/v1:CronJob
"""


# ─── Basic mapping ─────────────────────────────────────────────────
def test_aws_resources_mapped():
    s = pulumi_to_system(text=_AWS_SAMPLE)
    types = {c.id: c.type for c in s.components}
    assert types["bucket"] == "object_storage"
    assert types["func"] == "serverless_function"
    assert types["role"] == "iam_principal"
    assert types["vpc"] == "network_segment"
    assert types["kms"] == "kms_key"
    assert types["rds"] == "database"
    assert types["bedrock"] == "llm_inference"
    assert types["waf"] == "waf"


def test_azure_resources_mapped():
    s = pulumi_to_system(text=_AZURE_SAMPLE)
    types = {c.id: c.type for c in s.components}
    assert types["stg"] == "object_storage"
    assert types["app"] == "web_application"
    assert types["plan"] == "cloud_compute"
    assert types["kv"] == "secrets_vault"
    assert types["aoai"] == "llm_inference"


def test_gcp_resources_mapped():
    s = pulumi_to_system(text=_GCP_SAMPLE)
    types = {c.id: c.type for c in s.components}
    assert types["bucket"] == "object_storage"
    assert types["fn"] == "serverless_function"
    assert types["bq"] == "data_warehouse"
    assert types["vertex_model"] == "ml_inference_endpoint"


def test_k8s_resources_mapped():
    s = pulumi_to_system(text=_K8S_SAMPLE)
    types = {c.id: c.type for c in s.components}
    assert types["web_dep"] == "container_runtime"
    assert types["web_svc"] == "load_balancer"
    assert types["cron"] == "batch_compute"


# ─── References / dataflows ────────────────────────────────────────
def test_template_refs_become_dataflows():
    s = pulumi_to_system(text=_AWS_SAMPLE)
    edges = {(df.source, df.target) for df in s.dataflows}
    assert ("func", "role") in edges
    assert ("func", "bucket") in edges
    assert ("rds", "kms") in edges


def test_dataflows_deduplicated():
    src = """
    name: dup
    runtime: yaml
    resources:
      a:
        type: aws:s3:Bucket
      b:
        type: aws:lambda:Function
        properties:
          env:
            x: ${a.id}
            y: ${a.arn}
            z: ${a.name}
    """
    s = pulumi_to_system(text=src)
    edges = [(df.source, df.target) for df in s.dataflows]
    assert edges.count(("b", "a")) == 1


# ─── Trust boundaries ──────────────────────────────────────────────
def test_vpc_creates_trust_boundary():
    s = pulumi_to_system(text=_AWS_SAMPLE)
    boundary_ids = {b.id for b in s.trust_boundaries}
    assert "pulumi:vpc" in boundary_ids
    assert s.trust_boundaries[0].type == "network"


def test_azure_vnet_creates_trust_boundary():
    src = """
    name: x
    runtime: yaml
    resources:
      vn:
        type: azure-native:network:VirtualNetwork
    """
    s = pulumi_to_system(text=src)
    assert len(s.trust_boundaries) == 1


# ─── Edge cases ────────────────────────────────────────────────────
def test_unknown_type_falls_back_to_other():
    src = """
    name: x
    runtime: yaml
    resources:
      weird:
        type: aws:unknown:Resource
    """
    s = pulumi_to_system(text=src)
    assert s.components[0].type == "other"


def test_empty_resources_raises():
    src = """
    name: x
    runtime: yaml
    resources: {}
    """
    with pytest.raises(ValueError, match="no `resources:"):
        pulumi_to_system(text=src)


def test_invalid_yaml_raises():
    src = "this is not: : valid yaml: ["
    with pytest.raises(ValueError, match="parse error"):
        pulumi_to_system(text=src)


def test_stack_name_picked_from_yaml():
    s = pulumi_to_system(text=_AWS_SAMPLE)
    assert s.name == "aws-demo"


def test_system_name_override():
    s = pulumi_to_system(text=_AWS_SAMPLE, system_name="custom")
    assert s.name == "custom"


def test_resource_metadata_carries_pulumi_type():
    s = pulumi_to_system(text=_AWS_SAMPLE)
    by_id = {c.id: c for c in s.components}
    assert by_id["bucket"].metadata.get("pulumi_type") == "aws:s3:Bucket"
    assert by_id["bucket"].metadata.get("source") == "pulumi-yaml"


def test_typescript_pulumi_program_rejected_with_helpful_message(tmp_path):
    """A Pulumi TS file isn't YAML; raise with a hint."""
    p = tmp_path / "index.ts"
    p.write_text("import * as aws from '@pulumi/aws';\nconst b = new aws.s3.Bucket('b');", encoding="utf-8")
    with pytest.raises(ValueError):
        pulumi_to_system(path=str(p))


# ─── Path vs text ──────────────────────────────────────────────────
def test_path_input_works(tmp_path):
    p = tmp_path / "Pulumi.yaml"
    p.write_text(_AWS_SAMPLE, encoding="utf-8")
    s = pulumi_to_system(path=p)
    assert len(s.components) == 8


def test_no_input_raises():
    with pytest.raises(ValueError, match="Provide either"):
        pulumi_to_system()
