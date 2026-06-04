"""Tests for the v0.14 IaC sample fixtures.

Ensures the bundled `samples/iac/docker-compose.yml` and `samples/iac/main.tf`
keep parsing cleanly across releases. Without these, the IaC ingest path
isn't part of `atms selftest` — by project convention "samples/ is part
of the test suite", so this is the round-trip guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from atms.ingest.docker_compose import parse_docker_compose
from atms.ingest.terraform import parse_terraform
from atms.workflow import analyze

SAMPLES_IAC = Path(__file__).resolve().parents[1] / "samples" / "iac"


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_compose_sample_loads_and_classifies():
    sys_obj = parse_docker_compose(SAMPLES_IAC / "docker-compose.yml")
    assert len(sys_obj.components) >= 9
    by_id = {c.id: c for c in sys_obj.components}
    # Spot-check vendor / type sniffing
    assert by_id["pg"].type == "database"
    assert by_id["vault"].type == "secrets_vault"
    assert by_id["minio"].type == "object_storage"
    assert by_id["ollama"].type == "llm_inference"
    assert by_id["pgvector"].type == "rag_vector_store"
    assert by_id["prometheus"].type == "observability_stack"
    # ports → user-facing flow
    assert any(c.type == "user" for c in sys_obj.components)
    # depends_on → dataflow
    assert any(df.source == "api" and df.target == "pg" for df in sys_obj.dataflows)


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_compose_sample_round_trips_through_workflow():
    sys_obj = parse_docker_compose(SAMPLES_IAC / "docker-compose.yml")
    tm = analyze(sys_obj)
    # v0.15.0: AI-scope gate filters out-of-scope components, so the
    # bound dropped from >=30 to >=15 (the compose sample has 1 LLM
    # primary + 6 AI-adjacent components in the blast radius).
    assert len(tm.threats) >= 15
    assert len(tm.attack_paths) >= 1
    # Mitigations should be D3FEND-decorated by v0.14
    assert any(m.d3fend for m in tm.mitigations), \
        "expected at least one mitigation to carry a D3FEND tag"


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_sample_loads_and_classifies():
    sys_obj = parse_terraform(SAMPLES_IAC / "main.tf")
    assert len(sys_obj.components) >= 12
    by_name = {c.name: c for c in sys_obj.components}
    # Spot-check type mapping
    assert by_name["aws_s3_bucket.documents"].type == "object_storage"
    assert by_name["aws_lambda_function.rag_handler"].type == "serverless_function"
    assert by_name["aws_iam_role.lambda_exec"].type == "iam_principal"
    assert by_name["aws_kms_key.documents_cmk"].type == "kms_key"
    assert by_name["aws_secretsmanager_secret.anthropic_api_key"].type == "secrets_vault"
    assert by_name["aws_dynamodb_table.sessions"].type == "database"
    assert by_name["aws_sqs_queue.evidence_jobs"].type == "message_queue"
    assert by_name["aws_apigatewayv2_api.front"].type == "api_gateway"
    assert by_name["aws_lb.front_alb"].type == "load_balancer"
    assert by_name["aws_security_group.alb_sg"].type == "firewall"
    assert by_name["aws_vpc.main"].type == "network_segment"
    assert by_name["aws_cloudwatch_log_group.rag_logs"].type == "observability_stack"
    assert by_name["aws_sagemaker_endpoint.embedder"].type == "llm_inference"
    assert by_name["aws_sagemaker_model.embedder_model"].type == "model_registry"
    # Vendor sniff
    assert by_name["aws_s3_bucket.documents"].metadata.get("vendor") == "AWS"


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_sample_dataflows_skip_pseudo_namespaces():
    """The sample has no `var.` / `local.` / `data.` references that should
    create dataflows. Lambda → IAM role + Lambda → S3 + Lambda → KMS +
    Lambda → secrets are valid because all those targets are real
    `resource` blocks."""
    sys_obj = parse_terraform(SAMPLES_IAC / "main.tf")
    pairs = {(df.source, df.target) for df in sys_obj.dataflows}
    # The lambda's depends_on is wired correctly:
    has_lambda_to_role = any(
        "lambda_function" in s and "iam_role" in t for s, t in pairs
    )
    has_lambda_to_secret = any(
        "lambda_function" in s and "secret" in t for s, t in pairs
    )
    assert has_lambda_to_role
    assert has_lambda_to_secret
    # Sagemaker model → IAM role via execution_role_arn interpolation
    has_model_to_role = any(
        "sagemaker_model" in s and "iam_role" in t for s, t in pairs
    )
    assert has_model_to_role


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_terraform_sample_round_trips_through_workflow():
    sys_obj = parse_terraform(SAMPLES_IAC / "main.tf")
    tm = analyze(sys_obj)
    # v0.15.0: AI-scope gate filters out-of-scope components.
    assert len(tm.threats) >= 12
    # Mitigations should carry D3FEND for the AWS-typical controls
    assert any(m.d3fend for m in tm.mitigations)


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_iac_samples_have_no_components_with_type_other():
    """If `type=other` shows up, the classifier missed something. Fix the
    sample (or the parser) before merging."""
    compose = parse_docker_compose(SAMPLES_IAC / "docker-compose.yml")
    tf = parse_terraform(SAMPLES_IAC / "main.tf")
    others = [c for c in compose.components if c.type == "other"]
    assert not others, f"compose has unclassified: {[c.name for c in others]}"
    others = [c for c in tf.components if c.type == "other"]
    assert not others, f"tf has unclassified: {[c.name for c in others]}"
