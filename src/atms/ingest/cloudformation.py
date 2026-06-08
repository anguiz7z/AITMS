"""AWS CloudFormation YAML/JSON → ATMS System (v0.18.4 Cycle T).

Pairs with `ingest/terraform.py` to cover the two dominant IaC dialects
for AWS. CloudFormation is the older + AWS-native one; many enterprises
still ship it because it's the AWS-supported native format.

Coverage: 60+ AWS resource types across compute, storage, identity,
network, AI/ML, security tooling. We map each `Resources.<Name>.Type`
(e.g. `AWS::Lambda::Function`) to an ATMS `ComponentType`, sniff
dependencies via `Ref` / `Fn::GetAtt` / `DependsOn`, and emit a
draft `System`. The user reviews + edits before analyse.

Both YAML and JSON CloudFormation are accepted (PyYAML can parse JSON
too — JSON is a strict YAML subset). We do NOT support short-form
intrinsic tags (`!Ref`, `!GetAtt`) because PyYAML rejects unknown
tags by default and we don't want to install a custom-tag loader.
Users with short-form templates can either:
  (a) convert to long-form via `aws cloudformation convert-template`
      (or `cfn-flip` — but we don't bundle it, just document the option)
  (b) use `cfn template-format-version` JSON output, or
  (c) hand-edit short-form to long-form `{"Ref": "Name"}` syntax.

Pure-Python, stdlib-friendly (uses PyYAML which is already a dep),
zero network calls, fully offline.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from ..features import gated
from ..models import Component, Dataflow, System, TrustBoundary

log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────
# CloudFormation resource-type → ATMS component_type map.
#
# Format: AWS::<Namespace>::<Type> → component_type
#
# Order: alphabetical by resource type for grep-friendliness. ~75
# entries covering the resources most commonly threat-modeled. Add
# more by appending — the lookup is just a dict.get(), no order
# dependencies.
# ────────────────────────────────────────────────────────────────────
_RESOURCE_MAP: dict[str, str] = {
    # ─── Compute ───────────────────────────────────────────────────
    "AWS::EC2::Instance": "cloud_compute",
    "AWS::Lambda::Function": "serverless_function",
    "AWS::Lambda::Url": "serverless_function",
    "AWS::ECS::Cluster": "container_orchestrator",
    "AWS::ECS::Service": "container_runtime",
    "AWS::ECS::TaskDefinition": "container_runtime",
    "AWS::EKS::Cluster": "container_orchestrator",
    "AWS::Batch::JobQueue": "batch_compute",
    "AWS::AppRunner::Service": "serverless_function",

    # ─── Storage ───────────────────────────────────────────────────
    "AWS::S3::Bucket": "object_storage",
    "AWS::EFS::FileSystem": "file_storage",
    "AWS::EBS::Volume": "block_storage",
    "AWS::EC2::Volume": "block_storage",
    "AWS::FSx::FileSystem": "file_storage",
    "AWS::Backup::BackupPlan": "backup_service",

    # ─── Databases ─────────────────────────────────────────────────
    "AWS::RDS::DBInstance": "database",
    "AWS::RDS::DBCluster": "database",
    "AWS::Aurora::DBCluster": "database",
    "AWS::DynamoDB::Table": "nosql_database",
    "AWS::DocumentDB::DBInstance": "nosql_database",
    "AWS::Neptune::DBInstance": "graph_database",
    "AWS::Timestream::Database": "time_series_database",
    "AWS::Redshift::Cluster": "data_warehouse",
    "AWS::ElastiCache::CacheCluster": "cache_store",
    "AWS::ElastiCache::ReplicationGroup": "cache_store",
    "AWS::MemoryDB::Cluster": "cache_store",

    # ─── Streaming / Messaging ─────────────────────────────────────
    "AWS::SQS::Queue": "message_queue",
    "AWS::SNS::Topic": "message_queue",
    "AWS::Kinesis::Stream": "stream_processor",
    "AWS::KinesisFirehose::DeliveryStream": "stream_processor",
    "AWS::MSK::Cluster": "stream_processor",
    "AWS::EventBridge::EventBus": "message_queue",
    "AWS::Events::EventBus": "message_queue",
    "AWS::StepFunctions::StateMachine": "etl_orchestrator",
    "AWS::Glue::Job": "etl_orchestrator",
    "AWS::Glue::Crawler": "etl_orchestrator",

    # ─── Networking ────────────────────────────────────────────────
    "AWS::EC2::VPC": "network_segment",
    "AWS::EC2::Subnet": "network_segment",
    "AWS::EC2::SecurityGroup": "firewall",
    "AWS::EC2::NetworkAcl": "firewall",
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "load_balancer",
    "AWS::ElasticLoadBalancing::LoadBalancer": "load_balancer",
    "AWS::CloudFront::Distribution": "cdn",
    "AWS::Route53::HostedZone": "dns_service",
    "AWS::Route53::RecordSet": "dns_service",
    "AWS::ApiGateway::RestApi": "api_gateway",
    "AWS::ApiGatewayV2::Api": "api_gateway",
    "AWS::AppMesh::Mesh": "service_mesh",
    "AWS::EC2::TransitGateway": "transit_gateway",
    "AWS::EC2::VPCEndpoint": "private_link",
    "AWS::EC2::VPNGateway": "vpn_gateway",
    "AWS::WAFv2::WebACL": "waf",
    "AWS::WAF::WebACL": "waf",
    "AWS::Shield::Protection": "ddos_mitigation",

    # ─── Identity / Secrets / KMS ──────────────────────────────────
    "AWS::IAM::Role": "iam_principal",
    "AWS::IAM::User": "iam_principal",
    "AWS::IAM::Group": "iam_principal",
    "AWS::IAM::ManagedPolicy": "iam_principal",
    "AWS::IAM::Policy": "iam_principal",
    "AWS::SecretsManager::Secret": "secrets_vault",
    "AWS::SSM::Parameter": "secrets_vault",
    "AWS::KMS::Key": "kms_key",
    "AWS::KMS::Alias": "kms_key",
    "AWS::CloudHSM::Cluster": "hsm",
    "AWS::Cognito::UserPool": "ciam_platform",
    "AWS::Cognito::IdentityPool": "ciam_platform",
    "AWS::ACMPCA::CertificateAuthority": "certificate_manager",
    "AWS::CertificateManager::Certificate": "certificate_manager",

    # ─── Observability ────────────────────────────────────────────
    "AWS::Logs::LogGroup": "log_aggregator",
    "AWS::CloudWatch::Alarm": "metrics_platform",
    "AWS::CloudTrail::Trail": "log_aggregator",
    "AWS::XRay::Group": "tracing_platform",

    # ─── Security tooling ─────────────────────────────────────────
    "AWS::GuardDuty::Detector": "siem",
    "AWS::SecurityHub::Hub": "cspm",
    "AWS::Inspector::AssessmentTarget": "vulnerability_scanner",
    "AWS::Inspector2::Filter": "vulnerability_scanner",
    "AWS::Config::ConfigRule": "cspm",
    "AWS::Macie::Session": "dlp",

    # ─── AI / ML ──────────────────────────────────────────────────
    "AWS::SageMaker::Endpoint": "ml_inference_endpoint",
    "AWS::SageMaker::Model": "model_registry",
    "AWS::SageMaker::EndpointConfig": "ml_inference_endpoint",
    "AWS::SageMaker::Pipeline": "ml_pipeline_orchestrator",
    "AWS::SageMaker::FeatureGroup": "ml_feature_store",
    "AWS::Bedrock::Agent": "agent",
    "AWS::Bedrock::KnowledgeBase": "rag_vector_store",
    "AWS::Bedrock::ModelInvocationLoggingConfiguration": "llm_inference",
    "AWS::Bedrock::Guardrail": "guardrails",
    "AWS::Kendra::Index": "rag_vector_store",
    "AWS::OpenSearchService::Domain": "rag_vector_store",
}


_REF_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]+$")


def _yaml_safe_load(text: str) -> dict:
    """Load YAML/JSON CloudFormation, rejecting short-form intrinsic
    tags so we don't have to register a custom loader. JSON loads
    natively via yaml.safe_load (JSON is a YAML subset)."""
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        # Most common cause: short-form intrinsic tags like `!Ref` /
        # `!GetAtt`. Give a clear hint instead of raw PyYAML message.
        if "could not determine a constructor for the tag" in str(exc):
            raise ValueError(
                "CloudFormation template uses short-form intrinsic tags "
                "(!Ref / !GetAtt / !Sub / etc.). Convert to long-form via "
                "AWS CLI: `aws cloudformation convert-template --template-body "
                "file://template.yaml`, or use the `cfn-flip` tool."
            ) from exc
        raise


def _collect_refs(value: object) -> list[str]:
    """Recursively walk a Properties dict and extract every logical-
    resource name referenced via `Ref` / `Fn::GetAtt` / `Fn::Sub`.

    Returns the list of resource names (de-duplicated downstream).
    """
    found: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "Ref" and isinstance(v, str) and _REF_PATTERN.match(v):
                found.append(v)
            elif k == "Fn::GetAtt":
                if isinstance(v, list) and v and isinstance(v[0], str):
                    found.append(v[0])
                elif isinstance(v, str):
                    # Dotted form: "ResourceName.AttrName"
                    found.append(v.split(".", 1)[0])
            elif k == "Fn::Sub":
                # ${LogicalId} interpolation — pull out all matches.
                if isinstance(v, str):
                    found.extend(re.findall(r"\$\{([A-Za-z][A-Za-z0-9]+)\}", v))
                elif isinstance(v, list) and len(v) >= 1 and isinstance(v[0], str):
                    found.extend(re.findall(r"\$\{([A-Za-z][A-Za-z0-9]+)\}", v[0]))
            else:
                found.extend(_collect_refs(v))
    elif isinstance(value, list):
        for item in value:
            found.extend(_collect_refs(item))
    return found


@gated("ingest_cfn")
def cloudformation_to_system(
    path: Path | str,
    system_name: str | None = None,
) -> System:
    """Parse a CloudFormation YAML or JSON template into a System.

    Returns a draft — review/edit before running `analyze()`.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    doc = _yaml_safe_load(text)

    if not isinstance(doc, dict):
        raise ValueError(
            f"{p}: top-level CloudFormation document must be a mapping; "
            f"got {type(doc).__name__}"
        )

    resources = doc.get("Resources")
    if not isinstance(resources, dict):
        raise ValueError(
            f"{p}: no Resources section found; not a valid CloudFormation "
            "template (or it's pre-processed cfn-init output)."
        )

    components: list[Component] = []
    cfn_id_to_comp: dict[str, str] = {}
    seen_comp_ids: set[str] = set()
    unknown_types: list[str] = []

    for logical_id, body in resources.items():
        if not isinstance(body, dict):
            continue
        cfn_type = body.get("Type", "")
        if not cfn_type:
            continue
        ctype = _RESOURCE_MAP.get(cfn_type)
        if ctype is None:
            unknown_types.append(cfn_type)
            ctype = "other"

        # Derive an ATMS component id. CFN logical IDs are already
        # alphanumeric (Pascal-case in convention), so lower-snake-case
        # them for ATMS convention.
        comp_id = re.sub(r"(?<!^)(?=[A-Z])", "_", logical_id).lower()
        comp_id = re.sub(r"[^a-z0-9_]+", "_", comp_id).strip("_") or "resource"
        original = comp_id
        n = 2
        while comp_id in seen_comp_ids:
            comp_id = f"{original}_{n}"
            n += 1
        seen_comp_ids.add(comp_id)
        cfn_id_to_comp[logical_id] = comp_id

        components.append(Component(
            id=comp_id,
            name=logical_id,
            type=ctype,  # type: ignore[arg-type]
            metadata={
                "source": f"cloudformation:{cfn_type}",
                "cfn_type": cfn_type,
                "vendor": "aws",
            },
        ))

    # Build dataflows from Ref / Fn::GetAtt / DependsOn relationships.
    dataflows: list[Dataflow] = []
    seen_edges: set[tuple[str, str]] = set()
    for logical_id, body in resources.items():
        if not isinstance(body, dict):
            continue
        src_comp_id = cfn_id_to_comp.get(logical_id)
        if src_comp_id is None:
            continue
        # Walk Properties for Refs.
        refs = _collect_refs(body.get("Properties", {}))
        # Also pick up DependsOn.
        dep = body.get("DependsOn")
        if isinstance(dep, str):
            refs.append(dep)
        elif isinstance(dep, list):
            refs.extend([d for d in dep if isinstance(d, str)])

        for target_logical in refs:
            target_comp_id = cfn_id_to_comp.get(target_logical)
            if not target_comp_id or target_comp_id == src_comp_id:
                continue
            edge = (src_comp_id, target_comp_id)
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            dataflows.append(Dataflow(
                source=src_comp_id, target=target_comp_id,
                label="references",
            ))

    # VPCs and Subnets become trust boundaries (network type). Any
    # resource referencing the VPC via Properties.VpcId / SubnetIds /
    # SubnetId is tagged as living inside that boundary.
    trust_boundaries: list[TrustBoundary] = []
    vpc_members: dict[str, list[str]] = {}
    subnet_members: dict[str, list[str]] = {}
    for logical_id, body in resources.items():
        if not isinstance(body, dict):
            continue
        comp_id = cfn_id_to_comp.get(logical_id)
        if not comp_id:
            continue
        # audit F054: Properties may be a YAML list (malformed template) --
        # guard before .items().
        props = body.get("Properties")
        props = props if isinstance(props, dict) else {}
        # Inspect VpcId / SubnetId(s) properties.
        for key, value in props.items():
            if key in ("VpcId",):
                ref_id = _collect_refs(value)
                for r in ref_id:
                    if r in cfn_id_to_comp:
                        vpc_members.setdefault(r, []).append(comp_id)
            elif key in ("SubnetId", "SubnetIds"):
                ref_id = _collect_refs(value)
                for r in ref_id:
                    if r in cfn_id_to_comp:
                        subnet_members.setdefault(r, []).append(comp_id)

    for vpc_logical, members in vpc_members.items():
        if not members:
            continue
        trust_boundaries.append(TrustBoundary(
            id=f"vpc_{cfn_id_to_comp[vpc_logical]}",
            type="network",
            components_inside=sorted(set(members)),
            description=f"VPC: {vpc_logical}",
        ))
    for sn_logical, members in subnet_members.items():
        if not members:
            continue
        trust_boundaries.append(TrustBoundary(
            id=f"subnet_{cfn_id_to_comp[sn_logical]}",
            type="network",
            components_inside=sorted(set(members)),
            description=f"Subnet: {sn_logical}",
        ))

    if unknown_types:
        log.info(
            "CloudFormation: %d resource type(s) classified as 'other' "
            "(no map entry): %s",
            len(unknown_types),
            ", ".join(sorted(set(unknown_types))[:5])
            + (" ..." if len(set(unknown_types)) > 5 else ""),
        )

    name = system_name or p.stem
    return System(
        name=name,
        components=components,
        dataflows=dataflows,
        trust_boundaries=trust_boundaries,
        industry="midmarket_other",  # caller can override via YAML edits
        deployment_stage="pilot",
    )


__all__ = ["cloudformation_to_system", "_RESOURCE_MAP"]
