"""Pulumi YAML → ATMS System (v0.18.18 Cycle HH).

Completes the IaC trifecta started by `cloudformation.py` (Cycle T) and
`azure_arm.py` (Cycle DD). Pulumi YAML is Pulumi's declarative dialect
(officially `runtime: yaml`) that maps cleanly to cloud resources
without requiring code execution.

Pulumi YAML resource notation differs from CloudFormation:

    AWS  (CloudFormation):  Type: AWS::S3::Bucket
    AWS  (Pulumi YAML):     type: aws:s3:Bucket
    Azure (Pulumi YAML):    type: azure-native:storage:StorageAccount
    GCP  (Pulumi YAML):     type: gcp:storage:Bucket
    K8s  (Pulumi YAML):     type: kubernetes:core/v1:Service

We map the most common ~80 types across AWS / Azure / GCP / Kubernetes
to ATMS component types. Cross-references via Pulumi's `${name.attr}`
template strings become dataflows; VPC / network resources become
trust boundaries.

We deliberately do NOT support Pulumi TypeScript / Python / Go inputs:
they require evaluating user code to surface the resource graph, which
is the kind of supply-chain risk this project (and its security
protocol) explicitly avoids. Users on those runtimes can:
  - run `pulumi stack export` (emits stack JSON we could parse later),
  - or convert their program to Pulumi YAML via `pulumi convert`.

Pure stdlib + PyYAML, zero new deps.
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
# Pulumi resource type → ATMS component type.
#
# Pulumi format is `<provider>:<module>:<Type>` (colon-separated,
# CamelCase Type). Listed alphabetically by namespace.
# ────────────────────────────────────────────────────────────────────
_RESOURCE_MAP: dict[str, str] = {
    # ─── AWS ───────────────────────────────────────────────────────
    "aws:apigateway:RestApi": "api_gateway",
    "aws:apigatewayv2:Api": "api_gateway",
    "aws:appsync:GraphQLApi": "api_gateway",
    "aws:athena:Database": "data_lake",
    "aws:athena:Workgroup": "data_lake",
    "aws:autoscaling:Group": "cloud_compute",
    "aws:backup:Plan": "backup_service",
    "aws:bedrock:Model": "llm_inference",
    "aws:bedrock:Provisioned-ModelThroughput": "llm_inference",
    "aws:bedrockfoundation:ProvisionedModel": "llm_inference",
    "aws:cloudfront:Distribution": "cdn",
    "aws:cognito:UserPool": "ciam_platform",
    "aws:cognito:IdentityPool": "ciam_platform",
    "aws:dynamodb:Table": "nosql_database",
    "aws:ec2:Instance": "cloud_compute",
    "aws:ec2:Volume": "block_storage",
    "aws:ec2:Vpc": "network_segment",
    "aws:ec2:Subnet": "network_segment",
    "aws:ec2:SecurityGroup": "firewall",
    "aws:efs:FileSystem": "file_storage",
    "aws:eks:Cluster": "container_orchestrator",
    "aws:elasticache:Cluster": "cache_store",
    "aws:elasticsearch:Domain": "data_lake",
    "aws:opensearch:Domain": "data_lake",
    "aws:elb:LoadBalancer": "load_balancer",
    "aws:lb:LoadBalancer": "load_balancer",
    "aws:fsx:Filesystem": "file_storage",
    "aws:iam:Role": "iam_principal",
    "aws:iam:User": "iam_principal",
    "aws:iam:Policy": "iam_principal",
    "aws:kms:Key": "kms_key",
    "aws:cloudhsm:Cluster": "hsm",
    "aws:lambda:Function": "serverless_function",
    "aws:lambda:Url": "serverless_function",
    "aws:msk:Cluster": "stream_processor",
    "aws:rds:Instance": "database",
    "aws:rds:Cluster": "database",
    "aws:redshift:Cluster": "data_warehouse",
    "aws:s3:Bucket": "object_storage",
    "aws:s3:BucketV2": "object_storage",
    "aws:sagemaker:Model": "ml_inference_endpoint",
    "aws:sagemaker:Endpoint": "ml_inference_endpoint",
    "aws:secretsmanager:Secret": "secrets_vault",
    "aws:ssm:Parameter": "secrets_vault",
    "aws:sns:Topic": "message_queue",
    "aws:sqs:Queue": "message_queue",
    "aws:wafv2:WebAcl": "waf",
    "aws:waf:WebAcl": "waf",
    "aws:guardduty:Detector": "ids_ips",
    "aws:securityhub:Hub": "siem",
    "aws:cloudwatch:LogGroup": "log_aggregator",

    # ─── Azure (azure-native) ──────────────────────────────────────
    "azure-native:storage:StorageAccount": "object_storage",
    "azure-native:web:WebApp": "web_application",
    "azure-native:web:AppServicePlan": "cloud_compute",
    "azure-native:sql:Server": "database",
    "azure-native:sql:Database": "database",
    "azure-native:dbforpostgresql:Server": "database",
    "azure-native:dbformysql:Server": "database",
    "azure-native:documentdb:DatabaseAccount": "nosql_database",
    "azure-native:cache:Redis": "cache_store",
    "azure-native:keyvault:Vault": "secrets_vault",
    "azure-native:cognitiveservices:Account": "llm_inference",
    "azure-native:machinelearningservices:Workspace": "ml_pipeline_orchestrator",
    "azure-native:containerservice:ManagedCluster": "container_orchestrator",
    "azure-native:containerinstance:ContainerGroup": "container_runtime",
    "azure-native:network:VirtualNetwork": "network_segment",
    "azure-native:network:NetworkSecurityGroup": "firewall",
    "azure-native:network:ApplicationGateway": "waf",
    "azure-native:network:LoadBalancer": "load_balancer",
    "azure-native:apimanagement:Service": "api_gateway",
    "azure-native:operationalinsights:Workspace": "siem",
    "azure-native:insights:Component": "observability_stack",
    "azure-native:logic:Workflow": "etl_orchestrator",
    "azure-native:eventhub:Namespace": "stream_processor",
    "azure-native:servicebus:Namespace": "message_queue",

    # ─── GCP ───────────────────────────────────────────────────────
    "gcp:storage:Bucket": "object_storage",
    "gcp:cloudfunctions:Function": "serverless_function",
    "gcp:cloudfunctionsv2:Function": "serverless_function",
    "gcp:cloudrun:Service": "container_runtime",
    "gcp:cloudrunv2:Service": "container_runtime",
    "gcp:compute:Instance": "cloud_compute",
    "gcp:compute:Network": "network_segment",
    "gcp:compute:Subnetwork": "network_segment",
    "gcp:compute:Firewall": "firewall",
    "gcp:compute:GlobalLoadBalancer": "load_balancer",
    "gcp:container:Cluster": "container_orchestrator",
    "gcp:firestore:Database": "nosql_database",
    "gcp:bigquery:Dataset": "data_warehouse",
    "gcp:pubsub:Topic": "message_queue",
    "gcp:secretmanager:Secret": "secrets_vault",
    "gcp:kms:CryptoKey": "kms_key",
    "gcp:aiplatform:Model": "ml_inference_endpoint",
    "gcp:aiplatform:Endpoint": "ml_inference_endpoint",
    "gcp:cloudsql:DatabaseInstance": "database",
    "gcp:sql:DatabaseInstance": "database",
    "gcp:redis:Instance": "cache_store",
    "gcp:apigateway:Api": "api_gateway",
    "gcp:dataloss:PreventionInspectTemplate": "dlp",

    # ─── Kubernetes (Pulumi-style) ─────────────────────────────────
    "kubernetes:apps/v1:Deployment": "container_runtime",
    "kubernetes:apps/v1:StatefulSet": "container_runtime",
    "kubernetes:apps/v1:DaemonSet": "container_runtime",
    "kubernetes:batch/v1:CronJob": "batch_compute",
    "kubernetes:batch/v1:Job": "batch_compute",
    "kubernetes:core/v1:Service": "load_balancer",
    "kubernetes:core/v1:Secret": "secrets_vault",
    "kubernetes:core/v1:ConfigMap": "data_source",
    "kubernetes:core/v1:PersistentVolumeClaim": "block_storage",
    "kubernetes:networking.k8s.io/v1:Ingress": "api_gateway",
    "kubernetes:networking.k8s.io/v1:NetworkPolicy": "firewall",
}


# Boundary resource types.
_BOUNDARY_TYPES = frozenset({
    "aws:ec2:Vpc",
    "azure-native:network:VirtualNetwork",
    "gcp:compute:Network",
})

# Pulumi template strings: ${resourceName.attribute} or
# ${resourceName.attribute.subattr}. We capture `resourceName`.
_TEMPLATE_REF_RE = re.compile(r"\$\{([A-Za-z_][\w-]*)(?:\.[A-Za-z_][\w.-]*)?\}")


def _collect_refs(obj, refs: list[str]) -> None:
    """Recursively walk a value tree looking for `${name.attr}` refs."""
    if isinstance(obj, str):
        for m in _TEMPLATE_REF_RE.finditer(obj):
            refs.append(m.group(1))
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_refs(v, refs)
    elif isinstance(obj, list):
        for v in obj:
            _collect_refs(v, refs)


@gated("ingest_pulumi")
def pulumi_to_system(
    path: str | Path | None = None,
    text: str | None = None,
    system_name: str | None = None,
) -> System:
    """Parse a Pulumi YAML file into an ATMS `System`.

    Args:
        path: Filesystem path to a Pulumi YAML file. Mutually
            exclusive with `text`.
        text: Raw YAML text. Use instead of `path` when the source
            isn't on disk.
        system_name: Override the system name (default: the Pulumi
            stack's `name` field, then `path.stem`, then "pulumi-import").

    Returns:
        ATMS System with resources mapped to components, refs as
        dataflows, networks as trust boundaries.

    Raises:
        ValueError: if `resources` is empty or the YAML is malformed.
    """
    if path is not None and text is None:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        default_name = p.stem
    elif text is not None:
        default_name = "pulumi-import"
    else:
        raise ValueError("Provide either `path` or `text`")

    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Pulumi YAML parse error: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("Pulumi YAML must be a mapping at the top level")

    runtime = doc.get("runtime")
    if runtime and runtime != "yaml" and not (isinstance(runtime, dict)
                                              and runtime.get("name") == "yaml"):
        log.warning(
            "Pulumi runtime is %r — only YAML is parseable offline. "
            "Resources will still be read; cross-references may be incomplete.",
            runtime,
        )

    resources = doc.get("resources") or {}
    if not isinstance(resources, dict) or not resources:
        raise ValueError(
            "Pulumi YAML has no `resources:` mapping. "
            "If this is a TypeScript / Python / Go Pulumi program, run "
            "`pulumi convert --language yaml` or `pulumi stack export` first."
        )

    components: list[Component] = []
    edges: list[tuple[str, str]] = []
    boundaries: list[TrustBoundary] = []

    for sym, spec in resources.items():
        if not isinstance(spec, dict):
            continue
        # v0.18.57 Phase I — Hypothesis found that YAML keys like
        # `False`, `True`, `Yes`, `null`, etc. parse as Python bool /
        # None, not as strings. Crash on `sym[:200]`. Coerce defensively.
        sym = str(sym)
        rtype = str(spec.get("type", ""))
        if not rtype:
            continue
        ctype = _RESOURCE_MAP.get(rtype, "other")
        # Truncate per model field limits.
        friendly = sym[:200]
        desc = f"Pulumi {rtype} (stack symbol `{sym}`)"
        if len(desc) > 1000:
            desc = desc[:1000]
        # Sanitise sym to fit Component.id max 64 chars.
        comp_id = re.sub(r"[^A-Za-z0-9_-]", "_", sym)[:64]
        if not comp_id:
            continue
        components.append(Component(
            id=comp_id, name=friendly, type=ctype,  # type: ignore[arg-type]
            description=desc,
            metadata={"pulumi_type": rtype, "source": "pulumi-yaml"},
        ))
        if rtype in _BOUNDARY_TYPES:
            boundaries.append(TrustBoundary(
                id=f"pulumi:{comp_id}", type="network",
                description=f"Pulumi VNet/VPC (`{sym}`)",
            ))
        # Collect ${...} refs inside `properties` / `options` etc.
        refs: list[str] = []
        for key in ("properties", "options", "get"):
            if key in spec:
                _collect_refs(spec[key], refs)
        for r in refs:
            r_id = re.sub(r"[^A-Za-z0-9_-]", "_", r)[:64]
            if r_id and r_id != comp_id:
                edges.append((comp_id, r_id))

    if not components:
        raise ValueError(
            "Pulumi YAML parse: no valid `resources` entries with a `type`."
        )

    valid_ids = {c.id for c in components}
    seen: set[tuple[str, str]] = set()
    dataflows: list[Dataflow] = []
    for s, t in edges:
        if s not in valid_ids or t not in valid_ids:
            continue
        if (s, t) in seen:
            continue
        seen.add((s, t))
        dataflows.append(Dataflow(source=s, target=t, label="references"))

    name = system_name or doc.get("name") or default_name
    return System(
        name=str(name),
        description=(
            f"Imported from Pulumi YAML ({len(components)} resources, "
            f"{len(dataflows)} refs). Review and refine before analyse."
        ),
        components=components,
        dataflows=dataflows,
        trust_boundaries=boundaries,
    )


@gated("ingest_pulumi")
def pulumi_state_to_system(
    path: str | Path | None = None,
    text: str | None = None,
    system_name: str | None = None,
) -> System:
    """Parse a `pulumi stack export` JSON state file into an ATMS System
    (v0.18.34 Cycle XX).

    Closes the TypeScript / Python / Go gap that `pulumi_to_system`
    explicitly rejects. Pulumi state is a JSON document with a
    `deployment.resources` array; each entry has `type` (the
    Pulumi-namespaced type, same vocabulary as YAML), `urn`, and
    `inputs` / `outputs` containing the resolved values.

    State files contain RESOLVED resource graphs — every cross-
    reference is already a string. We mine the `urn` and `inputs`
    of each resource to reconstruct the same kind of dataflow graph
    as the YAML parser produces.
    """
    import json as _json
    if path is not None and text is None:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        default_name = p.stem
    elif text is not None:
        default_name = "pulumi-state-import"
    else:
        raise ValueError("Provide either `path` or `text`")

    try:
        doc = _json.loads(text)
    except _json.JSONDecodeError as exc:
        raise ValueError(f"Pulumi state JSON parse error: {exc}") from exc

    # Pulumi state schema: top-level either has `deployment` (v3+) or
    # is the deployment object directly.
    deployment = doc.get("deployment") if isinstance(doc, dict) else None
    if deployment is None and isinstance(doc, dict) and "resources" in doc:
        deployment = doc
    if not deployment or "resources" not in deployment:
        raise ValueError(
            "Not a Pulumi state file: missing `deployment.resources`. "
            "If this is a Pulumi YAML stack, use `pulumi_to_system` instead."
        )

    resources = deployment["resources"]
    if not isinstance(resources, list):
        raise ValueError("Pulumi state `resources` must be an array")

    components: list[Component] = []
    seen_ids: set[str] = set()
    urn_to_id: dict[str, str] = {}
    edges: list[tuple[str, str]] = []
    boundaries: list[TrustBoundary] = []

    for r in resources:
        if not isinstance(r, dict):
            continue
        rtype = str(r.get("type", ""))
        urn = str(r.get("urn", ""))
        # Pulumi stack-meta resources have type 'pulumi:pulumi:Stack'
        # or providers — skip them.
        if rtype.startswith("pulumi:") or not rtype:
            continue
        # `urn` ends with `::<resource-name>` — extract the friendly name.
        name = urn.rsplit("::", 1)[-1] if "::" in urn else (r.get("id", "") or rtype)
        if not name:
            continue
        comp_id = re.sub(r"[^A-Za-z0-9_-]", "_", name)[:64]
        if not comp_id or comp_id in seen_ids:
            continue
        seen_ids.add(comp_id)
        urn_to_id[urn] = comp_id

        ctype = _RESOURCE_MAP.get(rtype, "other")
        components.append(Component(
            id=comp_id, name=name[:200], type=ctype,  # type: ignore[arg-type]
            description=f"Pulumi state resource {rtype} (urn=`{urn}`)"[:1000],
            metadata={"pulumi_type": rtype, "source": "pulumi-state",
                      "pulumi_urn": urn},
        ))
        if rtype in _BOUNDARY_TYPES:
            boundaries.append(TrustBoundary(
                id=f"pulumi-state:{comp_id}", type="network",
                description=f"Pulumi VNet/VPC ({name})"[:500],
            ))

    # State files record `dependencies` on each resource explicitly.
    for r in resources:
        if not isinstance(r, dict):
            continue
        urn = str(r.get("urn", ""))
        if urn not in urn_to_id:
            continue
        src_id = urn_to_id[urn]
        for dep in r.get("dependencies") or []:
            if not isinstance(dep, str):
                continue
            if dep in urn_to_id and urn_to_id[dep] != src_id:
                edges.append((src_id, urn_to_id[dep]))
        # `propertyDependencies` is a richer alternative (per-input).
        prop_deps = r.get("propertyDependencies") or {}
        if isinstance(prop_deps, dict):
            for deps in prop_deps.values():
                if not isinstance(deps, list):
                    continue
                for dep in deps:
                    if isinstance(dep, str) and dep in urn_to_id and urn_to_id[dep] != src_id:
                        edges.append((src_id, urn_to_id[dep]))

    if not components:
        raise ValueError(
            "Pulumi state parse: no recognisable resources. "
            "Confirm the file is from `pulumi stack export`."
        )

    seen: set[tuple[str, str]] = set()
    dataflows: list[Dataflow] = []
    for s, t in edges:
        if (s, t) in seen:
            continue
        seen.add((s, t))
        dataflows.append(Dataflow(source=s, target=t, label="references"))

    return System(
        name=system_name or default_name,
        description=(
            f"Imported from Pulumi state export ({len(components)} resources, "
            f"{len(dataflows)} refs)."
        ),
        components=components,
        dataflows=dataflows,
        trust_boundaries=boundaries,
    )


__all__ = ["pulumi_to_system", "pulumi_state_to_system", "_RESOURCE_MAP"]
