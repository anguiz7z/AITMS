"""Best-effort fix-up of common authoring mistakes in System YAML.

A user editing the YAML by hand will sometimes type a human-friendly
component type label (``IoT Device``, ``Web Application``) instead of
the snake_case enum slug Pydantic expects. The strict literal check
then dumps a 40-name error blob that's hostile to non-experts.

This module slug-normalises free-text type values, resolves a small
synonym dictionary, and falls back to ``other`` when nothing fits.
Used by both the web UI's `/analyze` route and the CLI's
`_load_system_yaml`. Surfacing the corrections back to the caller is
the responsibility of the call site (banner / log line).
"""

from __future__ import annotations

import re
from typing import get_args

import yaml
from pydantic import ValidationError

from .models import ComponentType

_VALID_COMPONENT_TYPES = frozenset(get_args(ComponentType))


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader that forbids YAML aliases.

    Untrusted System YAML has no legitimate need for anchors/aliases, and a
    nested-alias 'billion laughs' payload (an ~870-byte file of anchors-of-
    anchors) expands to hundreds of MB when the parsed structure is traversed
    by model_validate / serialization -- an OOM DoS (audit F051). Banning
    aliases neutralises it while accepting every legitimate System YAML (no
    bundled sample uses one).
    """

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            event = self.get_event()
            raise yaml.constructor.ConstructorError(
                None, None,
                "YAML aliases are not permitted in System input "
                "(guards against alias-expansion denial of service).",
                event.start_mark,
            )
        return super().compose_node(parent, index)


def safe_load_system_yaml(text: str):
    """``yaml.safe_load`` for *untrusted* System YAML: SafeLoader semantics
    plus a hard ban on aliases (alias-expansion DoS guard, audit F051)."""
    # _NoAliasSafeLoader subclasses yaml.SafeLoader (no arbitrary-object
    # construction); it only adds the alias ban, so this is safe.
    return yaml.load(text, Loader=_NoAliasSafeLoader)  # noqa: S506


def _slug(s: str) -> str:
    """Lowercase + replace non-alnum runs with `_`. The standard ATMS slug."""
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")


# Common synonym → canonical slug. Kept small + obvious; everything that
# doesn't slug-match and isn't here falls back to `other` rather than
# guessing.
_SYNONYMS: dict[str, str] = {
    "llm": "llm_inference",
    "model": "llm_inference",
    "model_inference": "llm_inference",
    "vector_store": "rag_vector_store",
    "vectorstore": "rag_vector_store",
    "rag": "rag_vector_store",
    "rag_store": "rag_vector_store",
    "agent_loop": "agent",
    "ai_agent": "agent",
    "vault": "secrets_vault",
    "secret_store": "secrets_vault",
    "kms": "kms_key",
    "key_management": "kms_key",
    "queue": "message_queue",
    "kafka": "message_queue",
    "rabbitmq": "message_queue",
    "s3": "object_storage",
    "blob": "object_storage",
    "bucket": "object_storage",
    "lambda": "serverless_function",
    "function": "serverless_function",
    "container": "container_runtime",
    "k8s": "container_runtime",
    "kubernetes": "container_runtime",
    "iam": "iam_principal",
    "role": "iam_principal",
    "ad": "directory_service",
    "active_directory": "directory_service",
    "ldap": "directory_service",
    "vpn": "vpn_gateway",
    "fw": "firewall",
    "lb": "load_balancer",
    "switch": "network_switch",
    "iot": "iot_device",
    "device": "iot_device",
    "sensor": "iot_device",
    "controller": "plc",
    "ot": "scada",
    "mainframe": "mainframe",        # v0.16: now a first-class type (replaces legacy_mainframe alias)
    "as400": "mainframe",
    "smtp": "email_server",
    "mail": "email_server",
    "mfa": "mfa_service",
    "okta": "directory_service",
    "logs": "observability_stack",
    "metrics": "observability_stack",
    "datadog": "observability_stack",
    "guardrail": "guardrails",
    "filter": "output_filter",
    "human": "user",
    "person": "user",
    "external": "external_api",
    "third_party_api": "external_api",
    # v0.16: cloud compute / container / storage / network expansion
    "ec2": "cloud_compute",
    "vm": "cloud_compute",
    "compute_engine": "cloud_compute",
    "azure_vm": "cloud_compute",
    "gce": "cloud_compute",
    "oci_compute": "cloud_compute",
    "eks": "container_orchestrator",
    "gke": "container_orchestrator",
    "aks": "container_orchestrator",
    "ecs": "container_orchestrator",
    "openshift": "container_orchestrator",
    "ecr": "container_registry",
    "acr": "container_registry",
    "gar": "container_registry",
    "lambda_at_edge": "edge_compute",
    "cloudflare_workers": "edge_compute",
    "ebs": "block_storage",
    "managed_disk": "block_storage",
    "persistent_disk": "block_storage",
    "efs": "file_storage",
    "azure_files": "file_storage",
    "filestore": "file_storage",
    "lake_formation": "data_lake",
    "adls": "data_lake",
    "data_lake_storage": "data_lake",
    "redshift": "data_warehouse",
    "synapse": "data_warehouse",
    "bigquery": "data_warehouse",
    "snowflake": "data_warehouse",
    "elasticache": "cache_store",
    "memorystore": "cache_store",
    "redis": "cache_store",
    "memcached": "cache_store",
    "dynamodb": "nosql_database",
    "cosmos_db": "nosql_database",
    "cosmosdb": "nosql_database",
    "firestore": "nosql_database",
    "documentdb": "nosql_database",
    "mongodb": "nosql_database",
    "neptune": "graph_database",
    "neo4j": "graph_database",
    "spanner_graph": "graph_database",
    "timestream": "time_series_database",
    "influxdb": "time_series_database",
    "kinesis": "stream_processor",
    "event_hubs": "stream_processor",
    "flink": "stream_processor",
    "dataflow": "stream_processor",
    "glue": "etl_orchestrator",
    "data_factory": "etl_orchestrator",
    "adf": "etl_orchestrator",
    "cloudfront": "cdn",
    "front_door": "cdn",
    "akamai": "cdn",
    "fastly": "cdn",
    "cloudflare": "cdn",
    "app_mesh": "service_mesh",
    "istio": "service_mesh",
    "linkerd": "service_mesh",
    "consul": "service_mesh",
    "privatelink": "private_link",
    "private_endpoint": "private_link",
    "psc": "private_link",
    "transit_gw": "transit_gateway",
    "vwan": "transit_gateway",
    "route_53": "dns_service",
    "azure_dns": "dns_service",
    "cloud_dns": "dns_service",
    # v0.16: network appliances
    "aws_waf": "waf",
    "azure_waf": "waf",
    "cloud_armor": "waf",
    "imperva": "waf",
    "f5_asm": "waf",
    "ids": "ids_ips",
    "ips": "ids_ips",
    "snort": "ids_ips",
    "suricata": "ids_ips",
    "firepower": "ids_ips",
    "shield_advanced": "ddos_mitigation",
    "azure_ddos": "ddos_mitigation",
    "ddos": "ddos_mitigation",
    "squid": "web_proxy",
    "zscaler": "web_proxy",
    "netskope": "web_proxy",
    "nginx_proxy": "reverse_proxy",
    "haproxy": "reverse_proxy",
    "traefik": "reverse_proxy",
    "envoy": "reverse_proxy",
    "cisco": "router",
    "juniper": "router",
    "mikrotik": "router",
    "velocloud": "sdwan_edge",
    "viptela": "sdwan_edge",
    "silver_peak": "sdwan_edge",
    "ise": "network_access_control",
    "clearpass": "network_access_control",
    "forescout": "network_access_control",
    "bastion": "bastion_host",
    "jumpbox": "bastion_host",
    "ssm_session_manager": "bastion_host",
    "iap": "bastion_host",
    "teleport": "bastion_host",
    "cyberark": "pam_vault",
    "beyondtrust": "pam_vault",
    "delinea": "pam_vault",
    # v0.16: identity / IdP family
    "entra_external_id": "identity_provider",
    "auth0": "identity_provider",
    "cognito": "identity_provider",
    "b2c": "ciam_platform",
    "iam_identity_center": "sso_service",
    "azure_sso": "sso_service",
    "ping": "sso_service",
    "onelogin": "sso_service",
    "acm": "certificate_manager",
    "key_vault_certs": "certificate_manager",
    "cloudhsm": "hsm",
    "azure_dedicated_hsm": "hsm",
    # v0.16: security tooling
    "sentinel": "siem",
    "chronicle": "siem",
    "splunk": "siem",
    "qradar": "siem",
    "sumo_logic": "siem",
    "xsoar": "soar",
    "tines": "soar",
    "torq": "soar",
    "crowdstrike": "edr_agent",
    "sentinelone": "edr_agent",
    "defender_endpoint": "edr_agent",
    "nessus": "vulnerability_scanner",
    "qualys": "vulnerability_scanner",
    "inspector": "vulnerability_scanner",
    "defender_cloud_apps": "casb",
    "purview": "dlp",
    "symantec_dlp": "dlp",
    "wiz": "cspm",
    "prisma": "cspm",
    "defender_cloud": "cspm",
    "aqua": "container_security",
    "sysdig": "container_security",
    "twistlock": "container_security",
    # v0.16: observability split
    "cloudwatch_logs": "log_aggregator",
    "log_analytics": "log_aggregator",
    "splunk_logs": "log_aggregator",
    "elk": "log_aggregator",
    "prometheus": "metrics_platform",
    "azure_monitor_metrics": "metrics_platform",
    "datadog_metrics": "metrics_platform",
    "x_ray": "tracing_platform",
    "app_insights": "tracing_platform",
    "honeycomb": "tracing_platform",
    "tempo": "tracing_platform",
    "pagerduty": "alerting_platform",
    "opsgenie": "alerting_platform",
    "victorops": "alerting_platform",
    # v0.16: endpoints + servers
    "windows_server": "server_windows",
    "linux_server": "server_linux",
    "solaris": "server_unix",
    "aix": "server_unix",
    "hpux": "server_unix",
    "ibm_z": "mainframe",
    "zos": "mainframe",
    "avd": "virtual_desktop",
    "workspaces": "virtual_desktop",
    "horizon": "virtual_desktop",
    "ios": "mobile_device",
    "android": "mobile_device",
    "intune": "mdm_emm",
    "jamf": "mdm_emm",
    "workspace_one": "mdm_emm",
    "kandji": "mdm_emm",
    # v0.16: OT expansion
    "remote_terminal_unit": "rtu",
    "intelligent_electronic_device": "ied",
    "human_machine_interface": "hmi",
    "distributed_control_system": "dcs",
    "safety_instrumented_system": "sis",
    "triconex": "sis",
    "greengrass": "iot_gateway",
    "iot_edge": "iot_gateway",
    "engineering_workstation": "ot_jumphost",
    # v0.16: dev / build infra
    "sftp": "file_transfer_service",
    "managed_ftp": "file_transfer_service",
    "transfer_family": "file_transfer_service",
    "github": "code_repository",
    "gitlab": "code_repository",
    "bitbucket": "code_repository",
    "codecommit": "code_repository",
    "jenkins": "ci_cd_pipeline",
    "github_actions": "ci_cd_pipeline",
    "gitlab_ci": "ci_cd_pipeline",
    "codepipeline": "ci_cd_pipeline",
    "cloud_build": "ci_cd_pipeline",
    "artifactory": "artifact_registry",
    "nexus": "artifact_registry",
    "github_packages": "artifact_registry",
    "launchdarkly": "feature_flag_service",
    "split": "feature_flag_service",
    "growthbook": "feature_flag_service",
    "flagsmith": "feature_flag_service",
    "cloudformation": "iac_template_registry",
    "arm": "iac_template_registry",
    "bicep": "iac_template_registry",
    "terraform_module": "iac_template_registry",
    # v0.16: AI/ML expansion
    "sagemaker_endpoint": "ml_inference_endpoint",
    "vertex_endpoint": "ml_inference_endpoint",
    "azure_ml_endpoint": "ml_inference_endpoint",
    "feature_store": "ml_feature_store",
    "sagemaker_feature_store": "ml_feature_store",
    "vertex_feature_store": "ml_feature_store",
    "mlflow": "ml_experiment_tracker",
    "wandb": "ml_experiment_tracker",
    "comet": "ml_experiment_tracker",
    "ground_truth": "ml_data_labeling",
    "sagemaker_pipelines": "ml_pipeline_orchestrator",
    "vertex_pipelines": "ml_pipeline_orchestrator",
    "aml_pipelines": "ml_pipeline_orchestrator",
    "bedrock_guardrails": "content_safety_classifier",
    "azure_content_safety": "content_safety_classifier",
    "perspective": "content_safety_classifier",
    "stt": "speech_pipeline",
    "tts": "speech_pipeline",
    "voice_agent": "speech_pipeline",
    "vision": "vision_pipeline",
}


def coerce_component_type(value: object) -> tuple[str, bool]:
    """Best-effort fix-up of a free-text component type.

    Returns ``(coerced_value, was_corrected)``. If the value is already
    a valid `ComponentType`, returns it unchanged. Otherwise tries
    slug-normalisation, then a synonym dictionary, then falls back to
    ``"other"``.
    """
    if not isinstance(value, str):
        return ("other", True)
    if value in _VALID_COMPONENT_TYPES:
        return (value, False)
    slug = _slug(value)
    if slug in _VALID_COMPONENT_TYPES:
        return (slug, True)
    if slug in _SYNONYMS:
        return (_SYNONYMS[slug], True)
    return ("other", True)


def autocorrect_system_yaml(raw: object) -> tuple[object, list[str]]:
    """Walk a parsed-YAML dict and fix common authoring mistakes before
    Pydantic validation. Returns ``(fixed_dict, corrections)``.

    Corrections currently applied:
    - Component types are coerced to valid ComponentType slugs.
    """
    corrections: list[str] = []
    if not isinstance(raw, dict):
        return raw, corrections
    components = raw.get("components")
    if isinstance(components, list):
        for i, c in enumerate(components):
            if not isinstance(c, dict):
                continue
            # v0.16.9 (Bug-008): also handle `type: null` / missing-`type`
            # by letting coerce_component_type map them to 'other'. The
            # previous `if t is not None:` guard let the user trip the
            # raw 40-name Pydantic literal_error.
            t = c.get("type")
            fixed, was_corrected = coerce_component_type(t)
            if was_corrected:
                label = c.get("name") or c.get("id") or f"#{i}"
                corrections.append(
                    f"Component {label!r}: type {t!r} → {fixed!r}"
                )
                c["type"] = fixed
    return raw, corrections


def format_validation_error(exc: Exception, raw: object = None) -> str:
    """Turn a Pydantic ValidationError (or a yaml parse error) into a
    short, plain-English message that points at the offending row."""
    if isinstance(exc, ValidationError):
        parts: list[str] = []
        for err in exc.errors():
            loc = err.get("loc", ())
            msg = err.get("msg", "")
            ctx_input = err.get("input", "")
            label = None
            if isinstance(raw, dict) and len(loc) >= 2 and loc[0] == "components":
                try:
                    idx = int(loc[1])
                    comps = raw.get("components") or []
                    if 0 <= idx < len(comps) and isinstance(comps[idx], dict):
                        label = comps[idx].get("name") or comps[idx].get("id")
                except (ValueError, TypeError):
                    label = None
            field = ".".join(str(p) for p in loc)
            if err.get("type") == "literal_error" and "type" in field:
                pretty_input = repr(ctx_input)
                hint = ""
                if isinstance(ctx_input, str):
                    slug = _slug(ctx_input)
                    if slug in _VALID_COMPONENT_TYPES:
                        hint = f" (try `{slug}`)"
                where = (
                    f"component {label!r}" if label
                    else f"component #{loc[1]}" if len(loc) >= 2
                    else "value"
                )
                parts.append(
                    f"Unknown component type {pretty_input} on {where}{hint}. "
                    "Use `other` if no specific type fits."
                )
            else:
                where = f"`{field}`"
                if label:
                    where += f" on component {label!r}"
                parts.append(f"{where}: {msg}")
        return " · ".join(parts) if parts else str(exc)
    # v0.16.9 (Bug-014): include the exception class name for non-
    # Pydantic errors so a non-trivial fault (e.g. an `AttributeError`
    # from a corrupt KB file) is not reduced to a bare message string.
    return f"{type(exc).__name__}: {exc}"


__all__ = [
    "coerce_component_type",
    "autocorrect_system_yaml",
    "format_validation_error",
]
