"""CycloneDX SBOM export (v0.18.29 Cycle SS).

The U.S. Executive Order 14028 (May 2021) and EU Cyber Resilience
Act (Art. 13) both require an SBOM as procurement artefact for
software supplied to government and critical-infrastructure
customers. ATMS already inventories the components of a system —
turning that into a CycloneDX SBOM is mostly a render step.

We emit **CycloneDX 1.5** (the latest stable as of 2024-06)
because that's the version the OWASP CycloneDX maintainers and
the NTIA SBOM minimum-elements doc both recommend.

The mapping is deliberately conservative:
  - Each ATMS `Component` becomes a CycloneDX `component`.
  - `type` is set to `application` for compute / workload types,
    `data` for storage types, `device` for endpoints, etc. — the
    CycloneDX spec lists these enum values.
  - `bom-ref` = the ATMS component id (stable across runs).
  - Metadata-rich fields use the component's `metadata` dict;
    e.g. `vendor` / `product` / `version` from a device-catalog
    match flow into the CycloneDX `supplier` + `version`.
  - Dataflows become `dependencies` (source DEPENDS_ON target —
    matches CycloneDX semantics where a dependency edge means
    "uses / is built on").
  - Trust boundaries become `services` (CycloneDX supports
    component-like services as logical boundary markers).

Output is pure JSON; no new deps. CI consumers can use any
CycloneDX-aware tool (dependency-track, OWASP DT, Syft) to
ingest it.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from .. import __version__
from ..models import ThreatModel

# ATMS ComponentType → CycloneDX component.type (1.5 enum)
# https://cyclonedx.org/docs/1.5/json/#components_items_type
#
# Phase 1 expansion: was 46/121 mapped (38%) with the rest defaulting
# to "application". Now 121/121 explicit, so SBOMs preserve the
# semantic distinction between (say) `identity_provider` (machine-
# learning-model? no — application) and `database` (data).
#
# Valid CycloneDX 1.5 type enum values:
#   application · framework · library · container · platform · device ·
#   firmware · file · machine-learning-model · data · cryptographic-asset
_TYPE_MAP = {
    # ─── AI / ML primitives ───────────────────────────────────────────
    "llm_inference": "machine-learning-model",
    "ml_inference_endpoint": "machine-learning-model",
    "rag_vector_store": "data",
    "agent": "application",
    "tool": "application",
    "mcp_server": "application",
    "training_pipeline": "application",
    "fine_tuning_pipeline": "application",
    "embedding_service": "application",
    "prompt_template_store": "data",
    "model_registry": "data",
    "guardrails": "application",
    "output_filter": "application",
    "ml_feature_store": "data",
    "ml_pipeline_orchestrator": "application",
    "ml_data_labeling": "application",
    "ml_experiment_tracker": "application",
    "vision_pipeline": "application",
    "speech_pipeline": "application",
    "content_safety_classifier": "application",
    # ─── External / data sources ──────────────────────────────────────
    "data_source": "data",
    "external_api": "application",
    "user": "device",  # actor, modelled as a device endpoint
    # ─── Compute ──────────────────────────────────────────────────────
    "cloud_compute": "platform",
    "serverless_function": "application",
    "container_runtime": "container",
    "container_orchestrator": "container",
    "container_registry": "container",
    "edge_compute": "platform",
    "batch_compute": "application",
    "high_performance_compute": "platform",
    # ─── Storage ──────────────────────────────────────────────────────
    "object_storage": "data",
    "block_storage": "data",
    "file_storage": "data",
    "data_lake": "data",
    "data_warehouse": "data",
    "cache_store": "data",
    "backup_service": "application",
    # ─── Databases ────────────────────────────────────────────────────
    "database": "data",
    "nosql_database": "data",
    "graph_database": "data",
    "time_series_database": "data",
    # ─── Messaging / streaming / search ───────────────────────────────
    "message_queue": "application",
    "stream_processor": "application",
    "etl_orchestrator": "application",
    # ─── Networking ───────────────────────────────────────────────────
    "load_balancer": "application",
    "cdn": "application",
    "api_gateway": "application",
    "service_mesh": "application",
    "private_link": "application",
    "network_segment": "platform",
    "transit_gateway": "application",
    "dns_service": "application",
    "firewall": "application",
    "waf": "application",
    "ids_ips": "application",
    "ddos_mitigation": "application",
    "web_proxy": "application",
    "reverse_proxy": "application",
    "vpn_gateway": "application",
    "router": "device",
    "network_switch": "device",
    "switch_l3": "device",
    "sdwan_edge": "device",
    "network_access_control": "application",
    "bastion_host": "application",
    # ─── Identity / secrets / keys ────────────────────────────────────
    "pam_vault": "cryptographic-asset",
    "iam_principal": "application",
    "directory_service": "application",
    "identity_provider": "application",
    "mfa_service": "application",
    "sso_service": "application",
    "ciam_platform": "application",
    "secrets_vault": "cryptographic-asset",
    "kms_key": "cryptographic-asset",
    "certificate_manager": "cryptographic-asset",
    "hsm": "cryptographic-asset",
    # ─── Security tooling ─────────────────────────────────────────────
    "siem": "application",
    "soar": "application",
    "edr_agent": "application",
    "vulnerability_scanner": "application",
    "casb": "application",
    "dlp": "application",
    "cspm": "application",
    "container_security": "application",
    "security_data_lake": "data",
    # ─── Observability ────────────────────────────────────────────────
    "observability_stack": "application",
    "log_aggregator": "application",
    "metrics_platform": "application",
    "tracing_platform": "application",
    "alerting_platform": "application",
    # ─── Endpoints / devices ──────────────────────────────────────────
    "endpoint": "device",
    "server_windows": "device",
    "server_linux": "device",
    "server_unix": "device",
    "mainframe": "device",
    "legacy_mainframe": "device",
    "virtual_desktop": "device",
    "mobile_device": "device",
    "mdm_emm": "application",
    # ─── OT / industrial ──────────────────────────────────────────────
    "plc": "device",
    "rtu": "device",
    "ied": "device",
    "hmi": "device",
    "scada": "platform",
    "dcs": "platform",
    "sis": "platform",
    "industrial_protocol": "application",
    "iot_device": "device",
    "iot_gateway": "device",
    "ot_jumphost": "device",
    # ─── Web / messaging / supply-chain ───────────────────────────────
    "web_application": "application",
    "email_server": "application",
    "file_transfer_service": "application",
    "code_repository": "application",
    "ci_cd_pipeline": "application",
    "artifact_registry": "data",
    "build_runner": "application",
    "feature_flag_service": "application",
    "iac_template_registry": "data",
    # ─── Catch-all ────────────────────────────────────────────────────
    "other": "application",
}


def _cdx_type(atms_type: str) -> str:
    """Map an ATMS ComponentType to CycloneDX component.type. Falls
    back to `application` since that's the most permissive value."""
    return _TYPE_MAP.get(atms_type, "application")


def render_sbom_cdx(model: ThreatModel) -> str:
    """Render the system as a CycloneDX 1.5 SBOM (JSON)."""
    sys = model.system
    # Deterministic serial derived from the system identity -- uuid.uuid4()
    # made the CycloneDX SBOM non-reproducible across runs (audit F043).
    bom_serial = "urn:uuid:" + str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"atms-sbom:{sys.name}:{len(sys.components)}")
    )
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")

    components = []
    for c in sys.components:
        meta = c.metadata or {}
        comp_obj: dict = {
            "type": _cdx_type(c.type),
            "bom-ref": c.id,
            "name": c.name,
            "description": (c.description or "")[:500],
            # Reserved CycloneDX `properties` lets us round-trip ATMS
            # specifics (atms_type / source / trust_zone) without
            # corrupting the standard.
            "properties": [
                {"name": "atms:component_type", "value": c.type},
                {"name": "atms:trust_zone", "value": c.trust_zone or "default"},
            ],
        }
        # Source attribution if present (e.g. ingest origin).
        if meta.get("source"):
            comp_obj["properties"].append(
                {"name": "atms:source", "value": str(meta["source"])}
            )
        # Vendor / product / version → CycloneDX supplier / version.
        if meta.get("vendor") or meta.get("product"):
            comp_obj["supplier"] = {"name": str(meta.get("vendor") or "")}
            if meta.get("product"):
                comp_obj["name"] = str(meta["product"])
        if meta.get("version"):
            comp_obj["version"] = str(meta["version"])
        if meta.get("cpe"):
            comp_obj["cpe"] = str(meta["cpe"])
        if meta.get("purl"):
            comp_obj["purl"] = str(meta["purl"])
        # Hostname / IP / FQDN as additional properties.
        for k in ("hostname", "ip", "fqdn"):
            if meta.get(k):
                comp_obj["properties"].append(
                    {"name": f"atms:{k}", "value": str(meta[k])}
                )
        components.append(comp_obj)

    # Dependencies — source depends-on target.
    dep_index: dict[str, set[str]] = {}
    for df in sys.dataflows:
        dep_index.setdefault(df.source, set()).add(df.target)
    dependencies = [
        {"ref": src, "dependsOn": sorted(targets)}
        for src, targets in sorted(dep_index.items())
    ]

    # Trust boundaries → CycloneDX `services` (logical boundary markers).
    services = []
    for tb in sys.trust_boundaries:
        services.append({
            "bom-ref": tb.id,
            "name": tb.id,
            "description": (tb.description or f"Trust boundary ({tb.type})")[:500],
            "properties": [
                {"name": "atms:boundary_type", "value": tb.type},
                {"name": "atms:boundary_role", "value": "trust_boundary"},
            ],
        })

    sbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{
                "vendor": "ATMS",
                "name": "atms",
                "version": __version__,
            }],
            "component": {
                "type": "application",
                "bom-ref": f"system:{sys.name}",
                "name": sys.name,
                "description": (sys.description or "ATMS-generated SBOM")[:500],
            },
        },
        "components": components,
    }
    if dependencies:
        sbom["dependencies"] = dependencies
    if services:
        sbom["services"] = services

    return json.dumps(sbom, indent=2, ensure_ascii=False)


__all__ = ["render_sbom_cdx"]
