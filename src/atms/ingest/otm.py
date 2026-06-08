"""Open Threat Model (OTM) ingest (v0.13).

OTM is the open, vendor-neutral threat-model interchange format
proposed by the IriusRisk + OWASP communities and supported by
pyTM, Threat Dragon, and IriusRisk itself.

Spec: https://github.com/iriusrisk/OpenThreatModel

We accept OTM v0.2.0 / v0.3.0 JSON or YAML and produce an ATMS
``System`` with components, dataflows, and trust-zones derived from
the OTM ``trustZones[].id`` field.

OTM component types are mapped to ATMS ``ComponentType`` via a small
keyword table; unrecognised OTM types fall back to ``other`` and the
ATMS reviewer is expected to fix them in the editor.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from ..features import gated
from ..models import Component, Dataflow, System, TrustBoundary

# OTM component-type slug → ATMS ComponentType (best-effort).
#
# Phase 6 cleanup: 16 duplicate keys (all mapping to the same value)
# removed; ruff F601 enforced. Keys grouped by target ComponentType
# for readability.
_OTM_TYPE_MAP: dict[str, str] = {
    # ─── Users ────────────────────────────────────────────────────
    "user": "user",
    "client": "user",
    "actor": "user",
    # ─── Web / API tier ───────────────────────────────────────────
    "web-application": "web_application",
    "webapplication": "web_application",
    "rest": "api_gateway",
    "graphql": "api_gateway",
    "api-gateway": "api_gateway",
    # ─── Serverless / compute ─────────────────────────────────────
    "lambda": "serverless_function",
    "azure-function": "serverless_function",
    "cloud-function": "serverless_function",
    "function-as-a-service": "serverless_function",
    "serverless-function": "serverless_function",
    "container": "container_runtime",
    "container-runtime": "container_runtime",
    "kubernetes": "container_runtime",
    "ecs": "container_runtime",
    # ─── Messaging / queues ───────────────────────────────────────
    "queue": "message_queue",
    "message-queue": "message_queue",
    "kafka": "message_queue",
    "service-bus": "message_queue",
    # ─── Storage / databases ──────────────────────────────────────
    "object-storage": "object_storage",
    "s3": "object_storage",
    "blob-storage": "object_storage",
    "database": "database",
    "rdbms": "database",
    "sql": "database",
    "nosql": "database",
    "mongo": "database",
    # ─── Identity / secrets / keys ────────────────────────────────
    "iam": "iam_principal",
    "iam-principal": "iam_principal",
    "secrets-manager": "secrets_vault",
    "secrets-vault": "secrets_vault",
    "vault": "secrets_vault",
    "key-vault": "secrets_vault",
    "kms": "kms_key",
    "kms-key": "kms_key",
    "directory": "directory_service",
    "directory-service": "directory_service",
    "active-directory": "directory_service",
    "ldap": "directory_service",
    "mfa": "mfa_service",
    "mfa-service": "mfa_service",
    # ─── Networking ───────────────────────────────────────────────
    "firewall": "firewall",
    "vpn": "vpn_gateway",
    "vpn-gateway": "vpn_gateway",
    "load-balancer": "load_balancer",
    "switch": "network_switch",
    "network-switch": "network_switch",
    "router": "network_switch",
    "network-segment": "network_segment",
    "subnet": "network_segment",
    "vpc": "network_segment",
    "vnet": "network_segment",
    # ─── Endpoints / legacy ───────────────────────────────────────
    "endpoint": "endpoint",
    "workstation": "endpoint",
    "mainframe": "legacy_mainframe",
    "legacy-mainframe": "legacy_mainframe",
    "as400": "legacy_mainframe",
    "iseries": "legacy_mainframe",
    # ─── OT / industrial ──────────────────────────────────────────
    "plc": "plc",
    "scada": "scada",
    "hmi": "scada",
    "iot": "iot_device",
    "iot-device": "iot_device",
    "industrial-protocol": "industrial_protocol",
    "modbus": "industrial_protocol",
    "opcua": "industrial_protocol",
    # ─── Email ────────────────────────────────────────────────────
    "email-server": "email_server",
    "exchange": "email_server",
    "mail": "email_server",
    # ─── AI / ML primitives ───────────────────────────────────────
    "agent": "agent",
    "ai-agent": "agent",
    "llm": "llm_inference",
    "llm-inference": "llm_inference",
    "model": "llm_inference",
    "inference": "llm_inference",
    "embedding": "embedding_service",
    "embedding-service": "embedding_service",
    "vector-store": "rag_vector_store",
    "rag-vector-store": "rag_vector_store",
    "rag": "rag_vector_store",
    "training-pipeline": "training_pipeline",
    "fine-tuning": "fine_tuning_pipeline",
    "fine-tuning-pipeline": "fine_tuning_pipeline",
    "model-registry": "model_registry",
    "prompt-template-store": "prompt_template_store",
    "prompt-template": "prompt_template_store",
    "prompt-store": "prompt_template_store",
    "guardrail": "guardrails",
    "guardrails": "guardrails",
    "output-filter": "output_filter",
    "tool": "tool",
    "mcp-server": "mcp_server",
    # ─── External / data sources ──────────────────────────────────
    "data-source": "data_source",
    "external-api": "external_api",
    "api": "external_api",
    # ─── Observability ────────────────────────────────────────────
    "observability": "observability_stack",
    "observability-stack": "observability_stack",
    "logging": "observability_stack",
    "monitoring": "observability_stack",
}


def _atms_type(otm_type: str) -> str:
    if not otm_type:
        return "other"
    key = otm_type.strip().lower().replace("_", "-")
    if key in _OTM_TYPE_MAP:
        return _OTM_TYPE_MAP[key]
    # Fuzzy: contains-match
    for k, v in _OTM_TYPE_MAP.items():
        if k in key or key in k:
            return v
    return "other"


@gated("ingest_otm")
def parse_otm(path: Path) -> System:
    """Parse an OTM JSON or YAML file into an ATMS System."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ValueError("OTM file must be a JSON or YAML object at the top level")

    project = raw.get("project") or {}
    name = (project.get("name") or raw.get("name") or "OTM-import").strip()
    description = (project.get("description") or raw.get("description") or "").strip()

    # Trust zones: id → label
    zones = {z.get("id"): (z.get("name") or z.get("id") or "default")
             for z in raw.get("trustZones", []) or [] if isinstance(z, dict)}

    components: list[Component] = []
    seen_ids: set[str] = set()
    for c in raw.get("components", []) or []:
        if not isinstance(c, dict):
            continue
        cid = (c.get("id") or "").strip()
        if not cid or cid in seen_ids:
            continue
        seen_ids.add(cid)
        # Prefer `attributes.atms_component_type` when present — that's
        # the lossless round-trip key the OTM exporter writes. Fall back
        # to the OTM `type` slug only when the ATMS-specific marker is
        # missing (e.g. when the OTM file came from another tool).
        attrs = c.get("attributes") or {}
        atms_explicit = (attrs.get("atms_component_type") if isinstance(attrs, dict) else "") or ""
        otm_type = atms_explicit or c.get("type") or (
            attrs.get("type", "") if isinstance(attrs, dict) else ""
        )
        # OTM `parent.component` references a parent COMPONENT, not a
        # zone — using it as a zone fallback was semantically wrong in
        # v0.14. We only consult `parent.trustZone` and the bare
        # `trustZone` attribute.
        # audit F057: OTM `parent` may be a scalar (component-id string) rather
        # than an object -- guard before .get().
        _parent = c.get("parent")
        zone_id = ((_parent.get("trustZone") if isinstance(_parent, dict) else None)
                   or c.get("trustZone")
                   or "")
        trust_zone = zones.get(zone_id, zone_id or "default")
        meta = {}
        # OTM `attributes` is an open dict; preserve vendor / product / version
        # if present.
        attrs = c.get("attributes") or {}
        if isinstance(attrs, dict):
            for k in ("vendor", "product", "version", "hostname", "ip", "fqdn", "cpe", "purl"):
                if attrs.get(k):
                    meta[k] = str(attrs[k])
        components.append(
            Component(
                id=cid,
                name=(c.get("name") or cid)[:200],
                type=_atms_type(otm_type),
                description=str(c.get("description", ""))[:1000],
                trust_zone=trust_zone or "default",
                metadata=meta,
            )
        )

    dataflows: list[Dataflow] = []
    for df in raw.get("dataflows", []) or []:
        if not isinstance(df, dict):
            continue
        src = df.get("source")
        tgt = df.get("destination") or df.get("target")
        if not src or not tgt:
            continue
        dataflows.append(Dataflow(
            source=str(src),
            target=str(tgt),
            label=str(df.get("name", ""))[:200],
            crosses_boundary=bool((df.get("attributes") or {}).get("crosses_boundary", False)),
            data_classification=str((df.get("attributes") or {}).get("classification", "internal"))[:32] or "internal",
        ))

    trust_boundaries: list[TrustBoundary] = []
    for z in raw.get("trustZones", []) or []:
        if not isinstance(z, dict):
            continue
        zid = z.get("id") or ""
        if not zid:
            continue
        # Components inside this zone
        inside = [c.id for c in components if c.trust_zone == zones.get(zid, "default")]
        outside = [c.id for c in components if c.id not in inside]
        trust_boundaries.append(TrustBoundary(
            id=str(zid)[:40],
            type="network",
            components_inside=inside,
            components_outside=outside,
            description=str(z.get("description", ""))[:500],
        ))

    return System(
        name=name[:200] or "OTM-import",
        description=description[:2000],
        components=components,
        dataflows=dataflows,
        trust_boundaries=trust_boundaries,
    )


__all__ = ["parse_otm"]
