"""draw.io / diagrams.net XML → ATMS System (v0.17.4 Cycle L).

Closes the largest competitive parity gap surfaced by the v0.17.4
research pass: draw.io is the dominant open architecture-diagram
format (AWS / Azure / GCP all ship official stencils with stable
mxgraph.aws4.* / mxgraph.azure.* / mxgraph.gcp2.* style prefixes;
Lucidchart + Gliffy can export to it; Visio can be one-click
converted to it).

Three-layer classification, scored and merged (highest wins):

  1. Style-prefix dictionary  (weight 1.0)  — match mxCell/@style
     against known cloud-stencil prefixes (mxgraph.aws4.s3 → object_storage).
  2. Label regex             (weight 0.5)  — case-insensitive tokens
     in mxCell/@value (\\b(lambda|cloud function|azure function)\\b →
     serverless_function).
  3. Fallback                (weight 0.0)  — `other`.

The unclassified-style fallback prefers `other` over guessing so the
user gets a clear "you may want to fix this" surface (the M2 catch-
all log already nudges them).

Pure-Python, stdlib XML parser, zero external deps, fully offline.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Component, Dataflow, System, TrustBoundary

log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────
# Style-prefix dictionary. Order is irrelevant — we use first-match-
# wins per cell. Keys are case-folded substrings; values are the
# canonical ATMS ComponentType.
#
# Sourced from the official mxgraph stencil libraries:
#   - mxgraph.aws4.*      (AWS 2017+ stencils)
#   - mxgraph.aws3.*      (AWS legacy)
#   - mxgraph.azure.*     (Azure stencils)
#   - mxgraph.gcp2.*      (GCP 2024+ stencils)
#   - mscae.*             (Microsoft Cloud + Enterprise legacy)
# ────────────────────────────────────────────────────────────────────
STYLE_PREFIX_MAP: list[tuple[str, str]] = [
    # ─── AWS ───────────────────────────────────────────────────────
    ("mxgraph.aws4.lambda", "serverless_function"),
    ("mxgraph.aws3.lambda", "serverless_function"),
    ("mxgraph.aws4.s3", "object_storage"),
    ("mxgraph.aws3.s3", "object_storage"),
    ("mxgraph.aws4.ec2", "cloud_compute"),
    ("mxgraph.aws4.virtual_private_cloud", "network_segment"),
    ("mxgraph.aws4.vpc", "network_segment"),
    ("mxgraph.aws4.rds", "database"),
    ("mxgraph.aws4.aurora", "database"),
    ("mxgraph.aws4.dynamodb", "nosql_database"),
    ("mxgraph.aws4.elasticache", "cache_store"),
    ("mxgraph.aws4.redshift", "data_warehouse"),
    ("mxgraph.aws4.api_gateway", "api_gateway"),
    ("mxgraph.aws4.cloudfront", "cdn"),
    ("mxgraph.aws4.route_53", "dns_service"),
    ("mxgraph.aws4.elastic_load_balancing", "load_balancer"),
    ("mxgraph.aws4.elb", "load_balancer"),
    ("mxgraph.aws4.kinesis", "stream_processor"),
    ("mxgraph.aws4.kms", "kms_key"),
    ("mxgraph.aws4.secrets_manager", "secrets_vault"),
    ("mxgraph.aws4.iam", "iam_principal"),
    ("mxgraph.aws4.cognito", "identity_provider"),
    ("mxgraph.aws4.cloudwatch", "observability_stack"),
    ("mxgraph.aws4.bedrock", "llm_inference"),
    ("mxgraph.aws4.sagemaker", "ml_inference_endpoint"),
    ("mxgraph.aws4.kendra", "rag_vector_store"),
    ("mxgraph.aws4.waf", "waf"),
    ("mxgraph.aws4.shield", "ddos_mitigation"),
    ("mxgraph.aws4.guardduty", "siem"),
    ("mxgraph.aws4.security_hub", "cspm"),
    ("mxgraph.aws4.sqs", "message_queue"),
    ("mxgraph.aws4.sns", "message_queue"),
    ("mxgraph.aws4.elastic_container", "container_runtime"),
    ("mxgraph.aws4.elastic_kubernetes", "container_orchestrator"),
    ("mxgraph.aws4.ecr", "container_registry"),
    ("mxgraph.aws4.efs", "file_storage"),
    ("mxgraph.aws4.ebs", "block_storage"),
    ("mxgraph.aws4.glue", "etl_orchestrator"),
    ("mxgraph.aws4.transit_gateway", "transit_gateway"),
    ("mxgraph.aws4.privatelink", "private_link"),
    ("mxgraph.aws4.app_mesh", "service_mesh"),
    # ─── Azure ─────────────────────────────────────────────────────
    ("mxgraph.azure.function", "serverless_function"),
    ("mxgraph.azure2.function", "serverless_function"),
    ("mscae.functions", "serverless_function"),
    ("mxgraph.azure.virtual_machine", "cloud_compute"),
    ("mxgraph.azure2.virtual_machine", "cloud_compute"),
    ("mxgraph.azure.blob", "object_storage"),
    ("mxgraph.azure2.storage_accounts", "object_storage"),
    ("mxgraph.azure.sql_database", "database"),
    ("mxgraph.azure2.sql_database", "database"),
    ("mxgraph.azure.cosmos_db", "nosql_database"),
    ("mxgraph.azure2.cosmos_db", "nosql_database"),
    ("mxgraph.azure.api_management", "api_gateway"),
    ("mxgraph.azure2.api_management", "api_gateway"),
    ("mxgraph.azure.front_door", "cdn"),
    ("mxgraph.azure2.front_door", "cdn"),
    ("mxgraph.azure.application_gateway", "load_balancer"),
    ("mxgraph.azure.openai", "llm_inference"),
    ("mxgraph.azure2.openai", "llm_inference"),
    ("mxgraph.azure.cognitive_search", "rag_vector_store"),
    ("mxgraph.azure2.cognitive_search", "rag_vector_search".replace("search", "store") if False else "rag_vector_store"),
    ("mxgraph.azure.key_vault", "secrets_vault"),
    ("mxgraph.azure2.key_vault", "secrets_vault"),
    ("mxgraph.azure.active_directory", "identity_provider"),
    ("mxgraph.azure2.entra_id", "identity_provider"),
    ("mxgraph.azure.firewall", "firewall"),
    ("mxgraph.azure2.firewall", "firewall"),
    ("mxgraph.azure.application_insights", "tracing_platform"),
    ("mxgraph.azure2.application_insights", "tracing_platform"),
    ("mxgraph.azure.synapse", "data_warehouse"),
    ("mxgraph.azure2.synapse_analytics", "data_warehouse"),
    ("mxgraph.azure.data_factory", "etl_orchestrator"),
    ("mxgraph.azure2.data_factory", "etl_orchestrator"),
    ("mxgraph.azure.event_hubs", "stream_processor"),
    ("mxgraph.azure2.event_hubs", "stream_processor"),
    ("mxgraph.azure.service_bus", "message_queue"),
    ("mxgraph.azure2.service_bus", "message_queue"),
    ("mxgraph.azure.kubernetes_service", "container_orchestrator"),
    ("mxgraph.azure2.kubernetes_services", "container_orchestrator"),
    # ─── GCP ───────────────────────────────────────────────────────
    ("mxgraph.gcp2.cloud_functions", "serverless_function"),
    ("mxgraph.gcp2.cloud_run", "serverless_function"),
    ("mxgraph.gcp2.compute_engine", "cloud_compute"),
    ("mxgraph.gcp2.cloud_storage", "object_storage"),
    ("mxgraph.gcp2.cloud_sql", "database"),
    ("mxgraph.gcp2.firestore", "nosql_database"),
    ("mxgraph.gcp2.bigquery", "data_warehouse"),
    ("mxgraph.gcp2.dataflow", "stream_processor"),
    ("mxgraph.gcp2.pub_sub", "message_queue"),
    ("mxgraph.gcp2.cloud_endpoints", "api_gateway"),
    ("mxgraph.gcp2.vertex_ai", "ml_inference_endpoint"),
    ("mxgraph.gcp2.cloud_kms", "kms_key"),
    ("mxgraph.gcp2.secret_manager", "secrets_vault"),
    ("mxgraph.gcp2.identity_platform", "identity_provider"),
    ("mxgraph.gcp2.cloud_armor", "waf"),
    ("mxgraph.gcp2.cloud_load_balancing", "load_balancer"),
    ("mxgraph.gcp2.cloud_cdn", "cdn"),
    ("mxgraph.gcp2.cloud_dns", "dns_service"),
    ("mxgraph.gcp2.kubernetes_engine", "container_orchestrator"),
    ("mxgraph.gcp2.cloud_logging", "log_aggregator"),
    # ─── Generic DFD / threat-model stencils ──────────────────────
    ("shape=actor", "user"),
    ("shape=mxgraph.threatmodeling.process", "web_application"),
    ("shape=mxgraph.threatmodeling.datastore", "database"),
    ("shape=mxgraph.threatmodeling.external", "external_api"),
]


# Label-regex fallback. Compiled once at import.
_LABEL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(lambda|λ|cloud\s*function|azure\s*function|serverless)s?\b", re.I), "serverless_function"),
    (re.compile(r"\b(ec2|vm|virtual\s*machine|gce|gcp\s*compute|instance)\b", re.I), "cloud_compute"),
    (re.compile(r"\b(s3|blob\s*storage|gcs|object\s*store|bucket)\b", re.I), "object_storage"),
    (re.compile(r"\b(rds|postgres|mysql|aurora|mariadb|cloud\s*sql|sql\s*database)\b", re.I), "database"),
    (re.compile(r"\b(dynamodb|cosmos|firestore|mongodb|documentdb)\b", re.I), "nosql_database"),
    (re.compile(r"\b(redshift|synapse|bigquery|snowflake|data\s*warehouse)\b", re.I), "data_warehouse"),
    (re.compile(r"\b(api\s*gw|api\s*gateway|apigee|api\s*management)\b", re.I), "api_gateway"),
    (re.compile(r"\b(cloudfront|front\s*door|cloud\s*cdn|akamai|fastly|cloudflare\s*cdn)\b", re.I), "cdn"),
    (re.compile(r"\b(alb|elb|nlb|load\s*balancer|application\s*gateway)\b", re.I), "load_balancer"),
    (re.compile(r"\b(route\s*53|cloud\s*dns|azure\s*dns)\b", re.I), "dns_service"),
    (re.compile(r"\b(kinesis|kafka|event\s*hubs|pub\s*sub|stream)\b", re.I), "stream_processor"),
    (re.compile(r"\b(sqs|sns|service\s*bus|rabbitmq|queue)\b", re.I), "message_queue"),
    (re.compile(r"\b(kms|key\s*vault|cloud\s*kms)\b", re.I), "kms_key"),
    (re.compile(r"\b(secrets?\s*manager|secrets?\s*vault|hashicorp\s*vault)\b", re.I), "secrets_vault"),
    (re.compile(r"\b(iam|service\s*principal|managed\s*identity)\b", re.I), "iam_principal"),
    (re.compile(r"\b(cognito|entra|auth0|okta|identity\s*provider)\b", re.I), "identity_provider"),
    (re.compile(r"\b(cloudwatch|app\s*insights|stackdriver|datadog|new\s*relic|prometheus)\b", re.I), "observability_stack"),
    (re.compile(r"\b(bedrock|llm|gpt|claude|gemini|open\s*ai|llama)\b", re.I), "llm_inference"),
    (re.compile(r"\b(sagemaker|vertex\s*ai|azure\s*ml)\b", re.I), "ml_inference_endpoint"),
    (re.compile(r"\b(kendra|cognitive\s*search|pinecone|weaviate|chroma|vector\s*store|rag)\b", re.I), "rag_vector_store"),
    (re.compile(r"\b(waf|cloud\s*armor|imperva|f5)\b", re.I), "waf"),
    (re.compile(r"\b(shield|ddos)\b", re.I), "ddos_mitigation"),
    (re.compile(r"\b(guardduty|sentinel|chronicle|splunk|siem)\b", re.I), "siem"),
    (re.compile(r"\b(wiz|prisma|defender|security\s*hub|cspm)\b", re.I), "cspm"),
    (re.compile(r"\b(eks|gke|aks|kubernetes|k8s)\b", re.I), "container_orchestrator"),
    (re.compile(r"\b(ecs|cloud\s*run|fargate|container\s*runtime)\b", re.I), "container_runtime"),
    (re.compile(r"\b(ecr|acr|gar|container\s*registry|artifactory)\b", re.I), "container_registry"),
    (re.compile(r"\b(efs|azure\s*files|filestore|file\s*storage)\b", re.I), "file_storage"),
    (re.compile(r"\b(ebs|managed\s*disk|persistent\s*disk|block\s*storage)\b", re.I), "block_storage"),
    (re.compile(r"\b(glue|data\s*factory|airflow|etl)\b", re.I), "etl_orchestrator"),
    (re.compile(r"\b(transit\s*gateway|vwan|network\s*connectivity)\b", re.I), "transit_gateway"),
    (re.compile(r"\b(privatelink|private\s*endpoint|psc)\b", re.I), "private_link"),
    (re.compile(r"\b(app\s*mesh|istio|linkerd|service\s*mesh)\b", re.I), "service_mesh"),
    (re.compile(r"\b(firewall|ngfw)\b", re.I), "firewall"),
    (re.compile(r"\b(vpn\s*gateway|site.*site\s*vpn)\b", re.I), "vpn_gateway"),
    (re.compile(r"\b(user|client|customer|browser|mobile\s*user|end.*user)\b", re.I), "user"),
    (re.compile(r"\b(actor|external\s*entity|3rd[\s\-]?party|third[\s\-]?party)\b", re.I), "user"),
    (re.compile(r"\b(plc|programmable\s*logic)\b", re.I), "plc"),
    (re.compile(r"\b(scada|historian)\b", re.I), "scada"),
    (re.compile(r"\b(hmi|human[\s\-]?machine)\b", re.I), "hmi"),
    (re.compile(r"\b(iot\s*device|sensor|actuator)\b", re.I), "iot_device"),
    (re.compile(r"\b(web\s*app|web\s*application|website|frontend|backend\s*api)\b", re.I), "web_application"),
    (re.compile(r"\b(database|db|rdbms|postgres|mysql)\b", re.I), "database"),
    (re.compile(r"\b(active\s*directory|ldap|directory\s*service)\b", re.I), "directory_service"),
]


def _classify_style(style: str) -> str | None:
    """Match the cell's @style attribute against known cloud-stencil
    prefixes. Returns the canonical component_type or None."""
    if not style:
        return None
    style_lower = style.lower()
    for prefix, ctype in STYLE_PREFIX_MAP:
        if prefix in style_lower:
            return ctype
    return None


def _classify_label(label: str) -> str | None:
    """Match the cell's @value (visible label) against regexes.
    Returns the canonical component_type or None."""
    if not label:
        return None
    for pat, ctype in _LABEL_PATTERNS:
        if pat.search(label):
            return ctype
    return None


def _classify_cell(style: str, label: str) -> tuple[str, str]:
    """Layered classification. Returns (component_type, source-tag).

    source-tag is one of: 'style' / 'label' / 'fallback' — used for
    confidence reporting + audit trail."""
    by_style = _classify_style(style)
    if by_style:
        return (by_style, "style")
    by_label = _classify_label(label)
    if by_label:
        return (by_label, "label")
    return ("other", "fallback")


def _safe_id(raw_id: str, used: set[str]) -> str:
    """Produce a YAML-friendly id that's unique in the system."""
    base = re.sub(r"[^a-zA-Z0-9_]+", "_", raw_id or "node").strip("_") or "node"
    candidate = base
    n = 2
    while candidate in used:
        candidate = f"{base}_{n}"
        n += 1
    used.add(candidate)
    return candidate


def _strip_html(s: str) -> str:
    """draw.io often wraps values in <p>, <font> etc. Strip tags."""
    if not s:
        return ""
    # Remove HTML tags. draw.io supports rich text so &amp;-decoded HTML
    # is common. ElementTree decoded entities; we just remove the tags.
    return re.sub(r"<[^>]+>", " ", s).strip()


# ────────────────────────────────────────────────────────────────────
# Trust-boundary inference (v0.17.4 Cycle M).
# ────────────────────────────────────────────────────────────────────

_BOUNDARY_LABEL_PATTERN = re.compile(
    # Container-y nouns only. We deliberately DO NOT include "firewall"
    # / "router" etc. — those are network DEVICES that should classify
    # as components, not boundary containers. Trust boundaries are
    # zones (VPC, DMZ, subnet, namespace, …) — the things that contain
    # devices, not the devices themselves.
    r"\b(vpc|subnet|dmz|zone|on[\s\-]?prem|cluster|namespace|tenant|"
    r"trust\s*boundary|perimeter|network|segment|enclave)\b",
    re.I,
)
_BOUNDARY_STYLE_TOKENS = (
    "trustboundary",
    "shape=mxgraph.threatmodeling.trust",
    "shape=mxgraph.aws4.virtual_private_cloud",
    "shape=mxgraph.aws4.vpc",
    "shape=mxgraph.azure.virtual_network",
    "shape=mxgraph.gcp2.vpc",
    "swimlane",
    "shape=mxgraph.security.cloud",
)


def _is_boundary_cell(style: str, label: str) -> bool:
    """A cell is a trust boundary when its STYLE matches a known
    boundary-stencil token OR its LABEL matches the boundary regex."""
    style_lower = (style or "").lower()
    for tok in _BOUNDARY_STYLE_TOKENS:
        if tok in style_lower:
            return True
    if _BOUNDARY_LABEL_PATTERN.search(label or ""):
        return True
    return False


def _classify_boundary_type(label: str, style: str) -> str:
    """Pick a TrustBoundaryType for the boundary based on label hints.
    Defaults to 'network' which is the most common case.

    Order matters: network keywords (vpc / subnet / dmz / etc.) win
    over generic stage tokens like 'prod' / 'staging' — otherwise
    "VPC: production" misclassifies as deployment_zone.
    """
    text = ((label or "") + " " + (style or "")).lower()
    # Network indicators first — most boundaries in real diagrams are
    # network zones.
    if any(tok in text for tok in (
        "vpc", "subnet", "dmz", "perimeter", "network", "segment",
        "enclave", "lan", "wan",
    )):
        return "network"
    if any(tok in text for tok in ("tenant", "tenancy", "namespace")):
        return "tenancy"
    if any(tok in text for tok in ("identity", "auth", "iam")):
        return "identity"
    if any(tok in text for tok in ("classification", "confidential", "restricted")):
        return "data_classification"
    if any(tok in text for tok in ("prod", "staging", "dev", "deployment")):
        return "deployment_zone"
    return "network"


def drawio_to_system(
    path: str | Path,
    system_name: str | None = None,
) -> System:
    """Parse a .drawio / .xml diagram into an ATMS System.

    Args:
        path: input file. Accepts `str` or `pathlib.Path`. Supports
              .drawio (most common) and .xml (older format / mxGraph
              dumps). v0.18.56 Phase G — was Path-only, surfaced by a
              property-based test that passes string paths from
              tempfile.mkstemp().
        system_name: optional override; defaults to the file stem.

    Returns: a `System` draft. Components carry a `metadata.source`
    tag ('style' / 'label' / 'fallback') so the user can audit which
    classifications were heuristic vs. high-confidence.

    The returned System is a DRAFT — the user is expected to review
    auto-classifications before running analyze().
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    root = ET.fromstring(text)

    # draw.io files have one or more <diagram>. We process all of them
    # (multi-page diagrams produce one System with all pages flattened).
    mx_cells: list[ET.Element] = []
    for diagram in root.iter("diagram"):
        # Inside <diagram> there's an <mxGraphModel>. Some files embed
        # it as a CDATA-encoded text node (compressed format); we don't
        # support that yet — only the uncompressed form.
        for cell in diagram.iter("mxCell"):
            mx_cells.append(cell)
    if not mx_cells:
        # Maybe the file IS the mxGraphModel directly.
        for cell in root.iter("mxCell"):
            mx_cells.append(cell)

    # First pass: identify boundary cells. These are visual containers
    # in the diagram (VPCs, subnets, DMZ rectangles, etc.) that will
    # become TrustBoundary objects on the System.
    boundary_cell_ids: set[str] = set()
    cell_meta: dict[str, dict] = {}  # raw_id → {style, value, parent}
    for cell in mx_cells:
        raw_id = cell.get("id", "")
        if not raw_id:
            continue
        style = cell.get("style", "") or ""
        value = _strip_html(cell.get("value", "") or "")
        parent = cell.get("parent", "")
        cell_meta[raw_id] = {"style": style, "value": value, "parent": parent}
        # A cell is a boundary candidate iff it has vertex="1" AND its
        # style/label indicates a boundary. Cells with vertex="1" but
        # without that signal are treated as regular components.
        if cell.get("vertex") == "1" and _is_boundary_cell(style, value):
            boundary_cell_ids.add(raw_id)

    def _nearest_boundary(start_raw_id: str) -> str | None:
        """Walk up the parent chain until we hit a boundary cell.
        Returns the boundary's raw_id, or None if the component is at
        the top level (no enclosing boundary)."""
        seen: set[str] = set()
        cur = cell_meta.get(start_raw_id, {}).get("parent", "")
        while cur and cur not in seen and cur in cell_meta:
            seen.add(cur)
            if cur in boundary_cell_ids:
                return cur
            cur = cell_meta[cur].get("parent", "")
        return None

    # Build TrustBoundary objects + record which boundary each
    # component lives under (raw_id → boundary_raw_id or None).
    used_ids: set[str] = set()
    cell_id_to_comp_id: dict[str, str] = {}
    components: list[Component] = []
    component_boundary: dict[str, str | None] = {}  # comp_id → boundary_raw_id
    for cell in mx_cells:
        if cell.get("vertex") != "1":
            continue
        raw_id = cell.get("id", "")
        if raw_id in boundary_cell_ids:
            continue  # boundaries become TrustBoundary objects, not components
        style = cell.get("style", "") or ""
        value = _strip_html(cell.get("value", "") or "")
        if not value and not style:
            continue
        ctype, src = _classify_cell(style, value)
        comp_id = _safe_id(raw_id, used_ids)
        cell_id_to_comp_id[raw_id] = comp_id
        boundary_raw = _nearest_boundary(raw_id)
        zone_label = (
            cell_meta[boundary_raw]["value"] if boundary_raw else "default"
        ).lower().replace(" ", "_")[:60] or "default"
        components.append(Component(
            id=comp_id,
            name=value or comp_id,
            type=ctype,  # type: ignore[arg-type]
            trust_zone=zone_label,
            metadata={"source": f"drawio:{src}", "raw_style": style[:200]},
        ))
        component_boundary[comp_id] = boundary_raw

    # Build TrustBoundary objects (one per boundary cell that contains
    # at least one component).
    trust_boundaries: list[TrustBoundary] = []
    boundary_used: set[str] = set()
    raw_to_boundary_id: dict[str, str] = {}
    for raw_id in boundary_cell_ids:
        members = [
            comp_id for comp_id, b in component_boundary.items() if b == raw_id
        ]
        if not members:
            continue
        meta = cell_meta[raw_id]
        boundary_id = _safe_id(raw_id, boundary_used)
        raw_to_boundary_id[raw_id] = boundary_id
        trust_boundaries.append(TrustBoundary(
            id=boundary_id,
            type=_classify_boundary_type(meta["value"], meta["style"]),  # type: ignore[arg-type]
            components_inside=members,
            description=meta["value"] or "(unnamed boundary)",
        ))

    # Second pass: edges → dataflows. Mark crosses_boundary when the
    # source and target live in different trust zones.
    dataflows: list[Dataflow] = []
    for cell in mx_cells:
        if cell.get("edge") != "1":
            continue
        src_raw = cell.get("source", "")
        tgt_raw = cell.get("target", "")
        src_id = cell_id_to_comp_id.get(src_raw)
        tgt_id = cell_id_to_comp_id.get(tgt_raw)
        if not (src_id and tgt_id):
            continue
        label = _strip_html(cell.get("value", "") or "")
        crosses = (
            component_boundary.get(src_id) != component_boundary.get(tgt_id)
        )
        dataflows.append(Dataflow(
            source=src_id, target=tgt_id,
            label=label,
            crosses_boundary=crosses,
        ))

    name = system_name or path.stem
    return System(
        name=name,
        components=components,
        dataflows=dataflows,
        trust_boundaries=trust_boundaries,
    )


def classification_summary(system: System) -> dict[str, int]:
    """Diagnostic: count components by classification source.

    Returns: {'style': N, 'label': N, 'fallback': N}. The CLI surfaces
    this so the user can see how many components were high-confidence
    vs. heuristic vs. unclassified.
    """
    counts = {"style": 0, "label": 0, "fallback": 0}
    for c in system.components:
        src = (c.metadata or {}).get("source", "")
        if isinstance(src, str) and src.startswith("drawio:"):
            kind = src.split(":", 1)[1]
            if kind in counts:
                counts[kind] += 1
    return counts


__all__ = [
    "drawio_to_system",
    "classification_summary",
    "STYLE_PREFIX_MAP",
]
