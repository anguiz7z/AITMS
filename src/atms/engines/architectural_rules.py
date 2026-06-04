"""Architectural-pattern rule engine (v0.18.5 Cycle R).

Per-component playbooks catch threats inherent to a component type
(e.g. "AWS Lambda may leak env vars"). But many real threats are
TOPOLOGY-LEVEL: they emerge from how components are arranged, not
from any single component. Examples:

  - "Database directly reachable from a Customer node, bypassing any
    app tier" — not a db threat, not a customer threat; an EDGE pattern.
  - "Secrets vault present but nothing references it" — orphan.
  - "Web app accessible from the Internet with no WAF/reverse-proxy
    in front" — multi-component arrangement.

This engine declares such patterns as `ArchRule` instances and fires
them by walking the topology. Inspired by Threagile's `risks/built-in`
pattern (MIT-licensed, studied at design time, NOT copy-pasted —
this is a clean-room Python re-implementation). The rule SHAPES are
the same idea (declared metadata + fire condition + per-asset
emission); the IMPLEMENTATIONS are written from scratch against
ATMS's own model.

Scope: 6 starter rules covering the highest-value patterns identified
in the v0.18.5 research pass. New rules are added as `ArchRule(...)`
entries in `ARCHITECTURAL_RULES`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from ..models import Component, Dataflow, System, Threat

log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────
# Rule shape.
# ────────────────────────────────────────────────────────────────────

Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class ArchRule:
    """A topology-pattern rule. Fires zero or more Threats per System.

    Attributes:
        name: snake_case identifier (also used as the threat-id prefix).
        title: human-readable threat title (rendered in the report).
        description: 2-3 sentences explaining the pattern + why it's risky.
        severity: default severity bucket. Individual fires can override
                  via `severity_override` returned by `fire`.
        mitigations: 3-5 concrete mitigation strings.
        refs: framework citations (ATLAS / ATT&CK / CWE / OWASP IDs).
        fire: callable that walks the system and returns a list of
              (subject_component, optional_severity_override) tuples.
              Each tuple becomes one Threat attached to the subject.
        stride_ai: STRIDE-for-AI categories the rule maps to.

    The clean-room re-implementation principle: this dataclass shape
    was DESIGNED for ATMS's NetworkX-style topology — not lifted from
    Threagile's Go struct. Threagile uses `RiskCategory + GenerateRisks()`;
    we use a single `ArchRule + fire()` callable because Python's
    closure model makes the metadata-as-attribute pattern cleaner.
    """

    name: str
    title: str
    description: str
    severity: Severity
    mitigations: tuple[str, ...]
    refs: tuple[str, ...]
    fire: Callable[[System], list[tuple[Component, Severity | None]]]
    stride_ai: tuple[str, ...] = ()


# ────────────────────────────────────────────────────────────────────
# Topology helpers used by multiple rules.
# ────────────────────────────────────────────────────────────────────

_INTERNET_FACING_TYPES = frozenset({"user"})

# v1.0.5 — defensibility: a `user` is not automatically "external-facing".
# An SSO-authenticated internal employee (trust_zone corp_internal) is not
# an Internet actor, and findings titled "...shares trust zone with
# external-facing components" must not fire just because such a user is
# co-located. A user counts as external-facing UNLESS its trust_zone is
# clearly an internal/trusted one. Components in an explicitly external /
# internet / public / untrusted zone are external-facing regardless of type.
_TRUSTED_ZONE_KEYWORDS = (
    "corp_internal", "corp_net", "corporate", "internal", "clinical",
    "trusted", "private", "intranet", "corp-internal", "corp_dmz",
)
_EXTERNAL_ZONE_KEYWORDS = (
    "internet", "public", "untrusted", "external", "dmz_external",
)


def _zone_is_trusted(zone: str) -> bool:
    z = (zone or "").lower()
    if not z:
        return False
    # Explicit external markers win even if a trusted token also appears.
    if any(k in z for k in _EXTERNAL_ZONE_KEYWORDS):
        return False
    return any(k in z for k in _TRUSTED_ZONE_KEYWORDS)


def _is_external_facing(comp: Component) -> bool:
    """True when a component represents (or sits at) an untrusted edge.

    A `user` is external-facing unless its trust_zone is an internal/
    trusted one. Any component whose trust_zone is an explicitly external/
    internet/public/untrusted zone is external-facing regardless of type."""
    zone = (comp.trust_zone or "").lower()
    if any(k in zone for k in _EXTERNAL_ZONE_KEYWORDS):
        return True
    if comp.type in _INTERNET_FACING_TYPES:
        # A user in a trusted zone (SSO employee) is NOT external-facing.
        return not _zone_is_trusted(comp.trust_zone or "")
    return False


_PROTECTIVE_TYPES = frozenset({
    "waf", "ddos_mitigation", "api_gateway", "load_balancer",
    "reverse_proxy", "firewall", "cdn", "web_proxy",
})

_SENSITIVE_DATA_STORES = frozenset({
    "database", "nosql_database", "graph_database", "time_series_database",
    "data_warehouse", "data_lake", "rag_vector_store", "secrets_vault",
    "kms_key", "hsm", "object_storage",
})

_SECRETS_CONSUMERS = frozenset({
    "agent", "serverless_function", "container_runtime", "container_orchestrator",
    "web_application", "ml_inference_endpoint", "llm_inference", "ci_cd_pipeline",
    "build_runner", "etl_orchestrator",
})


def _inbound(system: System, comp_id: str) -> list[Dataflow]:
    return [df for df in system.dataflows if df.target == comp_id]


def _outbound(system: System, comp_id: str) -> list[Dataflow]:
    return [df for df in system.dataflows if df.source == comp_id]


def _component_by_id(system: System, comp_id: str) -> Component | None:
    return next((c for c in system.components if c.id == comp_id), None)


# ────────────────────────────────────────────────────────────────────
# Rule 1: unguarded_access_from_internet
# ────────────────────────────────────────────────────────────────────

def _fire_unguarded_internet(system: System):
    """Sensitive component directly reachable from a `user` /
    Internet-facing node without a WAF / load-balancer / API gateway
    / reverse-proxy hop in front."""
    out: list[tuple[Component, Severity | None]] = []
    # v1.0.5: only EXTERNAL-facing actors make this an "Internet exposure"
    # finding. An internal SSO employee/agent reaching a component is not an
    # Internet path — flagging it as such overstates the exposure.
    user_ids = {c.id for c in system.components if _is_external_facing(c)}
    if not user_ids:
        return out
    for comp in system.components:
        if comp.type in _PROTECTIVE_TYPES:
            continue
        if comp.type in _INTERNET_FACING_TYPES:
            continue
        for edge in _inbound(system, comp.id):
            if edge.source in user_ids:
                # Severity escalates for sensitive data stores.
                sev: Severity | None = "critical" if comp.type in _SENSITIVE_DATA_STORES else None
                out.append((comp, sev))
                break
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 2: missing_waf
# ────────────────────────────────────────────────────────────────────

# WAF can be declared three ways, not just as a dedicated component type:
#   - type ∈ {waf, ddos_mitigation, cdn}
#   - a `waf` / `web application firewall` token in name / description
#   - a `waf` control on the component's `controls` list
# v1.0.5: rules 16-25 already scan controls/description for declared
# controls; missing_waf was the one older rule that didn't, which produced
# indefensible false positives (flagging "Azure Front Door + WAF" for
# *lacking* a WAF). This brings it in line.
_WAF_COMPONENT_TYPES = frozenset({"waf", "ddos_mitigation", "cdn"})
_WAF_HINTS = ("waf", "web application firewall", "web-application-firewall",
              "app gateway waf", "front door", "frontdoor", "cloudflare",
              "app protect", "cloud armor", "imperva")


def _declares_waf(comp: Component | None) -> bool:
    """True when a component IS a WAF or declares one inline (name /
    description / controls). Mirrors the controls-aware detection used by
    the operational-control rules (16-25)."""
    if comp is None:
        return False
    if comp.type in _WAF_COMPONENT_TYPES:
        return True
    haystack = " ".join([
        comp.name or "",
        comp.description or "",
        " ".join(comp.controls or []),
    ])
    return _has_any_hint(haystack, _WAF_HINTS)


def _fire_missing_waf(system: System):
    """A web-tier component DIRECTLY reachable from an Internet actor (a
    `user`, or a component in an internet/public/untrusted trust zone)
    with no WAF in front. v1.0.5: scoped to a *direct* inbound internet
    edge (one hop), not any 4-hop-transitive reachability — a private
    inference endpoint several hops behind an API gateway is not an
    'internet-facing web tier'. A WAF declared inline on the entry
    component (or any directly-upstream hop) satisfies the rule."""
    out: list[tuple[Component, Severity | None]] = []
    internet_zone_keywords = ("internet", "public", "untrusted", "external")
    internet_ids = {
        c.id for c in system.components
        if c.type in _INTERNET_FACING_TYPES
        or any(k in (c.trust_zone or "").lower() for k in internet_zone_keywords)
    }
    if not internet_ids:
        return out
    web_tier = {"web_application", "api_gateway", "ml_inference_endpoint", "llm_inference"}
    for comp in system.components:
        if comp.type not in web_tier:
            continue
        # The component itself can be the WAF (e.g. "Azure Front Door + WAF").
        if _declares_waf(comp):
            continue
        # Only consider a DIRECT inbound edge from an Internet actor.
        inbound_sources = [
            _component_by_id(system, e.source) for e in _inbound(system, comp.id)
        ]
        directly_internet_facing = any(
            (src is not None and src.id in internet_ids) for src in inbound_sources
        )
        if not directly_internet_facing:
            continue
        # A WAF on any directly-upstream hop also protects it.
        if any(_declares_waf(src) for src in inbound_sources):
            continue
        out.append((comp, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 3: unguarded_direct_datastore_access
# ────────────────────────────────────────────────────────────────────

def _fire_direct_datastore_access(system: System):
    """A data store has an inbound edge directly from a `user` or
    external-facing component. Datastores should be fronted by an
    app/service tier; never expose DB ports to clients."""
    out: list[tuple[Component, Severity | None]] = []
    untrusted_zone_keywords = ("external", "untrusted", "internet", "public")
    # v1.0.5: an internal SSO employee is not an untrusted source for a
    # "datastore exposed to clients" finding; use the zone-aware classifier.
    user_ids = {c.id for c in system.components if _is_external_facing(c)}
    untrusted_ids = {
        c.id for c in system.components
        if any(k in (c.trust_zone or "").lower() for k in untrusted_zone_keywords)
    }
    bad_sources = user_ids | untrusted_ids
    for comp in system.components:
        if comp.type not in _SENSITIVE_DATA_STORES:
            continue
        for edge in _inbound(system, comp.id):
            if edge.source in bad_sources:
                out.append((comp, "high"))
                break
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 4: missing_vault
# ────────────────────────────────────────────────────────────────────

def _fire_missing_vault(system: System):
    """The system has secrets-consuming components but no secrets_vault
    or hsm component is modelled. Fires once on each consumer."""
    has_vault = any(
        c.type in {"secrets_vault", "hsm", "kms_key"}
        for c in system.components
    )
    if has_vault:
        return []
    out: list[tuple[Component, Severity | None]] = []
    for comp in system.components:
        if comp.type in _SECRETS_CONSUMERS:
            out.append((comp, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 5: missing_network_segmentation
# ────────────────────────────────────────────────────────────────────

def _fire_missing_network_segmentation(system: System):
    """A sensitive data store shares a trust zone with at least one
    `user` or external-facing component. Datastores should live in
    their own segment, not co-located with traffic-handling tiers."""
    out: list[tuple[Component, Severity | None]] = []
    zone_members: dict[str, list[Component]] = {}
    for c in system.components:
        zone_members.setdefault(c.trust_zone or "default", []).append(c)
    for _zone, members in zone_members.items():
        stores = [m for m in members if m.type in _SENSITIVE_DATA_STORES]
        # v1.0.5: only EXTERNAL-facing co-tenants count. An internal SSO
        # employee sharing the zone is not an "external-facing component",
        # so the finding's own title stays accurate.
        externals = [m for m in members if _is_external_facing(m)]
        if stores and externals:
            for s in stores:
                out.append((s, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 6: orphan_secrets_vault
# ────────────────────────────────────────────────────────────────────

def _fire_orphan_vault(system: System):
    """A secrets_vault / hsm / kms_key component exists but no other
    component reads from it (no inbound edge from a consumer, no
    outbound edge to anything). Suggests either:
      (a) the vault is decorative (modelled but unused — bad),
      (b) the dataflows are incomplete (missing edges).
    Either way, surface it."""
    out: list[tuple[Component, Severity | None]] = []
    for comp in system.components:
        if comp.type not in {"secrets_vault", "hsm", "kms_key"}:
            continue
        used = bool(_inbound(system, comp.id) or _outbound(system, comp.id))
        if not used:
            out.append((comp, "low"))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 7 (v0.18.6): unencrypted_communication
# ────────────────────────────────────────────────────────────────────

# Label tokens that signal a dataflow is encrypted in transit.
_ENCRYPTION_HINTS = (
    "tls", "https", "ssl", "mtls", "wss", "sftp", "scp", "ipsec",
    "encrypted", "vpn", "tls 1.2", "tls 1.3",
)

# Components where data-at-rest / in-transit semantics are inherent
# (the very purpose of the component is to handle encrypted material).
_INHERENTLY_ENCRYPTED = frozenset({
    "kms_key", "hsm", "secrets_vault", "certificate_manager",
})


def _fire_unencrypted_communication(system: System):
    """A cross-boundary dataflow whose label contains no encryption
    hint (tls/https/ssl/mtls/encrypted) is treated as unencrypted —
    a common architectural oversight."""
    out: list[tuple[Component, Severity | None]] = []
    emitted_components: set[str] = set()
    for df in system.dataflows:
        if not df.crosses_boundary:
            continue
        # Inherent encryption endpoints skip (KMS, HSM, vault).
        src = _component_by_id(system, df.source)
        tgt = _component_by_id(system, df.target)
        if src and src.type in _INHERENTLY_ENCRYPTED:
            continue
        if tgt and tgt.type in _INHERENTLY_ENCRYPTED:
            continue
        label_lc = (df.label or "").lower()
        if any(hint in label_lc for hint in _ENCRYPTION_HINTS):
            continue
        # Fire the threat against the TARGET (the recipient that
        # accepts unencrypted input). One threat per target component
        # — avoid spamming if multiple unencrypted edges hit the same
        # node.
        if tgt is None or tgt.id in emitted_components:
            continue
        emitted_components.add(tgt.id)
        out.append((tgt, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 8: missing_authentication
# ────────────────────────────────────────────────────────────────────

_AUTH_HINTS = (
    "auth", "token", "oauth", "oidc", "saml", "jwt", "mfa", "sso",
    "bearer", "api key", "api-key", "apikey", "session",
)

_SENSITIVE_RECEIVERS = frozenset({
    "web_application", "api_gateway", "ml_inference_endpoint",
    "llm_inference", "agent", "serverless_function", "container_runtime",
    "database", "nosql_database", "graph_database", "data_warehouse",
    "rag_vector_store", "secrets_vault",
})


def _fire_missing_authentication(system: System):
    """A sensitive receiver has inbound edges with no auth-bearing
    label hint AND no identity-provider / mfa component anywhere in
    the system. Suggests an unauthenticated endpoint."""
    out: list[tuple[Component, Severity | None]] = []
    # Globally check: does the system have any auth infrastructure?
    has_idp = any(
        c.type in {"identity_provider", "mfa_service", "directory_service",
                    "ciam_platform", "sso_service"}
        for c in system.components
    )
    for comp in system.components:
        if comp.type not in _SENSITIVE_RECEIVERS:
            continue
        inbound = _inbound(system, comp.id)
        if not inbound:
            continue
        # If ALL inbound edges mention auth in the label, we're good.
        # Otherwise fire.
        all_authed = True
        for df in inbound:
            label_lc = (df.label or "").lower()
            if not any(hint in label_lc for hint in _AUTH_HINTS):
                all_authed = False
                break
        if all_authed:
            continue
        # Severity escalates when there's no IdP anywhere — strong
        # signal that auth was never modelled, vs. an IdP that simply
        # isn't on this particular edge.
        sev: Severity | None = "high" if not has_idp else None
        out.append((comp, sev))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 9: logs_capture_secrets
# ────────────────────────────────────────────────────────────────────

_LOGGING_SINKS = frozenset({
    "log_aggregator", "observability_stack", "siem", "tracing_platform",
    "metrics_platform",
})

_SECRET_BEARING_SOURCES = frozenset({
    "secrets_vault", "hsm", "kms_key", "certificate_manager",
    "database", "nosql_database",  # often log SQL queries verbatim
    "identity_provider", "directory_service", "ciam_platform",
})

_REDACTION_HINTS = ("redact", "scrub", "mask", "sanitize", "filter")


def _fire_logs_capture_secrets(system: System):
    """A secret-bearing source has an outbound edge to a logging /
    observability sink without any 'redact' / 'scrub' / 'mask' hint
    in the label. Surfaces the "secrets in logs" anti-pattern."""
    out: list[tuple[Component, Severity | None]] = []
    emitted: set[str] = set()
    for df in system.dataflows:
        src = _component_by_id(system, df.source)
        tgt = _component_by_id(system, df.target)
        if src is None or tgt is None:
            continue
        if src.type not in _SECRET_BEARING_SOURCES:
            continue
        if tgt.type not in _LOGGING_SINKS:
            continue
        label_lc = (df.label or "").lower()
        if any(hint in label_lc for hint in _REDACTION_HINTS):
            continue
        if src.id in emitted:
            continue
        emitted.add(src.id)
        out.append((src, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 10: unrestricted_external_egress
# ────────────────────────────────────────────────────────────────────

_GATEWAY_EXEMPT = frozenset({
    "api_gateway", "load_balancer", "cdn", "reverse_proxy",
    "web_proxy", "firewall", "ddos_mitigation", "waf",
    "transit_gateway", "private_link", "vpn_gateway",
    "service_mesh",
})


def _fire_unrestricted_external_egress(system: System):
    """A non-gateway component has > 2 outbound edges to external_api
    or user components. Suggests broad data-exfiltration surface or
    a workload acting as a de-facto gateway without the controls."""
    out: list[tuple[Component, Severity | None]] = []
    external_ids = {
        c.id for c in system.components
        if c.type in {"external_api", "user"}
    }
    if not external_ids:
        return out
    for comp in system.components:
        if comp.type in _GATEWAY_EXEMPT:
            continue
        outbound = _outbound(system, comp.id)
        external_outbound = [df for df in outbound if df.target in external_ids]
        if len(external_outbound) > 2:
            out.append((comp, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 11 (v0.18.9 Cycle Y): container_platform_escape
# ────────────────────────────────────────────────────────────────────

_CONTAINER_TYPES = frozenset({"container_runtime", "container_orchestrator"})
_CONTAINER_SECURITY_TYPES = frozenset({
    "container_security", "edr_agent", "cspm",
})


def _fire_container_platform_escape(system: System):
    """A container runtime / orchestrator is in scope but no
    container-security component (Aqua / Sysdig / Falco / Twistlock)
    or EDR / CSPM is modeled to detect platform escape. High-value
    attack surface left without runtime detection."""
    has_container_sec = any(
        c.type in _CONTAINER_SECURITY_TYPES for c in system.components
    )
    if has_container_sec:
        return []
    return [
        (c, None) for c in system.components if c.type in _CONTAINER_TYPES
    ]


# ────────────────────────────────────────────────────────────────────
# Rule 12: missing_identity_propagation
# ────────────────────────────────────────────────────────────────────

def _fire_missing_identity_propagation(system: System):
    """A request enters with an auth-bearing edge (token/oauth/oidc/…)
    but the next hop downstream has NO auth signal — the identity has
    been DROPPED mid-flow. Common when an api_gateway authenticates
    the caller but then opens an unauthenticated socket to the backend."""
    out: list[tuple[Component, Severity | None]] = []
    emitted: set[str] = set()
    for comp in system.components:
        if comp.type not in {"api_gateway", "load_balancer", "reverse_proxy",
                              "web_application", "service_mesh"}:
            continue
        inbound = _inbound(system, comp.id)
        # Does at least one inbound edge carry an auth hint?
        has_inbound_auth = False
        for df in inbound:
            label_lc = (df.label or "").lower()
            if any(hint in label_lc for hint in _AUTH_HINTS):
                has_inbound_auth = True
                break
        if not has_inbound_auth:
            continue
        # Now check outbound: is ANY outbound edge missing auth?
        outbound = _outbound(system, comp.id)
        for df in outbound:
            tgt = _component_by_id(system, df.target)
            if tgt is None or tgt.type in _INHERENTLY_ENCRYPTED:
                continue
            # Skip internal infrastructure where identity propagation
            # isn't really meaningful (e.g., a CDN's outbound to its
            # own origin, or to observability).
            if tgt.type in {"log_aggregator", "observability_stack",
                             "metrics_platform", "tracing_platform"}:
                continue
            label_lc = (df.label or "").lower()
            if not any(hint in label_lc for hint in _AUTH_HINTS):
                if tgt.id in emitted:
                    continue
                emitted.add(tgt.id)
                out.append((tgt, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 13: accidental_secret_leak
# ────────────────────────────────────────────────────────────────────

_SECRET_USING_INFRA = frozenset({
    "code_repository", "ci_cd_pipeline", "build_runner",
    "iac_template_registry", "artifact_registry",
})


def _fire_accidental_secret_leak(system: System):
    """A code repository, CI/CD pipeline, build runner, or IaC registry
    is modeled but there's no edge to a secrets_vault / hsm. Almost
    certainly means secrets are baked into source files, config, or
    CI variables — the textbook 'AWS keys in github' antipattern."""
    out: list[tuple[Component, Severity | None]] = []
    vault_ids = {
        c.id for c in system.components
        if c.type in {"secrets_vault", "hsm", "kms_key"}
    }
    if not vault_ids:
        # No vault at all → defer to missing_vault rule. Don't double-fire.
        return out
    for comp in system.components:
        if comp.type not in _SECRET_USING_INFRA:
            continue
        outbound = _outbound(system, comp.id)
        references_vault = any(df.target in vault_ids for df in outbound)
        if not references_vault:
            out.append((comp, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 14: missing_build_infrastructure
# ────────────────────────────────────────────────────────────────────

_BUILD_INFRA_TYPES = frozenset({
    "ci_cd_pipeline", "build_runner", "code_repository",
    "artifact_registry", "container_registry",
})


def _fire_missing_build_infrastructure(system: System):
    """A production deployment with container runtimes but no
    code_repository / ci_cd_pipeline / build_runner / artifact registry
    modeled. The model is incomplete — supply-chain threats are
    invisible without these. Low severity because the FINDING is
    'audit the model', not 'fix the system'."""
    deployment_stage = (system.deployment_stage or "").lower()
    if deployment_stage not in {"production", "pilot"}:
        return []
    has_workload = any(
        c.type in _CONTAINER_TYPES or c.type == "serverless_function"
        for c in system.components
    )
    if not has_workload:
        return []
    has_build = any(c.type in _BUILD_INFRA_TYPES for c in system.components)
    if has_build:
        return []
    # Fire once on the first workload as the "subject" of the finding.
    for comp in system.components:
        if comp.type in _CONTAINER_TYPES or comp.type == "serverless_function":
            return [(comp, None)]
    return []


# ────────────────────────────────────────────────────────────────────
# Rule 15: excessive_principal_blast_radius
# ────────────────────────────────────────────────────────────────────

def _fire_excessive_principal_blast_radius(system: System):
    """An iam_principal has outbound edges to more than 3 distinct
    sensitive data stores. If the principal is compromised, the
    blast radius spans all of them — split into per-purpose roles
    with least-privilege scopes."""
    out: list[tuple[Component, Severity | None]] = []
    for comp in system.components:
        if comp.type != "iam_principal":
            continue
        outbound = _outbound(system, comp.id)
        # Count distinct sensitive-store targets.
        sensitive_targets: set[str] = set()
        for df in outbound:
            tgt = _component_by_id(system, df.target)
            if tgt and tgt.type in _SENSITIVE_DATA_STORES:
                sensitive_targets.add(tgt.id)
        if len(sensitive_targets) > 3:
            out.append((comp, None))
    return out


# ────────────────────────────────────────────────────────────────────
# v0.18.12 Cycle BB — Operational-security-controls rules (16-20).
#
# Theme: the previous batches covered exposure / auth / secrets /
# supply-chain. This batch covers the operational controls a SOC /
# auditor expects to see — logging, backup, intrusion detection,
# MFA at the perimeter, and encryption-at-rest. Each rule maps to a
# named NIST SP 800-53 control and an ISO/IEC 27001 Annex A control
# so the findings translate directly to compliance language.
# ────────────────────────────────────────────────────────────────────

# Components that count as "running workload" — these are the assets
# whose absence-of-logging / absence-of-detection a SOC would flag.
_WORKLOAD_TYPES = frozenset({
    "web_application", "api_gateway", "serverless_function",
    "container_runtime", "container_orchestrator", "llm_inference",
    "ml_inference_endpoint", "agent", "batch_compute",
    "edge_compute", "high_performance_compute", "ml_training_job",
})

# Components that count as "centralised log/event collection".
_LOGGING_TYPES = frozenset({
    "siem", "log_aggregator", "security_data_lake", "observability_stack",
})

# Components that count as "active intrusion / threat detection".
# SIEM alone is a passive collector; SI-4 wants active detection.
_DETECTION_TYPES = frozenset({
    "ids_ips", "edr_agent", "container_security", "casb", "dlp",
})

# Datastores whose loss / corruption demands a backup strategy.
_BACKUPABLE_STORES = frozenset({
    "database", "nosql_database", "graph_database", "time_series_database",
    "data_warehouse", "data_lake", "object_storage", "block_storage",
    "file_storage",
})

# Dataflow-label hints that indicate a backup / replication relationship.
_BACKUP_LABEL_HINTS = ("backup", "snapshot", "replicat", "restore",
                       "archive", "pitr", "wal-ship")

# Component-control hints that suppress the backup rule.
_BACKUP_CONTROL_HINTS = ("backup", "snapshot", "replicat", "pitr",
                        "point_in_time", "immutable")

# MFA hints scanned in dataflow labels / component controls.
_MFA_HINTS = ("mfa", "totp", "webauthn", "fido", "u2f",
              "otp", "2fa", "two-factor", "two_factor", "push notification")

# Encryption-at-rest hints scanned in description / controls / metadata.
_ENCRYPTION_AT_REST_HINTS = (
    "encrypt", "tde", "sse-s3", "sse-kms", "sse-c", "kms", "envelope",
    "at rest", "at-rest", "at_rest", "cmk", "customer managed key",
    "luks", "dm-crypt", "filevault", "bitlocker",
)

# Datastores whose unencrypted-at-rest finding is HIGH (vs medium for
# bulk object storage).
_SENSITIVE_AT_REST_STORES = frozenset({
    "database", "nosql_database", "graph_database", "time_series_database",
    "data_warehouse", "secrets_vault",
})


def _has_any_hint(text: str, hints: tuple[str, ...]) -> bool:
    """Case-insensitive substring scan for any hint in `text`."""
    if not text:
        return False
    lower = text.lower()
    return any(h in lower for h in hints)


# ────────────────────────────────────────────────────────────────────
# Rule 16: missing_centralized_logging  (NIST AU-2 / ISO A.12.4)
# ────────────────────────────────────────────────────────────────────

def _fire_missing_centralized_logging(system: System):
    """≥3 workload components are modeled but no SIEM / log_aggregator
    / xdr_platform exists. Without centralised logging, incident
    response is blind and audit-trail completeness (NIST AU-2,
    ISO 27001 A.12.4.1) cannot be demonstrated."""
    workloads = [c for c in system.components if c.type in _WORKLOAD_TYPES]
    if len(workloads) < 3:
        return []
    has_logging = any(c.type in _LOGGING_TYPES for c in system.components)
    if has_logging:
        return []
    # Suppress if every workload's `controls` lists 'centralized_logging'
    # or similar — the user has declared the control out-of-band.
    declared = all(
        any("logging" in ctl.lower() or "audit" in ctl.lower()
            for ctl in w.controls)
        for w in workloads
    )
    if declared:
        return []
    # Fire once per workload so the gap is visible across the diagram.
    return [(w, None) for w in workloads]


# ────────────────────────────────────────────────────────────────────
# Rule 17: missing_backup_for_critical_data  (NIST CP-9 / ISO A.12.3)
# ────────────────────────────────────────────────────────────────────

def _fire_missing_backup_for_critical_data(system: System):
    """A sensitive datastore has no backup relationship modeled and
    no `backup_service` component anywhere in the system. Triggers a
    finding because CP-9 / ISO A.12.3.1 require a working backup
    strategy for restoration after destruction or ransomware."""
    out: list[tuple[Component, Severity | None]] = []
    has_backup_service = any(c.type == "backup_service" for c in system.components)
    stage = (system.deployment_stage or "").lower()
    for comp in system.components:
        if comp.type not in _BACKUPABLE_STORES:
            continue
        # Suppress if a backup_service exists AND has any edge from
        # this datastore to the backup service.
        if has_backup_service:
            outbound = _outbound(system, comp.id)
            inbound = _inbound(system, comp.id)
            edges_to_backup = [
                e for e in (outbound + inbound)
                if (_component_by_id(system, e.target) or
                    _component_by_id(system, e.source)).type == "backup_service"
                if (_component_by_id(system, e.target) is not None or
                    _component_by_id(system, e.source) is not None)
            ]
            if edges_to_backup:
                continue
        # Suppress if the user has declared an out-of-band control.
        if any(_has_any_hint(ctl, _BACKUP_CONTROL_HINTS) for ctl in comp.controls):
            continue
        # Suppress if any outbound edge label suggests backup / replication.
        outbound = _outbound(system, comp.id)
        if any(_has_any_hint(df.label, _BACKUP_LABEL_HINTS) for df in outbound):
            continue
        sev: Severity | None = "high" if stage == "production" else None
        out.append((comp, sev))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 18: missing_intrusion_detection  (NIST SI-4 / ISO A.13.1)
# ────────────────────────────────────────────────────────────────────

def _fire_missing_intrusion_detection(system: System):
    """≥3 workload components in production/pilot but no IDS/IPS /
    EDR / XDR / container-security agent is modeled. SIEM alone
    counts as passive log collection, not active detection —
    SI-4 / ISO A.13.1.1 require detection capability."""
    stage = (system.deployment_stage or "").lower()
    if stage not in {"production", "pilot"}:
        return []
    workloads = [c for c in system.components if c.type in _WORKLOAD_TYPES]
    if len(workloads) < 3:
        return []
    has_detection = any(c.type in _DETECTION_TYPES for c in system.components)
    if has_detection:
        return []
    # Suppress if every workload declares an edr / xdr / ids control.
    declared = all(
        any(_has_any_hint(ctl, ("edr", "xdr", "ids", "ips", "endpoint protection"))
            for ctl in w.controls)
        for w in workloads
    )
    if declared:
        return []
    return [(w, None) for w in workloads]


# ────────────────────────────────────────────────────────────────────
# Rule 19: mfa_not_enforced  (NIST IA-2(1) / ISO A.9.4.2)
# ────────────────────────────────────────────────────────────────────

_AUTH_BACKENDS = frozenset({
    "identity_provider", "ciam_platform", "sso_service", "directory_service",
})


def _fire_mfa_not_enforced(system: System):
    """A `user` node has an edge to an authentication backend
    (`auth_service` / `iam_identity_provider` / `ciam_platform`) but
    no MFA signal is present anywhere — no `mfa_service` component,
    no MFA hint on the edge label, and the auth backend's `controls`
    list does not declare `mfa_required`. NIST IA-2(1) /
    ISO A.9.4.2 require MFA at the perimeter for privileged or
    internet-facing access paths."""
    user_ids = {c.id for c in system.components if c.type in _INTERNET_FACING_TYPES}
    if not user_ids:
        return []
    if any(c.type == "mfa_service" for c in system.components):
        return []
    out: list[tuple[Component, Severity | None]] = []
    seen_backends: set[str] = set()
    for df in system.dataflows:
        if df.source not in user_ids:
            continue
        backend = _component_by_id(system, df.target)
        if backend is None or backend.type not in _AUTH_BACKENDS:
            continue
        if backend.id in seen_backends:
            continue
        # Suppress if the backend or the edge declares MFA.
        if any(_has_any_hint(ctl, _MFA_HINTS) for ctl in backend.controls):
            seen_backends.add(backend.id)
            continue
        if _has_any_hint(df.label, _MFA_HINTS):
            seen_backends.add(backend.id)
            continue
        seen_backends.add(backend.id)
        out.append((backend, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 20: data_at_rest_unencrypted  (NIST SC-28 / ISO A.10.1)
# ────────────────────────────────────────────────────────────────────

def _fire_data_at_rest_unencrypted(system: System):
    """A sensitive datastore shows no evidence of encryption-at-rest:
    its description, metadata, and `controls` list lack any
    encryption / KMS / TDE hint, AND no `kms_key` / `hsm` component
    is referenced by the datastore. SC-28 / ISO A.10.1.1 require
    cryptographic protection of data at rest for confidential or
    restricted information."""
    out: list[tuple[Component, Severity | None]] = []
    has_kms = any(c.type in {"kms_key", "hsm"} for c in system.components)
    for comp in system.components:
        if comp.type not in _BACKUPABLE_STORES and comp.type != "secrets_vault":
            continue
        # Search description + controls + metadata for encryption hints.
        haystack_parts = [comp.description or ""]
        haystack_parts.extend(comp.controls)
        for k, v in (comp.metadata or {}).items():
            haystack_parts.append(f"{k}={v}")
        haystack = " ".join(haystack_parts)
        if _has_any_hint(haystack, _ENCRYPTION_AT_REST_HINTS):
            continue
        # Suppress if any inbound or outbound edge connects this store
        # to a kms_key / hsm — implies the store consumes the KMS.
        if has_kms:
            related = _inbound(system, comp.id) + _outbound(system, comp.id)
            touches_kms = False
            for df in related:
                other = _component_by_id(system, df.source) \
                    if df.target == comp.id else _component_by_id(system, df.target)
                if other and other.type in {"kms_key", "hsm"}:
                    touches_kms = True
                    break
            if touches_kms:
                continue
        sev: Severity | None = "high" if comp.type in _SENSITIVE_AT_REST_STORES else None
        out.append((comp, sev))
    return out


# ────────────────────────────────────────────────────────────────────
# v0.18.28 Cycle RR — AI-specific operational controls (rules 21-25).
#
# Theme: the BB/V/Y batches covered cloud-IT operational controls
# (logging / backup / IDS / MFA / encryption-at-rest). RR fills in
# the AI-specific gaps that competitors (IriusRisk, ThreatModeler)
# don't address directly: prompt-injection guardrails, PII redaction
# at the LLM boundary, model provenance / signed weights, unbounded
# agent tool access, and human oversight on high-risk AI Act systems.
# Each rule maps to OWASP LLM Top 10 + MITRE ATLAS + EU AI Act.
# ────────────────────────────────────────────────────────────────────

_LLM_COMPONENTS = frozenset({"llm_inference", "ml_inference_endpoint", "agent"})

_PROMPT_GUARDRAIL_TYPES = frozenset({
    "guardrails", "content_safety_classifier", "output_filter",
})

# Hints in dataflow labels that indicate redaction / DLP.
_PII_REDACTION_HINTS = (
    "redact", "scrub", "mask", "sanitize", "sanitise", "anonymize",
    "anonymise", "dlp", "pii filter", "tokenize",
)

# Component-control vocabulary that satisfies the corresponding rule.
_PROVENANCE_CONTROL_HINTS = ("signed", "sigstore", "cosign", "model_card",
                              "model card", "provenance", "slsa", "in-toto",
                              "sbom")


# ────────────────────────────────────────────────────────────────────
# Rule 21: missing_prompt_injection_guard  (OWASP LLM01:2025)
# ────────────────────────────────────────────────────────────────────

def _fire_missing_prompt_injection_guard(system: System):
    """An LLM/agent component receives inbound data flows but no
    guardrails / content_safety_classifier / output_filter component
    is modelled, and no `prompt_injection_guard` / `guardrails`
    control is declared on the LLM. OWASP LLM01:2025 (prompt
    injection) is the #1 risk for LLM apps; absence of an inline
    filter is a clear finding."""
    out: list[tuple[Component, Severity | None]] = []
    has_guard = any(c.type in _PROMPT_GUARDRAIL_TYPES for c in system.components)
    for comp in system.components:
        if comp.type not in _LLM_COMPONENTS:
            continue
        inbound = _inbound(system, comp.id)
        if not inbound:
            continue
        # Suppress if the component declares a guardrails-shaped control.
        declared = any(
            _has_any_hint(ctl, ("guardrail", "prompt_injection_guard",
                                  "content_safety", "input_filter"))
            for ctl in comp.controls
        )
        if has_guard or declared:
            continue
        out.append((comp, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 22: missing_pii_redaction_at_llm_boundary  (LLM06:2025)
# ────────────────────────────────────────────────────────────────────

def _fire_missing_pii_redaction(system: System):
    """A sensitive data store has an outbound flow into an LLM or
    ML inference endpoint, but the dataflow label carries no PII /
    redaction hint AND no `dlp` component sits in the system.
    OWASP LLM06:2025 (sensitive-information disclosure) — sending
    raw customer data through a black-box model is the most common
    way it leaks."""
    out: list[tuple[Component, Severity | None]] = []
    has_dlp = any(c.type == "dlp" for c in system.components)
    if has_dlp:
        return []
    for df in system.dataflows:
        src = _component_by_id(system, df.source)
        tgt = _component_by_id(system, df.target)
        if src is None or tgt is None:
            continue
        if src.type not in _SENSITIVE_DATA_STORES:
            continue
        if tgt.type not in _LLM_COMPONENTS:
            continue
        if _has_any_hint(df.label, _PII_REDACTION_HINTS):
            continue
        # Fire on the target (LLM) — that's the boundary where the
        # control should sit.
        out.append((tgt, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 23: missing_model_provenance  (ATLAS AML.T0010 + SLSA)
# ────────────────────────────────────────────────────────────────────

def _fire_missing_model_provenance(system: System):
    """A `model_registry` component is in scope but neither the
    registry nor any LLM/inference component declares a provenance
    / signing control (sigstore / cosign / SLSA / SBOM /
    model_card). Without provenance, attackers can swap models —
    ATLAS AML.T0010 (Supply Chain Compromise: Model)."""
    has_registry = any(c.type == "model_registry" for c in system.components)
    if not has_registry:
        return []
    out: list[tuple[Component, Severity | None]] = []
    for comp in system.components:
        if comp.type not in ({"model_registry"} | _LLM_COMPONENTS):
            continue
        declared = any(
            _has_any_hint(ctl, _PROVENANCE_CONTROL_HINTS)
            for ctl in comp.controls
        )
        # Also accept a hint in the description.
        if _has_any_hint(comp.description or "", _PROVENANCE_CONTROL_HINTS):
            declared = True
        if declared:
            continue
        out.append((comp, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 24: unbounded_agent_tool_access  (OWASP LLM08:2025)
# ────────────────────────────────────────────────────────────────────

def _fire_unbounded_agent_tool_access(system: System):
    """An `agent` component has outbound edges to > 5 distinct
    `tool` / `mcp_server` / `external_api` targets without any
    `tool_access_control` / `function_call_allowlist` declared on
    the agent. OWASP LLM08:2025 (excessive agency) — an agent that
    can call anything in the system is a confused-deputy risk."""
    out: list[tuple[Component, Severity | None]] = []
    tool_types = {"tool", "mcp_server", "external_api"}
    for comp in system.components:
        if comp.type != "agent":
            continue
        outbound = _outbound(system, comp.id)
        tool_targets: set[str] = set()
        for df in outbound:
            tgt = _component_by_id(system, df.target)
            if tgt and tgt.type in tool_types:
                tool_targets.add(tgt.id)
        if len(tool_targets) <= 5:
            continue
        declared = any(
            _has_any_hint(ctl, ("tool_access_control", "function_call_allowlist",
                                  "scope_restriction", "least_privilege_agent"))
            for ctl in comp.controls
        )
        if declared:
            continue
        out.append((comp, None))
    return out


# ────────────────────────────────────────────────────────────────────
# Rule 25: missing_human_oversight_high_risk  (EU AI Act Art. 14)
# ────────────────────────────────────────────────────────────────────

def _fire_missing_human_oversight(system: System):
    """The system is flagged `is_high_risk_under_eu_ai_act=True`
    AND contains AI components, but no `user` component sits
    downstream of the AI outputs (i.e. no human reviewer in the
    decision loop). EU AI Act Article 14 requires human oversight
    on Annex III high-risk systems."""
    if not getattr(system, "is_high_risk_under_eu_ai_act", False):
        return []
    ai_comp_ids = {c.id for c in system.components if c.type in _LLM_COMPONENTS}
    if not ai_comp_ids:
        return []
    # Does ANY user component receive inbound traffic from an AI
    # component (directly or one hop)?
    user_ids = {c.id for c in system.components if c.type == "user"}
    if not user_ids:
        # No user at all → human oversight definitely absent.
        out: list[tuple[Component, Severity | None]] = []
        for c in system.components:
            if c.id in ai_comp_ids:
                out.append((c, "high"))
        return out
    has_human_in_loop = False
    for df in system.dataflows:
        if df.source in ai_comp_ids and df.target in user_ids:
            has_human_in_loop = True
            break
        # 1-hop relay
        if df.source in ai_comp_ids:
            for df2 in system.dataflows:
                if df2.source == df.target and df2.target in user_ids:
                    has_human_in_loop = True
                    break
    if has_human_in_loop:
        return []
    out: list[tuple[Component, Severity | None]] = []
    for c in system.components:
        if c.id in ai_comp_ids:
            out.append((c, "high"))
    return out


# ────────────────────────────────────────────────────────────────────
# ARCHITECTURAL_RULES — the registry.
# ────────────────────────────────────────────────────────────────────

ARCHITECTURAL_RULES: tuple[ArchRule, ...] = (
    ArchRule(
        name="unguarded_access_from_internet",
        title="Sensitive component directly reachable from the Internet",
        description=(
            "A sensitive component receives traffic directly from an "
            "Internet-facing actor with no protective hop (WAF, load "
            "balancer, API gateway, reverse proxy) in between. Attackers "
            "can scan it directly, bypassing perimeter controls."
        ),
        severity="high",
        mitigations=(
            "Insert a WAF or reverse proxy in front of the component.",
            "Route all external traffic through an API gateway with auth and rate limits.",
            "Move the component to a private subnet; expose only the public-facing tier.",
            "Apply security-group rules denying 0.0.0.0/0 ingress on the sensitive component's port.",
        ),
        refs=("CWE-693", "OWASP-A05:2021", "ATLAS-AML.T0049"),
        fire=_fire_unguarded_internet,
        stride_ai=("Elevation_of_Privilege", "Information_Disclosure"),
    ),
    ArchRule(
        name="missing_waf",
        title="Internet-facing web tier without a WAF",
        description=(
            "A web application / API gateway / inference endpoint is "
            "reachable from Internet actors with no Web Application "
            "Firewall in the request path. WAFs are a baseline control "
            "for OWASP Top 10 protection."
        ),
        severity="high",
        mitigations=(
            "Front the web tier with AWS WAF / Azure WAF / Cloudflare / F5.",
            "Enable managed rule sets (OWASP CRS / AWS managed rules).",
            "Enable rate-limit and bot-protection rules.",
        ),
        refs=("CWE-1357", "OWASP-A03:2021", "AWS-SRA:WAF"),
        fire=_fire_missing_waf,
        stride_ai=("Tampering", "Denial_of_Service"),
    ),
    ArchRule(
        name="unguarded_direct_datastore_access",
        title="Datastore reachable directly from an untrusted source",
        description=(
            "A sensitive datastore has an inbound edge directly from a "
            "user / external / Internet-zone source. Clients should "
            "never speak directly to the DB; an app/service tier must "
            "mediate authorisation."
        ),
        severity="high",
        mitigations=(
            "Place the datastore behind an application or service layer.",
            "Restrict DB security-group ingress to the app-tier security group only.",
            "Enforce DB-level row/column ACLs even if network controls fail.",
            "Block public-IP attachment / disable public-access modes.",
        ),
        refs=("CWE-284", "OWASP-A01:2021", "NIST-SP800-53:AC-3"),
        fire=_fire_direct_datastore_access,
        stride_ai=("Elevation_of_Privilege", "Information_Disclosure"),
    ),
    ArchRule(
        name="missing_vault",
        title="Secrets-consuming component but no secrets vault in the model",
        description=(
            "Components that typically need credentials (agents, "
            "Lambdas, containers, CI/CD pipelines, ML inference) are "
            "modelled, but no secrets vault (Vault / Secrets Manager / "
            "Key Vault / KMS) is present. The system likely stores "
            "long-lived credentials in env vars or config — high risk "
            "of leakage and credential sprawl."
        ),
        severity="medium",
        mitigations=(
            "Introduce a secrets-management service (Vault / AWS Secrets Manager / Azure Key Vault).",
            "Fetch credentials at runtime; never bake into images or env vars.",
            "Rotate credentials short-TTL (<24h) via the vault.",
            "Audit existing components for hard-coded secrets.",
        ),
        refs=("CWE-798", "OWASP-A07:2021", "NIST-SP800-57"),
        fire=_fire_missing_vault,
        stride_ai=("Information_Disclosure",),
    ),
    ArchRule(
        name="missing_network_segmentation",
        title="Datastore shares trust zone with external-facing components",
        description=(
            "A sensitive datastore lives in the same trust zone / "
            "subnet as a user / external-facing component. Trust zones "
            "should isolate tiers — when an external-facing component "
            "is compromised, the blast radius extends to whatever "
            "shares its zone."
        ),
        severity="medium",
        mitigations=(
            "Move datastores to a dedicated private subnet / security group.",
            "Define explicit trust boundaries between web tier, app tier, and data tier.",
            "Enforce east-west ACLs / network policies between zones.",
        ),
        refs=("CWE-923", "NIST-SP800-53:SC-7", "AWS-SRA:Segmentation"),
        fire=_fire_missing_network_segmentation,
        stride_ai=("Information_Disclosure", "Elevation_of_Privilege"),
    ),
    ArchRule(
        name="orphan_secrets_vault",
        title="Secrets vault present but no component references it",
        description=(
            "A secrets_vault / hsm / kms_key component exists in the "
            "model but has no inbound or outbound dataflows. Either "
            "the vault is decorative (modelled but not consumed — "
            "still a deployment risk), or the dataflows are incomplete "
            "(audit the diagram for missing edges)."
        ),
        severity="low",
        mitigations=(
            "If decorative: remove the unused vault to reduce attack surface.",
            "If a real consumer exists: add the missing dataflow so the model is accurate.",
        ),
        refs=("CWE-1059",),
        fire=_fire_orphan_vault,
        stride_ai=(),
    ),
    # ─── v0.18.6 Cycle V: 4 more rules ────────────────────────────
    ArchRule(
        name="unencrypted_communication",
        title="Cross-boundary dataflow with no encryption hint",
        description=(
            "A dataflow crosses a trust boundary but its label contains "
            "no encryption marker (TLS / HTTPS / SSL / mTLS / encrypted "
            "/ VPN). Cross-zone traffic without confidentiality / "
            "integrity guarantees enables eavesdropping + tampering."
        ),
        severity="high",
        mitigations=(
            "Enforce TLS 1.2+ on the dataflow; reject plaintext.",
            "Use mTLS for service-to-service when both sides can present certs.",
            "Tag the dataflow label with the protocol (e.g. 'HTTPS', 'TLS') so future audits pass.",
            "Disable any plaintext fallback paths in the receiver.",
        ),
        refs=("CWE-319", "OWASP-A02:2021", "NIST-SP800-52"),
        fire=_fire_unencrypted_communication,
        stride_ai=("Information_Disclosure", "Tampering"),
    ),
    ArchRule(
        name="missing_authentication",
        title="Sensitive receiver with no authentication hint on inbound edges",
        description=(
            "A sensitive component (web app, API gateway, ML endpoint, "
            "datastore, …) has inbound edges whose labels carry no "
            "auth signal (token / OAuth / OIDC / SAML / JWT / MFA / "
            "SSO / API key). Combined with the absence of an identity "
            "provider in the system, this suggests an unauthenticated "
            "endpoint."
        ),
        severity="high",
        mitigations=(
            "Place an identity provider (Cognito / Entra / Okta) in front of the endpoint.",
            "Require an authenticated token on every inbound edge.",
            "Add the auth protocol to dataflow labels (e.g. 'POST /api (OIDC bearer)').",
            "For machine-to-machine: enforce mTLS or signed JWT.",
        ),
        refs=("CWE-306", "OWASP-A07:2021", "NIST-SP800-63"),
        fire=_fire_missing_authentication,
        stride_ai=("Spoofing", "Elevation_of_Privilege"),
    ),
    ArchRule(
        name="logs_capture_secrets",
        title="Sensitive source sends to logging sink without a redaction hint",
        description=(
            "A secret-bearing component (secrets vault, KMS, identity "
            "store, database) sends data to a log aggregator / SIEM / "
            "observability stack but the dataflow label has no "
            "'redact' / 'scrub' / 'mask' / 'sanitize' hint. Secrets "
            "in plaintext logs is one of the most common high-impact "
            "operational leaks."
        ),
        severity="medium",
        mitigations=(
            "Apply field-level redaction at the source before emitting log records.",
            "Use structured logging that separates PII / secrets from message bodies.",
            "Annotate the dataflow label with 'redacted' / 'scrubbed' so audits pass.",
            "Restrict access to the log sink to a small operations group.",
        ),
        refs=("CWE-532", "OWASP-A09:2021"),
        fire=_fire_logs_capture_secrets,
        stride_ai=("Information_Disclosure",),
    ),
    ArchRule(
        name="unrestricted_external_egress",
        title="Non-gateway component has broad external egress (> 2 destinations)",
        description=(
            "A workload (not a gateway / proxy / firewall / mesh) has "
            "more than 2 outbound edges to external_api or user "
            "components. Wide egress fan-out enlarges the data-"
            "exfiltration surface and suggests the component should "
            "either (a) live behind a controlled egress gateway, or "
            "(b) the diagram is missing the gateway hop."
        ),
        severity="low",
        mitigations=(
            "Route all external egress through an egress proxy or NAT gateway with allow-lists.",
            "Apply DLP / egress monitoring on the workload's network egress.",
            "Audit which external destinations are actually required — remove the rest.",
        ),
        refs=("CWE-200", "MITRE-ATT&CK-TA0010"),
        fire=_fire_unrestricted_external_egress,
        stride_ai=("Information_Disclosure",),
    ),
    # ─── v0.18.9 Cycle Y: 5 more rules ────────────────────────────
    ArchRule(
        name="container_platform_escape",
        title="Container runtime / orchestrator without runtime security",
        description=(
            "A container runtime (Kubernetes, ECS, EKS, etc.) is in "
            "scope but no container-security component (Aqua / Sysdig "
            "/ Falco / Twistlock / Prisma) and no EDR / CSPM is "
            "modeled to detect platform-escape attacks. Container "
            "platform escape (CVE-2022-0185, etc.) is a documented "
            "TTP — runtime detection is the practical mitigation."
        ),
        severity="medium",
        mitigations=(
            "Deploy a container-runtime security agent (Falco, Aqua, Sysdig, Defender for Containers).",
            "Enable kernel-level seccomp + AppArmor / SELinux profiles on pods.",
            "Restrict privileged containers + hostPath mounts via Pod Security Standards.",
        ),
        refs=("MITRE-ATT&CK-T1611", "CWE-269", "CIS-Kubernetes-5.7"),
        fire=_fire_container_platform_escape,
        stride_ai=("Elevation_of_Privilege",),
    ),
    ArchRule(
        name="missing_identity_propagation",
        title="Identity dropped between gateway and backend",
        description=(
            "A gateway-tier component (API gateway, load balancer, "
            "reverse proxy, web app) accepts traffic with an auth "
            "hint on the inbound edge, but at least one outbound edge "
            "to a non-observability backend has no auth signal. The "
            "caller's identity is dropped before reaching the "
            "backend, which then trusts the gateway implicitly — a "
            "classic confused-deputy setup."
        ),
        severity="medium",
        mitigations=(
            "Propagate the caller's JWT / bearer token to the backend.",
            "Use mTLS + SPIFFE / SPIRE for service-to-service identity propagation.",
            "Make the backend verify the identity independently — don't trust the gateway alone.",
        ),
        refs=("CWE-441", "OWASP-A01:2021"),
        fire=_fire_missing_identity_propagation,
        stride_ai=("Spoofing", "Elevation_of_Privilege"),
    ),
    ArchRule(
        name="accidental_secret_leak",
        title="Code / CI / build infra not connected to the secrets vault",
        description=(
            "The system has a secrets_vault and one or more of "
            "code_repository / ci_cd_pipeline / build_runner / "
            "artifact_registry / iac_template_registry, but the "
            "build-time components don't reference the vault. Almost "
            "certainly means secrets are baked into source files, "
            "CI environment variables, or pipeline definitions — "
            "the textbook 'AWS keys in github' antipattern."
        ),
        severity="high",
        mitigations=(
            "Fetch secrets at build/deploy time from the vault — never bake them into source.",
            "Enable secret-scanning on the code_repository (GitGuardian, GitHub secret scanning).",
            "Rotate any credentials that have appeared in version control history.",
            "Use OIDC-based federated identity for CI → cloud (no long-lived keys).",
        ),
        refs=("CWE-798", "CWE-540", "OWASP-A07:2021"),
        fire=_fire_accidental_secret_leak,
        stride_ai=("Information_Disclosure",),
    ),
    ArchRule(
        name="missing_build_infrastructure",
        title="Production workload but no build / supply-chain components modeled",
        description=(
            "The system is at deployment_stage=production or pilot "
            "and has container runtimes or serverless functions, but "
            "no code_repository / ci_cd_pipeline / build_runner / "
            "artifact_registry is modeled. The supply-chain threat "
            "surface (compromised dependency, signed image bypass, "
            "build-cache poisoning) is invisible to this analysis — "
            "audit the model for missing components."
        ),
        severity="low",
        mitigations=(
            "Add the actual code repository + CI/CD pipeline to the System YAML.",
            "Include the artifact / container registry that workloads pull from.",
            "Once modeled, the supply-chain playbook threats will fire automatically.",
        ),
        refs=("OWASP-CICD-1", "SLSA-Framework"),
        fire=_fire_missing_build_infrastructure,
        stride_ai=("Tampering",),
    ),
    ArchRule(
        name="excessive_principal_blast_radius",
        title="IAM principal has broad access (> 3 sensitive stores)",
        description=(
            "An iam_principal has outbound edges to more than 3 "
            "distinct sensitive data stores (DB, S3, vault, KMS, "
            "etc.). If the principal's credentials are compromised "
            "the blast radius spans all of them. Split the principal "
            "into per-purpose roles with least-privilege scopes."
        ),
        severity="medium",
        mitigations=(
            "Split the principal into one role per consuming workload.",
            "Apply least-privilege IAM policies — grant access only to the resources actually needed.",
            "Rotate the principal's credentials regularly + use short-lived STS sessions where possible.",
            "Monitor unusual access patterns with CloudTrail / Defender / GuardDuty.",
        ),
        refs=("CWE-269", "OWASP-A01:2021", "NIST-AC-6"),
        fire=_fire_excessive_principal_blast_radius,
        stride_ai=("Elevation_of_Privilege",),
    ),
    # ─── v0.18.12 Cycle BB: 5 more rules (operational controls) ──
    ArchRule(
        name="missing_centralized_logging",
        title="Workloads in scope but no centralised logging / SIEM",
        description=(
            "Three or more running workloads are modeled but no "
            "SIEM / log_aggregator / XDR component is present to "
            "collect their logs. Without centralised logging, "
            "incident response is blind and audit-trail "
            "completeness cannot be demonstrated under NIST "
            "SP 800-53 AU-2/AU-6 or ISO/IEC 27001 A.12.4.1."
        ),
        severity="medium",
        mitigations=(
            "Stand up a SIEM (Sentinel / Chronicle / Splunk / "
            "Sumo Logic / QRadar) and forward workload logs to it.",
            "Define a retention policy compliant with applicable "
            "regulations (e.g. 1 year hot + 6 years cold for finance).",
            "Send authentication + authorisation events at minimum; "
            "expand to application-level audit logs over time.",
            "Configure detection rules / correlation searches on the "
            "ingested logs so the SIEM produces alerts, not archives.",
        ),
        refs=("NIST-SP800-53:AU-2", "NIST-SP800-53:AU-6",
              "ISO-27001:A.12.4.1", "CWE-778"),
        fire=_fire_missing_centralized_logging,
        stride_ai=("Repudiation",),
    ),
    ArchRule(
        name="missing_backup_for_critical_data",
        title="Sensitive datastore with no backup relationship modeled",
        description=(
            "A sensitive datastore (DB / NoSQL / data warehouse / "
            "data lake / object / block storage) has no edge to a "
            "backup_service component, no backup-labeled outbound "
            "dataflow, and no backup-related entry in its `controls`. "
            "Without a working backup strategy, the system cannot "
            "recover from ransomware, accidental deletion, or "
            "corruption — required by NIST CP-9 and ISO A.12.3.1."
        ),
        severity="medium",
        mitigations=(
            "Enable native backup (RDS automated backups / S3 "
            "versioning + replication / Azure Backup / GCP Backup "
            "and DR) on the datastore.",
            "Store backups in a separate account / region and make "
            "them immutable (Object Lock, immutable blob storage).",
            "Test restore procedures at least quarterly — backups "
            "you have not restored from are not real backups.",
            "Model the backup_service component + dataflow in the "
            "diagram so the ATMS register reflects reality.",
        ),
        refs=("NIST-SP800-53:CP-9", "ISO-27001:A.12.3.1",
              "CWE-693", "MITRE-ATT&CK-T1485"),
        fire=_fire_missing_backup_for_critical_data,
        stride_ai=("Denial_of_Service", "Tampering"),
    ),
    ArchRule(
        name="missing_intrusion_detection",
        title="Production workloads without active intrusion detection",
        description=(
            "Three or more workloads are deployed to production / "
            "pilot but no IDS/IPS / EDR / XDR / container-security "
            "agent is modeled to actively detect intrusions. SIEM "
            "alone is passive log collection — NIST SP 800-53 SI-4 "
            "and ISO/IEC 27001 A.13.1.1 require active detection "
            "capability that produces alerts, not just an archive."
        ),
        severity="medium",
        mitigations=(
            "Deploy an EDR / XDR agent on every workload host "
            "(CrowdStrike, SentinelOne, Defender for Endpoint).",
            "Add network IDS/IPS at egress points (Suricata, Snort, "
            "AWS Network Firewall, Defender for Cloud).",
            "For container workloads add a runtime-security agent "
            "(Falco, Aqua, Sysdig, Defender for Containers).",
            "Wire detection-source alerts into the SIEM so the SOC "
            "has a single pane of glass.",
        ),
        refs=("NIST-SP800-53:SI-4", "ISO-27001:A.13.1.1",
              "CWE-693", "MITRE-DEFEND:D3-NTA"),
        fire=_fire_missing_intrusion_detection,
        stride_ai=("Tampering", "Elevation_of_Privilege"),
    ),
    ArchRule(
        name="mfa_not_enforced",
        title="User → auth backend without an MFA hint",
        description=(
            "A `user` node has an edge to an authentication backend "
            "(`identity_provider` / `sso_service` / `ciam_platform` / "
            "`directory_service`) with no MFA signal anywhere: no "
            "`mfa_service` component, no MFA hint in the edge label, "
            "and no `mfa_required` control on the backend. Single-"
            "factor authentication on perimeter login paths violates "
            "NIST IA-2(1) and ISO/IEC 27001 A.9.4.2 — and is the "
            "proximate cause of most credential-stuffing breaches in "
            "the OWASP A07 category."
        ),
        severity="high",
        mitigations=(
            "Add an `mfa_service` component to the model and route "
            "the user→auth edge through it, or annotate the existing "
            "auth backend with the control `mfa_required`.",
            "Enforce MFA for ALL users at the IdP — not just admins. "
            "Phishing-resistant factors (FIDO2/WebAuthn) preferred.",
            "Apply step-up MFA on high-risk actions (privilege "
            "escalation, payment, secret access).",
            "Disable legacy authentication protocols that bypass MFA "
            "(IMAP, POP, basic auth).",
        ),
        refs=("NIST-SP800-53:IA-2(1)", "NIST-SP800-63B:5.1",
              "ISO-27001:A.9.4.2", "OWASP-A07:2021", "CWE-308"),
        fire=_fire_mfa_not_enforced,
        stride_ai=("Spoofing", "Elevation_of_Privilege"),
    ),
    # ─── v0.18.28 Cycle RR: 5 more rules (AI-specific) ──────────
    ArchRule(
        name="missing_prompt_injection_guard",
        title="LLM/agent has no prompt-injection guardrail",
        description=(
            "An LLM, ML-inference endpoint, or agent component "
            "receives inbound dataflows but neither a "
            "`guardrails` / `content_safety_classifier` / "
            "`output_filter` component is modelled, nor does the "
            "LLM declare a `prompt_injection_guard` / `guardrails` / "
            "`content_safety` / `input_filter` control. OWASP "
            "LLM01:2025 (prompt injection) is the #1 LLM risk; "
            "absent inline filtering is a clear finding."
        ),
        severity="high",
        mitigations=(
            "Insert a content-safety classifier (Azure Content Safety / "
            "Bedrock Guardrails / Lakera) on every inbound path.",
            "Declare a structured system prompt + instruction-defence "
            "layer (e.g. delimiter parsing, role separation).",
            "Add the `prompt_injection_guard` control to the LLM "
            "component once mitigation is in place so future audits pass.",
            "For agents: enforce a function-call allowlist + sandbox "
            "tool invocations.",
        ),
        refs=("OWASP-LLM01:2025", "MITRE-ATLAS-AML.T0051",
              "NIST-AI-100-2:S.6.3"),
        fire=_fire_missing_prompt_injection_guard,
        stride_ai=("Tampering", "Elevation_of_Privilege"),
    ),
    ArchRule(
        name="missing_pii_redaction_at_llm_boundary",
        title="Sensitive datastore → LLM with no PII redaction hint",
        description=(
            "A sensitive datastore (DB / NoSQL / data warehouse / "
            "RAG vector store / etc.) has an outbound dataflow into "
            "an LLM or ML-inference endpoint, but the dataflow label "
            "carries no redaction signal (redact / scrub / mask / "
            "sanitise / DLP / tokenise) AND no `dlp` component "
            "exists in the system. OWASP LLM06:2025 (sensitive-"
            "information disclosure) — sending raw customer data "
            "through a black-box model is the most common leakage "
            "path."
        ),
        severity="high",
        mitigations=(
            "Add a DLP component (Azure Purview / AWS Macie / "
            "BigID / Privitar) on the data path.",
            "Tokenise PII fields before passing them to the LLM; "
            "detokenise only inside the trust boundary.",
            "Tag the dataflow label with the redaction protocol so "
            "audits + this rule see it explicitly.",
            "Configure prompt templates to NEVER ask the model to "
            "echo back PII verbatim.",
        ),
        refs=("OWASP-LLM06:2025", "GDPR-Art.32", "NIST-AI-100-2:S.5.5"),
        fire=_fire_missing_pii_redaction,
        stride_ai=("Information_Disclosure",),
    ),
    ArchRule(
        name="missing_model_provenance",
        title="Model registry without signing / provenance evidence",
        description=(
            "A `model_registry` component is modelled but neither "
            "the registry nor any consuming LLM declares a "
            "provenance / signing control (sigstore / cosign / "
            "SLSA / SBOM / model_card). Without provenance an "
            "attacker can swap the model — MITRE ATLAS AML.T0010 "
            "(Supply-Chain Compromise: Model) — and the system has "
            "no way to detect it."
        ),
        severity="medium",
        mitigations=(
            "Sign model artefacts with sigstore / cosign at build time; "
            "verify signature at load time.",
            "Adopt SLSA provenance for the training + packaging steps.",
            "Publish a model card per registered version (intended use, "
            "training data, evaluation, known limitations).",
            "Capture and persist an SBOM for every served model.",
        ),
        refs=("MITRE-ATLAS-AML.T0010", "SLSA-Framework",
              "NIST-AI-100-2:S.4.2"),
        fire=_fire_missing_model_provenance,
        stride_ai=("Tampering", "Spoofing"),
    ),
    ArchRule(
        name="unbounded_agent_tool_access",
        title="Agent with > 5 tool targets and no access-control declaration",
        description=(
            "An `agent` component has outbound edges to more than 5 "
            "distinct `tool` / `mcp_server` / `external_api` targets "
            "without declaring a `tool_access_control` / "
            "`function_call_allowlist` / `scope_restriction` / "
            "`least_privilege_agent` control. OWASP LLM08:2025 "
            "(excessive agency) — an agent that can call anything in "
            "the system is a confused-deputy risk."
        ),
        severity="medium",
        mitigations=(
            "Maintain a per-action allowlist; deny by default.",
            "Split high-privilege actions behind explicit user "
            "approval (human-in-the-loop confirmation).",
            "Restrict the agent's IAM role to the minimum the tool "
            "needs (least-privilege).",
            "Add the `tool_access_control` control to the agent "
            "component once enforced so audits + this rule pass.",
        ),
        refs=("OWASP-LLM08:2025", "OWASP-AGT:AGT06", "MITRE-ATLAS-AML.T0050"),
        fire=_fire_unbounded_agent_tool_access,
        stride_ai=("Elevation_of_Privilege",),
    ),
    ArchRule(
        name="missing_human_oversight_high_risk",
        title="EU AI Act high-risk system with no human reviewer downstream",
        description=(
            "The system is flagged `is_high_risk_under_eu_ai_act=True` "
            "and contains AI components, but no `user` component sits "
            "downstream (directly or 1 hop) of the AI outputs. EU AI "
            "Act Article 14 requires human oversight on Annex III "
            "high-risk systems. This rule fires on each AI component "
            "with `severity=high` to flag the obligation."
        ),
        severity="high",
        mitigations=(
            "Model a reviewer `user` component on the AI's output "
            "path so the diagram reflects the human-in-the-loop step.",
            "If automation is the intent, document the override / "
            "appeal mechanism (Article 14(4)(d) → opt-out).",
            "Capture per-decision evidence (input, output, reviewer "
            "decision, reason) for the Article 13 transparency log.",
        ),
        refs=("EU-AI-ACT-Art.14", "EU-AI-ACT-Art.13", "NIST-AI-RMF:GOVERN-4.1"),
        fire=_fire_missing_human_oversight,
        stride_ai=("Repudiation",),
    ),
    ArchRule(
        name="data_at_rest_unencrypted",
        title="Sensitive datastore with no encryption-at-rest evidence",
        description=(
            "A sensitive datastore (database, NoSQL, warehouse, "
            "data lake, object storage, secrets vault) shows no "
            "evidence of encryption-at-rest: no encryption / KMS / "
            "TDE / cmk hint in its description, controls, or "
            "metadata, and no edge to a `kms_key` / `hsm` "
            "component. NIST SP 800-53 SC-28 and ISO/IEC 27001 "
            "A.10.1.1 require cryptographic protection of stored "
            "data for confidential / restricted classifications, "
            "and most regulatory regimes (HIPAA, PCI-DSS, GDPR "
            "Art. 32) make encryption-at-rest a baseline."
        ),
        severity="medium",
        mitigations=(
            "Enable native encryption-at-rest on the datastore "
            "(SSE-KMS on S3, TDE on RDS / SQL Server, "
            "Azure Storage Service Encryption).",
            "Use customer-managed keys (CMK / cmek) in a KMS / HSM "
            "rather than provider-managed defaults — adds "
            "compromise-recovery options.",
            "Model the `kms_key` / `hsm` component and its dataflow "
            "edge to this datastore so the diagram reflects reality.",
            "For secrets / PII, layer envelope encryption: app "
            "encrypts payload, KMS encrypts the data key.",
        ),
        refs=("NIST-SP800-53:SC-28", "ISO-27001:A.10.1.1",
              "CWE-311", "CWE-326", "OWASP-A02:2021"),
        fire=_fire_data_at_rest_unencrypted,
        stride_ai=("Information_Disclosure",),
    ),
)


# ────────────────────────────────────────────────────────────────────
# Engine entry point.
# ────────────────────────────────────────────────────────────────────

def evaluate_arch_rules(
    system: System,
    rules: Iterable[ArchRule] = ARCHITECTURAL_RULES,
) -> list[Threat]:
    """Walk every rule against the system; return a list of new Threats.

    Each fire emits one Threat per matched component. Threat ids follow
    the convention `<component_id>.A_<rule_name_upper>` so they don't
    clash with playbook threat ids (`<component_id>.T_PLAYBOOK_NNN`).
    """
    out: list[Threat] = []
    for rule in rules:
        try:
            fires = rule.fire(system)
        except Exception as exc:  # noqa: BLE001
            log.warning("Arch rule %s raised %s; skipping.", rule.name, exc)
            continue
        for comp, severity_override in fires:
            tid = f"{comp.id}.A_{rule.name.upper()}"
            sev = severity_override or rule.severity
            # Likelihood + impact derived from severity bucket. Coarse
            # but reasonable; the per-component playbooks already do
            # finer-grained L×I, and architectural rules are about
            # PATTERN risk where the topology dominates the score.
            likelihood = {"low": 2, "medium": 3, "high": 4, "critical": 5, "info": 1}[sev]
            impact = likelihood
            out.append(Threat(
                id=tid,
                component_id=comp.id,
                title=rule.title,
                description=rule.description,
                severity=sev,  # type: ignore[arg-type]
                likelihood=likelihood,
                impact=impact,
                stride_ai=list(rule.stride_ai),
                references=list(rule.refs),
                mitigation_ids=[],
                confidence=0.85,
            ))
    return out


__all__ = [
    "ArchRule",
    "ARCHITECTURAL_RULES",
    "evaluate_arch_rules",
]
