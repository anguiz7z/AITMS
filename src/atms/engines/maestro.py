"""MAESTRO + OWASP-Agentic enrichment.

Two responsibilities:

1. **Component → MAESTRO layers**. Default mapping by component type. Users
   may override per-component via `component.maestro_layers` in their YAML.

2. **Threat → MAESTRO threat IDs + OWASP-Agentic IDs**. For each existing
   threat we look at:
     - The component type and its default MAESTRO layers.
     - The threat's keywords (title + description).
     - The MAESTRO and OWASP-Agentic catalogue's `keywords` and `applies_to`.

Pure-Python and deterministic. Adds MAESTRO + OWASP-Agentic IDs in-place; never
removes existing IDs.
"""

from __future__ import annotations

import re

from ..kb import KnowledgeBase, get_kb
from ..models import Component, Threat

# Default MAESTRO-layer assignment for each ATMS component type.
# Components naturally span multiple layers; we err on the side of inclusion
# so cross-layer threats fire when relevant.
DEFAULT_LAYER_MAP: dict[str, list[str]] = {
    # AI / agentic primitives
    "llm_inference":          ["M.L1", "M.L4"],
    "model_registry":         ["M.L1"],
    "training_pipeline":      ["M.L1", "M.L2"],
    "fine_tuning_pipeline":   ["M.L1", "M.L2"],
    "embedding_service":      ["M.L2"],
    "rag_vector_store":       ["M.L2"],
    "data_source":            ["M.L2"],
    "agent":                  ["M.L3", "M.L7"],
    "tool":                   ["M.L3", "M.L7"],
    "prompt_template_store":  ["M.L3"],
    "mcp_server":             ["M.L3", "M.L4", "M.L7"],
    "external_api":           ["M.L4", "M.L7"],
    "guardrails":             ["M.L5", "M.L6"],
    "output_filter":          ["M.L5", "M.L6"],
    "user":                   ["M.L7"],
    # Cloud-infrastructure components — almost all in L4 (Deployment & Infrastructure);
    # IAM / KMS / vault also touch L6 (Security & Compliance); observability is L5.
    "iam_principal":          ["M.L4", "M.L6"],
    "secrets_vault":          ["M.L4", "M.L6"],
    "object_storage":         ["M.L2", "M.L4"],
    "network_segment":        ["M.L4"],
    "serverless_function":    ["M.L4"],
    "api_gateway":            ["M.L4", "M.L7"],
    "container_runtime":      ["M.L4"],
    "kms_key":                ["M.L4", "M.L6"],
    "message_queue":          ["M.L2", "M.L4"],
    "observability_stack":    ["M.L5", "M.L6"],
    # IT / Network / OT / Legacy / Identity components (added v0.10).
    # Most live in L4 (Deployment & Infrastructure); identity controls touch L6;
    # users/endpoints participate in L7 (Agent Ecosystem) when they interact with
    # agents and at L1/L2 when they are data sources.
    "database":               ["M.L2", "M.L4"],
    "firewall":               ["M.L4"],
    "directory_service":      ["M.L4", "M.L6"],
    "web_application":        ["M.L4", "M.L7"],
    "endpoint":               ["M.L4", "M.L7"],
    "legacy_mainframe":       ["M.L2", "M.L4"],
    "plc":                    ["M.L4"],
    "scada":                  ["M.L4", "M.L5"],
    "iot_device":             ["M.L4", "M.L7"],
    "load_balancer":          ["M.L4"],
    "vpn_gateway":            ["M.L4", "M.L6"],
    "network_switch":         ["M.L4"],
    "email_server":           ["M.L4", "M.L7"],
    "mfa_service":            ["M.L4", "M.L6"],
    "industrial_protocol":    ["M.L4"],
    "other":                  [],
}


def _tokenize(text: object) -> set[str]:
    if text is None:
        return set()
    return set(re.findall(r"[a-zA-Z]+", str(text).lower()))


def layers_for(component: Component) -> list[str]:
    """Return MAESTRO layer IDs for a component (explicit override wins)."""
    if component.maestro_layers:
        return list(component.maestro_layers)
    return list(DEFAULT_LAYER_MAP.get(component.type, []))


def enrich_with_maestro(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
) -> list[Threat]:
    kb = kb or get_kb()
    comp_by_id = {c.id: c for c in components}

    for threat in threats:
        comp = comp_by_id.get(threat.component_id)
        if comp is None:
            continue

        # MAESTRO layers — default + override
        comp_layers = layers_for(comp)
        for layer in comp_layers:
            if layer not in threat.maestro_layers:
                threat.maestro_layers.append(layer)

        # MAESTRO threat IDs — score by keyword overlap × layer/component match
        threat_tokens = _tokenize(threat.title + " " + threat.description)
        scored: list[tuple[str, int]] = []
        for mid, mthreat in kb.maestro_threats.items():
            if mid in threat.maestro_threats:
                continue
            kw_tokens: set[str] = set()
            for kw in mthreat.get("keywords", []):
                kw_tokens.update(_tokenize(kw))
            kw_overlap = len(threat_tokens & kw_tokens)

            comp_match = comp.type in set(mthreat.get("applies_to", []))
            layer_match = mthreat.get("layer") in comp_layers or mthreat.get("layer") == "cross"

            score = kw_overlap * 2
            if comp_match:
                score += 3
            if layer_match:
                score += 1
            if score >= 4:
                scored.append((mid, score))
        scored.sort(key=lambda t: t[1], reverse=True)
        for mid, _ in scored[:3]:
            if mid not in threat.maestro_threats:
                threat.maestro_threats.append(mid)

        # OWASP Agentic IDs — only if component is in the agentic family
        if comp.type in {"agent", "tool", "mcp_server"} or any(
            ag for ag in threat.maestro_threats if ag.startswith("M.L7") or ag.startswith("M.L3")
        ):
            agt_scored: list[tuple[str, int]] = []
            for agt_id, agt in kb.owasp_agentic.items():
                if agt_id in threat.owasp_agentic:
                    continue
                kw_tokens = set()
                for kw in agt.get("keywords", []):
                    kw_tokens.update(_tokenize(kw))
                kw_overlap = len(threat_tokens & kw_tokens)
                comp_match = comp.type in set(agt.get("applies_to", []))
                stride_match = bool(set(agt.get("stride_ai", [])) & set(threat.stride_ai))
                score = kw_overlap * 2 + (3 if comp_match else 0) + (1 if stride_match else 0)
                if score >= 4:
                    agt_scored.append((agt_id, score))
            agt_scored.sort(key=lambda t: t[1], reverse=True)
            for agt_id, _ in agt_scored[:2]:
                if agt_id not in threat.owasp_agentic:
                    threat.owasp_agentic.append(agt_id)

    return threats
