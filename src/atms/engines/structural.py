"""Propose structural architecture edits (v0.16.5).

The security-architect critique of v0.15.1 (finding A-03) noted that
ATMS enumerates threats per component but never proposes a NEW component.
A cluster of 4 critical agent threats — excessive agency, indirect
prompt injection, memory poisoning, intent-breaking — often has ONE
structural fix: "insert a `policy_engine` between `agent_service` and
its tool calls."

This engine inspects the threats + components and emits a small list
of `StructuralRecommendation` objects. Each recommendation is an
architecture edit (insert / split / relocate / harden_in_place) that
addresses a cluster of threats jointly. It is meant to live alongside
the per-component mitigation list, not replace it.

The detection rules are deterministic + opt-in:
  - When >=3 critical/high threats with `applicable_to_topology` =
    multi-agent or `owasp_agentic` AGT01/AGT02/AGT06 land on the same
    `agent` component, recommend inserting a `policy_engine` / `guardrails`
    component between agent and tool calls (so the agent can never
    invoke a tool without policy evaluation).
  - When >=2 LLM threats (T_LLMINF_*) reference "output disclosure"
    keywords land on the same llm_inference component without a
    paired `output_filter` downstream, recommend inserting an
    output_filter.
  - When >=2 RAG threats reference "ACL" / "cross-tenant" / "indirect
    prompt injection" on a rag_vector_store without an upstream
    `content_safety_classifier`, recommend a guardrail layer
    in front of retrieval.
  - When an agent has tool_scope=admin/write and no PAM/`pam_vault`
    component is present in the system, recommend introducing one.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import StructuralRecommendation, System, Threat
from ._ids import stable_id


def _safe_name(name: str, budget: int = 100) -> str:
    """v0.16.9 — clip a component name for safe interpolation into a
    StructuralRecommendation.title (capped at 200 chars). Component.name
    allows 200 chars; the fixed prefix in each rule is ~70 chars; we
    need to clip to keep the formatted title under the cap. Bug-001."""
    if len(name) <= budget:
        return name
    return name[: budget - 1] + "…"


def propose_structural_recommendations(
    threats: list[Threat],
    system: System,
) -> list[StructuralRecommendation]:
    """Emit structural architecture-edit recommendations.

    Cap: 5 recommendations per threat model. Engineers can act on a
    small list; a long list signals over-reach and erodes trust.
    """
    out: list[StructuralRecommendation] = []
    components_by_id = {c.id: c for c in system.components}
    component_types = {c.type for c in system.components}
    threats_by_component: dict[str, list[Threat]] = defaultdict(list)
    for t in threats:
        threats_by_component[t.component_id].append(t)

    for comp in system.components:
        comp_threats = threats_by_component.get(comp.id, [])
        if not comp_threats:
            continue

        # Rule 1: agent with >=3 critical/high agentic threats + no
        # policy/guardrails layer → recommend inserting one.
        if comp.type == "agent":
            agentic_severe = [
                t for t in comp_threats
                if t.severity in {"critical", "high"}
                and (
                    set(t.owasp_agentic) & {"AGT01", "AGT02", "AGT03", "AGT06", "AGT15"}
                    or "excessive agency" in t.title.lower()
                    or "indirect prompt" in t.title.lower()
                    or "memory poisoning" in t.title.lower()
                )
            ]
            already_has_guardrail = "guardrails" in component_types or "content_safety_classifier" in component_types
            if len(agentic_severe) >= 3 and not already_has_guardrail:
                out.append(StructuralRecommendation(
                    id=stable_id("REC", "guardrails", comp.id),
                    title=f"Insert a policy_engine / guardrails layer between {_safe_name(comp.name)} and its tool calls",
                    summary=(
                        f"{comp.name} has {len(agentic_severe)} critical/high agentic threats "
                        "with overlapping root cause (the agent can invoke tools without policy "
                        "evaluation). A separate guardrail component sitting between the agent "
                        "and its tool surface closes them jointly."
                    ),
                    edit_kind="insert",
                    proposed_component_type="guardrails",
                    affected_threats=[t.id for t in agentic_severe],
                    affected_components=[comp.id],
                    rationale=(
                        "Stride-by-Component-Edit, not Stride-by-Component. "
                        "Single new component closes the cluster; current per-threat "
                        "mitigations enumerate the symptom but never recommend the cure."
                    ),
                    sample_dfd_edit=(
                        f"Add new component:\n"
                        f"  - id: policy_engine\n    type: guardrails\n"
                        f"    description: Policy engine — evaluates every tool call "
                        f"from {comp.id} against an allow-list + intent classifier.\n\n"
                        f"Modify dataflows: route all of {comp.id}'s outbound tool calls "
                        f"through policy_engine instead of directly to the tool."
                    ),
                    estimated_effort="medium",
                ))

        # Rule 2: llm_inference with output-disclosure threats but no
        # output_filter downstream → recommend output_filter.
        if comp.type == "llm_inference":
            disclosure = [
                t for t in comp_threats
                if t.severity in {"critical", "high"}
                and (
                    "disclosure" in t.title.lower()
                    or "extract" in t.title.lower()
                    or "exfil" in t.title.lower()
                    or any(o in (t.owasp_llm or []) for o in ("LLM02:2025", "LLM07:2025"))
                )
            ]
            if len(disclosure) >= 2 and "output_filter" not in component_types:
                out.append(StructuralRecommendation(
                    id=stable_id("REC", "output_filter", comp.id),
                    title=f"Insert an output_filter downstream of {_safe_name(comp.name)}",
                    summary=(
                        f"{comp.name} has {len(disclosure)} disclosure / extraction "
                        "threats. An output_filter component (PII / secret pattern "
                        "redactor + jailbreak-response detector) sitting between "
                        "the LLM and downstream consumers blocks the leakage at the "
                        "boundary instead of relying on prompt hygiene alone."
                    ),
                    edit_kind="insert",
                    proposed_component_type="output_filter",
                    affected_threats=[t.id for t in disclosure],
                    affected_components=[comp.id],
                    rationale=(
                        "Defence-in-depth. Prompt-injection prevention is a probabilistic "
                        "control; output filtering is a deterministic one. Both are needed; "
                        "the output filter is the structural addition that's missing."
                    ),
                    sample_dfd_edit=(
                        f"Add new component:\n"
                        f"  - id: response_filter\n    type: output_filter\n"
                        f"    description: PII + jailbreak-response detector.\n\n"
                        f"Modify dataflows: insert response_filter between {comp.id} "
                        "and every downstream consumer."
                    ),
                    estimated_effort="medium",
                ))

        # Rule 3: rag_vector_store with ACL / indirect-injection threats
        # but no upstream content safety classifier → recommend retrieval-
        # time content safety.
        if comp.type == "rag_vector_store":
            rag_severe = [
                t for t in comp_threats
                if t.severity in {"critical", "high"}
                and (
                    "indirect prompt" in t.title.lower()
                    or "acl" in t.title.lower()
                    or "cross-tenant" in t.title.lower()
                    or "poisoning" in t.title.lower()
                )
            ]
            already_has_classifier = "content_safety_classifier" in component_types
            if len(rag_severe) >= 2 and not already_has_classifier:
                out.append(StructuralRecommendation(
                    id=stable_id("REC", "content_safety_classifier", comp.id),
                    title=f"Insert a content_safety_classifier between {_safe_name(comp.name)} and the model",
                    summary=(
                        f"{comp.name} carries {len(rag_severe)} severe RAG-poisoning / "
                        "ACL-bypass / cross-tenant threats. A content safety classifier "
                        "scanning every retrieved chunk before it enters the prompt "
                        "context blocks the injection / poisoning at the boundary."
                    ),
                    edit_kind="insert",
                    proposed_component_type="content_safety_classifier",
                    affected_threats=[t.id for t in rag_severe],
                    affected_components=[comp.id],
                    rationale=(
                        "Retrieved content is untrusted by default. A classifier between "
                        "retrieval and the LLM is the structural fix for indirect prompt "
                        "injection — guardrails on the user-prompt side don't see the "
                        "retrieved chunks."
                    ),
                    sample_dfd_edit=(
                        "Add new component:\n"
                        "  - id: rag_safety_filter\n    type: content_safety_classifier\n"
                        "    description: Scan retrieved RAG chunks for adversarial content + "
                        "tenant-ACL match before forwarding to the LLM.\n\n"
                        f"Modify dataflows: route {comp.id}'s output through rag_safety_filter "
                        "before reaching the model."
                    ),
                    estimated_effort="medium",
                ))

        # Rule 4: privileged agent (admin/write tool_scope) without PAM
        # vault present → recommend introducing PAM.
        if comp.type == "agent":
            scope = str((comp.metadata or {}).get("tool_scope", "")).lower()
            scope_list = scope.split(",") if "," in scope else [scope]
            scope_set = {s.strip() for s in scope_list}
            if scope_set & {"admin", "write"} and "pam_vault" not in component_types and "secrets_vault" not in component_types:
                out.append(StructuralRecommendation(
                    id=stable_id("REC", "pam_vault", comp.id),
                    title=f"Introduce a PAM vault to broker credentials for {_safe_name(comp.name)}",
                    summary=(
                        f"{comp.name} has write/admin scope tools but no PAM/Vault component "
                        "in the model. Agent-held long-lived credentials are a common compromise "
                        "vector; a PAM broker issues short-TTL credentials per task with full "
                        "audit + just-in-time approval."
                    ),
                    edit_kind="insert",
                    proposed_component_type="pam_vault",
                    affected_threats=[t.id for t in comp_threats if t.severity in {"critical", "high"}],
                    affected_components=[comp.id],
                    rationale=(
                        "Standing privileges on a write/admin-capable agent are the canonical "
                        "supply-chain compromise vector. PAM with just-in-time issuance + "
                        "session recording is the structural fix."
                    ),
                    sample_dfd_edit=(
                        "Add new component:\n"
                        "  - id: pam_broker\n    type: pam_vault\n"
                        "    description: Short-TTL credential broker for agent tool calls.\n\n"
                        f"Modify dataflows: every privileged tool call from {comp.id} pulls a "
                        "scoped credential from pam_broker instead of using a static key."
                    ),
                    estimated_effort="high",
                ))

        if len(out) >= 5:
            break

    return out[:5]


__all__ = ["propose_structural_recommendations"]
