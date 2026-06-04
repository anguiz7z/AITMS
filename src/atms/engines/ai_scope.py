"""AI-anchored scoping (v0.15.0).

ATMS evaluates **AI-induced risk** across the full architecture the AI
sits in. That has two consequences for the engine:

1. A system with **zero AI components** is out of scope. The user should
   get a clear "this isn't an AI system" rejection, not a misleading
   wall of generic IT findings tagged with OWASP-LLM IDs.

2. For a hybrid system (e.g. a banking core + an LLM fraud-detection
   sidecar) the analysis covers every component, but only emits threats
   that exist *because of* the AI integration. A firewall in a system
   with no LLM produces zero threats; the same firewall fronting an LLM
   API picks up "model-cost DoS via repeated requests" tagged with
   provenance pointing at the LLM that creates the risk.

This module computes that scoping deterministically:
- `is_ai_component(c)` — primary AI/ML/agentic component types
- `find_ai_components(system)` — list of AI primaries in the system
- `compute_ai_blast_radius(system)` — for each non-AI component, which
  AI components reach it via the dataflow graph (forward + backward,
  bounded so we don't trace through arbitrary trust boundaries)
- `ai_relevance(component, blast_radius)` →
  `"primary" | "adjacent" | "out_of_scope"`

Every downstream enricher takes the relevance map and emits threats
only for `primary` and `adjacent` components, attaching the AI
provenance (which AI component(s) created the risk) to every emitted
threat.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Literal

from ..models import Component, Dataflow, System

# ─── AI primary-component classification ──────────────────────────────────
# These are the component types whose presence in a System makes ATMS
# the right tool. Everything else is "non-AI infrastructure" — it can
# still pick up threats, but only as `adjacent` to one of these.
AI_PRIMARY_TYPES: frozenset[str] = frozenset({
    "agent",
    "llm_inference",
    "rag_vector_store",
    "embedding_service",
    "training_pipeline",
    "fine_tuning_pipeline",
    "model_registry",
    "prompt_template_store",
    "guardrails",
    "output_filter",
    "tool",
    "mcp_server",
    # v0.16 — additional AI primary types
    "ml_feature_store",
    "ml_pipeline_orchestrator",
    "ml_data_labeling",
    "ml_experiment_tracker",
    "ml_inference_endpoint",
    "vision_pipeline",
    "speech_pipeline",
    "content_safety_classifier",
})


AIRelevance = Literal["primary", "adjacent", "out_of_scope"]


def is_ai_component(component: Component) -> bool:
    """True iff this component is an AI/ML/agentic primitive.

    Type-only check by design: the metadata field is user-supplied and
    can't be trusted as a signal. Adding `metadata.ai_integration: true`
    to flag a non-AI-typed component is supported via
    :func:`find_ai_components` (sees the metadata flag).
    """
    return component.type in AI_PRIMARY_TYPES


def find_ai_components(system: System) -> list[Component]:
    """All components that ATMS considers 'AI primary' in this system.

    A component qualifies if either:
    - its `type` is in ``AI_PRIMARY_TYPES``, OR
    - `metadata.ai_integration` is truthy (lets the user mark a
      non-AI-typed component as AI-bearing — e.g. a `serverless_function`
      that runs an LLM call).

    The metadata escape hatch is deliberately narrow. We don't keyword-
    search names ("anything called `llm_*`") because that's how the
    false-positive cascades start.
    """
    out: list[Component] = []
    for c in system.components:
        if is_ai_component(c):
            out.append(c)
            continue
        meta = c.metadata or {}
        if meta.get("ai_integration"):
            out.append(c)
    return out


def _build_adjacency(dataflows: list[Dataflow]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return (forward_adj, reverse_adj) keyed by component id."""
    fwd: dict[str, set[str]] = defaultdict(set)
    rev: dict[str, set[str]] = defaultdict(set)
    for d in dataflows:
        if d.source and d.target:
            fwd[d.source].add(d.target)
            rev[d.target].add(d.source)
    return fwd, rev


def compute_ai_blast_radius(
    system: System,
    max_hops: int = 3,
) -> dict[str, list[str]]:
    """Map each component id → list of AI component ids that reach it.

    A non-AI component is "in the AI blast radius" if at least one AI
    component is connected to it via the dataflow graph within
    ``max_hops`` (default 3 — enough to capture e.g. user → API →
    agent → tool → database without dragging in everything on the
    network).

    Both forward (AI → ...) and reverse (... → AI) reachability are
    counted: a database that an LLM *reads from* and a database that an
    LLM *writes to* both pick up risk from the LLM.

    Returns a flat dict so callers can ask "what AI does this firewall
    sit in front of?" with one lookup. AI components map to themselves.
    """
    ai = find_ai_components(system)
    if not ai:
        return {}
    fwd, rev = _build_adjacency(system.dataflows)
    radius: dict[str, set[str]] = defaultdict(set)
    for ai_comp in ai:
        # AI primary maps to itself
        radius[ai_comp.id].add(ai_comp.id)
        # BFS forward + reverse, bounded by max_hops
        for adj in (fwd, rev):
            visited: set[str] = {ai_comp.id}
            frontier: deque[tuple[str, int]] = deque([(ai_comp.id, 0)])
            while frontier:
                node, hops = frontier.popleft()
                if hops >= max_hops:
                    continue
                for nxt in adj.get(node, ()):
                    if nxt in visited:
                        continue
                    visited.add(nxt)
                    radius[nxt].add(ai_comp.id)
                    frontier.append((nxt, hops + 1))
    return {k: sorted(v) for k, v in radius.items()}


def ai_relevance(
    component: Component,
    blast_radius: dict[str, list[str]],
) -> AIRelevance:
    """Classify a component for the threat-emission gate.

    - ``primary``: this IS an AI component. Run the full AI threat
      enumeration.
    - ``adjacent``: a non-AI component that sits in the dataflow blast
      radius of an AI component. Run the AI-adjacent threat playbook
      with provenance tagging.
    - ``out_of_scope``: no AI reaches this component. Skip — emitting
      threats here is the false-positive failure mode v0.14 had.
    """
    if is_ai_component(component):
        return "primary"
    if component.id in blast_radius:
        # The AI component itself is in the dict but maps to itself —
        # it'd already be classified `primary` above. So if we land
        # here, it's truly adjacent.
        return "adjacent"
    return "out_of_scope"


def ai_provenance(
    component: Component,
    blast_radius: dict[str, list[str]],
) -> list[str]:
    """Return the list of AI component ids responsible for this
    component being in scope. For primaries, [component.id]. For
    adjacent, the list of AI components reaching it. For out-of-scope,
    an empty list."""
    if is_ai_component(component):
        return [component.id]
    return list(blast_radius.get(component.id, []))


class NoAIComponentsError(ValueError):
    """Raised when ATMS is asked to analyse a system with zero AI
    components. The CLI / web layer renders this as a friendly message
    rather than a stack trace."""

    def __init__(self) -> None:
        super().__init__(
            "No AI components found in this system. ATMS evaluates AI-induced "
            "risk only — for a system with zero AI/ML/agentic components, use "
            "a general-purpose threat modeler such as OWASP Threat Dragon, "
            "Microsoft Threat Modeling Tool, or IriusRisk. To mark a "
            "non-AI-typed component as AI-bearing (e.g. a serverless function "
            "that calls an LLM), set `metadata.ai_integration: true` on it."
        )


__all__ = [
    "AI_PRIMARY_TYPES",
    "AIRelevance",
    "NoAIComponentsError",
    "ai_provenance",
    "ai_relevance",
    "compute_ai_blast_radius",
    "find_ai_components",
    "is_ai_component",
]
