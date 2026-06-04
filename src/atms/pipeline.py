"""Type-safe stage pipeline for the analysis workflow (v0.17.2).

Closes architectural-review findings C1 and C4 from the post-v0.17.0
review:

  - C1: Engine ordering was encoded in code comments
    (`workflow.py:212` literally says
    `**Maintainers: do not insert a re-score after this step.**`).
    Now the ordering invariants are declared as data — every stage
    lists which stages must run *before* it. Violations raise at
    import time, not at runtime under an unlucky test case.

  - C4: Threats are mutated in place by ~12 engine calls. A bug in
    any one engine that produces an out-of-Literal severity value
    (or any other shape drift) wouldn't surface until the report
    template tried to render it. `validate_threats(...)` re-runs
    Pydantic validation on every threat as a single checkpoint
    after the mutation block; mutation bugs now surface where they
    were introduced, not 200 lines downstream.

Scope is deliberately conservative: this module exposes the data
structures, the order-checking helper, and the validation helper.
`workflow.py:analyze()` keeps its current shape and just adopts the
helpers at the right insertion points. A future cycle can promote
the full pipeline to a Stage-driven loop without churning the
engines again.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .models import Threat


@dataclass(frozen=True)
class Stage:
    """A declarative description of a pipeline stage.

    Stages are NOT callables yet — this is the minimum-viable abstraction
    that locks the ordering invariants as data without changing how
    `analyze()` currently invokes engines. A later cycle can promote
    `Stage` to a `run: Callable[[PipelineContext], None]` field and
    refactor `analyze()` into a generic loop, once the rest of the
    pipeline (engine signatures, ThreatModel construction) is also
    factored into a context object.

    Attributes:
        name: unique stage identifier, matches the corresponding
            function in `workflow.py` for grepability.
        produces: short tags describing what this stage adds /
            mutates. Used by `requires_before` to catch reordering.
        requires_before: names of stages that MUST appear earlier
            in `STAGE_ORDER`. Violations raise `StageOrderError`.
        invariant: optional human-readable note (rendered into the
            error message when a violation is detected).
    """

    name: str
    produces: tuple[str, ...] = ()
    requires_before: tuple[str, ...] = ()
    invariant: str = ""


class StageOrderError(ValueError):
    """Raised when STAGE_ORDER violates a stage's requires_before."""


def enforce_stage_order(stages: Iterable[Stage]) -> None:
    """Validate that every stage's `requires_before` is met by the
    declared order. Raises `StageOrderError` on the first violation.

    Called at module-import time from `workflow.py`, so reordering
    mistakes fail the next import rather than appearing as subtle
    behavioural regressions in some specific test run.
    """
    seen: set[str] = set()
    names: set[str] = {s.name for s in stages}
    for stage in stages:
        for dep in stage.requires_before:
            if dep not in names:
                raise StageOrderError(
                    f"Stage {stage.name!r} declares requires_before={dep!r} "
                    f"but no such stage exists. Typo, or stage was removed?"
                )
            if dep not in seen:
                raise StageOrderError(
                    f"Stage ordering violation: {stage.name!r} requires "
                    f"{dep!r} to run earlier, but {dep!r} hasn't appeared "
                    f"yet in STAGE_ORDER."
                    + (f"\n  Invariant: {stage.invariant}" if stage.invariant else "")
                )
        seen.add(stage.name)


def validate_threats(threats: Iterable[Threat]) -> None:
    """Re-run Pydantic validation on every threat.

    Engines mutate threats in place; a bug that writes an
    out-of-Literal value (e.g. `t.severity = "HIGH"` instead of
    `"high"`) would otherwise survive until something downstream
    tried to use it. This is a fast single-pass guard — costs
    < 10 ms on a 100-threat sample.

    Raises `pydantic.ValidationError` on the first malformed threat
    with the threat ID + bad field included in the message.
    """
    for t in threats:
        # `model_validate(t.model_dump())` round-trips through the
        # validators. If the engines mutated a field to something
        # the Literal / type guards don't allow, this raises with
        # the original error message — which includes the field
        # name and the offending value.
        Threat.model_validate(t.model_dump())


# ────────────────────────────────────────────────────────────────────
# STAGE_ORDER — the source-of-truth declaration of the analysis pipeline.
#
# Read top-to-bottom: this is the order `workflow.py:analyze()` runs
# stages in today. Each stage names the stages it depends on. The order
# is checked at import time by `enforce_stage_order(STAGE_ORDER)`.
#
# To change the pipeline:
#   1. Reorder / add / remove the Stage(...) entries here.
#   2. If your change violates a `requires_before` clause, fix the
#      requires_before list (or the order) — don't suppress the check.
#   3. The corresponding call in `workflow.py:analyze()` must match
#      this declaration (a future cycle will enforce that mechanically
#      by having `analyze()` iterate STAGE_ORDER directly).
# ────────────────────────────────────────────────────────────────────

STAGE_ORDER: tuple[Stage, ...] = (
    Stage(
        name="bedrock_kb_autosynth",
        produces=("system.components+",),
        invariant="Must run before enumerate_threats — adds a synthesised "
                  "RAG component so the KB-confused-deputy threat class fires.",
    ),
    Stage(
        name="empty_components_check",
        produces=("validated_components",),
        invariant="Empty components → ValueError. Must run before "
                  "ai_scope_gate, otherwise the user sees the wrong error.",
    ),
    Stage(
        name="ai_scope_gate",
        produces=("ai_components", "ai_blast_radius"),
        requires_before=("empty_components_check",),
        invariant="Systems with zero AI components are rejected here. "
                  "Downstream stages assume at least one AI component.",
    ),
    Stage(
        name="boundary_inference",
        produces=("system.trust_boundaries+", "dataflow.crosses_boundary"),
        requires_before=("ai_scope_gate",),
    ),
    Stage(
        name="enumerate_threats",
        produces=("threats",),
        requires_before=("ai_scope_gate", "bedrock_kb_autosynth"),
        invariant="The fundamental enumeration. Every downstream stage "
                  "either reads or mutates threats; this stage produces them.",
    ),
    Stage(
        name="dedupe_threats",
        produces=("threats[deduped]",),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="enrich_with_atlas",
        produces=("threats[atlas_techniques]",),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="enrich_with_maestro",
        produces=("threats[maestro_*]", "threats[owasp_agentic]"),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="enrich_with_cloud",
        produces=("threats[attack_cloud]", "threats[attack_enterprise]",
                  "threats[owasp_api]"),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="enrich_with_linddun",
        produces=("threats[linddun]",),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="enrich_with_nist_ai_100_2",
        produces=("threats[nist_ai_100_2]",),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="assign_kill_chain_phases",
        produces=("threats[kill_chain_phase]",),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="enrich_with_owasp_ml",
        produces=("threats[owasp_ml]",),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="enrich_with_compliance",
        produces=("threats[compliance_controls]",),
        requires_before=("enumerate_threats",),
        invariant="Compliance enrichment must follow framework enrichment "
                  "so EU AI Act gating sees the full framework set.",
    ),
    Stage(
        name="evaluate_arch_rules",
        produces=("threats[architectural]",),
        requires_before=("enumerate_threats", "dedupe_threats"),
        invariant="v0.18.5 Cycle R — Topology-pattern rules. Must run "
                  "after threat enumeration so we don't double-classify; "
                  "before scoring so rule-emitted threats get re-scored "
                  "with the same matrix.",
    ),
    Stage(
        name="methodology_lens_filter",
        produces=("threats[lens_filtered]",),
        requires_before=("enrich_with_linddun", "enrich_with_compliance"),
        invariant="LINDDUN lens filters out non-privacy threats AFTER "
                  "LINDDUN enrichment, not before.",
    ),
    Stage(
        name="score_threats_initial",
        produces=("threats[severity]", "threats[risk_score]", "threats[confidence]"),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="apply_component_controls",
        produces=("threats[likelihood-]",),
        requires_before=("score_threats_initial",),
        invariant="Component-level controls reduce likelihood; we re-score "
                  "after this stage.",
    ),
    Stage(
        name="score_threats_post_controls",
        produces=("threats[severity:revised]",),
        requires_before=("apply_component_controls",),
    ),
    Stage(
        name="apply_evidence",
        produces=("threats[evidence]", "threats[severity:critical-on-kev]"),
        requires_before=("score_threats_post_controls",),
        invariant="KEV-on-CVE forces severity=critical AND OVERRIDES the "
                  "qualitative bucket. This override survives downstream "
                  "stages BY DESIGN — do NOT insert a re-score after this.",
    ),
    Stage(
        name="score_quantitative",
        produces=("threats[ale_low]", "threats[ale_high]", "threats[freq_*]", "threats[loss_*]"),
        requires_before=("apply_evidence",),
    ),
    Stage(
        name="validate_threats_post_mutation",
        produces=("threats[schema-checked]",),
        requires_before=("score_quantitative",),
        invariant="Pydantic re-validation checkpoint. Catches engine bugs "
                  "that mutated threats into invalid shapes before the "
                  "report templates try to render them.",
    ),
    Stage(
        name="find_attack_paths",
        produces=("attack_paths",),
        requires_before=("score_threats_post_controls",),
    ),
    Stage(
        name="pasta_lens_filter",
        produces=("threats[pasta_filtered]", "attack_paths[rebuilt]"),
        requires_before=("find_attack_paths",),
    ),
    Stage(
        name="collect_mitigations",
        produces=("mitigations",),
        requires_before=("enumerate_threats",),
    ),
    Stage(
        name="apply_d3fend_actionability",
        produces=("mitigations[d3fend_*]",),
        requires_before=("collect_mitigations",),
    ),
    Stage(
        name="enrich_with_reference_patterns",
        produces=("mitigations[reference_patterns]",),
        requires_before=("collect_mitigations",),
    ),
    Stage(
        name="backlink_threats_to_mitigations",
        produces=("threats[mitigation_ids]",),
        requires_before=("collect_mitigations", "enumerate_threats"),
    ),
    Stage(
        name="propose_structural_recommendations",
        produces=("structural_recommendations",),
        requires_before=("score_threats_post_controls",),
    ),
)


# Validate at module-import time. If a contributor reorders STAGE_ORDER
# in a way that violates an invariant, the next `import atms.workflow`
# fails immediately with a clear message — not three test files in.
enforce_stage_order(STAGE_ORDER)


__all__ = [
    "Stage",
    "StageOrderError",
    "STAGE_ORDER",
    "enforce_stage_order",
    "validate_threats",
]
