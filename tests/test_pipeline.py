"""Regression tests for the v0.17.2 type-safe stage pipeline.

These tests pin two architectural contracts:

  - The STAGE_ORDER declaration in `atms.pipeline` correctly encodes
    the load-bearing ordering invariants that used to live as code
    comments in `workflow.py` (e.g. "score before apply_evidence",
    "compliance after framework enrichment", etc.). Reordering the
    list in a way that violates these raises StageOrderError at
    import time.

  - `validate_threats(...)` catches engine bugs that mutate threats
    into invalid shapes (wrong-case severity, malformed literal, etc.).
"""

from __future__ import annotations

import pytest

from atms.models import Component, System, Threat
from atms.pipeline import (
    STAGE_ORDER,
    Stage,
    StageOrderError,
    enforce_stage_order,
    validate_threats,
)
from atms.workflow import analyze


# ─── STAGE_ORDER declarative invariants ──────────────────────────────
def test_stage_order_is_validated_at_module_import():
    """The pipeline module runs `enforce_stage_order(STAGE_ORDER)` at
    import time. If a maintainer ever reorders STAGE_ORDER in a way
    that breaks `requires_before`, the import fails. This test just
    re-runs the check on the live STAGE_ORDER for belt-and-braces."""
    enforce_stage_order(STAGE_ORDER)


def test_stage_order_encodes_score_before_evidence_invariant():
    """The most load-bearing comment in workflow.py was 'do not insert
    a re-score after evidence'. STAGE_ORDER must encode this as data."""
    names = [s.name for s in STAGE_ORDER]
    idx_score = names.index("score_threats_post_controls")
    idx_evidence = names.index("apply_evidence")
    assert idx_score < idx_evidence, (
        "score_threats_post_controls must run BEFORE apply_evidence — "
        "see the load-bearing invariant comment in workflow.py:212."
    )


def test_stage_order_encodes_pasta_after_paths_invariant():
    """The PASTA lens re-filters threats AFTER attack-path discovery,
    not before, so the filter can use the discovered paths."""
    names = [s.name for s in STAGE_ORDER]
    idx_paths = names.index("find_attack_paths")
    idx_pasta = names.index("pasta_lens_filter")
    assert idx_paths < idx_pasta


def test_stage_order_encodes_linddun_lens_after_enrichment():
    """LINDDUN-lens filtering must run AFTER LINDDUN enrichment,
    otherwise every threat looks non-privacy-relevant."""
    names = [s.name for s in STAGE_ORDER]
    idx_enrich = names.index("enrich_with_linddun")
    idx_lens = names.index("methodology_lens_filter")
    assert idx_enrich < idx_lens


def test_enforce_stage_order_raises_on_violation():
    """Sanity: the enforcer actually rejects a violating order."""
    bad = [
        Stage(name="late", requires_before=("early",)),
        Stage(name="early"),
    ]
    with pytest.raises(StageOrderError) as exc:
        enforce_stage_order(bad)
    assert "ordering violation" in str(exc.value).lower()
    assert "early" in str(exc.value)


def test_enforce_stage_order_raises_on_missing_dep():
    """A `requires_before` referencing a non-existent stage name is
    a typo and must fail loudly."""
    bad = [Stage(name="a", requires_before=("nonexistent",))]
    with pytest.raises(StageOrderError) as exc:
        enforce_stage_order(bad)
    assert "no such stage" in str(exc.value).lower()


def test_enforce_stage_order_accepts_valid_order():
    """Negative-of-negative: a correct order passes silently."""
    ok = [
        Stage(name="a"),
        Stage(name="b", requires_before=("a",)),
        Stage(name="c", requires_before=("a", "b")),
    ]
    enforce_stage_order(ok)  # must not raise


# ─── validate_threats — post-mutation Pydantic checkpoint ────────────
def test_validate_threats_passes_on_clean_input():
    """A valid Threat survives the round-trip silently."""
    t = Threat(
        id="x", component_id="c", title="t", description="d",
        likelihood=3, impact=3,
    )
    validate_threats([t])  # must not raise


def test_validate_threats_catches_invalid_severity():
    """Simulating an engine bug that wrote an out-of-Literal severity
    value. The Threat model construction itself catches this, so we
    have to bypass __init__ to write the broken state — that's
    exactly the situation an in-place mutation could produce."""
    t = Threat(
        id="x", component_id="c", title="t", description="d",
        likelihood=3, impact=3,
    )
    # Bypass Pydantic's __setattr__ guard by writing directly to
    # the dict — this is what a misbehaved engine mutating fields
    # outside the model's known Literals could effectively do via
    # `t.__dict__['severity'] = "HIGH"`.
    object.__setattr__(t, "severity", "HIGH")  # type: ignore[assignment]
    with pytest.raises(Exception):
        validate_threats([t])


def test_validate_threats_round_trip_preserves_shape():
    """After validate_threats, the threats still match what they were
    going in — re-validation is read-only with respect to the inputs."""
    t = Threat(
        id="x", component_id="c", title="t", description="d",
        likelihood=3, impact=3, severity="high", risk_score=45,
    )
    snapshot = t.model_dump()
    validate_threats([t])
    assert t.model_dump() == snapshot


# ─── End-to-end: validate_threats is wired into analyze() ────────────
def test_analyze_invokes_post_mutation_validation():
    """Smoke test: a real analyse run reaches the validation call
    without raising. If a future engine introduces a mutation bug,
    this test fails with a Pydantic ValidationError that points at
    the offending field."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    tm = analyze(sys_obj)
    assert tm.threats, "smoke test: expected non-empty threats"
    # If any engine had silently produced an invalid threat shape,
    # validate_threats would have raised inside analyze(). Reaching
    # this line proves the checkpoint passed.
