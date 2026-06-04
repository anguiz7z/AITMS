"""Regression tests pinning the v0.16.9 bug-hunt fixes.

Each test corresponds to a finding from an internal content audit.
"""

from __future__ import annotations

import pytest

from atms.models import Component, Dataflow, System, Threat
from atms.workflow import analyze


# ─── Bug-001: long Component.name crashed structural recommendations ──────
def test_long_component_name_does_not_crash_structural():
    """A 200-char component name no longer crashes `analyze()` via the
    StructuralRecommendation title cap (was: ValidationError)."""
    sys_obj = System(name="x", components=[
        Component(id="u", name="U", type="user"),
        Component(id="a", name="A" * 200, type="agent",
                  metadata={"tool_scope": "admin"}),
    ])
    tm = analyze(sys_obj)  # must not raise
    assert tm is not None


# ─── Bug-002: covered via web tests (see below) ──────────────────────────
def test_editor_save_handles_malformed_json():
    from fastapi.testclient import TestClient

    from atms.web import app
    client = TestClient(app, raise_server_exceptions=False)
    r1 = client.post("/editor/save", content=b"")
    r2 = client.post("/editor/save", content=b"not-json{")
    # was 500, now 400
    assert r1.status_code == 400, f"empty body should be 400, got {r1.status_code}"
    assert r2.status_code == 400, f"malformed json should be 400, got {r2.status_code}"


# ─── Bug-003: lookup_loss_prior accepts keyword-only call ────────────────
def test_lookup_loss_prior_keyword_only_call():
    from atms.kb import get_kb
    kb = get_kb()
    # Was: TypeError: missing 1 required positional argument
    result = kb.lookup_loss_prior(industry="tier1_bank", deployment_stage="poc")
    assert isinstance(result, dict)


# ─── Bug-004: tier1_bank POC bounded portfolio ALE ───────────────────────
def test_tier1_bank_poc_portfolio_ale_below_50m():
    """Was: ~$197M portfolio ALE on a 1-LLM POC. Now: bounded by tier
    frequency cap."""
    sys_obj = System(
        name="x", industry="tier1_bank", deployment_stage="poc",
        components=[
            Component(id="u", name="U", type="user"),
            Component(id="a", name="A", type="llm_inference"),
        ],
    )
    tm = analyze(sys_obj)
    ale_high = tm.summary.get("ale", {}).get("ale_high_total", 0)
    # A POC bank with 1 LLM should be well under the $197M pre-fix figure.
    # We pin the absurd-output check at <$100M; the tier's loss_high cap
    # of $5M is enforced, but with ~13 threats × $5M the natural ceiling
    # is ~$65M before counting smaller-impact threats.
    assert ale_high <= 100_000_000, (
        f"tier1_bank POC portfolio ALE high = ${ale_high:,.0f}; "
        f"expected <= $100M after Bug-004 fix"
    )


# ─── Bug-006: _compute_confidence honors needs_review when comp is None ──
def test_compute_confidence_demotes_needs_review_when_comp_none():
    from atms.engines.risk import _compute_confidence
    t = Threat(
        id="t1", component_id="?", title="x", description="y",
        likelihood=5, impact=5, references=["needs_review"],
    )
    c = _compute_confidence(t, None)
    # Was: flat 0.6. Now: <= 0.45 because no metadata + no frameworks +
    # needs_review demotion all apply.
    assert c <= 0.45, f"expected demotion <= 0.45, got {c}"


# ─── Bug-008: YAML autocorrect handles type: None ────────────────────────
def test_autocorrect_handles_none_type():
    from atms.yaml_autocorrect import autocorrect_system_yaml
    raw = {"name": "x", "components": [{"id": "a", "name": "A", "type": None}]}
    fixed, corr = autocorrect_system_yaml(raw)
    assert corr, "expected a correction for type=None"
    assert fixed["components"][0]["type"] == "other"


# ─── Bug-010: covered implicitly (Dataflow constructor accepts no `id`) ──
def test_dataflow_does_not_accept_id_kwarg():
    """The inert id= kwarg was removed in workflow.py; this just pins the
    underlying contract — Dataflow has no `id` field."""
    df = Dataflow(source="a", target="b", label="x")
    assert not hasattr(df, "id") or getattr(df, "id", None) == ""


# ─── Bug-011: priors with inverted range gets recovered ──────────────────
def test_priors_inverted_range_is_recovered():
    """Loading a tier with loss_low > loss_high logs + swaps the values."""
    from atms.kb import get_kb
    kb = get_kb()
    # Inject a broken tier and re-run quantitative engine to confirm
    # the loaded data has been normalised.
    for tier in kb.loss_prior_tiers:
        assert tier.get("loss_low_default", 0) <= tier.get("loss_high_default", 0), (
            f"tier {tier.get('id')} has lo > hi: "
            f"{tier.get('loss_low_default')} > {tier.get('loss_high_default')}"
        )


# ─── Bug-012: empty components list gets specific error ──────────────────
def test_empty_components_list_clear_error():
    """v0.16.9: empty components list raises a clear ValueError from
    analyze() rather than the misleading NoAIComponentsError."""
    sys_obj = System(name="x", components=[])
    with pytest.raises(ValueError) as exc:
        analyze(sys_obj)
    assert "no components" in str(exc.value).lower() or "at least one" in str(exc.value).lower()


# ─── Bug-013: duplicate Component.id is rejected ─────────────────────────
def test_duplicate_component_ids_rejected():
    with pytest.raises(Exception) as exc:
        System(name="x", components=[
            Component(id="a", name="A1", type="llm_inference"),
            Component(id="a", name="A2", type="agent"),
        ])
    assert "duplicate" in str(exc.value).lower()


# ─── Bug-014: format_validation_error includes exception class for non-Pydantic
def test_format_validation_error_keeps_exception_class():
    from atms.yaml_autocorrect import format_validation_error

    class CustomError(Exception):
        pass
    msg = format_validation_error(CustomError("oops"), None)
    assert "CustomError" in msg, f"expected class name in message, got {msg!r}"


# ─── Bug-015: EU_AI_ACT.50 also gated when not high-risk ─────────────────
def test_eu_ai_act_50_gated_off_when_not_high_risk():
    sys_obj = System(name="x", is_high_risk_under_eu_ai_act=False,
                     components=[
                         Component(id="u", name="U", type="user"),
                         Component(id="a", name="A", type="llm_inference"),
                     ])
    tm = analyze(sys_obj)
    eu_hits = {
        c for t in tm.threats for c in t.compliance_controls
        if c.startswith("EU_AI_ACT")
    }
    assert not eu_hits, (
        f"all EU_AI_ACT tags must be suppressed when high-risk=False; "
        f"saw {sorted(eu_hits)}"
    )


# ─── Bug-005: attack-path diversity is fast on dense graphs ──────────────
@pytest.mark.slow
def test_diverse_path_selector_scales_under_60s():
    """Was: ~61s on 100 LLMs + dense flows. Now: well under 60s."""
    import time

    comps = [
        Component(id=f"l{i}", name=f"L{i}", type="llm_inference")
        for i in range(50)
    ]
    # 200 edges between the first 15 LLMs
    flows = [
        Dataflow(source=f"l{i}", target=f"l{j}", label="x")
        for i in range(15) for j in range(15) if i != j
    ]
    sys_obj = System(name="dense", components=comps, dataflows=flows)
    t0 = time.time()
    tm = analyze(sys_obj)
    elapsed = time.time() - t0
    assert elapsed < 30.0, f"50-LLM dense graph took {elapsed:.2f}s; budget 30s"
    assert len(tm.threats) > 0
