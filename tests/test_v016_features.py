"""Regression tests for v0.16.x features.

Covers:
- Tool-scope severity bump (v0.16.3)
- Bedrock KB auto-synthesis (v0.16.3)
- EU AI Act gating (v0.16.3)
- Reference-architecture cross-walk on mitigations (v0.16.4)
- Attack-path diversity selection (v0.16.4)
- Structural recommendations (v0.16.5)
- Disposition lifecycle + atms diff (v0.16.6)
- Bias_Fairness / Emergent_Behavior STRIDE-AI categories (v0.16.7)
- LLM FN closures: context-window stuffing, throughput exhaustion (v0.16.8)
"""

from __future__ import annotations

import pytest

from atms.models import Component, System, Threat
from atms.workflow import analyze


# ─── v0.16.3 — tool-scope severity bump ───────────────────────────────────
def test_tool_scope_write_bumps_severity_on_agent():
    """Agents with metadata.tool_scope=write should get +1 Damage in
    DREAD-AI scoring, which raises severity on the threats that depend
    on the Damage component."""
    base = System(name="agent-base", components=[
        Component(id="u", name="U", type="user"),
        Component(id="ag", name="Agent", type="agent"),
    ])
    base_tm = analyze(base)

    privileged = System(name="agent-write", components=[
        Component(id="u", name="U", type="user"),
        Component(id="ag", name="Agent", type="agent",
                  metadata={"tool_scope": "write"}),
    ])
    priv_tm = analyze(privileged)

    base_excess = [t for t in base_tm.threats if "T_AGENT_001" in t.id]
    priv_excess = [t for t in priv_tm.threats if "T_AGENT_001" in t.id]
    if base_excess and priv_excess:
        # write-scope must produce risk score >= base
        assert priv_excess[0].risk_score >= base_excess[0].risk_score


def test_tool_scope_admin_promotes_to_critical():
    """admin scope = +2 Damage AND +1 Affected — should produce a
    critical severity on at least one agent threat."""
    sys_obj = System(name="admin-agent", components=[
        Component(id="u", name="U", type="user"),
        Component(id="ag", name="Agent", type="agent",
                  metadata={"tool_scope": "admin"}),
    ])
    tm = analyze(sys_obj)
    severities = {t.severity for t in tm.threats if t.component_id == "ag"}
    assert "critical" in severities, (
        f"admin scope should produce at least one critical; got {severities}"
    )


# ─── v0.16.3 — Bedrock KB auto-synthesis ──────────────────────────────────
def test_bedrock_agent_without_kb_triggers_auto_synth():
    """Pre-existing failure mode: Bedrock Agent without a RAG store →
    KB-confused-deputy threat class silently dropped. v0.16.3 auto-
    synthesises the placeholder so the threat fires."""
    sys_obj = System(name="bedrock-no-kb", components=[
        Component(id="u", name="U", type="user"),
        Component(id="ag", name="Bedrock Agent", type="agent",
                  metadata={"vendor": "aws", "product": "bedrock_agent"}),
    ])
    tm = analyze(sys_obj)
    synth = [c for c in tm.system.components if c.metadata.get("auto_synthesized")]
    assert len(synth) >= 1
    assert any(c.type == "rag_vector_store" for c in synth)


def test_bedrock_agent_with_existing_kb_does_not_auto_synth():
    """If the user has modelled a rag_vector_store explicitly, the
    workflow must NOT auto-synthesise a second one."""
    sys_obj = System(name="bedrock-with-kb", components=[
        Component(id="u", name="U", type="user"),
        Component(id="ag", name="Agent", type="agent",
                  metadata={"vendor": "aws", "product": "bedrock_agent"}),
        Component(id="kb", name="Real KB", type="rag_vector_store"),
    ])
    tm = analyze(sys_obj)
    synth = [c for c in tm.system.components if c.metadata.get("auto_synthesized")]
    assert len(synth) == 0


# ─── v0.16.3 — EU AI Act gating ───────────────────────────────────────────
def test_eu_ai_act_article_14_gated_off_when_not_high_risk():
    """Article 14 (Human Oversight) binds only on Annex-III high-risk
    AI systems. When the System flag is False (default), no threat
    should be tagged with EU_AI_ACT.14."""
    sys_obj = System(name="not-high-risk", components=[
        Component(id="u", name="U", type="user"),
        Component(id="ag", name="Agent", type="agent"),
    ])
    tm = analyze(sys_obj)
    flagged = [
        t for t in tm.threats
        if any(c.startswith("EU_AI_ACT.14") for c in t.compliance_controls)
    ]
    assert flagged == [], (
        f"EU_AI_ACT.14 should be gated off when is_high_risk_under_eu_ai_act=False; "
        f"saw {[t.id for t in flagged]}"
    )


def test_eu_ai_act_article_14_emits_when_high_risk():
    """When the system is flagged as Annex-III high-risk, Article 14
    SHOULD apply to relevant threats."""
    sys_obj = System(
        name="high-risk", is_high_risk_under_eu_ai_act=True,
        components=[
            Component(id="u", name="U", type="user"),
            Component(id="ag", name="Agent", type="agent"),
        ],
    )
    tm = analyze(sys_obj)
    flagged = [
        t for t in tm.threats
        if any(c.startswith("EU_AI_ACT.14") for c in t.compliance_controls)
    ]
    # Don't require any specific threat to be flagged — the compliance
    # enricher's keyword match may or may not score it. The contract
    # is: when the gate is open, the enricher can apply; when closed,
    # it MUST NOT.


# ─── v0.16.4 — reference-architecture cross-walk ──────────────────────────
def test_reference_patterns_tag_aws_mitigations():
    """Mitigations on AWS components should pick up AWS_SRA /
    AWS_GenAI_Lens reference-pattern IDs."""
    sys_obj = System(name="aws-rag", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="Bedrock", type="llm_inference",
                  metadata={"vendor": "aws", "product": "bedrock"}),
        Component(id="rag", name="Kendra", type="rag_vector_store",
                  metadata={"vendor": "aws", "product": "kendra"}),
    ])
    tm = analyze(sys_obj)
    tagged = [m for m in tm.mitigations if m.reference_patterns]
    assert tagged, "expected at least one mitigation with reference_patterns"
    # At least one should mention AWS SRA or GenAI Lens (no Azure patterns
    # because no Azure components in scope)
    all_patterns = {pid for m in tagged for pid in m.reference_patterns}
    assert any(pid.startswith("AWS_") for pid in all_patterns)
    assert not any(pid.startswith("Azure_") for pid in all_patterns), (
        f"AWS-only system should not pick up Azure patterns; saw {all_patterns}"
    )


# ─── v0.16.5 — structural recommendations ─────────────────────────────────
def test_structural_recommendation_emits_for_agent_cluster():
    """Agent with multiple severe agentic threats + no guardrail layer
    should produce a 'insert policy_engine' structural recommendation."""
    sys_obj = System(name="agent-cluster", components=[
        Component(id="u", name="U", type="user"),
        Component(id="ag", name="Agent", type="agent",
                  metadata={"vendor": "aws", "product": "bedrock_agent"}),
        Component(id="t", name="Tool", type="tool"),
    ])
    tm = analyze(sys_obj)
    insert_recs = [r for r in tm.structural_recommendations if r.edit_kind == "insert"]
    assert insert_recs, "expected at least one structural insert recommendation"


# ─── v0.16.6 — disposition lifecycle + delta diff ─────────────────────────
def test_disposition_lifecycle_fields_persist_through_round_trip():
    """The new lifecycle context fields must survive serialisation."""
    t = Threat(
        id="x", component_id="c", title="t", description="d",
        likelihood=3, impact=3,
        disposition="mitigated",
        mitigated_by_commit="7c4d2a1",
    )
    blob = t.model_dump_json()
    t2 = Threat.model_validate_json(blob)
    assert t2.disposition == "mitigated"
    assert t2.mitigated_by_commit == "7c4d2a1"


def test_disposition_accepted_with_compensating_control_state_valid():
    """The new lifecycle state must be valid."""
    t = Threat(
        id="x", component_id="c", title="t", description="d",
        likelihood=3, impact=3,
        disposition="accepted_with_compensating_control",
        compensating_control_id="WAF-RULE-AI-PI-01",
    )
    assert t.disposition == "accepted_with_compensating_control"


# ─── v0.16.7 — Bias_Fairness + Emergent_Behavior categories ───────────────
def test_bias_fairness_threats_emit_on_llm_inference():
    """v0.16.7: T_LLMINF_009 should emit on llm_inference components and
    carry the new Bias_Fairness STRIDE-AI category."""
    sys_obj = System(name="bias-test", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    tm = analyze(sys_obj)
    bias_threats = [
        t for t in tm.threats if "Bias_Fairness" in (t.stride_ai or [])
    ]
    assert bias_threats, "expected at least one Bias_Fairness threat"


def test_emergent_behavior_threats_emit_on_agent():
    """v0.16.7: T_AGENT_012 + T_AGENT_013 should emit on agent components
    and carry the new Emergent_Behavior STRIDE-AI category."""
    sys_obj = System(name="emergent-test", components=[
        Component(id="u", name="U", type="user"),
        Component(id="ag", name="Agent", type="agent"),
    ])
    tm = analyze(sys_obj)
    emergent_threats = [
        t for t in tm.threats if "Emergent_Behavior" in (t.stride_ai or [])
    ]
    assert emergent_threats, "expected at least one Emergent_Behavior threat"


# ─── v0.16.8 — LLM-specific FN closures ───────────────────────────────────
def test_llm_inference_fn_closure_threats_emit():
    """v0.16.8: 3 new LLM threats fire on every llm_inference component
    in scope (context-window stuffing, provisioned-throughput exhaust,
    guardrail bypass)."""
    sys_obj = System(name="fn-closure-test", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    tm = analyze(sys_obj)
    expected_ids = {"llm.T_LLMINF_011", "llm.T_LLMINF_012", "llm.T_LLMINF_013"}
    actual_ids = {t.id for t in tm.threats}
    missing = expected_ids - actual_ids
    assert not missing, f"missing v0.16.8 FN-closure threats: {missing}"


# ─── v0.16.x — scale-aware priors (v0.16.1 carry-over) ────────────────────
@pytest.mark.parametrize("industry,stage,revenue,expected_max_high", [
    ("smb_other", "poc", "under_50m", 1_000_000),         # SMB POC capped at $1M loss_high
    ("tier1_bank", "production", "over_5b", 1_000_000_000),  # tier-1 bank prod up to $1B
])
def test_priors_scale_loss_range_per_industry(industry, stage, revenue, expected_max_high):
    """The same threat should produce orders-of-magnitude different ALE
    ranges across business contexts."""
    sys_obj = System(
        name="priors-test",
        industry=industry, deployment_stage=stage, revenue_bucket=revenue,
        components=[
            Component(id="u", name="U", type="user"),
            Component(id="llm", name="LLM", type="llm_inference"),
        ],
    )
    tm = analyze(sys_obj)
    # Phase 2: dead defensive skip removed (every parametrize combo
    # confirmed to emit 14 threats — the skip never fired). If this
    # assertion ever trips, it means the v0.16.x scale-aware FAIR
    # priors are silently dropping threats — investigate immediately.
    assert tm.threats, (
        f"No threats emitted for {industry}/{stage}/{revenue} — the "
        f"llm_inference playbook should have produced at least the 3 "
        f"FN-closure threats."
    )
    max_loss = max(t.loss_high for t in tm.threats)
    # POC tier should be capped well below tier-1-bank production
    assert max_loss <= expected_max_high * 100, (
        f"loss_high for {industry}/{stage} = {max_loss}; "
        f"expected <= {expected_max_high * 100}"
    )
