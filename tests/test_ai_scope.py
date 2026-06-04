"""Tests for v0.15.0 AI-anchored scoping.

The product positioning changed in v0.15.0: ATMS evaluates AI-induced
risk across the full architecture, not generic IT threats. Three
behaviors must hold:

1. A system with zero AI components is REJECTED at analysis time with
   `NoAIComponentsError`. This is the bug the v0.14 banking-ATM report
   exposed (false-positive findings tagged with OWASP-LLM IDs against
   firewalls and switches).
2. An AI-only system analyses normally. Every threat carries
   `ai_relevance="primary"`.
3. A hybrid system (AI + non-AI components) emits threats only for
   components in the AI dataflow blast radius. Out-of-scope components
   produce zero threats. AI-adjacent threats carry `ai_caused_by`
   pointing at the AI components responsible.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from atms.engines.ai_scope import (
    NoAIComponentsError,
    ai_relevance,
    compute_ai_blast_radius,
    find_ai_components,
    is_ai_component,
)
from atms.models import Component, Dataflow, System
from atms.workflow import analyze

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ─── Rejection: pure-IT system ─────────────────────────────────────────────
def test_pure_it_system_is_rejected():
    """The exact regression that motivated v0.15.0: a banking-ATM
    diagram (firewall + database + switch + mainframe) should NOT
    produce a wall of AI-framework-tagged false-positive findings.
    Reject at analyse time."""
    sys_obj = System(name="banking-atm", components=[
        Component(id="fw", name="Firewall", type="firewall"),
        Component(id="db", name="Core DB", type="database"),
        Component(id="sw", name="L2 Switch", type="network_switch"),
        Component(id="mf", name="AS400", type="legacy_mainframe"),
    ])
    with pytest.raises(NoAIComponentsError) as exc:
        analyze(sys_obj)
    msg = str(exc.value)
    assert "no ai components" in msg.lower() or "ai-induced risk" in msg.lower()
    # Caller should be pointed at general-purpose tools instead.
    assert ("threat dragon" in msg.lower()
            or "general-purpose" in msg.lower()
            or "ai_integration" in msg.lower())


def test_metadata_ai_integration_flag_marks_component_as_ai():
    """Escape hatch: a non-AI-typed component with
    `metadata.ai_integration: true` counts as an AI primary. Lets users
    flag a `serverless_function` that calls an LLM, for instance."""
    sys_obj = System(name="serverless-llm", components=[
        Component(id="fn", name="LLM caller", type="serverless_function",
                  metadata={"ai_integration": True}),
        Component(id="store", name="Result store", type="object_storage"),
    ])
    ai_components = find_ai_components(sys_obj)
    assert len(ai_components) == 1
    assert ai_components[0].id == "fn"
    # Should analyse without rejection.
    tm = analyze(sys_obj)
    assert tm.threats


# ─── AI-only system ────────────────────────────────────────────────────────
def test_ai_only_system_marks_all_threats_primary():
    sys_obj = System(name="rag", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(id="rag", name="Vector store", type="rag_vector_store"),
        Component(id="emb", name="Embedder", type="embedding_service"),
    ])
    tm = analyze(sys_obj)
    assert tm.threats
    # Every AI-component threat is `primary`. The user gets `adjacent`
    # if reached, or out-of-scope (no threats).
    for t in tm.threats:
        if t.component_id in {"llm", "rag", "emb"}:
            assert t.ai_relevance == "primary", (
                f"AI primary {t.component_id} got relevance={t.ai_relevance!r}"
            )
            assert t.ai_caused_by == [], "primaries shouldn't list themselves"


# ─── Hybrid system: out-of-scope components get zero threats ──────────────
def test_hybrid_system_skips_out_of_scope_components():
    """A banking core (atm, web_banking, customer) with an LLM sidecar
    bolted on. The LLM only touches the database + queue; the ATM
    network is not in the LLM's blast radius. ATMS must produce zero
    threats for components outside the radius."""
    sys_obj = System(name="bank-with-llm", components=[
        # The customer-facing IT layer (NO AI touches this):
        Component(id="atm", name="ATM", type="endpoint"),
        Component(id="atm_net", name="ATM net", type="network_segment"),
        Component(id="customer", name="Customer", type="user"),
        Component(id="web", name="Web banking", type="web_application"),
        # The bridge — touches both:
        Component(id="db", name="Core DB", type="database"),
        Component(id="queue", name="Txn queue", type="message_queue"),
        # The AI sidecar:
        Component(id="llm", name="Fraud LLM", type="llm_inference"),
        Component(id="rag", name="Rules vec", type="rag_vector_store"),
    ], dataflows=[
        # Customer-facing path (no AI):
        Dataflow(id="1", source="customer", target="atm", label="card"),
        Dataflow(id="2", source="atm", target="atm_net", label="ISO 8583"),
        Dataflow(id="3", source="customer", target="web", label="HTTPS"),
        # AI bridge:
        Dataflow(id="4", source="db", target="queue", label="event"),
        Dataflow(id="5", source="queue", target="llm", label="txn ctx"),
        Dataflow(id="6", source="llm", target="rag", label="retrieve"),
    ])
    tm = analyze(sys_obj)

    threat_components = {t.component_id for t in tm.threats}

    # AI primaries must be present:
    assert "llm" in threat_components
    assert "rag" in threat_components

    # AI-adjacent (within the LLM's blast radius) must be present:
    assert "queue" in threat_components, "queue is one hop from LLM"
    assert "db" in threat_components, "db is two hops from LLM via queue"

    # Customer-facing IT must NOT produce threats:
    assert "atm" not in threat_components, "ATM endpoint should be out of scope"
    assert "atm_net" not in threat_components, (
        "ATM private network should be out of scope"
    )
    assert "web" not in threat_components, (
        "web banking has no AI dataflow — out of scope"
    )


def test_hybrid_threats_carry_ai_provenance():
    """Every adjacent threat must point back at the AI component that
    created its in-scope status. Without this, the report can't tell
    a reviewer 'why is this database threat here?'."""
    sys_obj = System(name="hybrid", components=[
        Component(id="db", name="Core DB", type="database"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ], dataflows=[
        Dataflow(id="1", source="llm", target="db", label="read"),
    ])
    tm = analyze(sys_obj)
    db_threats = [t for t in tm.threats if t.component_id == "db"]
    assert db_threats
    for t in db_threats:
        assert t.ai_relevance == "adjacent"
        assert "llm" in t.ai_caused_by, (
            f"DB threat {t.id} missing AI provenance: {t.ai_caused_by!r}"
        )


def test_hybrid_blast_radius_respects_max_hops():
    """A long chain (a → b → c → d → llm) puts everything within 3
    hops of the LLM in the blast radius; a 5-hop chain leaves the
    far end out-of-scope."""
    components = [
        Component(id=f"n{i}", name=f"Node {i}", type="endpoint")
        for i in range(6)
    ]
    components.append(Component(id="llm", name="LLM", type="llm_inference"))
    dataflows = [
        Dataflow(id=str(i), source=f"n{i}", target=f"n{i+1}", label="x")
        for i in range(5)
    ] + [Dataflow(id="x", source="n5", target="llm", label="prompt")]
    sys_obj = System(name="chain", components=components, dataflows=dataflows)
    radius = compute_ai_blast_radius(sys_obj, max_hops=3)
    # n5 (1 hop), n4 (2), n3 (3) should be in scope; n2, n1, n0 outside.
    in_scope = set(radius)
    assert "n5" in in_scope and "n4" in in_scope and "n3" in in_scope
    assert "n2" not in in_scope and "n1" not in in_scope and "n0" not in in_scope


def test_bundled_bank_sample_is_correctly_scoped():
    """The canonical hybrid demo: customer-facing components (atm_*,
    customer, web_banking) emit zero threats; AI primaries + AI-
    adjacent core get threats with provenance."""
    raw = yaml.safe_load((SAMPLES / "bank_with_llm_fraud.yaml").read_text(encoding="utf-8"))
    sys_obj = System.model_validate(raw)
    tm = analyze(sys_obj)

    threat_components = {t.component_id for t in tm.threats}

    # Customer-facing IT — out of scope, zero threats:
    for cid in ("atm_terminal", "atm_network", "customer", "web_banking"):
        assert cid not in threat_components, (
            f"{cid} should be out of AI scope but produced threats"
        )

    # AI primaries — full coverage:
    for cid in ("fraud_llm", "fraud_rules_rag",
                "fraud_rules_curator", "fraud_guardrails"):
        assert cid in threat_components, f"AI primary {cid} missing threats"
        primary_threats = [t for t in tm.threats if t.component_id == cid]
        assert any(t.ai_relevance == "primary" for t in primary_threats)

    # AI-adjacent — should be present and provenance-tagged:
    for cid in ("core_banking", "customer_db", "fraud_iam", "fraud_secrets"):
        assert cid in threat_components
        adj = [t for t in tm.threats if t.component_id == cid]
        assert all(t.ai_relevance == "adjacent" for t in adj)
        assert all(t.ai_caused_by for t in adj), (
            f"AI-adjacent threats on {cid} must carry provenance"
        )


# ─── ai_relevance classifier directly ──────────────────────────────────────
def test_ai_relevance_classifier_three_outcomes():
    sys_obj = System(name="x", components=[
        Component(id="llm", name="L", type="llm_inference"),
        Component(id="db", name="D", type="database"),
        Component(id="lone", name="LL", type="firewall"),
    ], dataflows=[
        Dataflow(id="1", source="llm", target="db", label="read"),
    ])
    radius = compute_ai_blast_radius(sys_obj)
    by_id = {c.id: c for c in sys_obj.components}
    assert ai_relevance(by_id["llm"], radius) == "primary"
    assert ai_relevance(by_id["db"], radius) == "adjacent"
    assert ai_relevance(by_id["lone"], radius) == "out_of_scope"


def test_is_ai_component_for_each_AI_primary_type():
    """Every type in AI_PRIMARY_TYPES must be classified as AI by
    is_ai_component()."""
    from atms.engines.ai_scope import AI_PRIMARY_TYPES
    for t in AI_PRIMARY_TYPES:
        c = Component(id="x", name="X", type=t)
        assert is_ai_component(c), f"{t} should be an AI primary"


def test_singapore_csa_guidelines_loaded():
    """v0.15.0: kb/csa_singapore/guidelines.yaml ships with ATMS so
    cross-walks against CSA principles work without an internet fetch."""
    from atms.kb import get_kb
    kb = get_kb()
    assert kb.csa_singapore, "CSA Singapore principles should be loaded"
    assert any(k.startswith("CSA_AI.") for k in kb.csa_singapore)
    # Spot-check the headline ones.
    assert "CSA_AI.DEPLOY.02" in kb.csa_singapore  # input validation / guardrails
    assert "CSA_AI.HUMAN.01" in kb.csa_singapore   # human oversight on consequential decisions
