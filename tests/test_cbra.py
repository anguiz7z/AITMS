"""CBRA — CSA Capabilities-Based Risk Assessment.

System Risk = Criticality x Autonomy x Access-Permissions x Impact-Radius.
Adopted to align AITMS with the CSA AI Safety Initiative's capabilities-based
risk method (complements the per-threat DREAD-AI score).
"""

from __future__ import annotations

from atms.engines.cbra import compute_cbra
from atms.models import Component, Dataflow, System


def test_cbra_high_capability_financial_agent():
    sys = System(
        name="t",
        business_context="financial portfolio investment platform",
        components=[
            Component(id="agent", name="A", type="agent", metadata={"tool_count": 6}),
            Component(id="db", name="D", type="nosql_database"),
            Component(id="llm", name="L", type="llm_inference"),
        ],
        dataflows=[
            Dataflow(source="agent", target="db", data_classification="restricted"),
            Dataflow(source="agent", target="llm", data_classification="confidential"),
        ],
    )
    r = compute_cbra(sys)
    # restricted data -> criticality 4; 6 tools / no HITL -> autonomy 4; write surface -> permissions 4
    assert r["dimensions"]["criticality"]["value"] == 4
    assert r["dimensions"]["autonomy"]["value"] == 4
    assert r["dimensions"]["access_permissions"]["value"] == 4
    assert r["score"] == (
        r["dimensions"]["criticality"]["value"]
        * r["dimensions"]["autonomy"]["value"]
        * r["dimensions"]["access_permissions"]["value"]
        * r["dimensions"]["impact_radius"]["value"]
    )
    assert r["tier"] in ("High", "Medium")  # >=32; depends only on impact-radius


def test_cbra_low_for_isolated_public_llm():
    sys = System(
        name="t2",
        business_context="public marketing copy generator",
        components=[Component(id="llm", name="L", type="llm_inference")],
    )
    r = compute_cbra(sys)
    assert r["dimensions"]["criticality"]["value"] == 1
    assert r["dimensions"]["autonomy"]["value"] == 1  # no agent
    assert r["score"] <= 16 and r["tier"] == "Low"


def test_cbra_hitl_caps_autonomy():
    sys = System(
        name="t3",
        components=[
            Component(id="agent", name="A", type="agent",
                      controls=["human_in_the_loop"], metadata={"tool_count": 8}),
        ],
    )
    r = compute_cbra(sys)
    assert r["dimensions"]["autonomy"]["value"] == 2  # HITL caps it despite 8 tools


def test_cbra_declared_autonomy_level_wins():
    sys = System(
        name="t4",
        components=[Component(id="agent", name="A", type="agent", autonomy_level="autonomous")],
    )
    assert compute_cbra(sys)["dimensions"]["autonomy"]["value"] == 4
