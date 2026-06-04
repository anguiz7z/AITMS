"""Regression tests for v0.18.24 Cycle NN — SOC 2 controls in the compliance KB."""

from __future__ import annotations

from atms.kb import get_kb
from atms.models import Component, System
from atms.reporting.compliance_matrix import compute_coverage
from atms.workflow import analyze


def test_soc2_controls_loaded():
    kb = get_kb()
    soc2 = [c for c in kb.compliance_controls.values() if c.get("framework") == "SOC2"]
    assert len(soc2) >= 25, f"Expected ≥25 SOC2 controls, got {len(soc2)}"


def test_soc2_covers_five_trust_principles():
    """SOC 2 has 5 categories: Common Criteria (CC), Availability (A1),
    Confidentiality (C1), Processing Integrity (PI1), Privacy (P*).
    Confirm every category has at least one control."""
    kb = get_kb()
    soc2_ids = [c["id"] for c in kb.compliance_controls.values()
                if c.get("framework") == "SOC2"]
    prefixes = set()
    for cid in soc2_ids:
        # IDs look like SOC2.CC6.1, SOC2.A1.2, SOC2.C1.1, SOC2.PI1.4, SOC2.P1.1
        head = cid.split(".")[1]  # CC6, A1, C1, PI1, P1
        # Strip trailing digits to get the category prefix.
        prefix = "".join(c for c in head if not c.isdigit())
        prefixes.add(prefix)
    # Categories: CC, A, C, PI, P
    for cat in ("CC", "A", "C", "PI", "P"):
        assert cat in prefixes, (
            f"SOC 2 category {cat} missing — got prefixes {sorted(prefixes)}"
        )


def test_every_soc2_control_has_required_fields():
    kb = get_kb()
    for cid, ctrl in kb.compliance_controls.items():
        if not cid.startswith("SOC2."):
            continue
        for field in ("framework", "title", "description", "applies_to", "keywords"):
            assert field in ctrl, f"{cid} missing {field}"
        assert ctrl["framework"] == "SOC2"
        assert isinstance(ctrl["applies_to"], list)
        assert isinstance(ctrl["keywords"], list)


def test_soc2_appears_in_compliance_matrix():
    """A simple system should produce a coverage matrix that includes
    SOC 2 rows (whether covered or uncovered — the rows must EXIST)."""
    s = System(name="t", components=[
        Component(id="u", name="u", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    m = analyze(s)
    rows = compute_coverage(m, framework="SOC2")
    assert len(rows) >= 25
    for r in rows:
        assert r["framework"] == "SOC2"
        assert r["status"] in {"covered", "mitigated", "uncovered", "not-applicable"}


def test_soc2_appears_in_framework_breakdown():
    """coverage_summary's per-framework breakdown should include SOC2."""
    from atms.reporting.compliance_matrix import coverage_summary
    s = System(name="t", components=[
        Component(id="u", name="u", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    m = analyze(s)
    rows = compute_coverage(m)  # all frameworks
    summ = coverage_summary(rows)
    assert "SOC2" in summ["frameworks"]


def test_soc2_cc6_1_in_scope_on_iam_heavy_system():
    """SOC2.CC6.1 (logical/physical access) applies_to mfa_service,
    iam_principal, identity_provider, etc. A system with such
    components should NOT mark CC6.1 as not-applicable."""
    s = System(name="t", components=[
        Component(id="u", name="u", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(id="idp", name="IdP", type="identity_provider"),
        Component(id="mfa", name="MFA", type="mfa_service"),
    ])
    m = analyze(s)
    rows = compute_coverage(m, framework="SOC2")
    cc61 = next((r for r in rows if r["control_id"] == "SOC2.CC6.1"), None)
    assert cc61 is not None
    # in-scope: either covered, mitigated, or uncovered (NOT n/a)
    assert cc61["status"] in {"covered", "mitigated", "uncovered"}
