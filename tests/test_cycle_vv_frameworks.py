"""Regression tests for v0.18.32 Cycle VV — 4 more frameworks."""

from __future__ import annotations

from atms.kb import get_kb


def test_fifteen_frameworks_loaded():
    kb = get_kb()
    fws = {c.get("framework") for c in kb.compliance_controls.values()
           if c.get("framework")}
    assert len(fws) >= 15
    for new in ("OWASP_MASVS", "OWASP_SAMM", "ISO27017", "ISO27018"):
        assert new in fws


def test_masvs_covers_required_categories():
    kb = get_kb()
    masvs_ids = [c["id"] for c in kb.compliance_controls.values()
                 if c.get("framework") == "OWASP_MASVS"]
    # MASVS v2 has 7 categories: STORAGE, CRYPTO, AUTH, NETWORK,
    # PLATFORM, CODE, RESILIENCE.
    prefixes = {cid.split(".")[1].split("-")[0] for cid in masvs_ids}
    for cat in ("STORAGE", "CRYPTO", "AUTH", "NETWORK", "PLATFORM", "CODE", "RESILIENCE"):
        assert cat in prefixes, f"MASVS category {cat} missing"


def test_samm_covers_business_functions():
    kb = get_kb()
    samm_ids = [c["id"] for c in kb.compliance_controls.values()
                if c.get("framework") == "OWASP_SAMM"]
    # SAMM v2 business functions: Governance, Design, Implementation,
    # Verification, Operations.
    prefixes = {cid.split(".")[1].split("-")[0] for cid in samm_ids}
    for bf in ("GOV", "DESIGN", "IMPL", "VERIFY", "OPS"):
        assert bf in prefixes, f"SAMM business function {bf} missing"


def test_iso27017_and_27018_have_cloud_specific_ids():
    kb = get_kb()
    c17 = [c["id"] for c in kb.compliance_controls.values()
            if c.get("framework") == "ISO27017"]
    c18 = [c["id"] for c in kb.compliance_controls.values()
            if c.get("framework") == "ISO27018"]
    assert c17 and c18
    # 27017 control IDs include "CLD." prefix (the cloud-specific addendum).
    assert any("CLD" in cid for cid in c17)


def test_all_new_controls_have_required_fields():
    kb = get_kb()
    new_frameworks = {"OWASP_MASVS", "OWASP_SAMM", "ISO27017", "ISO27018"}
    for cid, ctrl in kb.compliance_controls.items():
        if ctrl.get("framework") not in new_frameworks:
            continue
        for field in ("framework", "title", "description", "applies_to", "keywords"):
            assert field in ctrl, f"{cid} missing {field}"
        assert isinstance(ctrl["applies_to"], list)
        assert isinstance(ctrl["keywords"], list)


def test_compliance_matrix_includes_new_frameworks():
    from atms.models import Component, System
    from atms.reporting.compliance_matrix import compute_coverage
    from atms.workflow import analyze
    s = System(name="t", components=[
        Component(id="u", name="u", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(id="mob", name="Mobile", type="mobile_device"),
    ])
    m = analyze(s)
    for fw in ("OWASP_MASVS", "OWASP_SAMM", "ISO27017", "ISO27018"):
        rows = compute_coverage(m, framework=fw)
        assert len(rows) > 0, f"{fw} produced no rows"
