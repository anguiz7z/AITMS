"""STRIDE-LM — Lateral Movement as a first-class threat category (v1.0.4).

The CSA Singapore *Guide to Cyber Threat Modelling* (Feb 2021) prescribes
STRIDE-LM (Muckin & Fitch 2019): classic STRIDE plus **Lateral Movement**,
because an attacker pivoting between components toward a crown jewel is a
distinct adversary objective the original six don't capture. ATMS already
models multi-hop pivots in attack paths + the CSA Table-of-Attack stepping
stones (v1.0.3); this gives the threat taxonomy a first-class home for them.

This file pins:
  * Lateral_Movement is a member of the StrideAI taxonomy (10 categories);
  * it has a published-framework provenance anchor (CSA SG + STRIDE-LM +
    MITRE ATT&CK TA0008), so the methodology / about page can answer
    "where does this category come from?";
  * it has a stride_ai_matrix entry with AI subcategories;
  * real playbook threats across several component types carry the tag,
    so it appears in actual analyses (not a dead enum value);
  * a Threat can be constructed + round-tripped with the category.

Every assertion below was verified empirically before it was written:
6 component types surface a Lateral_Movement threat; the per-component
enumeration is the engine path that real analyses use.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from atms.engines.stride_ai import enumerate_threats
from atms.kb import get_kb
from atms.models import Component, StrideAI, Threat

_KB_DIR = Path(__file__).resolve().parents[1] / "kb"

# Component types whose playbooks were tagged with Lateral_Movement.
_LM_COMPONENT_TYPES = (
    "server_windows", "server_linux", "network_segment",
    "transit_gateway", "bastion_host", "ot_jumphost",
)


# ─── Taxonomy membership ────────────────────────────────────────────


def test_lateral_movement_in_stride_taxonomy():
    assert "Lateral_Movement" in StrideAI.__args__


def test_stride_taxonomy_has_ten_categories():
    """STRIDE-LM (6 classic + LM) + ATMS's Defense_Evasion / Bias_Fairness /
    Emergent_Behavior extensions = 10. Guards an accidental drop."""
    assert len(StrideAI.__args__) == 10


def test_classic_stride_lm_seven_all_present():
    """The seven STRIDE-LM categories the CSA guide names must all exist."""
    stride_lm = {
        "Spoofing", "Tampering", "Repudiation", "Information_Disclosure",
        "Denial_of_Service", "Elevation_of_Privilege", "Lateral_Movement",
    }
    assert stride_lm <= set(StrideAI.__args__)


# ─── Provenance + matrix anchoring ──────────────────────────────────


def test_lateral_movement_has_methodology_provenance():
    kb = get_kb()
    assert "Lateral_Movement" in kb.methodology_provenance
    entry = kb.methodology_provenance["Lateral_Movement"]
    for field in ("anchor", "url", "standing", "summary"):
        assert field in entry, f"provenance missing {field!r}"
    assert entry["standing"] == "atms_extension"
    assert entry["url"].startswith("http")


def test_lateral_movement_provenance_cites_csa_and_attack():
    """The anchor must name its real published sources (STRIDE-LM + CSA
    guide + MITRE ATT&CK) so an auditor can trace the category."""
    kb = get_kb()
    anchor = kb.methodology_provenance["Lateral_Movement"]["anchor"]
    assert "STRIDE-LM" in anchor
    assert "CSA" in anchor
    assert "TA0008" in anchor  # MITRE ATT&CK Lateral Movement tactic


def test_lateral_movement_in_stride_matrix():
    """stride_ai_matrix.yaml documents the category with AI subcategories."""
    matrix = yaml.safe_load(
        (_KB_DIR / "stride_ai_matrix.yaml").read_text(encoding="utf-8")
    )
    assert "Lateral_Movement" in matrix
    assert matrix["Lateral_Movement"].get("ai_subcategories")


def test_every_stride_category_round_trips_to_provenance():
    """Literal and provenance keys must match exactly — the same contract
    test_methodology_branding enforces, re-asserted here so this file is
    self-contained."""
    kb = get_kb()
    assert set(StrideAI.__args__) == set(kb.methodology_provenance.keys())


# ─── The category actually appears in real threats ──────────────────


def test_construct_threat_with_lateral_movement():
    t = Threat(
        id="x", component_id="c", title="pivot", description="d",
        stride_ai=["Lateral_Movement", "Defense_Evasion"],
        likelihood=4, impact=4,
    )
    assert "Lateral_Movement" in t.stride_ai


def test_server_windows_surfaces_lateral_movement():
    """server_windows has classic LM threats (cred-dump, PowerShell/WMI)."""
    threats = enumerate_threats([Component(id="w", name="DC01", type="server_windows")])
    lm = [t for t in threats if "Lateral_Movement" in (t.stride_ai or [])]
    assert lm, "server_windows must surface >=1 Lateral_Movement threat"


def test_pivot_point_components_surface_lateral_movement():
    """Dedicated pivot-point components (bastion, OT jump host, transit
    gateway) must tag LM."""
    for ctype in ("bastion_host", "ot_jumphost", "transit_gateway"):
        threats = enumerate_threats([Component(id="p", name="P", type=ctype)])
        lm = [t for t in threats if "Lateral_Movement" in (t.stride_ai or [])]
        assert lm, f"{ctype} must surface >=1 Lateral_Movement threat"


def test_lateral_movement_appears_across_multiple_playbooks():
    """The category should be live across several component types, not a
    one-off — proving it's wired into the KB, not a dead enum value.
    Verified: 6 component types currently surface it."""
    tagged = 0
    for ctype in _LM_COMPONENT_TYPES:
        threats = enumerate_threats([Component(id="c", name="C", type=ctype)])
        if any("Lateral_Movement" in (t.stride_ai or []) for t in threats):
            tagged += 1
    assert tagged >= 5, f"expected >=5 component types tagging LM, got {tagged}"


def test_lateral_movement_threat_carries_attack_mapping():
    """An LM-tagged threat should also carry MITRE ATT&CK technique IDs —
    the category isn't a bare label, it co-occurs with real technique
    mappings (e.g. T1021 remote services, T1570 lateral tool transfer)."""
    threats = enumerate_threats([Component(id="j", name="J", type="ot_jumphost")])
    lm = [t for t in threats if "Lateral_Movement" in (t.stride_ai or [])]
    assert lm
    assert any(t.attack_enterprise for t in lm), (
        "LM threats should co-occur with ATT&CK Enterprise technique IDs"
    )


def test_about_page_surfaces_lateral_movement_provenance():
    """End-to-end: the /about page must render the Lateral_Movement
    provenance row. This is the user-facing surface that silently dropped
    the category in v1.0.4 (hardcoded `order` list), so pin it explicitly."""
    from fastapi.testclient import TestClient

    from atms.web import app
    html = TestClient(app, raise_server_exceptions=False).get("/about").text
    assert "Lateral_Movement" in html
    assert "TA0008" in html  # the MITRE ATT&CK Lateral Movement anchor


def test_onscreen_report_shows_stride_lm_column():
    """The on-screen analysis report must display a STRIDE-LM column with the
    category pills. The web/report.html threats table historically had no
    STRIDE column at all (only OWASP/ATLAS/etc.), so STRIDE categories —
    including Lateral_Movement — were invisible on screen even though the
    downloadable reports showed them. v1.0.4 adds the column."""
    import re

    from fastapi.testclient import TestClient

    from atms.web import app
    c = TestClient(app, raise_server_exceptions=False)
    # aws_bedrock_agent has a network_segment component → a Lateral_Movement
    # threat (T_NET_004).
    y = open("samples/aws_bedrock_agent.yaml", encoding="utf-8").read()
    r = c.post("/analyze", data={"yaml": y, "methodology": "stride-ai"})
    assert r.status_code == 200
    assert "STRIDE-LM" in r.text, "on-screen report missing the STRIDE-LM column header"
    assert "Lateral_Movement" in r.text, "on-screen report missing Lateral_Movement pill"

    # Table integrity: every body row has the same cell count as the header,
    # so the new column didn't shatter the table.
    thead = re.search(
        r'<table id="threats-table">.*?<thead><tr>(.*?)</tr>', r.text, re.S
    ).group(1)
    nhead = thead.count("<th")
    rows = re.findall(r'<tr data-severity="[^"]*">(.*?)</tr>', r.text, re.S)
    assert rows, "no threat rows rendered"
    assert {row.count("<td") for row in rows} == {nhead}, (
        "a threat row's cell count doesn't match the header column count"
    )
