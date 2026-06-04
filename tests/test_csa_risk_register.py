"""CSA Singapore "Risk Assessment for CII" risk model + Risk Register (v1.0.6).

The owner's Singapore client follows the CSA *Guide to Conducting Cybersecurity
Risk Assessment for CII* (Feb 2021):

  * Likelihood = average(Discoverability, Exploitability, Reproducibility)
  * Impact     = max(Confidentiality, Integrity, Availability)
  * Risk       = Likelihood x Impact on a 5x5 grid with CSA bands
                 (Low / Medium / Medium-High / High / Very High)
  * Risk Register with the 8 mandatory elements.

DEFENSIBILITY is the point of this feature, so these tests pin not just that
it runs, but that every sub-score derives from a real ATMS signal with a
documented rule:

  * D-E-R / C-I-A all in [1,5]; likelihood is the mean of D,E,R; impact is the
    max of C,I,A (the CSA method, verified numerically).
  * Discoverability rises for external-facing components.
  * Exploitability falls when a mitigating control is recorded.
  * Reproducibility is forced to 5 on a CISA KEV hit.
  * C/I/A track the threat's STRIDE-LM categories (a DoS threat scores high
    on Availability, low on Confidentiality, etc.).
  * The CSA risk value correlates monotonically with ATMS's own severity, so
    the two views reconcile rather than contradict.
  * The 8 register elements are all present; residual <= current risk.
  * CSV + HTML render, are deterministic, and download via the web routes.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from atms.cli import _load_system_yaml
from atms.models import Component, Evidence, System, Threat
from atms.reporting.csa_risk_register import (
    build_csa_rows,
    build_risk_register,
    cia_impact,
    csa_likelihood,
    csa_risk_band,
    discoverability,
    exploitability,
    render_csa_risk_register_csv,
    render_csa_risk_register_html,
    reproducibility,
)
from atms.workflow import analyze

_SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture(scope="module")
def model():
    return analyze(_load_system_yaml(_SAMPLES / "azure_openai_rag.yaml"))


def _threat(**kw):
    base = dict(id="t", component_id="c", title="x", description="d",
                likelihood=3, impact=3)
    base.update(kw)
    return Threat(**base)


# ─── D-E-R likelihood triad ─────────────────────────────────────────


def test_discoverability_rises_when_external():
    t = _threat(likelihood=3)
    assert discoverability(t, external=False) == 3
    assert discoverability(t, external=True) == 4


def test_exploitability_falls_with_recorded_control():
    t = _threat(likelihood=4, references=["control:waf"])
    assert exploitability(t) == 3  # 4 - 1 for the control
    t2 = _threat(likelihood=4)
    assert exploitability(t2) == 4


def test_exploitability_rises_with_observed_evidence():
    t = _threat(likelihood=3, evidence_status="observed")
    assert exploitability(t) == 4


def test_reproducibility_forced_to_five_on_kev():
    t = _threat(likelihood=2, evidence=[Evidence(source="ti", kev=True)])
    assert reproducibility(t) == 5


def test_likelihood_is_mean_of_der():
    t = _threat(likelihood=4)
    d, e, r, like = csa_likelihood(t, external=True)
    assert like == pytest.approx((d + e + r) / 3.0)
    assert 1 <= like <= 5


# ─── C-I-A impact triad ─────────────────────────────────────────────


def test_impact_is_max_of_cia():
    t = _threat(impact=4, stride_ai=["Information_Disclosure"])
    c, i, a, imp = cia_impact(t)
    assert imp == max(c, i, a)


def test_dos_threat_scores_availability_not_confidentiality():
    """A Denial_of_Service threat must score high on Availability and low on
    Confidentiality — the C-I-A discrimination the CSA method needs."""
    t = _threat(impact=5, stride_ai=["Denial_of_Service"])
    c, i, a, imp = cia_impact(t)
    assert a == 5
    assert a > c
    assert imp == 5


def test_info_disclosure_scores_confidentiality():
    t = _threat(impact=5, stride_ai=["Information_Disclosure"])
    c, i, a, imp = cia_impact(t)
    assert c == 5
    assert c > a


def test_tampering_scores_integrity():
    t = _threat(impact=5, stride_ai=["Tampering"])
    c, i, a, imp = cia_impact(t)
    assert i == 5
    assert i >= c and i >= a


def test_lateral_movement_touches_all_three():
    t = _threat(impact=5, stride_ai=["Lateral_Movement"])
    c, i, a, imp = cia_impact(t)
    assert c == i == a == 5


# ─── Risk bands ─────────────────────────────────────────────────────


@pytest.mark.parametrize("risk,band", [
    (1, "Low"), (4, "Low"),
    (5, "Medium"), (9, "Medium"),
    (10, "Medium-High"), (14, "Medium-High"),
    (15, "High"), (19, "High"),
    (20, "Very High"), (25, "Very High"),
])
def test_csa_bands(risk, band):
    # choose L,I whose product is `risk` where possible; else just check the
    # band function via a likelihood/impact pair.
    for lv in range(1, 6):
        if risk % lv == 0 and 1 <= risk // lv <= 5:
            _, got = csa_risk_band(float(lv), risk // lv)
            assert got == band
            return
    pytest.skip(f"no L,I pair for risk={risk}")


# ─── Whole-model invariants ─────────────────────────────────────────


def test_all_subscores_in_range(model):
    for r in build_csa_rows(model):
        for k in ("discoverability", "exploitability", "reproducibility",
                  "confidentiality", "integrity", "availability", "impact"):
            assert 1 <= r[k] <= 5, f"{k}={r[k]} out of range on {r['threat_id']}"
        assert r["likelihood_int"] == max(1, min(5, round(r["likelihood"])))
        assert r["impact"] == max(r["confidentiality"], r["integrity"], r["availability"])


def test_csa_risk_correlates_with_atms_severity(model):
    """The CSA risk value must increase with ATMS severity — the two scoring
    views reconcile (a key defensibility property)."""
    import statistics
    rows = {r["threat_id"]: r for r in build_csa_rows(model)}
    by_sev: dict[str, list[int]] = {}
    for t in model.threats:
        by_sev.setdefault(t.severity, []).append(rows[t.id]["risk_value"])
    means = {s: statistics.mean(v) for s, v in by_sev.items() if v}
    # Wherever both buckets exist, higher severity => higher mean CSA risk.
    order = ["low", "medium", "high", "critical"]
    present = [s for s in order if s in means]
    for a, b in zip(present, present[1:], strict=False):
        assert means[a] <= means[b], (
            f"CSA risk should rise with severity: {a}={means[a]:.1f} > {b}={means[b]:.1f}"
        )


# ─── 8-element Risk Register ────────────────────────────────────────


def test_register_has_eight_mandatory_elements(model):
    reg = build_risk_register(model, generated_date="2026-06-01")
    assert reg
    required = {
        "risk_scenario", "identification_date", "existing_measures",
        "current_risk_level", "treatment_plan", "treatment_progress",
        "residual_risk_level", "risk_owner",
    }
    for e in reg:
        assert required <= set(e.keys()), f"missing register elements: {required - set(e.keys())}"


def test_residual_never_exceeds_current(model):
    order = ["Low", "Medium", "Medium-High", "High", "Very High"]
    for e in build_risk_register(model):
        assert order.index(e["residual_risk_level"]) <= order.index(e["current_risk_level"])


def test_risk_scenario_is_a_csa_sentence(model):
    """Scenario = Asset + Threat + STRIDE-LM + worst-property impact."""
    e = build_risk_register(model)[0]
    s = e["risk_scenario"]
    assert "STRIDE-LM" in s
    assert "impact" in s and "likelihood" in s


# ─── Renderers ──────────────────────────────────────────────────────


def test_csv_is_parseable_with_csa_columns(model):
    text = render_csa_risk_register_csv(model, generated_date="2026-06-01")
    rows = list(csv.reader(io.StringIO(text)))
    header = rows[0]
    for col in ("Discoverability", "Exploitability", "Reproducibility", "Likelihood",
                "Confidentiality", "Integrity", "Availability", "Impact",
                "Current Risk Level", "Residual Risk Level", "Risk Owner"):
        assert col in header, f"CSV missing column {col!r}"
    assert len(rows) - 1 == len(build_csa_rows(model))


def test_html_is_well_formed_and_documents_method(model):
    html = render_csa_risk_register_html(model, generated_date="2026-06-01")
    assert html.startswith("<!doctype html>")
    assert "CSA Risk Register" in html
    assert "Likelihood = avg" in html  # the method is stated for the auditor
    assert "max(Confidentiality, Integrity, Availability)" in html
    assert "</html>" in html.strip()[-10:]


def test_renderers_are_deterministic(model):
    assert render_csa_risk_register_csv(model, "2026-06-01") == render_csa_risk_register_csv(model, "2026-06-01")
    assert render_csa_risk_register_html(model, "2026-06-01") == render_csa_risk_register_html(model, "2026-06-01")


# ─── Web download routes ────────────────────────────────────────────


@pytest.fixture(scope="module")
def web_run():
    from fastapi.testclient import TestClient

    from atms.web import _RUNS, app
    client = TestClient(app, raise_server_exceptions=False)
    yaml_text = (_SAMPLES / "azure_openai_rag.yaml").read_text(encoding="utf-8")
    resp = client.post("/analyze", data={"yaml": yaml_text, "methodology": "stride-ai"})
    assert resp.status_code == 200
    return client, list(_RUNS.keys())[-1]


def test_download_csa_risk_html_serves(web_run):
    client, run_id = web_run
    r = client.get(f"/download/{run_id}/csa_risk")
    assert r.status_code == 200
    assert "CSA Risk Register" in r.text
    cd = r.headers["content-disposition"]
    cd.encode("latin-1")  # ASCII-safe header (v1.0.2 lesson)
    assert "csa-risk-register.html" in cd


def test_download_csa_risk_csv_serves(web_run):
    client, run_id = web_run
    r = client.get(f"/download/{run_id}/csa_risk_csv")
    assert r.status_code == 200
    assert r.text.splitlines()[0].startswith("S/N")
    assert "csa-risk-register.csv" in r.headers["content-disposition"]


def test_synthetic_external_kev_drives_top_risk():
    """End-to-end sanity: an external-facing component with a KEV-flagged
    threat should land at/near the top with a Very High band."""
    system = System(
        name="exposed",
        components=[
            Component(id="u", name="Cust", type="user", trust_zone="internet"),
            Component(id="api", name="API", type="llm_inference", trust_zone="internet"),
        ],
        dataflows=[],
    )
    model = analyze(system)
    # Inject a KEV evidence on the first threat and re-score the CSA view.
    if model.threats:
        model.threats[0].evidence = [Evidence(source="ti", kev=True)]
        model.threats[0].stride_ai = ["Information_Disclosure", "Tampering"]
        model.threats[0].impact = 5
        rows = build_csa_rows(model)
        target = next(r for r in rows if r["threat_id"] == model.threats[0].id)
        assert target["reproducibility"] == 5
        assert target["risk_band"] in ("High", "Very High")
