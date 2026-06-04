"""Regression tests for v0.18.33 Cycle WW — 3 vertical samples."""

from __future__ import annotations

from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.mark.parametrize("filename,min_comp,min_threats", [
    ("healthcare_ehr_fhir.yaml",    20, 30),
    ("fintech_payment_ledger.yaml", 25, 25),
    ("ot_water_treatment.yaml",     18, 15),
])
def test_vertical_sample_parses_and_analyzes(filename, min_comp, min_threats):
    """Each vertical sample loads, validates, and produces meaningful
    output through the full analyse pipeline. AI-scope is permissive
    because the OT sample has no AI components by design."""
    from atms.cli import _load_system_yaml
    from atms.workflow import analyze
    p = SAMPLES / filename
    assert p.exists(), f"sample missing: {p}"
    s = _load_system_yaml(p)
    assert len(s.components) >= min_comp
    m = analyze(s, require_ai_components=False)
    assert len(m.threats) >= min_threats


def test_healthcare_sample_is_high_risk_under_eu_ai_act():
    from atms.cli import _load_system_yaml
    s = _load_system_yaml(SAMPLES / "healthcare_ehr_fhir.yaml")
    assert s.is_high_risk_under_eu_ai_act is True


def test_fintech_sample_industry_is_fintech():
    from atms.cli import _load_system_yaml
    s = _load_system_yaml(SAMPLES / "fintech_payment_ledger.yaml")
    assert s.industry == "fintech"


def test_ot_sample_industry_is_critical_infrastructure():
    from atms.cli import _load_system_yaml
    s = _load_system_yaml(SAMPLES / "ot_water_treatment.yaml")
    assert s.industry == "critical_infrastructure"


def test_healthcare_sample_has_human_oversight_for_eu_ai_act():
    """Cycle RR rule missing_human_oversight_high_risk should NOT fire
    on this sample because we explicitly model a reviewer downstream
    of the CDS LLM."""
    from atms.cli import _load_system_yaml
    from atms.workflow import analyze
    s = _load_system_yaml(SAMPLES / "healthcare_ehr_fhir.yaml")
    m = analyze(s, require_ai_components=False)
    arch_ids = [t.id for t in m.threats
                if t.id.endswith(".A_MISSING_HUMAN_OVERSIGHT_HIGH_RISK")]
    assert arch_ids == [], (
        f"Expected reviewer to satisfy human-oversight rule, but it fired on: "
        f"{arch_ids}"
    )
