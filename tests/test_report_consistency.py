"""Report-consistency regressions (audit F011/F012/F013/F014)."""

from __future__ import annotations

import yaml

from atms.models import System
from atms.reporting.csa_risk_register import _residual_band, build_risk_register
from atms.reporting.exec_summary import _table_threats
from atms.workflow import analyze

_SAMPLE = "samples/chatbot.yaml"


def _model():
    return analyze(System.model_validate(yaml.safe_load(open(_SAMPLE, encoding="utf-8"))))


def test_exec_summary_top5_excludes_closed_threats():
    """F013/F014: a triaged-away (false_positive) threat must not be presented
    as a Top-5 risk while the headline reports it inactive."""
    tm = _model()
    top = sorted(tm.threats, key=lambda x: x.risk_score, reverse=True)[0]
    top.disposition = "false_positive"
    html = _table_threats(tm.threats)
    assert top.id not in html


def test_csa_existing_measures_only_when_real_control():
    """F011: 'mitigating control(s) recorded' must come from a real control:*
    tag, not the exploitability<discoverability heuristic. The chatbot sample's
    threats declare no controls, so no row may claim one."""
    reg = build_risk_register(_model())
    claiming = [e for e in reg if "mitigating control" in e["existing_measures"]]
    assert claiming == [], f"{len(claiming)} rows falsely claim a recorded control"


def test_csa_existing_measures_driven_by_has_control_signal():
    """F011: 'mitigating control(s) recorded' is driven by the has_control
    signal (a real control:* tag), not inferred from D-E-R numbers."""
    from atms.reporting.csa_risk_register import _existing_measures
    base = {"external_facing": False, "evidence_status": "hypothetical"}
    assert "mitigating control" in _existing_measures({**base, "has_control": True})
    assert "mitigating control" not in _existing_measures({**base, "has_control": False})


def test_csa_residual_band_not_dropped_for_open_proposed_mitigation():
    """F012: residual = risk after treatment APPLIED. An open threat with only
    a suggested mitigation keeps its current band; real treatment drops it."""
    assert _residual_band("Very High", True, "open") == "Very High"
    assert _residual_band("Very High", True, "deferred") == "Very High"
    assert _residual_band("Very High", True, "mitigated") == "Medium-High"     # -2
    assert _residual_band("Very High", True, "accepted_with_compensating_control") == "High"  # -1
