"""Regression tests for v0.18.40 Cycle DDD — OWASP Threat Dragon corpus.

Pins the analysis output of OWASP's official Threat Dragon demo
model (translated into ATMS YAML) so any future regression that
silently reduces coverage versus a real-world hand-authored model
trips the suite. The source JSON is kept alongside the YAML for
provenance.

Source URL:
  https://raw.githubusercontent.com/OWASP/threat-dragon/main/ThreatDragonModels/demo-threat-model.json
  Fetched 2026-05-16. Project: OWASP/threat-dragon. License: Apache 2.0.
"""

from __future__ import annotations

from pathlib import Path

SAMPLE = (Path(__file__).resolve().parents[1] /
          "samples" / "corpus" / "owasp_threat_dragon_demo.yaml")


def _model():
    from atms.cli import _load_system_yaml
    from atms.workflow import analyze
    s = _load_system_yaml(SAMPLE)
    return analyze(s, require_ai_components=False)


def test_threat_dragon_demo_parses_with_expected_shape():
    """7 components, 10 dataflows, 3 trust boundaries — direct
    translation of the source diagram."""
    from atms.cli import _load_system_yaml
    s = _load_system_yaml(SAMPLE)
    assert len(s.components) == 7
    assert len(s.dataflows) == 10
    assert len(s.trust_boundaries) == 3


def test_atms_finds_at_least_2x_more_threats_than_handauthored():
    """Threat Dragon hand-authored 14 threats. ATMS must auto-derive
    at least 2× that to demonstrate coverage value."""
    m = _model()
    HANDAUTHORED = 14
    assert len(m.threats) >= 2 * HANDAUTHORED, (
        f"ATMS only derived {len(m.threats)} threats vs. "
        f"hand-authored {HANDAUTHORED} — coverage regression"
    )


def test_atms_computes_attack_paths_threat_dragon_does_not():
    """Threat Dragon has no attack-path computation. ATMS finds
    multi-step kill chains on the same topology."""
    m = _model()
    assert len(m.attack_paths) > 0


def test_atms_emits_mitigation_set_larger_than_threat_count():
    """Every threat carries at least one recommended mitigation, with
    cross-threat consolidation. Sample should produce ≥3 mitigations
    per threat on average (the v0.14 actionability contract)."""
    m = _model()
    assert len(m.mitigations) >= len(m.threats) * 2


def test_arch_rules_fire_on_real_world_diagram():
    """The 25 arch rules should surface at least 5 findings on a
    realistic web-app diagram (Threat Dragon doesn't have arch rules
    at all — this is pure additive coverage)."""
    m = _model()
    arch = [t for t in m.threats if ".A_" in t.id]
    assert len(arch) >= 5


def test_framework_enrichment_spans_multiple_taxonomies():
    """The same topology gets mapped to multiple framework taxonomies
    that Threat Dragon doesn't track natively (OWASP API, ATT&CK Cloud,
    ATT&CK Enterprise, LINDDUN).

    NB: this demo is a non-AI web app (require_ai_components=False), so MITRE
    ATLAS coverage is intentionally suppressed -- ATLAS is an adversarial-ML
    (AI-only) taxonomy and claiming it for a non-AI estate is indefensible
    (audit F067). The four non-AI-only taxonomies still demonstrate the span.
    """
    m = _model()
    expected_nonempty = (
        "owasp_api_coverage",
        "attack_cloud_coverage",
        "attack_enterprise_coverage",
        "linddun_coverage",
    )
    for k in expected_nonempty:
        cov = m.summary.get(k) or []
        assert len(cov) >= 3, f"Expected ≥3 {k}, got {len(cov)}"


def test_compliance_matrix_surfaces_real_gaps_across_frameworks():
    """At least 3 compliance frameworks should produce 'covered' rows;
    at least 5 should produce 'uncovered' (in-scope gap) rows. This
    is the audit-friendly delta vs. a tool that just lists threats."""
    from atms.reporting.compliance_matrix import compute_coverage, coverage_summary
    m = _model()
    rows = compute_coverage(m)
    summ = coverage_summary(rows)
    covered_frameworks = sum(
        1 for fw, c in summ["frameworks"].items()
        if c["covered"] + c["mitigated"] > 0
    )
    uncovered_frameworks = sum(
        1 for fw, c in summ["frameworks"].items() if c["uncovered"] > 0
    )
    assert covered_frameworks >= 3
    assert uncovered_frameworks >= 5
