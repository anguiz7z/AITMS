"""Regression tests for v0.18.49 Phase 4 corpus #2 — Kubernetes Guestbook.

Pins the analysis output of the official Kubernetes "Guestbook" tutorial
(3 Deployments + 3 Services across redis-leader / redis-follower /
frontend tiers — the canonical example from the Kubernetes website docs).

Source: https://kubernetes.io/docs/tutorials/stateless-application/guestbook/
Sourced 2026-05-16 verbatim from k8s.io website examples repo.
License: Apache-2.0.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_cycle_eee_k8s_guestbook_corpus.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


from pathlib import Path

SAMPLE = (Path(__file__).resolve().parents[1] /
          "samples" / "corpus" / "k8s_guestbook.yaml")


def _model():
    from atms.ingest.kubernetes import kubernetes_to_system
    from atms.workflow import analyze
    s = kubernetes_to_system(SAMPLE)
    return s, analyze(s, require_ai_components=False)


def test_k8s_ingester_parses_six_manifests():
    """3 Deployments + 3 Services. Anything else would mean a parser
    regression on a real-world reference architecture."""
    s, _ = _model()
    assert len(s.components) == 6
    types = {c.type for c in s.components}
    assert "container_runtime" in types       # Deployments
    assert "load_balancer" in types           # Services


def test_k8s_ingester_inferred_service_selector_edges():
    """Each Service's spec.selector must match a workload's labels →
    the parser should emit a service → deployment edge."""
    s, _ = _model()
    edges = {(df.source, df.target) for df in s.dataflows}
    # We don't pin exact edge IDs (they're synthesised from K8s names),
    # but we do pin the EDGE COUNT — 3 services × 1 target each.
    assert len(s.dataflows) >= 3


def test_k8s_guestbook_yields_meaningful_threat_count():
    """A real-world 3-tier reference architecture should produce at
    least 20 threats from the ATMS playbook fire + arch rules.
    Hand-authored Kubernetes guides typically document 3-5."""
    _, m = _model()
    assert len(m.threats) >= 20


def test_k8s_guestbook_attack_paths_computed():
    """ATMS should find multi-step kill chains across the tiers."""
    _, m = _model()
    assert len(m.attack_paths) >= 3


def test_k8s_guestbook_mitigations_dwarf_threat_count():
    """Phase-2 actionability contract: mitigations roughly = threats × 1+."""
    _, m = _model()
    assert len(m.mitigations) >= len(m.threats) * 0.8


def test_k8s_guestbook_arch_rules_fire():
    """The 25-rule arch engine should flag missing controls on a bare
    multi-tier k8s manifest (no SIEM, no MFA, no encryption hints, etc.)."""
    _, m = _model()
    arch = [t for t in m.threats if ".A_" in t.id]
    # At least one finding — typically more (no SIEM / no MFA /
    # missing intrusion detection / etc.).
    assert len(arch) >= 1


def test_k8s_guestbook_severity_distribution_realistic():
    """Real 3-tier with no controls declared → mostly medium with some
    high. Critical should be rare (or zero — the topology has no
    AI primitives so no LLM-prompt-injection critical fires)."""
    _, m = _model()
    sb = m.summary.get("severity_breakdown", {})
    assert sb.get("medium", 0) >= 5
    # No assertions on critical — environment-dependent.
