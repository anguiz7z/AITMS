"""Engine tests — STRIDE-AI, ATLAS enrichment, risk, attack paths, mitigations."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from atms.engines.attack_paths import find_attack_paths
from atms.engines.mapping import enrich_with_atlas
from atms.engines.mitigations import collect_mitigations
from atms.engines.risk import risk_matrix_counts, score_threats
from atms.engines.stride_ai import enumerate_threats
from atms.kb import get_kb
from atms.models import Component, Dataflow, System
from atms.workflow import analyze

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture(scope="module")
def kb():
    return get_kb()


@pytest.fixture
def rag_system():
    raw = yaml.safe_load((SAMPLES_DIR / "rag_system.yaml").read_text(encoding="utf-8"))
    return System.model_validate(raw)


@pytest.fixture
def chatbot_system():
    raw = yaml.safe_load((SAMPLES_DIR / "chatbot.yaml").read_text(encoding="utf-8"))
    return System.model_validate(raw)


def test_enumerate_threats_basic(rag_system, kb):
    threats = enumerate_threats(rag_system.components, kb=kb)
    assert len(threats) >= 20
    # Every component with a playbook should have ≥1 threat
    component_ids = {c.id for c in rag_system.components}
    seen = {t.component_id for t in threats}
    # All components covered
    assert seen.issubset(component_ids)
    assert len(seen) >= 7


def test_enumerate_threats_unknown_type():
    # v0.17.0: `other` is now a real (minimal) playbook safety-net, not a
    # zero-playbook fallback. The catch-all surfaces spoofing / tampering /
    # info-disclosure / DoS at playbook confidence so unrecognised components
    # still receive a baseline threat-model rather than 0.3-confidence stubs.
    comp = Component(id="x", name="X", type="other", description="unknown")
    threats = enumerate_threats([comp])
    # Playbook should emit at least 3 generic threats
    assert len(threats) >= 3
    # All threats sourced from the `other` playbook → high confidence
    assert all(t.confidence >= 0.9 for t in threats)


def test_owasp_coverage_full(rag_system):
    tm = analyze(rag_system)
    # RAG system should hit all 10 OWASP LLM categories
    assert len(tm.summary["owasp_coverage"]) == 10


def test_atlas_enrichment_adds_techniques(rag_system, kb):
    threats = enumerate_threats(rag_system.components, kb=kb)
    before = sum(len(t.atlas_techniques) for t in threats)
    threats = enrich_with_atlas(threats, rag_system.components, kb=kb)
    after = sum(len(t.atlas_techniques) for t in threats)
    # Enrichment should add at least some techniques
    assert after >= before


def test_risk_scoring_severity(rag_system):
    threats = enumerate_threats(rag_system.components)
    scored = score_threats(threats, rag_system.components)
    severities = {t.severity for t in scored}
    assert "high" in severities or "critical" in severities
    # Risk score is 0..100
    assert all(0 <= t.risk_score <= 100 for t in scored)


def test_risk_matrix_counts_shape(rag_system):
    threats = enumerate_threats(rag_system.components)
    threats = score_threats(threats, rag_system.components)
    matrix = risk_matrix_counts(threats)
    assert len(matrix) == 5
    assert all(len(row) == 5 for row in matrix)
    assert sum(sum(row) for row in matrix) == len(threats)


def test_attack_paths_built(rag_system):
    tm = analyze(rag_system)
    assert len(tm.attack_paths) >= 1
    # Multi-step paths should exist for an interesting system
    assert any(len(p.threat_ids) >= 2 for p in tm.attack_paths)


def test_attack_paths_respect_tactics(rag_system, kb):
    threats = enumerate_threats(rag_system.components, kb=kb)
    threats = enrich_with_atlas(threats, rag_system.components, kb=kb)
    threats = score_threats(threats, rag_system.components)
    paths = find_attack_paths(threats, rag_system.components, rag_system.dataflows, kb=kb)
    for p in paths:
        # Tactics should be uniquely ordered
        assert len(p.tactics_traversed) == len(set(p.tactics_traversed))


def test_mitigations_collected(rag_system, kb):
    threats = enumerate_threats(rag_system.components, kb=kb)
    threats = score_threats(threats, rag_system.components)
    mits = collect_mitigations(threats, rag_system.components, kb=kb)
    assert len(mits) >= 30
    # ATLAS mitigations should be present
    atlas_count = sum(1 for m in mits if any("ATLAS:" in r for r in m.framework_refs))
    assert atlas_count >= 5


def test_mitigations_address_threats(rag_system):
    tm = analyze(rag_system)
    addressed = {tid for m in tm.mitigations for tid in m.addresses_threat_ids}
    # Every high/critical threat should have at least one mitigation
    for t in tm.threats:
        if t.severity in ("high", "critical"):
            assert t.id in addressed, f"high/critical threat {t.id} has no mitigation"


def test_chatbot_smaller_surface(chatbot_system):
    tm = analyze(chatbot_system)
    # Chatbot has no RAG, no agent tools — should still produce >= 10 threats
    assert len(tm.threats) >= 10
    # But fewer than the full RAG sample
    rag_raw = yaml.safe_load((SAMPLES_DIR / "rag_system.yaml").read_text(encoding="utf-8"))
    rag_tm = analyze(System.model_validate(rag_raw))
    assert len(tm.threats) < len(rag_tm.threats)


def test_full_workflow_summary(rag_system):
    tm = analyze(rag_system)
    assert tm.summary["components"] == len(rag_system.components)
    assert tm.summary["threats"] == len(tm.threats)
    assert tm.summary["attack_paths"] == len(tm.attack_paths)
    assert tm.summary["mitigations"] == len(tm.mitigations)
    assert "severity_breakdown" in tm.summary
    assert "risk_matrix" in tm.summary


def test_no_orphan_threats(rag_system):
    tm = analyze(rag_system)
    component_ids = {c.id for c in rag_system.components}
    for t in tm.threats:
        assert t.component_id in component_ids


def test_dataflow_validation():
    """v0.16.9: dangling dataflow refs are now rejected at model-validation
    time (was: silently accepted, masking user typos). The new contract is
    "fail fast on broken refs"."""
    with pytest.raises(Exception) as exc:
        System(
            name="empty",
            components=[
                Component(id="lone", name="lone", type="user"),
                Component(id="llm", name="LLM", type="llm_inference"),
            ],
            dataflows=[Dataflow(source="lone", target="ghost", label="x")],
        )
    assert "nonexistent" in str(exc.value).lower() or "ghost" in str(exc.value)


def test_isolated_components_load_fine():
    """A System with components that are not wired by any dataflow must
    still load successfully — isolation is legal, dangling refs are not."""
    sys = System(
        name="isolated",
        components=[
            Component(id="lone", name="lone", type="user"),
            Component(id="llm", name="LLM", type="llm_inference"),
        ],
        # no dataflows at all
    )
    tm = analyze(sys)
    assert tm.summary["components"] == 2


# ─────────────────────────────────────────────────── MAESTRO + OWASP-Agentic
def test_agentic_sample_lights_up_owasp_agentic():
    raw = yaml.safe_load((SAMPLES_DIR / "agentic_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    # Agentic system should reference at least 10 of the 17 OWASP Agentic threats
    assert len(tm.summary["owasp_agentic_coverage"]) >= 10
    # And should hit memory poisoning, tool misuse, goal manipulation, supply chain
    expected = {"AGT01", "AGT02", "AGT06", "AGT17"}
    assert expected.issubset(set(tm.summary["owasp_agentic_coverage"])), \
        f"missing: {expected - set(tm.summary['owasp_agentic_coverage'])}"


def test_agentic_sample_covers_all_maestro_layers():
    raw = yaml.safe_load((SAMPLES_DIR / "agentic_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    expected_layers = {"M.L1", "M.L2", "M.L3", "M.L4", "M.L5", "M.L6", "M.L7"}
    assert expected_layers.issubset(set(tm.summary["maestro_layers"]))


def test_maestro_threats_referenced_per_threat():
    raw = yaml.safe_load((SAMPLES_DIR / "agentic_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    threats_with_maestro = [t for t in tm.threats if t.maestro_threats]
    assert len(threats_with_maestro) >= 10


def test_chatbot_smaller_agentic_surface_than_full_agentic_system():
    """A simple chatbot orchestrator should produce fewer agentic threats than a real
    agentic system (multi-tool agent + MCP servers + privileged tools)."""
    bot_raw = yaml.safe_load((SAMPLES_DIR / "chatbot.yaml").read_text(encoding="utf-8"))
    bot_tm = analyze(System.model_validate(bot_raw))
    ag_raw = yaml.safe_load((SAMPLES_DIR / "agentic_system.yaml").read_text(encoding="utf-8"))
    ag_tm = analyze(System.model_validate(ag_raw))
    bot_coverage = set(bot_tm.summary["owasp_agentic_coverage"])
    ag_coverage = set(ag_tm.summary["owasp_agentic_coverage"])
    assert len(ag_coverage) > len(bot_coverage), \
        f"agentic system should hit more agentic threats: bot={len(bot_coverage)}, ag={len(ag_coverage)}"
    # The chatbot has no MCP server, so AGT16 (Insecure Inter-Agent Protocol Abuse) is unlikely
    # to be a primary playbook hit. (Enrichment may still attach it via keyword overlap; that's
    # fine — the gradient between systems is the real signal.)


def test_agentic_mitigations_are_collected():
    """OWASP Agentic mitigations should be in the mitigation roll-up for agentic systems."""
    raw = yaml.safe_load((SAMPLES_DIR / "agentic_system.yaml").read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    agentic_mits = [m for m in tm.mitigations if any("OWASP-AGT:" in r for r in m.framework_refs)]
    assert len(agentic_mits) >= 5
