"""KB loading + search tests."""

from __future__ import annotations

import pytest

from atms.kb import get_kb


@pytest.fixture(scope="module")
def kb():
    return get_kb()


def test_owasp_loaded(kb):
    assert len(kb.owasp_llm) == 10
    assert "LLM01:2025" in kb.owasp_llm
    assert "LLM10:2025" in kb.owasp_llm
    assert kb.owasp_llm["LLM01:2025"]["title"] == "Prompt Injection"


def test_atlas_loaded(kb):
    assert len(kb.atlas_techniques) >= 30
    assert "AML.T0051" in kb.atlas_techniques  # Prompt Injection
    assert "AML.T0024" in kb.atlas_techniques  # Exfiltration via inference API
    assert len(kb.atlas_tactics) >= 14
    assert len(kb.atlas_mitigations) >= 20


def test_playbooks_loaded(kb):
    expected_types = {
        "llm_inference",
        "rag_vector_store",
        "agent",
        "tool",
        "mcp_server",
        "training_pipeline",
        "fine_tuning_pipeline",
        "embedding_service",
        "prompt_template_store",
        "model_registry",
        "guardrails",
        "output_filter",
        "data_source",
        "external_api",
        "user",
    }
    assert expected_types.issubset(set(kb.playbooks.keys()))
    assert all(len(pb.get("threats", [])) > 0 for pb in kb.playbooks.values())


def test_search_prompt_injection(kb):
    results = kb.search("prompt injection", limit=10)
    assert results
    ids = [r["id"] for r in results]
    # Both ATLAS and OWASP should hit
    assert "LLM01:2025" in ids
    assert "AML.T0051" in ids


def test_search_framework_filter(kb):
    only_atlas = kb.search("model extraction", framework="atlas", limit=10)
    assert all(r["framework"] == "atlas" for r in only_atlas)
    # "owasp" is the umbrella covering both LLM Top 10 and Agentic AI ASI
    only_owasp = kb.search("supply chain", framework="owasp", limit=10)
    assert all(r["framework"].startswith("owasp") for r in only_owasp)
    only_owasp_llm = kb.search("supply chain", framework="owasp_llm", limit=10)
    assert all(r["framework"] == "owasp_llm" for r in only_owasp_llm)
    only_agentic = kb.search("memory poisoning", framework="owasp_agentic", limit=10)
    assert all(r["framework"] == "owasp_agentic" for r in only_agentic)
    only_maestro = kb.search("agent identity", framework="maestro", limit=10)
    assert all(r["framework"] == "maestro" for r in only_maestro)


def test_search_empty_query(kb):
    assert kb.search("") == []


def test_owasp_agentic_loaded(kb):
    assert len(kb.owasp_agentic) == 17
    for n in range(1, 18):
        assert f"AGT{n:02d}" in kb.owasp_agentic
    # Spot-check a couple of well-known threats
    assert kb.owasp_agentic["AGT01"]["title"] == "Memory Poisoning"
    assert kb.owasp_agentic["AGT16"]["title"] == "Insecure Inter-Agent Protocol Abuse"
    # Each threat has mitigations and a STRIDE-AI mapping
    for agt in kb.owasp_agentic.values():
        assert agt["mitigations"], f"{agt['id']} missing mitigations"
        assert agt["stride_ai"], f"{agt['id']} missing stride_ai"


def test_maestro_loaded(kb):
    assert len(kb.maestro_layers) == 7
    for layer_id in ["M.L1", "M.L2", "M.L3", "M.L4", "M.L5", "M.L6", "M.L7"]:
        assert layer_id in kb.maestro_layers
    # Threats catalogue covers all 7 layers + cross-layer
    layers_with_threats = {t["layer"] for t in kb.maestro_threats.values()}
    assert {"M.L1", "M.L2", "M.L3", "M.L4", "M.L5", "M.L6", "M.L7", "cross"}.issubset(layers_with_threats)


def test_search_maestro_finds_layer(kb):
    results = kb.search("agent ecosystem", framework="maestro", limit=5)
    ids = [r["id"] for r in results]
    assert "M.L7" in ids or any("L7" in i for i in ids)
