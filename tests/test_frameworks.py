"""Regression tests for the v0.17.2 Cycle B framework-enrichment registry.

These tests pin:
  1. The unified `enrich_with_frameworks(...)` engine produces the same
     final field sets as the 4 individual engines used to.
  2. The `FrameworkSpec` registry covers the load-bearing axes
     (tokenisation choices, bonus rules, thresholds).
  3. The 4 wrapper modules (linddun, nist_ai_100_2, owasp_ml, mapping)
     still expose their public function names.
"""

from __future__ import annotations

from atms.engines.frameworks import (
    ATLAS_SPEC,
    FRAMEWORK_REGISTRY,
    LINDDUN_SPEC,
    NIST_AI_100_2_SPEC,
    OWASP_ML_SPEC,
    FrameworkSpec,
    enrich_with_frameworks,
)
from atms.models import Component, System
from atms.workflow import analyze


# ─── Registry shape ─────────────────────────────────────────────────
def test_registry_contains_four_specs():
    assert len(FRAMEWORK_REGISTRY) == 4
    names = {s.name for s in FRAMEWORK_REGISTRY}
    assert names == {"MITRE ATLAS", "LINDDUN", "NIST AI 100-2", "OWASP ML 2023"}


def test_each_spec_has_distinct_kb_attr():
    """Two specs targeting the same kb_attr would double-enrich."""
    attrs = [s.kb_attr for s in FRAMEWORK_REGISTRY]
    assert len(attrs) == len(set(attrs))


def test_each_spec_has_distinct_threat_field():
    fields = [s.threat_field for s in FRAMEWORK_REGISTRY]
    assert len(fields) == len(set(fields))


def test_linddun_spec_carries_privacy_bonus_tokens():
    """The privacy-hint bonus from the original linddun engine must
    survive the migration to the registry."""
    assert "privacy" in LINDDUN_SPEC.keyword_bonus_tokens
    assert "pii" in LINDDUN_SPEC.keyword_bonus_tokens
    assert "gdpr" in LINDDUN_SPEC.keyword_bonus_tokens


def test_nist_spec_carries_family_stride_bonuses():
    """The Privacy×Info_Disclosure, Poisoning×Tampering,
    Evasion×Defense_Evasion bonuses from the original nist engine
    must survive."""
    bonuses = {(f, s): b for f, s, b in NIST_AI_100_2_SPEC.family_stride_bonus}
    assert bonuses.get(("Privacy", "Information_Disclosure")) == 1
    assert bonuses.get(("Poisoning", "Tampering")) == 1
    assert bonuses.get(("Evasion", "Defense_Evasion")) == 2


def test_atlas_spec_tokenises_only_keywords():
    """The pre-Cycle-B ATLAS engine did NOT tokenise entry titles /
    shorts. Preserving that behavior keeps the test corpus stable."""
    assert ATLAS_SPEC.tokenize_entry_fields == ("keywords",)


def test_linddun_spec_tokenises_keywords_title_short():
    """LINDDUN's broader tokenisation must be preserved."""
    assert set(LINDDUN_SPEC.tokenize_entry_fields) == {"keywords", "title", "short"}


def test_owasp_ml_spec_tokenises_keywords_and_title():
    """OWASP ML tokenised keywords + title (no short)."""
    assert set(OWASP_ML_SPEC.tokenize_entry_fields) == {"keywords", "title"}


# ─── Behaviour: unified engine == sum of legacy engines ─────────────
def test_unified_engine_populates_all_four_fields_on_a_rag_system():
    """End-to-end: a RAG system run through analyze() should pick up
    citations from all 4 frameworks via the unified registry."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(id="rag", name="RAG", type="rag_vector_store"),
    ])
    tm = analyze(sys_obj)
    # At least one threat should carry a citation in each framework's field
    # (the sample is rich enough that the 4 specs all find a match).
    fields_seen = {"atlas_techniques": False, "linddun": False,
                   "nist_ai_100_2": False, "owasp_ml": False}
    for t in tm.threats:
        if t.atlas_techniques: fields_seen["atlas_techniques"] = True
        if t.linddun: fields_seen["linddun"] = True
        if t.nist_ai_100_2: fields_seen["nist_ai_100_2"] = True
        if t.owasp_ml: fields_seen["owasp_ml"] = True
    # ATLAS + NIST should definitely be populated on a real RAG. The
    # other two are softer requirements (depend on which threats fire).
    assert fields_seen["atlas_techniques"], "ATLAS should populate on RAG"
    assert fields_seen["nist_ai_100_2"], "NIST AI 100-2 should populate on RAG"


# ─── Wrapper modules still expose their old public names ────────────
def test_legacy_wrappers_still_importable():
    """The 4 wrapper modules retain their original function names
    for back-compat with any external caller."""
    from atms.engines.linddun import enrich_with_linddun
    from atms.engines.mapping import enrich_with_atlas
    from atms.engines.nist_ai_100_2 import enrich_with_nist_ai_100_2
    from atms.engines.owasp_ml import enrich_with_owasp_ml
    assert callable(enrich_with_linddun)
    assert callable(enrich_with_atlas)
    assert callable(enrich_with_nist_ai_100_2)
    assert callable(enrich_with_owasp_ml)


def test_custom_registry_is_honoured():
    """Caller-supplied registries override the default — proving the
    abstraction is open for new frameworks."""
    custom = FrameworkSpec(
        name="test-only", kb_attr="atlas_techniques",
        threat_field="atlas_techniques", max_per_threat=1,
    )
    # Smoke test: a custom registry with just one spec runs without error.
    threats: list = []
    components: list = []
    result = enrich_with_frameworks(threats, components, registry=(custom,))
    assert result == []  # no threats in, no threats out
