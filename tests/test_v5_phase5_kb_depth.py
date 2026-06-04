"""Roadmap V5 Phase 5 — KB depth for the KEEP frameworks.

Credibility = the core-promise framework mappings are real and
populated. Probing the KB found it already in good shape — every
AI-primary playbook carries OWASP refs, and across the AI sample fleet
(1040 threats) the five core-promise frameworks are well-populated:

    OWASP LLM        59% of threats
    OWASP Agentic    32%
    MITRE ATLAS      60%
    MAESTRO          79%
    CSA Singapore    55%

So Phase 5 is a KB-integrity regression net — it pins this coverage so
it can't silently degrade (e.g. a playbook edit that drops refs, or a
mapping engine that stops firing). No content invented; no production
change.

KEEP suite (flags off).
"""

from __future__ import annotations

import glob
from pathlib import Path

import yaml

from atms.engines.ai_scope import find_ai_components
from atms.kb import get_kb
from atms.models import System
from atms.workflow import analyze

ROOT = Path(__file__).resolve().parents[1]

# AI-primary component types whose playbooks MUST carry framework refs.
_AI_PRIMARY = [
    "llm_inference", "agent", "rag_vector_store", "mcp_server", "tool",
    "guardrails", "output_filter", "prompt_template_store",
    "training_pipeline", "fine_tuning_pipeline", "model_registry",
]


def _ai_samples():
    out = []
    for f in sorted(glob.glob(str(ROOT / "samples" / "*.yaml"))):
        s = System.model_validate(yaml.safe_load(Path(f).read_text(encoding="utf-8")))
        if find_ai_components(s):
            out.append(f)
    return out


# ─── KB ships the core-promise frameworks ───────────────────────────


def test_kb_loads_csa_singapore_controls():
    csa = get_kb().csa_singapore
    assert isinstance(csa, dict)
    assert len(csa) >= 10, f"expected >=10 CSA controls, got {len(csa)}"


def test_kb_has_121_playbooks():
    pb = get_kb().playbooks
    assert len(pb) >= 121, f"expected >=121 playbooks, got {len(pb)}"


# ─── Every AI-primary playbook carries threats + framework refs ─────


def test_ai_primary_playbooks_have_threats_with_refs():
    kb = get_kb()
    for ctype in _AI_PRIMARY:
        p = kb.get_playbook(ctype)
        assert p, f"missing playbook for AI-primary type {ctype}"
        threats = p.get("threats", []) if isinstance(p, dict) else []
        assert threats, f"{ctype} playbook has no threats"
        # At least one threat carries an OWASP (LLM or Agentic) ref.
        has_owasp = any(
            th.get("owasp_llm") or th.get("owasp_agentic") for th in threats)
        assert has_owasp, f"{ctype} playbook carries no OWASP refs"


# ─── Fleet-level coverage floors (pin the measured numbers) ─────────


def test_core_frameworks_populated_across_ai_fleet():
    """Across the AI sample fleet, each core-promise framework must be
    carried by at least a floor fraction of threats. Floors are set
    well below the measured numbers so normal KB evolution doesn't trip
    them, but a wholesale regression (a framework dropping to ~0) is
    caught."""
    fields_floor = {
        "owasp_llm": 0.40,        # measured 59%
        "owasp_agentic": 0.15,    # measured 32%
        "atlas_techniques": 0.40,  # measured 60%
        "maestro_threats": 0.55,  # measured 79%
        "csa_singapore": 0.35,    # measured 55%
    }
    total = 0
    agg = {k: 0 for k in fields_floor}
    for f in _ai_samples():
        s = System.model_validate(yaml.safe_load(Path(f).read_text(encoding="utf-8")))
        tm = analyze(s)
        total += len(tm.threats)
        for fld in fields_floor:
            agg[fld] += sum(1 for t in tm.threats if getattr(t, fld))
    assert total > 0
    for fld, floor in fields_floor.items():
        frac = agg[fld] / total
        assert frac >= floor, (
            f"{fld} coverage {frac:.0%} below floor {floor:.0%} "
            f"({agg[fld]}/{total} threats) — KB framework mapping regressed"
        )


def test_every_core_framework_represented_on_some_threat():
    """Each core-promise framework must appear on >=1 threat somewhere
    in the AI fleet (catches a framework wired to zero)."""
    seen = {"owasp_llm": False, "owasp_agentic": False,
            "atlas_techniques": False, "maestro_threats": False,
            "csa_singapore": False}
    for f in _ai_samples():
        s = System.model_validate(yaml.safe_load(Path(f).read_text(encoding="utf-8")))
        tm = analyze(s)
        for t in tm.threats:
            for k in seen:
                if getattr(t, k):
                    seen[k] = True
    missing = [k for k, v in seen.items() if not v]
    assert not missing, f"frameworks never represented across fleet: {missing}"


# ─── Refs resolve to real KB entries (no dangling) ──────────────────


def test_owasp_llm_refs_resolve_to_kb():
    """Every OWASP LLM ref on an analysed threat resolves to a real KB
    entry (no typos / dangling ids)."""
    kb = get_kb()
    s = System.model_validate(
        yaml.safe_load((ROOT / "samples" / "rag_system.yaml").read_text(encoding="utf-8")))
    tm = analyze(s)
    for t in tm.threats:
        for ref in t.owasp_llm:
            assert kb.get_owasp(ref) is not None, f"dangling OWASP LLM ref: {ref}"
