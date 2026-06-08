"""Misc hardening regressions (audit F046/F059/F062/F063)."""

from __future__ import annotations

import os
import pickle

from atms.engines.mitigations import collect_mitigations
from atms.engines.quantitative import score_quantitative
from atms.engines.stride_ai import enumerate_threats
from atms.kb import get_kb
from atms.models import Component, System, Threat
from atms.workflow import analyze


def test_kb_cache_rejects_unauthenticated_pickle(tmp_path, monkeypatch):
    """F046: a planted .atms_kb_cache.pkl with no valid HMAC must NOT be
    deserialised (pickle.loads is RCE); the KB rebuilds instead."""
    import atms.kb as kb_mod
    monkeypatch.delenv("ATMS_KB_NO_CACHE", raising=False)
    cache = tmp_path / ".atms_kb_cache.pkl"
    monkeypatch.setattr(kb_mod, "_cache_path", lambda root: cache)
    kb_mod.get_kb.cache_clear()
    kb1 = kb_mod.get_kb()  # cold -> writes an authenticated cache + key
    assert cache.exists() and kb1.playbooks

    sentinel = tmp_path / "PWNED"

    class _Evil:
        def __reduce__(self):
            return (os.system, (f"echo x > {sentinel}",))

    cache.write_bytes(b"\x00" * 32 + pickle.dumps(_Evil()))  # bad MAC
    kb_mod.get_kb.cache_clear()
    kb2 = kb_mod.get_kb()  # must reject the planted pickle and rebuild
    assert kb2.playbooks
    assert not sentinel.exists(), "unauthenticated pickle was deserialised (RCE)"
    kb_mod.get_kb.cache_clear()


def test_dotted_component_id_keeps_inline_mitigations():
    """F062: a component id containing a dot (e.g. 'llm.v2') must still link
    its inline playbook mitigations (the local id was parsed from the wrong
    end of the threat id)."""
    kb = get_kb()

    def coverage(cid):
        c = Component(id=cid, name="L", type="llm_inference")
        ts = enumerate_threats([c], kb=kb)
        mits = collect_mitigations(ts, [c], kb=kb)
        addressed = {tid for m in mits for tid in m.addresses_threat_ids}
        return len(mits), sum(1 for t in ts if t.id in addressed)

    assert coverage("llm") == coverage("llm.v2")
    assert coverage("llm.v2")[0] > 0


def test_pii_loss_floor_respects_poc_tier_cap():
    """F063: the PII loss floor must not override a deliberately-capped
    POC/pilot deployment tier."""
    s = System(name="poc",
               components=[Component(id="llm", name="L", type="llm_inference")],
               deployment_stage="poc")
    t = Threat(id="llm.t", component_id="llm", title="PII leak", description="leaks pii",
               likelihood=4, impact=4, severity="high", linddun=["L1_Linking"])
    score_quantitative([t], system=s)
    assert t.loss_high <= 200_000, f"POC PII loss_high {t.loss_high} blew past the tier cap"


def test_attack_path_components_have_no_repeated_adjacent_hop():
    """F059: the printed component sequence collapses only ADJACENT duplicates,
    so every hop corresponds to a real edge -- there must be no two identical
    consecutive components (a global de-dup could drop a real revisit)."""
    import yaml
    tm = analyze(System.model_validate(
        yaml.safe_load(open("samples/enterprise_rag_agent.yaml", encoding="utf-8"))
    ))
    for p in tm.attack_paths:
        comps = p.components
        assert all(comps[i] != comps[i + 1] for i in range(len(comps) - 1)), (
            f"adjacent duplicate component in path {p.id}: {comps}"
        )
