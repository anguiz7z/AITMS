"""AICM control-domain + shared-responsibility ownership mapping (CSA AICM v1.0.3)."""

from __future__ import annotations

from types import SimpleNamespace

from atms.engines.aicm import DOMAINS, compute_aicm


def _t(tid, comp, owasp=(), stride=()):
    return SimpleNamespace(id=tid, component_id=comp, owasp_llm=list(owasp), stride_ai=list(stride))


def _c(cid, ctype):
    return SimpleNamespace(id=cid, type=ctype)


def test_aicm_maps_owasp_to_domains_and_owner():
    threats = [
        _t("t1", "llm", owasp=["LLM01:2025"]),   # injection -> AIS + MOS; llm -> Model Provider
        _t("t2", "rag", owasp=["LLM02:2025"]),   # disclosure -> DSP; rag -> Application Provider
        _t("t3", "agent", owasp=["LLM06:2025"]),  # excessive agency -> IAM + MOS; agent -> Orchestrated
    ]
    comps = [_c("llm", "llm_inference"), _c("rag", "rag_vector_store"), _c("agent", "agent")]
    r = compute_aicm(threats, comps)
    dom_ids = {d["id"] for d in r["domains"]}
    assert {"AIS", "MOS", "DSP", "IAM"} <= dom_ids
    assert all(d["id"] in DOMAINS for d in r["domains"])
    owners = {o["actor"] for o in r["ownership"]}
    assert {"Model Provider", "Application Provider", "Orchestrated Service Provider"} <= owners


def test_aicm_falls_back_and_attributes_customer():
    r = compute_aicm([_t("t", "x")], [_c("x", "user")])
    assert r["domains"] and r["domains"][0]["id"] == "TVM"  # default domain
    assert r["ownership"][0]["actor"] == "AI Customer"
    assert "243" in r["note"]  # honest scope note present
