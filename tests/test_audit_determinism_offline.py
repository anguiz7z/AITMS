"""Lock in two flagship README claims for the AITMS analyze path:

  1. DETERMINISM — analysing the SAME system twice yields the IDENTICAL
     set of threat IDs (and the identical count). The whole "diffable,
     cacheable, reference-an-ID-in-a-ticket" pitch rests on this; a
     regression to uuid4-style IDs (the v0.19.1 bug class) or any
     order/membership drift would break it.

  2. OFFLINE — the analyze path makes NO network calls. The README sells
     a "local, deterministic, fully-offline AI threat modeler"; the only
     network code in the package is confined to `atms.feeds.*`
     (cve_lookup / refresh), NOT the analysis pipeline. The strongest
     form of this assertion is to monkeypatch `socket.socket` AND
     `socket.create_connection` to raise on any use, then run analyze and
     assert it STILL completes and still produces real playbook threats.

These tests only call the public `analyze()` API and construct models via
`atms.models`. They do not modify src or any existing test.

Run:
  cd E:/Jarvis/builds/aitms && PYTHONPATH=src ATMS_KB_NO_CACHE=1 \
    python -m pytest tests/test_audit_determinism_offline.py -q -p no:cacheprovider
"""

from __future__ import annotations

import socket

import pytest

from atms.models import Component, Dataflow, System
from atms.workflow import analyze

# Threat IDs we KNOW the representative system must produce. These come
# from the bundled playbooks (kb/playbooks/*.yaml) — read directly to
# pin the exact ids:
#   - llm.T_LLMINF_001 : "Direct prompt injection / jailbreak"
#                        (kb/playbooks/llm_inference.yaml, likelihood 5)
#   - rag.T_RAG_001    : "Indirect prompt injection via retrieved content"
#                        (kb/playbooks/rag_vector_store.yaml)
#   - ag.T_AGENT_001   : "Excessive agency / unintended high-impact actions"
#                        (kb/playbooks/agent.yaml)
# Format is `{component_id}.{playbook_threat_id}` (see
# engines.stride_ai._threat_from_playbook). None of these carry
# applicability predicates that this topology fails, so they are
# guaranteed to fire.
EXPECTED_CORE_IDS = {
    "llm.T_LLMINF_001",
    "rag.T_RAG_001",
    "ag.T_AGENT_001",
}


def _build_system() -> System:
    """A representative AI system: an LLM behind a RAG store driven by an
    autonomous agent, with the natural dataflows between them. This is the
    canonical AI-primary shape (llm_inference + rag_vector_store + agent),
    so the AI-scope gate passes with the default require_ai_components=True.

    Built fresh on every call: `analyze()` mutates the System in place
    (infers trust boundaries, annotates dataflows, may synthesise a
    Bedrock KB), so a determinism comparison MUST feed two independent
    System instances or the second run sees the first run's mutations.
    """
    return System(
        name="Representative AI System",
        description="LLM + RAG + agent reference topology",
        components=[
            Component(id="llm", name="LLM Inference", type="llm_inference"),
            Component(id="rag", name="RAG Vector Store", type="rag_vector_store"),
            Component(id="ag", name="Task Agent", type="agent"),
        ],
        dataflows=[
            Dataflow(source="ag", target="llm", label="prompt"),
            Dataflow(source="ag", target="rag", label="retrieve"),
            Dataflow(source="rag", target="llm", label="context"),
        ],
    )


# ─────────────────────────── DETERMINISM ────────────────────────────────
def test_threat_ids_identical_across_two_runs():
    """README claim: analysing the SAME system twice is deterministic.

    The SET of threat IDs and the COUNT must match exactly across two
    independent analyses of an equivalent system.
    """
    a = analyze(_build_system())
    b = analyze(_build_system())

    ids_a = sorted(t.id for t in a.threats)
    ids_b = sorted(t.id for t in b.threats)

    # Count is identical.
    assert len(a.threats) == len(b.threats), (
        f"threat count drifted across runs: {len(a.threats)} vs {len(b.threats)}"
    )
    # The summary's own count agrees with the materialised list.
    assert a.summary["threats"] == len(a.threats)
    assert b.summary["threats"] == len(b.threats)
    assert a.summary["threats"] == b.summary["threats"]

    # Set of IDs is identical (no membership drift, no uuid4 leakage).
    assert set(ids_a) == set(ids_b), (
        "threat-id SET drifted across runs; symmetric difference: "
        f"{set(ids_a) ^ set(ids_b)}"
    )
    # Stronger: the sorted ID lists are equal element-for-element, which
    # also rules out a duplicate ID appearing in exactly one run.
    assert ids_a == ids_b

    # No duplicate IDs within a single run (analyze() dedups by id).
    assert len(ids_a) == len(set(ids_a)), "duplicate threat IDs within a run"


def test_expected_core_threats_present_and_stable():
    """The representative system must yield the known core playbook
    threats, and they must repeat across runs. This anchors the
    determinism test to REAL content — guarding against a regression that
    keeps the count stable while silently swapping which threats fire."""
    a = analyze(_build_system())
    b = analyze(_build_system())
    ids_a = {t.id for t in a.threats}
    ids_b = {t.id for t in b.threats}

    missing = EXPECTED_CORE_IDS - ids_a
    assert not missing, f"expected core threats absent from analysis: {missing}"
    # Same anchored set on the second run.
    assert EXPECTED_CORE_IDS <= ids_b

    # And the threat objects themselves are well-formed (real titles,
    # severities, framework mappings) — not empty stubs.
    by_id = {t.id: t for t in a.threats}
    direct_pi = by_id["llm.T_LLMINF_001"]
    assert direct_pi.title  # non-empty
    assert direct_pi.severity in {"info", "low", "medium", "high", "critical"}
    assert "LLM01:2025" in direct_pi.owasp_llm
    assert direct_pi.component_id == "llm"


# ───────────────────────────── OFFLINE ──────────────────────────────────
class _NetworkUsedError(RuntimeError):
    """Raised if anything in the analyze path tries to open a socket."""


def test_analyze_makes_no_network_calls(monkeypatch):
    """README claim: the analyze path is fully offline.

    Strongest form: hard-disable the network at the socket layer. We
    monkeypatch BOTH `socket.socket` (the constructor every higher-level
    client — urllib, requests, httpx — ultimately calls) and
    `socket.create_connection` (the fast path several stdlib clients use)
    so ANY attempt to touch the network raises immediately. analyze()
    must still complete and still produce real threats. Network code in
    this package is confined to `atms.feeds.*`, which the pipeline never
    invokes.
    """

    def _blocked_socket(*args, **kwargs):
        raise _NetworkUsedError(
            "analyze() opened a socket — the offline contract is broken"
        )

    def _blocked_create_connection(*args, **kwargs):
        raise _NetworkUsedError(
            "analyze() called socket.create_connection — offline contract broken"
        )

    monkeypatch.setattr(socket, "socket", _blocked_socket)
    monkeypatch.setattr(socket, "create_connection", _blocked_create_connection)

    # Must not raise _NetworkUsedError — i.e. analyze touches no socket.
    tm = analyze(_build_system())

    # And it must still do its job: produce real threats, not an empty or
    # degraded model.
    assert tm.threats, "analyze produced no threats with the network disabled"
    assert tm.summary["threats"] == len(tm.threats)

    # The core playbook threats still fire offline (proves the KB resolved
    # locally — no network fetch was silently substituting for it).
    ids = {t.id for t in tm.threats}
    missing = EXPECTED_CORE_IDS - ids
    assert not missing, (
        f"offline analysis missing core threats {missing}; KB may have "
        "depended on the network"
    )


def test_offline_result_matches_online_result(monkeypatch):
    """The offline run is not just non-empty — it is IDENTICAL to a normal
    run. Disabling the network must change NOTHING about the threat set,
    which is the precise meaning of 'the analysis path makes no network
    calls': the network is simply never on the path.
    """
    online = analyze(_build_system())
    online_ids = sorted(t.id for t in online.threats)

    monkeypatch.setattr(
        socket, "socket",
        lambda *a, **k: (_ for _ in ()).throw(_NetworkUsedError("socket")),
    )
    monkeypatch.setattr(
        socket, "create_connection",
        lambda *a, **k: (_ for _ in ()).throw(_NetworkUsedError("create_connection")),
    )
    offline = analyze(_build_system())
    offline_ids = sorted(t.id for t in offline.threats)

    assert offline_ids == online_ids, (
        "offline and online threat sets differ; symmetric difference: "
        f"{set(offline_ids) ^ set(online_ids)}"
    )


def test_monkeypatch_actually_blocks_network(monkeypatch):
    """Guard the guard: confirm the socket monkeypatch genuinely raises,
    so the offline tests above can't pass vacuously (e.g. if a future
    refactor made the patch a no-op)."""
    monkeypatch.setattr(socket, "socket", lambda *a, **k: (_ for _ in ()).throw(_NetworkUsedError("x")))
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(_NetworkUsedError("x")))
    with pytest.raises(_NetworkUsedError):
        socket.socket()
    with pytest.raises(_NetworkUsedError):
        socket.create_connection(("example.com", 80))
