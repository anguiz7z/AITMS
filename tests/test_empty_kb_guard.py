"""Regression: analysis must FAIL LOUD on an empty/unresolved knowledge base.

Audit 2026-06 found a stale v1.0.4 global install whose bundled kb/ did not
resolve, so `atms analyze` silently produced a worthless threat model (generic
STRIDE stubs, 0/10 OWASP, 0 ATLAS, junk ALE) with no warning. The pipeline now
raises EmptyKnowledgeBaseError instead of emitting that junk.
"""

from __future__ import annotations

import pytest

from atms import workflow
from atms.kb import EmptyKnowledgeBaseError
from atms.models import Component, System


def test_analyze_raises_on_empty_kb(monkeypatch):
    """workflow.analyze must raise (not silently emit) when 0 playbooks load."""

    class _EmptyKB:
        playbooks: dict = {}

    monkeypatch.setattr(workflow, "get_kb", lambda: _EmptyKB())
    system = System(
        name="empty-kb-probe",
        components=[Component(id="llm", name="Claude inference", type="llm_inference")],
    )
    with pytest.raises(EmptyKnowledgeBaseError):
        workflow.analyze(system)


def test_loaded_kb_does_not_trip_the_guard():
    """The real bundled KB loads playbooks, so analysis proceeds normally."""
    from atms.kb import get_kb

    kb = get_kb()
    assert kb.playbooks, "bundled KB should load >0 playbooks from source"
    system = System(
        name="loaded-kb-probe",
        components=[Component(id="llm", name="Claude inference", type="llm_inference")],
    )
    model = workflow.analyze(system)  # must not raise
    assert model.threats, "a loaded KB should produce threats"
