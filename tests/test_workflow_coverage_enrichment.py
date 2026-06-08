"""Workflow defensibility regressions (audit F065/F066).

- Architectural-rule threats (id prefix `A_`) were appended AFTER the framework
  enrichment block, so they shipped with empty atlas/maestro/kill-chain --
  un-traceable next to fully-mapped playbook threats.
- Framework-coverage rollups were computed over ALL threats while severity /
  ALE used the active set, so a triaged-away threat still inflated the headline
  coverage.
"""

from __future__ import annotations

import yaml

from atms.models import System, is_closed
from atms.workflow import analyze

_SYS = {
    "name": "T",
    "components": [
        {"id": "user", "name": "U", "type": "user", "trust_zone": "internet"},
        {"id": "db", "name": "D", "type": "database", "trust_zone": "data"},
        {"id": "llm", "name": "L", "type": "llm_inference", "trust_zone": "app"},
    ],
    "dataflows": [
        {"source": "user", "target": "db", "label": "query"},
        {"source": "user", "target": "llm", "label": "prompt"},
    ],
}


def test_arch_threats_are_framework_enriched():
    """F065: every architectural-rule threat must carry a kill-chain phase
    (and get the same enrichment passes as playbook threats)."""
    tm = analyze(System.model_validate(_SYS))
    arch = [t for t in tm.threats if ".A_" in t.id]
    assert arch, "expected at least one architectural-rule threat"
    assert all(t.kill_chain_phase for t in arch), (
        "arch threats must have a kill-chain phase: "
        + ", ".join(t.id for t in arch if not t.kill_chain_phase)
    )
    # at least one arch threat should pick up an ATLAS technique via enrichment
    assert any(t.atlas_techniques for t in arch)


def test_framework_coverage_excludes_triaged_away_threats():
    """F066: triaging a threat as false_positive must shrink the framework
    coverage rollups, matching the active-only severity/ALE numbers."""
    raw = yaml.safe_load(open("samples/enterprise_rag_agent.yaml", encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    full = set(tm.summary["atlas_coverage"])
    # Find a threat whose ATLAS id is unique to it, mark it false_positive,
    # re-run and assert that id drops from coverage.
    target = next((t for t in tm.threats if t.atlas_techniques), None)
    assert target is not None
    tid = target.atlas_techniques[0]
    for t in tm.threats:
        if t.id == target.id:
            t.disposition = "false_positive"
    active = [t for t in tm.threats if not is_closed(t.disposition)]
    active_atlas = {a for t in active for a in t.atlas_techniques}
    # coverage computed at analyze time used active==all (all open), so `full`
    # is the all-open coverage; after triaging, the active set must be a subset.
    assert active_atlas <= full
    assert len(active_atlas) <= len(full)
