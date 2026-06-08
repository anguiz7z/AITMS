"""Risk-engine consistency regressions (audit F052/F064)."""

from __future__ import annotations

import yaml

from atms.models import System
from atms.workflow import analyze

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def test_quoted_tool_count_does_not_crash():
    """F052: a quoted YAML integer in metadata.tool_count ('12') is a routine
    user mistake that must not abort analyze with a TypeError."""
    s = System(**yaml.safe_load(
        "name: S\n"
        "components:\n"
        "  - {id: a1, name: Orch, type: agent, trust_zone: internet, metadata: {tool_count: \"12\"}}\n"
        "  - {id: l1, name: LLM, type: llm_inference}\n"
        "dataflows: [{source: a1, target: l1}]\n"
    ))
    tm = analyze(s)  # must not raise
    assert tm.threats


def test_risk_score_never_inverts_severity():
    """F064: the displayed risk_score must never rank a lower-severity threat
    above a higher-severity one (it is now the confidence-weighted score that
    also drives severity)."""
    for sample in ("enterprise_rag_agent.yaml", "rag_system.yaml", "chatbot.yaml"):
        tm = analyze(System.model_validate(
            yaml.safe_load(open(f"samples/{sample}", encoding="utf-8"))
        ))
        ths = tm.threats
        for a in ths:
            for b in ths:
                if _SEV_RANK[a.severity] < _SEV_RANK[b.severity]:
                    assert a.risk_score <= b.risk_score, (
                        f"{sample}: {a.severity} threat {a.id} (risk {a.risk_score}) "
                        f"outranks {b.severity} threat {b.id} (risk {b.risk_score})"
                    )
