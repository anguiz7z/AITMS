"""CSA Capabilities-Based Risk Assessment (CBRA).

System Risk = Criticality x Autonomy x Access-Permissions x Impact-Radius —
a multiplicative, capability-driven score from the CSA AI Safety Initiative's
Capabilities-Based Risk Assessment (CBRA, 2025-11). This COMPLEMENTS the
per-threat DREAD-AI score (Likelihood x Impact) with a per-system / per-agent
*capability* assessment: how much damage the AI is structurally able to do,
independent of any single threat. Deterministic, no LLM; every dimension traces
to a real model field, mirroring the honesty discipline in csa_risk_register.py.

Each dimension is a 1-4 anchor scale; the product (1-256) maps to a tier:
  <=16 Low  ·  17-64 Medium  ·  >64 High
"""

from __future__ import annotations

from ..models import Component, System

_TIER_CUTS = ((16, "Low"), (64, "Medium"), (10**9, "High"))


def _to_int(v: object) -> int:
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _criticality(system: System) -> tuple[int, str]:
    ctx = ((system.business_context or "") + " " + (system.criticality or "")).lower()
    classes = {df.data_classification for df in system.dataflows}
    if "restricted" in classes or any(
        k in ctx for k in ("safety", "life-", "medical", "health", "critical infrastructure", "ot", "safety-critical")
    ):
        return 4, "safety-critical or restricted data"
    if "confidential" in classes or any(
        k in ctx for k in ("financial", "payment", "pii", "personal", "investment", "portfolio", "fraud")
    ):
        return 3, "financial / PII / confidential data"
    if "internal" in classes:
        return 2, "internal-only data"
    return 1, "public / low-criticality"


def _autonomy(system: System) -> tuple[int, str]:
    agents = [c for c in system.components if c.type == "agent"]
    if not agents:
        return 1, "no autonomous agent in scope"
    levels = {"none": 1, "assisted": 2, "supervised": 2, "autonomous": 4}
    declared = [levels[a.autonomy_level.lower()] for a in agents if a.autonomy_level.lower() in levels]
    if declared:
        return max(declared), "declared agent autonomy_level"
    hitl = any(
        any(c in (a.controls or []) for c in ("human_in_the_loop", "hitl", "human_review"))
        for a in agents
    )
    max_tools = max((_to_int(a.metadata.get("tool_count", 0)) for a in agents), default=0)
    if hitl:
        return 2, "agent with human-in-the-loop"
    if max_tools >= 5:
        return 4, f"agent with broad tool autonomy ({max_tools} tools), no HITL"
    return 3, "agent with limited tools, no HITL"


def _permissions(system: System) -> tuple[int, str]:
    tool_count = sum(_to_int(c.metadata.get("tool_count", 0)) for c in system.components)
    scopes = " ".join(str(c.metadata.get("tool_scope", "")) for c in system.components).lower()
    writes = any(
        c.type in ("database", "nosql_database", "object_storage", "batch_compute", "cloud_compute", "serverless_function")
        for c in system.components
    )
    if any(k in scopes for k in ("admin", "write", "delete", "*", "broad")) or tool_count >= 5:
        return 4, "broad / write / admin tool surface"
    if writes or tool_count >= 2:
        return 3, "write access to data or compute"
    if tool_count >= 1:
        return 2, "limited tool access"
    return 1, "read-only / no tools"


def _impact_radius(system: System) -> tuple[int, str]:
    try:
        from .ai_scope import compute_ai_blast_radius

        radius = compute_ai_blast_radius(system) or {}
        reachable = len({c for v in radius.values() for c in (v or [])})
    except Exception:
        reachable = 0
    total = len(system.components) or 1
    frac = reachable / total
    if frac >= 0.66:
        return 4, f"AI blast radius reaches {reachable}/{total} components"
    if frac >= 0.33:
        return 3, f"AI blast radius reaches {reachable}/{total} components"
    if reachable >= 1:
        return 2, f"AI blast radius reaches {reachable}/{total} components"
    return 1, "AI is well isolated"


def compute_cbra(system: System) -> dict:
    """Return the CBRA capabilities-based risk score + tier for a system."""
    dims = {
        "criticality": _criticality(system),
        "autonomy": _autonomy(system),
        "access_permissions": _permissions(system),
        "impact_radius": _impact_radius(system),
    }
    score = 1
    for v, _ in dims.values():
        score *= v
    tier = next(t for cut, t in _TIER_CUTS if score <= cut)
    return {
        "method": "CSA Capabilities-Based Risk Assessment (CBRA)",
        "formula": "Criticality x Autonomy x Access-Permissions x Impact-Radius (each 1-4)",
        "score": score,
        "max_score": 256,
        "tier": tier,
        "tier_bands": "<=16 Low | 17-64 Medium | >64 High",
        "dimensions": {k: {"value": v, "rationale": why} for k, (v, why) in dims.items()},
        "source": "CSA AI Safety Initiative — Capabilities-Based Risk Assessment (2025-11)",
    }
