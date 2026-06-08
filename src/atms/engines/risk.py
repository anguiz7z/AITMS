"""DREAD-AI scoring + 5x5 risk matrix.

Adapted from classic DREAD with AI-specific weighting:
  - Damage:        model integrity loss, training-data PII exposure, agentic blast radius
  - Reproducibility: how reliably the attack works
  - Exploitability:  effort/skill required
  - Affected users:  single-tenant vs multi-tenant
  - Discoverability: how easily an attacker finds the vulnerability

For workflow-mode ATMS we derive D/R/E/A/D from the playbook's likelihood + impact
when not otherwise specified, plus heuristics on component type. The output is a
0-100 score and a 5x5 severity bucket.
"""

from __future__ import annotations

from ..models import Component, Threat

# Indexed [likelihood][impact] with 1-based access; row 0 unused but kept so we
# can use natural 1..5 indices.
SEVERITY_MATRIX = [
    ["info", "info", "low", "low", "medium"],            # row 0 (unused)
    ["info", "low", "low", "medium", "medium"],          # likelihood=1
    ["low", "low", "medium", "medium", "high"],          # likelihood=2
    ["low", "medium", "medium", "high", "high"],         # likelihood=3
    ["medium", "medium", "high", "high", "critical"],    # likelihood=4
    ["medium", "high", "high", "critical", "critical"],  # likelihood=5
]


def _severity_bucket(likelihood: int, impact: int) -> str:
    likelihood = max(1, min(5, int(likelihood)))
    impact = max(1, min(5, int(impact)))
    return SEVERITY_MATRIX[likelihood][impact - 1]


def _dread_ai_score(threat: Threat, comp: Component | None) -> float:
    """Compute a 0..100 DREAD-AI score from the threat's likelihood/impact + heuristics."""
    # Map likelihood → Reproducibility, Exploitability, Discoverability
    # Map impact → Damage, Affected users
    # Each on 1..5; total 5..25; rescale to 0..100.
    R = threat.likelihood
    E = threat.likelihood
    Dscore = threat.impact
    A = threat.impact
    Disc = threat.likelihood

    # Multi-tenant components have higher A
    if comp and comp.metadata.get("multi_tenant"):
        A = min(5, A + 1)
    # Components in trust_zone "internet" raise Discoverability
    if comp and comp.trust_zone == "internet":
        Disc = min(5, Disc + 1)
    # Agentic systems with broad tool surface raise Damage. Coerce tool_count
    # defensively (audit F052): a quoted YAML integer ('12') is a routine user
    # mistake that must not abort the whole analysis with a TypeError.
    try:
        _tool_count = int(comp.metadata.get("tool_count", 0)) if comp else 0
    except (TypeError, ValueError):
        _tool_count = 0
    if comp and comp.type == "agent" and _tool_count >= 5:
        Dscore = min(5, Dscore + 1)

    # v0.16.3 — tool-scope severity bump. Agents with explicit
    # write / admin tool scope have higher blast radius regardless of
    # how many tools they have. `metadata.tool_scope` accepts
    # 'read' / 'write' / 'admin' (single value or list).
    if comp and comp.type in ("agent", "mcp_server", "tool"):
        scope = comp.metadata.get("tool_scope", "")
        scope_list = scope if isinstance(scope, list) else [scope]
        scope_lower = {str(s).lower() for s in scope_list}
        if "admin" in scope_lower:
            Dscore = min(5, Dscore + 2)
            A = min(5, A + 1)
        elif "write" in scope_lower:
            Dscore = min(5, Dscore + 1)

    raw = R + E + Dscore + A + Disc
    return round((raw - 5) / 20 * 100, 1)


def score_threats(threats: list[Threat], components: list[Component]) -> list[Threat]:
    comp_by_id = {c.id: c for c in components}
    for t in threats:
        comp = comp_by_id.get(t.component_id)
        t.risk_score = _dread_ai_score(t, comp)
        # v0.16.1 — compute per-threat confidence from metadata richness +
        # framework coverage instead of hard-coding 0.95 (risk-assessment
        # expert finding R-5). The constant value made every threat look
        # equally confident, defeating triage.
        t.confidence = _compute_confidence(t, comp)
        # Effective severity: collapse high-risk low-confidence findings
        # so the report's CRITICAL bucket isn't 80%+ of every report
        # (risk-assessment expert finding M-06).
        effective = t.risk_score * t.confidence
        t.severity = _bucket_from_score(effective, t.likelihood, t.impact)  # type: ignore[assignment]
        # audit F064: display the confidence-weighted (effective) score as the
        # risk_score, so the number can never invert the severity ordering.
        # The raw DREAD score ignored confidence, so a low-confidence MEDIUM
        # could show a HIGHER risk_score than a high-confidence HIGH.
        t.risk_score = round(effective, 1)
    return threats


def recompute_risk_scores(threats: list[Threat], components: list[Component]) -> list[Threat]:
    """Recompute ONLY the numeric ``risk_score`` from each threat's current
    likelihood/impact.

    Used after evidence application (audit F040): ``apply_evidence`` mutates
    likelihood / severity / confidence in place but the qualitative
    ``risk_score`` was last computed in the pre-evidence pass, so a threat
    could render as ``likelihood=5 / severity=critical`` with a stale
    medium-band ``risk_score`` -- an internally contradictory row. This
    refreshes the numeric score WITHOUT re-bucketing ``severity`` (the
    evidence severity override is intentional -- see workflow step 3c), so the
    number stays consistent with the displayed coordinates.
    """
    comp_by_id = {c.id: c for c in components}
    for t in threats:
        # Keep risk_score == effective (confidence-weighted) score, consistent
        # with score_threats (audit F064), using the evidence-adjusted
        # likelihood/impact and confidence.
        comp = comp_by_id.get(t.component_id)
        t.risk_score = round(_dread_ai_score(t, comp) * t.confidence, 1)
    return threats


def _compute_confidence(threat: Threat, comp: Component | None) -> float:
    """Per-threat confidence on [0.4, 0.95].

    Designed to *differentiate*, not uniformly demote. A threat with no
    metadata but rich framework refs (the common case for a freshly-
    described system) keeps confidence near 0.80. A threat with rich
    metadata + frameworks climbs to 0.95. A generic stub or a framework-
    less threat drops below 0.70.

    Inputs:
      - Component metadata richness: vendor / product / version /
        hostname / ip / cpe / purl populated → +.
      - Framework coverage: at least one ATLAS / ATT&CK / OWASP / MAESTRO
        / NIST / LINDDUN ID → +.
      - Generic-stub penalty: threats tagged ``needs_review`` (no
        playbook matched the type) get demoted.
    """
    # v0.16.9 (Bug-006): previously short-circuited to 0.6 when comp was
    # None, bypassing the `needs_review` demotion. Now we treat a missing
    # component the same as zero-metadata and still apply the framework /
    # stub penalties — so a needs_review stub on a missing component
    # correctly lands at < 0.45.
    rich_keys = ("vendor", "product", "version", "hostname", "ip", "fqdn", "cpe", "purl", "cidr")
    md = (comp.metadata or {}) if comp is not None else {}
    populated = sum(1 for k in rich_keys if md.get(k))
    # Base 0.80 with no metadata; +0.03 per populated key up to +0.15.
    metadata_bonus = 0.03 * min(5, populated)

    has_frameworks = bool(
        threat.atlas_techniques
        or threat.attack_cloud
        or threat.attack_enterprise
        or threat.owasp_llm
        or threat.owasp_agentic
        or threat.owasp_api
        or threat.maestro_threats
        or threat.maestro_layers
        or threat.nist_ai_100_2
        or threat.nist_ai_rmf
        or threat.linddun
        or threat.owasp_ml
    )
    framework_penalty = 0.0 if has_frameworks else -0.20

    # Generic stubs fire only because no playbook matched. Explicit
    # low-confidence so a reviewer treats them as low-priority.
    is_generic_stub = "needs_review" in (threat.references or [])
    generic_penalty = -0.30 if is_generic_stub else 0.0

    score = 0.80 + metadata_bonus + framework_penalty + generic_penalty
    return round(min(0.95, max(0.4, score)), 2)


def _bucket_from_score(effective_score: float, likelihood: int, impact: int) -> str:
    """Map an effective_score (risk_score × confidence) to a severity bucket.

    For tight backwards compatibility with the 5×5 matrix, we keep the
    matrix bucket as a floor and only DEMOTE based on effective score —
    we never promote. A high-likelihood, high-impact threat whose
    confidence is 0.4 still gets demoted; a high-confidence threat in
    the matrix's HIGH bucket cannot be promoted to CRITICAL just by
    high confidence.
    """
    matrix_bucket = _severity_bucket(likelihood, impact)
    # Effective-score thresholds (calibrated against the matrix's
    # natural bucket cut-offs: ~50/65/85 for medium/high/critical
    # in the existing scoring).
    if effective_score >= 80:
        score_bucket = "critical"
    elif effective_score >= 60:
        score_bucket = "high"
    elif effective_score >= 35:
        score_bucket = "medium"
    elif effective_score >= 15:
        score_bucket = "low"
    else:
        score_bucket = "info"

    # Take the LOWER of the two (most conservative). This caps the
    # severity by both the matrix AND the confidence-weighted score.
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if rank[score_bucket] < rank[matrix_bucket]:
        return score_bucket
    return matrix_bucket


def risk_matrix_counts(threats: list[Threat]) -> list[list[int]]:
    """Return a 5x5 matrix of threat counts, indexed [likelihood-1][impact-1]."""
    matrix = [[0 for _ in range(5)] for _ in range(5)]
    for t in threats:
        l = max(1, min(5, t.likelihood))  # noqa: E741
        i = max(1, min(5, t.impact))
        matrix[l - 1][i - 1] += 1
    return matrix
