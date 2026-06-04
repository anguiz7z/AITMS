"""FAIR-lite quantitative-risk engine (v0.13).

Translates each threat's qualitative likelihood (1..5) and impact (1..5)
into a defensible **annual loss expectancy (ALE)** range:

    ALE_low  = freq_low(L)  * loss_low(I)
    ALE_high = freq_high(L) * loss_high(I)

Frequency is derived from likelihood using a calibrated default table:

    L=1  → 0.05–0.20 events/year   (rare)
    L=2  → 0.20–1.0
    L=3  → 1.0–5.0                 (annual+)
    L=4  → 5.0–20.0
    L=5  → 20.0–100.0              (weekly+)

Loss magnitude is derived from impact using calibrated dollar ranges:

    I=1  → $1k    – $10k
    I=2  → $10k   – $100k
    I=3  → $100k  – $1M
    I=4  → $1M    – $10M
    I=5  → $10M   – $100M

Authors can override any threat's range explicitly by setting
``Threat.loss_low`` / ``loss_high`` / ``freq_low`` / ``freq_high``
before this engine runs (in a custom playbook for example).

This is a deliberately wide range — FAIR practitioners use Monte-Carlo
to narrow the cone, but a 1-OOM cone is enough for a board-level
top-10 conversation.
"""

from __future__ import annotations

from ..models import System, Threat

_FREQ_BY_LIKELIHOOD: dict[int, tuple[float, float]] = {
    1: (0.05, 0.20),
    2: (0.20, 1.0),
    3: (1.0, 5.0),
    4: (5.0, 20.0),
    5: (20.0, 100.0),
}

_LOSS_BY_IMPACT: dict[int, tuple[float, float]] = {
    1: (1_000, 10_000),
    2: (10_000, 100_000),
    3: (100_000, 1_000_000),
    4: (1_000_000, 10_000_000),
    5: (10_000_000, 100_000_000),
}


def score_quantitative(threats: list[Threat], system: System | None = None) -> list[Threat]:
    """Populate freq / loss / ALE fields per threat.

    Author overrides: if the author set EITHER ``freq_low`` or
    ``freq_high`` (asymmetric override), the missing side is derived
    from the same likelihood-bucket value, then any zero side is
    replaced. The naive ``a == 0 and b == 0`` check used in v0.14.0
    silently undid asymmetric overrides like ``freq_low=10,
    freq_high=0``.

    v0.16.1 — when ``system`` is provided, look up the scale-aware tier
    from ``kb/priors/loss_priors.yaml`` keyed on
    ``(system.industry × system.revenue_bucket × system.deployment_stage)``.
    The tier's ``loss_high_default`` caps the threat's loss_high (so a
    POC at a fintech can't be stamped with a $1B ALE); the tier's
    ``frequency_multiplier`` scales freq. Author overrides on Threat
    still win. Without a system or with the catchall tier, behaviour
    is the same as v0.15.1.
    """
    tier: dict = {}
    if system is not None:
        from ..kb import get_kb
        kb = get_kb()
        tier = kb.lookup_loss_prior(
            industry=getattr(system, "industry", None),
            revenue_bucket=getattr(system, "revenue_bucket", None),
            deployment_stage=getattr(system, "deployment_stage", None),
        )
    tier_loss_high_cap = tier.get("loss_high_default")
    tier_loss_low_floor = tier.get("loss_low_default")
    tier_freq_mult = float(tier.get("frequency_multiplier", 1.0))
    # v0.16.9 (Bug-004): hard freq ceiling per tier. Without this, a POC
    # tier with loss_high=$5M would still produce 20-events/yr ×$5M =
    # $100M/threat ALE, which compounds to ~$200M portfolio on a single
    # LLM POC — exactly the "$10B-on-a-POC defect" the priors were meant
    # to prevent. Tiers can set `freq_high_cap` explicitly; if absent and
    # the multiplier is <=0.2 (a "POC/pilot" signal), apply an implicit
    # cap of 2 events/year.
    tier_freq_high_cap = tier.get("freq_high_cap")
    if tier_freq_high_cap is None and tier_freq_mult <= 0.2:
        tier_freq_high_cap = 2.0

    # v0.16.2 — PII floor. Threats that explicitly touch PII / personal
    # data have a regulator-driven floor (per IBM CoDB 2025 average
    # per-record cost). Lower bound below this is indefensible to an
    # auditor.
    PII_LOSS_FLOOR_LOW = 50_000
    PII_LOSS_FLOOR_HIGH = 500_000

    for t in threats:
        # Frequency (apply tier multiplier to the baseline defaults)
        default_lo, default_hi = _FREQ_BY_LIKELIHOOD.get(t.likelihood, (1.0, 5.0))
        default_lo *= tier_freq_mult
        default_hi *= tier_freq_mult
        # v0.16.9 (Bug-004): apply tier frequency-high cap. Keeps POC/pilot
        # tiers from inflating per-threat ALE via the L=5 base of 100/yr.
        if tier_freq_high_cap is not None:
            default_hi = min(default_hi, float(tier_freq_high_cap))
            default_lo = min(default_lo, default_hi)
        if t.freq_low == 0 and t.freq_high == 0:
            t.freq_low, t.freq_high = default_lo, default_hi
        else:
            if t.freq_low == 0:
                t.freq_low = min(default_lo, t.freq_high)
            if t.freq_high == 0:
                t.freq_high = max(default_hi, t.freq_low)
            # Also clamp author-supplied freq_high to tier cap.
            if tier_freq_high_cap is not None:
                t.freq_high = min(t.freq_high, float(tier_freq_high_cap))
                t.freq_low = min(t.freq_low, t.freq_high)
        # Loss (apply tier cap + floor to the baseline range)
        default_lo_l, default_hi_l = _LOSS_BY_IMPACT.get(t.impact, (100_000, 1_000_000))
        if tier_loss_high_cap is not None and tier_loss_low_floor is not None:
            tier_lo = float(tier_loss_low_floor)
            tier_hi = float(tier_loss_high_cap)
            # If the impact-bucket's natural range is entirely above the
            # tier's cap (e.g. tier-1 bank POC, where impact=5 implies
            # $10M-$100M but the tier caps at $5M), substitute the
            # tier's range directly. Without this, the range collapses
            # to a degenerate single point.
            if default_lo_l > tier_hi:
                default_lo_l = tier_lo
                default_hi_l = tier_hi
            else:
                # Otherwise: cap the high end, keep the natural low end
                # (but not below the tier floor when the floor is
                # within the natural range).
                default_hi_l = min(default_hi_l, tier_hi)
                if tier_lo > default_lo_l and tier_lo < default_hi_l:
                    # Tier floor lies inside the natural range — promote
                    # to the floor (the tier knows this magnitude class
                    # better than the generic impact bucket).
                    default_lo_l = tier_lo
                else:
                    default_lo_l = min(default_lo_l, default_hi_l)
        if t.loss_low == 0 and t.loss_high == 0:
            t.loss_low, t.loss_high = default_lo_l, default_hi_l
        else:
            if t.loss_low == 0:
                t.loss_low = min(default_lo_l, t.loss_high)
            if t.loss_high == 0:
                t.loss_high = max(default_hi_l, t.loss_low)

        # v0.16.2 — Apply PII floor on threats with a clear PII / privacy
        # angle. We detect this via LINDDUN tags or any framework ID
        # implying data subject impact. PER-RECORD costs (IBM CoDB 2025:
        # $160-$166/record avg, $4.4M avg breach) make sub-$50K loss
        # claims indefensible to a regulator.
        touches_pii = bool(t.linddun) or any(
            "personally_identifiable" in (n or "").lower() or "pii" in (n or "").lower()
            for n in (t.nist_ai_100_2 or [])
        )
        if touches_pii:
            t.loss_low = max(t.loss_low, PII_LOSS_FLOOR_LOW)
            t.loss_high = max(t.loss_high, PII_LOSS_FLOOR_HIGH)

        # Final ALE
        t.ale_low = round(t.freq_low * t.loss_low, 2)
        t.ale_high = round(t.freq_high * t.loss_high, 2)
    return threats


def portfolio_ale(threats: list[Threat]) -> dict:
    """Aggregate the threat-model's annual loss expectancy."""
    total_low = sum(t.ale_low for t in threats)
    total_high = sum(t.ale_high for t in threats)
    # Top contributors by midpoint
    top = sorted(
        threats,
        key=lambda t: (t.ale_low + t.ale_high) / 2,
        reverse=True,
    )[:5]
    return {
        "ale_low_total": round(total_low, 2),
        "ale_high_total": round(total_high, 2),
        "top_contributors": [
            {
                "id": t.id,
                "title": t.title,
                "ale_low": t.ale_low,
                "ale_high": t.ale_high,
                "severity": t.severity,
            }
            for t in top
        ],
    }


__all__ = ["score_quantitative", "portfolio_ale", "_FREQ_BY_LIKELIHOOD", "_LOSS_BY_IMPACT"]
