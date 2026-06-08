"""Mitigation-roadmap export (v0.18.23 Cycle MM).

The HTML report already shows a "Recommended roadmap" table — the
top-N mitigations ranked by priority. But that's locked inside the
report; people who want to TURN those into a project plan (epic +
tickets, Confluence wiki page, GitHub issue list, Notion DB) need a
clean exportable artefact.

This module produces two:
  - **roadmap.md** — Markdown with checkboxes, severity callouts,
    grouped by control_family, ready to paste into Confluence /
    Notion / GitHub issues.
  - **roadmap.json** — JSON array of task objects suitable for
    pipeline-driven ticket creation:
        [{
          "rank": 1,
          "mitigation_id": "M_...",
          "title": "...",
          "family": "...",
          "effort": "medium",
          "risk_reduction": 4,
          "automatable": true,
          "d3fend": ["D3-NTA"],
          "validation_test": "...",
          "addresses_threats": ["t1.T_001", ...],
          "frameworks": ["NIST_800_53:AC-3"],
          "ai_relevance": "core"
        }]

Both renderers are pure-stdlib (no template engine for the JSON, just
`json.dumps`; the Markdown is hand-formatted for stability).
"""

from __future__ import annotations

import json

from ..models import Mitigation, ThreatModel


def _top_mitigations(model: ThreatModel, top_n: int | None = None) -> list[Mitigation]:
    """Return the priority-ordered mitigation list.

    The workflow exposes the ranked IDs via
    `summary["priority_mitigation_ids"]`. We look up the full objects
    and fall back to `model.mitigations` if the summary wasn't built
    (e.g. older runs)."""
    pri = model.summary.get("priority_mitigation_ids") if model.summary else []
    by_id = {m.id: m for m in model.mitigations}
    if pri:
        ordered = [by_id[mid] for mid in pri if mid in by_id]
    else:
        ordered = list(model.mitigations)
    if top_n is not None:
        ordered = ordered[:top_n]
    return ordered


def _addressed_severities(mitigation: Mitigation, model: ThreatModel) -> dict[str, int]:
    """Count the severity buckets across the threats this mitigation
    addresses. Used to bias the roadmap callouts."""
    threat_by_id = {t.id: t for t in model.threats}
    counts: dict[str, int] = {}
    for tid in mitigation.addresses_threat_ids:
        t = threat_by_id.get(tid)
        if t:
            counts[t.severity] = counts.get(t.severity, 0) + 1
    return counts


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def render_roadmap_md(model: ThreatModel, top_n: int | None = None) -> str:
    """Render the priority mitigation roadmap as Markdown.

    Groups by `control_family`; within each family, ranks by the
    workflow's already-computed priority order. Includes effort,
    risk-reduction, validation-test, and threat-count callouts."""
    top = _top_mitigations(model, top_n=top_n)
    sys_name = model.system.name
    out: list[str] = []
    out.append(f"# Mitigation roadmap — {sys_name}")
    out.append("")
    out.append(f"Generated from {len(model.threats)} threats. "
                f"Showing {len(top)} prioritised mitigations.")
    out.append("")
    out.append("> Each item is a single action with an explicit owner-friendly "
                "validation test. Tick the box when verified in production.")
    out.append("")

    # Group by control_family, but preserve the priority-ordered position.
    families: dict[str, list[tuple[int, Mitigation]]] = {}
    for i, m in enumerate(top, start=1):
        fam = m.control_family or "other"
        families.setdefault(fam, []).append((i, m))

    for family in sorted(families.keys()):
        out.append(f"## {family.title()}")
        out.append("")
        for rank, m in families[family]:
            sev_counts = _addressed_severities(m, model)
            top_sev = max(sev_counts, key=sev_counts.get, default=None)
            sev_badge = f"_{top_sev}_" if top_sev else ""
            auto_badge = " ⚙️ auto" if m.automatable else ""
            out.append(f"### {rank}. {m.title} `{m.id}`{auto_badge}")
            out.append("")
            out.append(f"- [ ] **Effort:** {m.effort}   "
                        f"**Risk reduction:** {m.risk_reduction}/5   "
                        f"**Addresses:** {len(m.addresses_threat_ids)} threats {sev_badge}")
            if m.validation_test:
                out.append(f"- **Validation test:** {m.validation_test}")
            if m.d3fend:
                out.append("- **MITRE D3FEND:** " + ", ".join(f"`{d}`" for d in m.d3fend))
            if m.framework_refs:
                out.append("- **Framework refs:** " + ", ".join(f"`{r}`" for r in m.framework_refs))
            if m.addresses_threat_ids:
                # Show up to 5 threat IDs.
                shown = m.addresses_threat_ids[:5]
                tail = ""
                if len(m.addresses_threat_ids) > 5:
                    tail = f" _(+{len(m.addresses_threat_ids) - 5} more)_"
                out.append("- **Threats addressed:** "
                            + ", ".join(f"`{t}`" for t in shown) + tail)
            out.append("")
        out.append("")

    out.append("---")
    out.append("_Generated by ATMS._")
    return "\n".join(out).rstrip() + "\n"


def render_roadmap_json(model: ThreatModel, top_n: int | None = None) -> str:
    """Render the same roadmap as a JSON array of task records.
    Suitable for piping into ticket-creation scripts."""
    top = _top_mitigations(model, top_n=top_n)
    threat_by_id = {t.id: t for t in model.threats}
    tasks = []
    for rank, m in enumerate(top, start=1):
        sev_counts = _addressed_severities(m, model)
        # audit F017: label a mitigation by the MOST-SEVERE severity it
        # addresses, not the most FREQUENT -- a fix that closes one critical
        # plus five lows is a critical-priority task, not a low one.
        _sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        top_sev = max(sev_counts, key=lambda s: _sev_rank.get(s, 0), default=None)
        # ai_relevance: take the mode across addressed threats.
        relevances = []
        for tid in m.addresses_threat_ids:
            t = threat_by_id.get(tid)
            if t and getattr(t, "ai_relevance", None):
                relevances.append(t.ai_relevance)
        ai_rel = max(set(relevances), key=relevances.count) if relevances else None
        tasks.append({
            "rank": rank,
            "mitigation_id": m.id,
            "title": m.title,
            "family": m.control_family or "other",
            "effort": m.effort,
            "risk_reduction": m.risk_reduction,
            "automatable": m.automatable,
            "d3fend": list(m.d3fend),
            "validation_test": m.validation_test,
            "addresses_threats": list(m.addresses_threat_ids),
            "frameworks": list(m.framework_refs),
            "top_addressed_severity": top_sev,
            "addressed_severities": sev_counts,
            "ai_relevance": ai_rel,
        })
    return json.dumps({"system": model.system.name, "tasks": tasks}, indent=2, ensure_ascii=False)


__all__ = ["render_roadmap_md", "render_roadmap_json"]
