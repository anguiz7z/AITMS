"""JIRA-compatible backlog export (v0.18.17 Cycle GG).

Renders ATMS threats as JIRA-importable artefacts so security
findings can flow directly into the engineering backlog:

  - **JIRA CSV** — Atlassian's `External System Import` accepts CSV
    with named columns (`Summary`, `Description`, `Issue Type`,
    `Priority`, `Labels`, `Component/s`, `External ID`, …) and a
    user-defined mapping at import time. Most enterprises use this
    path because it works offline + air-gapped.
  - **JIRA JSON** — REST-API-friendly bulk-create payload (one
    `{"fields": …}` object per threat) so CI/CD pipelines using
    `curl POST /rest/api/3/issue/bulk` don't need an intermediate
    spreadsheet.

Severity → Priority mapping follows the JIRA default priority list:

    ATMS severity   JIRA Priority
    ─────────────   ─────────────
    critical        Highest
    high            High
    medium          Medium
    low             Low
    info            Lowest

Disposition → Status mapping (best-effort — JIRA workflows are
configurable, but these names are the defaults that ship with most
schemes):

    ATMS disposition                    JIRA Status
    ────────────────────────────────    ───────────
    open                                Open
    mitigated                           Done
    accepted                            Won't Do
    accepted_with_compensating_control  Won't Do
    transferred                         Won't Do
    false_positive                      Closed
    duplicate                           Closed
    deferred                            Backlog

Both renderers are pure-stdlib (csv + json). No new deps.
"""

from __future__ import annotations

import csv
import io
import json

from ..models import ThreatModel
from .csv_export import safe_csv_writer  # audit F047: formula-injection-safe CSV

# Severity → JIRA priority.
_PRIORITY_MAP = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

# Disposition → JIRA status (matches most-common workflow schemes).
_STATUS_MAP = {
    "open": "Open",
    "mitigated": "Done",
    "accepted": "Won't Do",
    "accepted_with_compensating_control": "Won't Do",
    "transferred": "Won't Do",
    "false_positive": "Closed",
    "duplicate": "Closed",
    "deferred": "Backlog",
}


def _sanitise_label(s: str) -> str:
    """JIRA labels can't contain whitespace; replace with `_`.
    Strip everything that isn't alnum, dash, dot, underscore."""
    out = []
    for ch in s:
        if ch.isalnum() or ch in "-._:":
            out.append(ch)
        elif ch.isspace():
            out.append("_")
    return "".join(out)[:64] or "atms"


def _build_labels(threat) -> list[str]:
    """Collect labels for a JIRA issue from a threat.

    Source priority:
      - `atms-threat` (always — discoverable by JQL `labels = atms-threat`)
      - `severity:<bucket>` (always)
      - `framework:<ref>` per reference (e.g. ATLAS-AML.T0049 → framework:ATLAS-AML.T0049)
      - `stride:<row>` per stride_ai entry
      - `kill-chain:<phase>` if set
    """
    labels = ["atms-threat", f"severity:{threat.severity}"]
    for ref in getattr(threat, "references", []) or []:
        labels.append(f"framework:{_sanitise_label(ref)}")
    for row in getattr(threat, "stride_ai", []) or []:
        labels.append(f"stride:{_sanitise_label(row)}")
    kc = getattr(threat, "kill_chain_phase", None)
    if kc:
        labels.append(f"kill-chain:{_sanitise_label(kc)}")
    # Dedup while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for lab in labels:
        if lab in seen:
            continue
        seen.add(lab)
        ordered.append(lab)
    return ordered


def _build_description(threat, model: ThreatModel) -> str:
    """Build a JIRA-friendly description that includes the threat
    narrative, recommended mitigations, and framework references.
    Uses JIRA's `*bold*` / bullet markup which renders in both v2
    and v3 wiki-markup-supporting fields."""
    parts: list[str] = []
    if threat.description:
        parts.append(threat.description.strip())
    parts.append("")
    parts.append(f"*Component:* {threat.component_name or threat.component_id}")
    parts.append(
        # audit F015: risk_score is a 0-100 DREAD-AI score (exec summary +
        # Navigator use /100); the '/25' label rendered every ticket as e.g.
        # '90/25' (=360%). Correct the denominator.
        f"*Risk score:* {threat.risk_score}/100  "
        f"(likelihood {threat.likelihood}, impact {threat.impact})"
    )
    if getattr(threat, "kill_chain_phase", None):
        parts.append(f"*Kill chain phase:* {threat.kill_chain_phase}")
    if getattr(threat, "references", None):
        parts.append("*Framework references:*")
        for ref in threat.references:
            parts.append(f"  * {ref}")
    # Recommended mitigations linked to this threat.
    mitigations = [
        m for m in model.mitigations
        if threat.id in (getattr(m, "addresses_threat_ids", []) or [])
    ]
    if mitigations:
        parts.append("*Recommended mitigations:*")
        for m in mitigations[:10]:
            effort = getattr(m, "effort", "") or ""
            reduction = getattr(m, "risk_reduction", 0) or 0
            parts.append(
                f"  * [{m.id}] {m.title} "
                f"(effort: {effort}, risk-reduction: {reduction}/5)"
            )
    if getattr(threat, "ai_relevance", None):
        parts.append(f"*AI scope:* {threat.ai_relevance}")
    parts.append("")
    parts.append(f"_Generated by ATMS · threat id `{threat.id}`._")
    return "\n".join(parts)


def render_jira_csv(model: ThreatModel) -> str:
    """Render the threat register as JIRA-compatible CSV.

    Columns (order matters for JIRA's auto-mapping suggestions):
      Summary, Description, Issue Type, Priority, Status,
      Component/s, Labels, External ID

    Labels are emitted as a SEMICOLON-separated list because JIRA's
    CSV importer splits labels on `;` by default. Component/s are
    likewise `;`-separated to allow multi-component threats (though
    each ATMS threat is single-component today).
    """
    buf = io.StringIO()
    w = safe_csv_writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow([
        "Summary", "Description", "Issue Type", "Priority", "Status",
        "Component/s", "Labels", "External ID",
    ])
    for t in model.threats:
        priority = _PRIORITY_MAP.get(t.severity, "Medium")
        status = _STATUS_MAP.get(getattr(t, "disposition", "open") or "open", "Open")
        component = (t.component_name or t.component_id or "").strip()
        labels = ";".join(_build_labels(t))
        # JIRA summary length limit is 255 chars; truncate defensively.
        summary = (t.title or t.id)[:250]
        w.writerow([
            summary,
            _build_description(t, model),
            "Risk",
            priority,
            status,
            component,
            labels,
            t.id,
        ])
    return buf.getvalue()


def render_jira_json(model: ThreatModel, project_key: str = "SEC") -> str:
    """Render the threat register as a JIRA REST bulk-create payload.

    The output is suitable for:
        curl -u user:token \\
             -H 'Content-Type: application/json' \\
             -X POST <jira>/rest/api/3/issue/bulk \\
             -d @threats.jira.json

    Args:
        model: ThreatModel to export.
        project_key: JIRA project key for all created issues
            (default: "SEC"). Override at render time per project.
    """
    issues = []
    for t in model.threats:
        priority = _PRIORITY_MAP.get(t.severity, "Medium")
        component = (t.component_name or t.component_id or "").strip()
        labels = _build_labels(t)
        summary = (t.title or t.id)[:250]
        fields: dict = {
            "project": {"key": project_key},
            "summary": summary,
            "description": _build_description(t, model),
            "issuetype": {"name": "Risk"},
            "priority": {"name": priority},
            "labels": labels,
        }
        if component:
            fields["components"] = [{"name": component}]
        issues.append({"fields": fields})
    return json.dumps({"issueUpdates": issues}, indent=2, ensure_ascii=False)


__all__ = ["render_jira_csv", "render_jira_json"]
