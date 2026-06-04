"""Compliance-coverage matrix report (v0.18.15 Cycle EE).

Renders a per-framework matrix showing how the threats + mitigations
in a `ThreatModel` cover the controls of a given framework. Auditors
quote control IDs (NIST 800-53 AC-3, ISO 27001 A.9.4.2, PCI DSS 8.3.1,
…); this view inverts the threat → control mapping into a
control → threats view, which is the shape every coverage-gap
discussion uses.

Each row is one control:

    | ID | Framework | Title | Status | # Threats | Top sev | Threat IDs |

Status logic:
    "covered"   — ≥1 in-scope threat references the control (open or
                  mitigated)
    "mitigated" — ≥1 covered threat AND every covered threat has a
                  disposition that closes it (mitigated /
                  accepted_with_compensating_control / transferred)
    "uncovered" — 0 threats reference the control AND it is in scope
                  for the system (applies_to matches at least one
                  component)
    "not-applicable" — 0 threats reference the control AND it is NOT
                  in scope (no applies_to overlap) — suppresses noise

The renderer outputs HTML (rich, sortable visually) or CSV (for
auditor spreadsheets). Both are self-contained — no JS, no external
CSS — so the artefact can be emailed or attached to evidence
packages without losing rendering.

Pure-Python (string-formatted templates), zero new deps.
"""

from __future__ import annotations

import csv
import io
from collections import Counter
from collections.abc import Iterable

from ..kb import get_kb
from ..models import ThreatModel

# Dispositions that count a threat as "closed" for matrix purposes.
_CLOSED_DISPOSITIONS = frozenset({
    "mitigated", "accepted_with_compensating_control",
    "transferred", "false_positive", "duplicate",
})


def _esc(s: str) -> str:
    """Minimal HTML escape — re-implemented here to keep the module
    deps-free + auditable. Matches `reporting/exec_summary.py:_esc`."""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )


# ────────────────────────────────────────────────────────────────────
# Coverage computation
# ────────────────────────────────────────────────────────────────────

def compute_coverage(
    model: ThreatModel,
    framework: str | None = None,
) -> list[dict]:
    """Return a list of coverage rows for the model.

    Args:
        model: ThreatModel produced by `analyze()`.
        framework: Optional framework filter (e.g. "NIST_800_53").
            None returns rows for every framework.

    Returns:
        List of dicts, one per control. Sorted by:
          (1) status — covered/mitigated above uncovered above n/a
          (2) framework, then control id (stable)
    """
    kb = get_kb()
    controls = kb.compliance_controls or {}
    # Component types in the system → for in-scope determination.
    system_types = {c.type for c in model.system.components}

    # Index threats by control.
    threat_index: dict[str, list] = {}
    for t in model.threats:
        for cid in getattr(t, "compliance_controls", []) or []:
            threat_index.setdefault(cid, []).append(t)

    # Index mitigations by control (via threat → mitigation linkage).
    mitig_index: dict[str, list] = {}
    threat_to_mitigations: dict[str, list] = {}
    for m in model.mitigations:
        for tid in getattr(m, "addresses_threat_ids", []) or []:
            threat_to_mitigations.setdefault(tid, []).append(m)
    for cid, ts in threat_index.items():
        seen: set[str] = set()
        for t in ts:
            for m in threat_to_mitigations.get(t.id, []):
                if m.id in seen:
                    continue
                seen.add(m.id)
                mitig_index.setdefault(cid, []).append(m)

    rows: list[dict] = []
    for cid, ctrl in controls.items():
        if framework and ctrl.get("framework") != framework:
            continue
        applies = set(ctrl.get("applies_to") or [])
        in_scope = (not applies) or bool(applies & system_types)
        ts = threat_index.get(cid, [])
        if ts:
            # Closed if EVERY covered threat is in _CLOSED_DISPOSITIONS.
            all_closed = all(
                (t.disposition or "open") in _CLOSED_DISPOSITIONS for t in ts
            )
            status = "mitigated" if all_closed else "covered"
        else:
            status = "uncovered" if in_scope else "not-applicable"

        severities = [t.severity for t in ts]
        sev_order = ["critical", "high", "medium", "low", "info"]
        top_sev = next((s for s in sev_order if s in severities), None)
        threat_ids = sorted({t.id for t in ts})
        mitig_ids = sorted({m.id for m in mitig_index.get(cid, [])})

        rows.append({
            "control_id": cid,
            "framework": ctrl.get("framework", ""),
            "title": ctrl.get("title", ""),
            "description": ctrl.get("description", "")[:300],
            "status": status,
            "threat_count": len(ts),
            "top_severity": top_sev,
            "threat_ids": threat_ids,
            "mitigation_ids": mitig_ids,
            "applies_to": sorted(applies),
        })

    status_rank = {"covered": 0, "mitigated": 1, "uncovered": 2, "not-applicable": 3}
    rows.sort(key=lambda r: (status_rank.get(r["status"], 9), r["framework"], r["control_id"]))
    return rows


def coverage_summary(rows: Iterable[dict]) -> dict:
    """Return aggregate counts: total, covered, mitigated, uncovered,
    not-applicable, and per-framework breakdown."""
    rows = list(rows)
    statuses = Counter(r["status"] for r in rows)
    per_framework: dict[str, dict[str, int]] = {}
    for r in rows:
        fw = r["framework"]
        per_framework.setdefault(fw, {"covered": 0, "mitigated": 0, "uncovered": 0, "not-applicable": 0})
        per_framework[fw][r["status"]] += 1
    return {
        "total": len(rows),
        "covered": statuses.get("covered", 0),
        "mitigated": statuses.get("mitigated", 0),
        "uncovered": statuses.get("uncovered", 0),
        "not_applicable": statuses.get("not-applicable", 0),
        "frameworks": per_framework,
    }


# ────────────────────────────────────────────────────────────────────
# HTML renderer
# ────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Compliance coverage — {system_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 1200px; margin: 28px auto; padding: 0 24px;
         color: #0e1116; background: #ffffff; line-height: 1.5; }}
  h1 {{ font-size: 24px; margin: 0; }}
  h1 small {{ color: #6e7681; font-size: 14px; font-weight: 400; }}
  h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: 0.06em;
        color: #57606a; border-bottom: 1px solid #d0d7de; padding-bottom: 4px;
        margin-top: 24px; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
              gap: 12px; margin: 12px 0 20px 0; }}
  .summary .card {{ background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 8px;
                    padding: 10px 14px; }}
  .summary .card .k {{ font-size: 11px; color: #57606a; text-transform: uppercase; letter-spacing: 0.04em; }}
  .summary .card .v {{ font-size: 22px; font-weight: 600; margin-top: 2px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12px; }}
  th, td {{ border-bottom: 1px solid #d0d7de; padding: 6px 8px; text-align: left;
            vertical-align: top; }}
  th {{ background: #f6f8fa; font-weight: 600; }}
  td.center, th.center {{ text-align: center; }}
  .status {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px;
             text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; }}
  .status-covered      {{ background: #ddf4ff; color: #0969da; }}
  .status-mitigated    {{ background: #dafbe1; color: #1a7f37; }}
  .status-uncovered    {{ background: #ffebe9; color: #cf222e; }}
  .status-not-applicable {{ background: #eaeef2; color: #57606a; }}
  .sev {{ display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .sev-critical {{ background: #5a1f1f; color: #ffd1d6; }}
  .sev-high     {{ background: #ffebe9; color: #cf222e; }}
  .sev-medium   {{ background: #fff5cc; color: #b08800; }}
  .sev-low      {{ background: #ddf4ff; color: #0969da; }}
  .sev-info     {{ background: #eaeef2; color: #57606a; }}
  code, .mono {{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 11px; }}
  .muted {{ color: #6e7681; }}
  .filter-note {{ background: #fff8c5; border: 1px solid #d4a72c; border-radius: 6px;
                  padding: 8px 12px; margin: 10px 0; font-size: 13px; }}
</style>
</head>
<body>
<h1>Compliance coverage matrix <small>· {system_name}</small></h1>
<p class="muted">Threats in this analysis tagged against {framework_label} controls.
Generated by ATMS v{version}.</p>
{filter_block}
<div class="summary">
  <div class="card"><div class="k">Controls in scope</div><div class="v">{total}</div></div>
  <div class="card"><div class="k">Covered</div><div class="v" style="color:#0969da;">{covered}</div></div>
  <div class="card"><div class="k">Mitigated</div><div class="v" style="color:#1a7f37;">{mitigated}</div></div>
  <div class="card"><div class="k">Uncovered</div><div class="v" style="color:#cf222e;">{uncovered}</div></div>
  <div class="card"><div class="k">Not applicable</div><div class="v" style="color:#57606a;">{na}</div></div>
</div>

<h2>Coverage detail</h2>
<table>
  <thead>
    <tr>
      <th>Control</th>
      <th>Framework</th>
      <th>Title</th>
      <th class="center">Status</th>
      <th class="center"># Threats</th>
      <th class="center">Top sev</th>
      <th>Top threat IDs</th>
      <th>Mitigations</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>

<p class="muted" style="margin-top: 18px; font-size: 11px;">
  <strong>Legend.</strong>
  <span class="status status-covered">Covered</span> ≥1 in-scope threat references the control (open).
  <span class="status status-mitigated">Mitigated</span> Every referencing threat has a closing disposition.
  <span class="status status-uncovered">Uncovered</span> No threat references the control though it applies to a component type in this system.
  <span class="status status-not-applicable">Not applicable</span> Control's applies_to scope doesn't match any component in the system — informational, not a gap.
</p>
</body>
</html>
"""

_ROW_TEMPLATE = """    <tr>
      <td><code>{cid}</code></td>
      <td>{framework}</td>
      <td>{title}</td>
      <td class="center"><span class="status status-{status_class}">{status}</span></td>
      <td class="center">{threat_count}</td>
      <td class="center">{sev_pill}</td>
      <td class="mono">{threat_ids}</td>
      <td class="mono">{mitigation_ids}</td>
    </tr>"""


def render_compliance_matrix_html(
    model: ThreatModel,
    framework: str | None = None,
) -> str:
    """Render the coverage matrix for `model` as a self-contained HTML
    document. Pass `framework="NIST_800_53"` to filter to one framework."""
    from .. import __version__
    rows = compute_coverage(model, framework=framework)
    summary = coverage_summary(rows)

    body_rows: list[str] = []
    for r in rows:
        sev = r.get("top_severity")
        sev_pill = (
            f'<span class="sev sev-{_esc(sev)}">{_esc(sev)}</span>' if sev else '<span class="muted">—</span>'
        )
        tids = ", ".join(_esc(x) for x in r["threat_ids"][:5])
        if len(r["threat_ids"]) > 5:
            tids += f' <span class="muted">+{len(r["threat_ids"]) - 5}</span>'
        mids = ", ".join(_esc(x) for x in r["mitigation_ids"][:5])
        if len(r["mitigation_ids"]) > 5:
            mids += f' <span class="muted">+{len(r["mitigation_ids"]) - 5}</span>'

        # Use the dotted slash version for CSS-friendly status names.
        status_class = r["status"].replace("-", "-").replace(" ", "-")
        body_rows.append(_ROW_TEMPLATE.format(
            cid=_esc(r["control_id"]),
            framework=_esc(r["framework"]),
            title=_esc(r["title"]),
            status=_esc(r["status"]),
            status_class=status_class,
            threat_count=r["threat_count"],
            sev_pill=sev_pill,
            threat_ids=tids or '<span class="muted">—</span>',
            mitigation_ids=mids or '<span class="muted">—</span>',
        ))

    framework_label = framework if framework else "all bundled"
    filter_block = (
        f'<div class="filter-note">Filtered to <code>{_esc(framework)}</code>. '
        f'Re-run without <code>--framework</code> to see every framework.</div>'
        if framework else ""
    )

    return _HTML_TEMPLATE.format(
        system_name=_esc(model.system.name),
        framework_label=_esc(framework_label),
        version=_esc(__version__),
        filter_block=filter_block,
        total=summary["total"],
        covered=summary["covered"],
        mitigated=summary["mitigated"],
        uncovered=summary["uncovered"],
        na=summary["not_applicable"],
        rows="\n".join(body_rows) or '    <tr><td colspan="8" class="muted center">No controls match the selected filter.</td></tr>',
    )


# ────────────────────────────────────────────────────────────────────
# CSV renderer
# ────────────────────────────────────────────────────────────────────

def render_compliance_matrix_csv(
    model: ThreatModel,
    framework: str | None = None,
) -> str:
    """Render the coverage matrix as CSV (one row per control)."""
    rows = compute_coverage(model, framework=framework)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow([
        "control_id", "framework", "title", "status",
        "threat_count", "top_severity",
        "threat_ids", "mitigation_ids",
        "applies_to", "description",
    ])
    for r in rows:
        w.writerow([
            r["control_id"], r["framework"], r["title"], r["status"],
            r["threat_count"], r.get("top_severity") or "",
            ";".join(r["threat_ids"]), ";".join(r["mitigation_ids"]),
            ";".join(r["applies_to"]), r["description"],
        ])
    return buf.getvalue()


__all__ = [
    "compute_coverage",
    "coverage_summary",
    "render_compliance_matrix_html",
    "render_compliance_matrix_csv",
]
