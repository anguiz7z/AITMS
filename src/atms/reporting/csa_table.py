"""CSA Singapore "Table of Attack" threat-library renderer (v1.0.3).

The Cyber Security Agency of Singapore's *Guide to Cyber Threat Modelling*
(Feb 2021) prescribes a specific deliverable for the Attack-Modelling step:
the **Table of Attack**. Local clients (and the CSA guide itself) expect the
threat library rendered in exactly these columns:

    | S/N | Point of Entry | Threat Actor(s) | Sequence of Attack |
    | Threat Description | Examples |

with two further CSA concepts overlaid:

  * **Crown jewel (★)** — the high-value asset an attack path terminates on.
  * **Stepping stones** — the intermediate components an attacker pivots
    through to reach the crown jewel.

ATMS already discovers multi-step `AttackPath` objects (ordered components,
ATLAS tactics traversed, the threats at each hop). This module *re-projects*
those — plus the per-component threats — into the CSA Table-of-Attack shape.
It is 100% deterministic (no LLM, no network), mirroring the rest of the
ATMS core.

Each attack path becomes one Table-of-Attack row:
  * Point of Entry   = first component on the path (the attack surface).
  * Threat Actor(s)  = derived from the entry component's type.
  * Sequence         = ordered hop list (entry → stepping stones → crown).
  * Threat Desc.     = the path's title + terminal objective.
  * Examples         = ATLAS techniques + OWASP refs seen along the path.

When a system has no multi-step paths, the table falls back to single-step
rows built from the highest-risk individual threats so the deliverable is
never empty.
"""

from __future__ import annotations

import csv
import io

from ..models import AttackPath, Component, Threat, ThreatModel

# ─── ATLAS tactic ID → human label ─────────────────────────────────────
# Authoritative MITRE atlas-data tactic names (kept in sync with
# engines/attack_paths.py:TACTIC_ORDER). Static so the renderer never
# depends on a KB load succeeding.
_ATLAS_TACTIC_NAMES: dict[str, str] = {
    "AML.TA0002": "Reconnaissance",
    "AML.TA0003": "Resource Development",
    "AML.TA0004": "Initial Access",
    "AML.TA0000": "AI Model Access",
    "AML.TA0005": "Execution",
    "AML.TA0006": "Persistence",
    "AML.TA0012": "Privilege Escalation",
    "AML.TA0007": "Defense Evasion",
    "AML.TA0013": "Credential Access",
    "AML.TA0008": "Discovery",
    "AML.TA0009": "Collection",
    "AML.TA0001": "AI Attack Staging",
    "AML.TA0014": "Command and Control",
    "AML.TA0010": "Exfiltration",
    "AML.TA0011": "Impact",
    "AML.TA0015": "Lateral Movement",
}


# ─── Crown-jewel component types ────────────────────────────────────────
# High-value assets an attacker ultimately wants: data stores, secrets,
# model/identity assets, training data. A path terminating on one of these
# is flagged ★.
_CROWN_JEWEL_TYPES: frozenset[str] = frozenset({
    "rag_vector_store", "object_storage", "database", "nosql_database",
    "graph_database", "data_warehouse", "data_lake", "ml_feature_store",
    "block_storage", "file_storage", "backup_service", "time_series_database",
    "cache_store",
    "model_registry", "training_pipeline", "fine_tuning_pipeline",
    "secrets_vault", "kms_key", "hsm",
    "directory_service", "identity_provider", "pam_vault",
    # OT crown jewels
    "scada", "dcs", "plc", "sis", "historian",
})


# ─── Threat-actor derivation by entry component type ────────────────────
_EXTERNAL_ENTRY_TYPES: frozenset[str] = frozenset({
    "user", "external_api", "web_application", "api_gateway", "load_balancer",
    "cdn", "waf", "reverse_proxy", "web_proxy", "vpn_gateway", "email_server",
    "mobile_device", "file_transfer_service", "dns_service", "private_link",
})
_SUPPLY_CHAIN_ENTRY_TYPES: frozenset[str] = frozenset({
    "training_pipeline", "fine_tuning_pipeline", "data_source",
    "model_registry", "ml_data_labeling", "container_registry",
    "artifact_registry", "code_repository", "ci_cd_pipeline", "build_runner",
    "iac_template_registry", "embedding_service", "prompt_template_store",
})
_INSIDER_ENTRY_TYPES: frozenset[str] = frozenset({
    "iam_principal", "agent", "tool", "mcp_server", "endpoint",
    "virtual_desktop", "bastion_host", "ot_jumphost", "server_windows",
    "server_linux", "server_unix", "directory_service",
})


def _classify_actors(entry: Component | None) -> list[str]:
    """Return the CSA threat-actor label(s) for a path's point of entry.

    Deterministic, type-driven. Returns at least one actor; never empty.
    """
    if entry is None:
        return ["External attacker"]
    ctype = entry.type
    if ctype in _SUPPLY_CHAIN_ENTRY_TYPES:
        return ["Supply-chain adversary"]
    if ctype in _INSIDER_ENTRY_TYPES:
        return ["Malicious insider / compromised account"]
    if ctype in _EXTERNAL_ENTRY_TYPES:
        # An internet-facing surface reachable by anyone, plus an
        # authenticated-abuse variant for surfaces fronting user sessions.
        if ctype == "user":
            return ["Malicious / compromised user"]
        return ["External attacker"]
    # OT / industrial entry points imply a more capable adversary.
    if ctype in {"plc", "rtu", "ied", "hmi", "scada", "dcs", "sis",
                 "industrial_protocol", "iot_device", "iot_gateway"}:
        return ["External attacker", "Nation-state / OT-capable adversary"]
    return ["External attacker"]


def _is_crown_jewel(component: Component | None) -> bool:
    if component is None:
        return False
    return component.type in _CROWN_JEWEL_TYPES


def _tactic_label(tid: str) -> str:
    """Human label for an ATLAS tactic ID, falling back to the raw ID."""
    return _ATLAS_TACTIC_NAMES.get(tid, tid)


def _examples_for(threats: list[Threat], limit: int = 6) -> list[str]:
    """Concrete attack 'examples' for the CSA column: ATLAS techniques and
    OWASP LLM / Agentic references seen across the path's threats, deduped
    and capped."""
    seen: list[str] = []

    def _add(value: str) -> None:
        if value and value not in seen:
            seen.append(value)

    for t in threats:
        for tech in t.atlas_techniques:
            _add(tech)
    for t in threats:
        for ref in t.owasp_llm:
            _add(ref)
    for t in threats:
        for ref in t.owasp_agentic:
            _add(ref)
    # Real-world anchors: any CVE / KEV evidence is the strongest "example".
    for t in threats:
        for e in t.evidence:
            for cve in e.cve:
                _add(cve)
    return seen[:limit]


def _row_from_path(
    sn: int,
    path: AttackPath,
    comp_index: dict[str, Component],
    threat_index: dict[str, Threat],
) -> dict:
    """Project one AttackPath into a CSA Table-of-Attack row."""
    comp_ids = path.components or []
    entry = comp_index.get(comp_ids[0]) if comp_ids else None
    target = comp_index.get(comp_ids[-1]) if comp_ids else None

    # Ordered hops (entry → … → target) with the component type.
    sequence: list[dict] = []
    for cid in comp_ids:
        c = comp_index.get(cid)
        sequence.append({
            "id": cid,
            "name": c.name if c else cid,
            "type": c.type if c else "",
        })
    sequence_names = [hop["name"] for hop in sequence]

    # Stepping stones = everything between entry and crown jewel.
    stepping_stones = sequence_names[1:-1] if len(sequence_names) >= 3 else []

    tactics = [_tactic_label(t) for t in path.tactics_traversed]
    path_threats = [threat_index[tid] for tid in path.threat_ids if tid in threat_index]

    # Threat description: the path title already reads "Entry → Target:
    # <terminal threat>". Enrich with the terminal threat's objective.
    description = path.title
    if path_threats:
        terminal = path_threats[-1]
        if terminal.description:
            description = f"{path.title}. {terminal.description.strip()[:240]}"

    return {
        "sn": sn,
        "point_of_entry": entry.name if entry else (comp_ids[0] if comp_ids else "—"),
        "point_of_entry_type": entry.type if entry else "",
        "threat_actors": _classify_actors(entry),
        "sequence": sequence,
        "sequence_str": " → ".join(sequence_names) if sequence_names else "—",
        "tactics": tactics,
        "tactics_str": " → ".join(tactics) if tactics else "—",
        "threat_description": description,
        "examples": _examples_for(path_threats),
        "crown_jewel": target.name if target else "—",
        "crown_jewel_type": target.type if target else "",
        "is_crown_jewel": _is_crown_jewel(target),
        "stepping_stones": stepping_stones,
        "difficulty": path.estimated_difficulty,
        "business_impact": path.business_impact,
        "path_id": path.id,
        "threat_ids": list(path.threat_ids),
    }


def _row_from_threat(sn: int, threat: Threat, comp_index: dict[str, Component]) -> dict:
    """Single-step fallback row (used only when no multi-step paths exist)."""
    comp = comp_index.get(threat.component_id)
    return {
        "sn": sn,
        "point_of_entry": comp.name if comp else threat.component_id,
        "point_of_entry_type": comp.type if comp else "",
        "threat_actors": _classify_actors(comp),
        "sequence": [{
            "id": threat.component_id,
            "name": comp.name if comp else threat.component_id,
            "type": comp.type if comp else "",
        }],
        "sequence_str": comp.name if comp else threat.component_id,
        "tactics": [_tactic_label(t) for t in []],
        "tactics_str": threat.kill_chain_phase or "—",
        "threat_description": (
            f"{threat.title}. {threat.description.strip()[:240]}"
            if threat.description else threat.title
        ),
        "examples": _examples_for([threat]),
        "crown_jewel": comp.name if comp else threat.component_id,
        "crown_jewel_type": comp.type if comp else "",
        "is_crown_jewel": _is_crown_jewel(comp),
        "stepping_stones": [],
        "difficulty": max(1, 6 - threat.likelihood),
        "business_impact": threat.impact,
        "path_id": "",
        "threat_ids": [threat.id],
    }


def build_table_of_attack(model: ThreatModel, max_rows: int = 50) -> list[dict]:
    """Build the CSA Table-of-Attack rows for a ThreatModel.

    One row per discovered attack path (ranked by business impact, then by
    how easy it is). Falls back to single-step rows from the highest-risk
    threats when the system has no multi-step paths, so the deliverable is
    never empty.
    """
    comp_index = {c.id: c for c in model.system.components}
    threat_index = {t.id: t for t in model.threats}

    rows: list[dict] = []
    if model.attack_paths:
        ranked = sorted(
            model.attack_paths,
            key=lambda p: (p.business_impact, -p.estimated_difficulty),
            reverse=True,
        )
        for i, path in enumerate(ranked[:max_rows], start=1):
            rows.append(_row_from_path(i, path, comp_index, threat_index))
    else:
        ranked_threats = sorted(
            model.threats,
            key=lambda t: (t.risk_score, t.impact),
            reverse=True,
        )
        for i, threat in enumerate(ranked_threats[:max_rows], start=1):
            rows.append(_row_from_threat(i, threat, comp_index))
    return rows


# ────────────────────────────────────────────────────────────────────
# CSV renderer
# ────────────────────────────────────────────────────────────────────

def render_csa_table_csv(model: ThreatModel) -> str:
    """Render the CSA Table of Attack as CSV (one row per attack path)."""
    rows = build_table_of_attack(model)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow([
        "S/N",
        "Point of Entry",
        "Entry Type",
        "Threat Actor(s)",
        "Sequence of Attack",
        "Tactics Traversed",
        "Threat Description",
        "Examples",
        "Crown Jewel",
        "Crown Jewel (high-value)",
        "Stepping Stones",
        "Difficulty (1-5)",
        "Business Impact (1-5)",
        "Path ID",
    ])
    for r in rows:
        w.writerow([
            r["sn"],
            r["point_of_entry"],
            r["point_of_entry_type"],
            "; ".join(r["threat_actors"]),
            r["sequence_str"],
            r["tactics_str"],
            r["threat_description"],
            "; ".join(r["examples"]),
            r["crown_jewel"],
            "yes" if r["is_crown_jewel"] else "",
            "; ".join(r["stepping_stones"]),
            r["difficulty"],
            r["business_impact"],
            r["path_id"],
        ])
    return buf.getvalue()


# ────────────────────────────────────────────────────────────────────
# Standalone HTML renderer (self-contained, emailable)
# ────────────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    """Minimal HTML escape (matches compliance_matrix._esc)."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CSA Table of Attack — {system_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 1280px; margin: 28px auto; padding: 0 24px;
         color: #0e1116; background: #ffffff; line-height: 1.5; }}
  h1 {{ font-size: 24px; margin: 0; }}
  h1 small {{ color: #6e7681; font-size: 14px; font-weight: 400; }}
  .muted {{ color: #6e7681; }}
  .intro {{ background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 8px;
            padding: 12px 16px; margin: 14px 0 20px 0; font-size: 13px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12px; margin-top: 8px; }}
  th, td {{ border: 1px solid #d0d7de; padding: 7px 9px; text-align: left; vertical-align: top; }}
  th {{ background: #0e1116; color: #fff; font-weight: 600; position: sticky; top: 0; }}
  tr:nth-child(even) td {{ background: #f6f8fa; }}
  td.sn {{ text-align: center; font-weight: 600; white-space: nowrap; }}
  .actor {{ display: inline-block; background: #eaeef2; border-radius: 999px;
            padding: 1px 8px; margin: 1px 2px; font-size: 11px; white-space: nowrap; }}
  .seq {{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 11px; }}
  .crown {{ font-weight: 600; }}
  .crown .star {{ color: #d4a72c; }}
  .tactics {{ color: #57606a; font-size: 11px; }}
  .ex {{ display: inline-block; background: #ddf4ff; color: #0969da; border-radius: 4px;
         padding: 1px 6px; margin: 1px 2px; font-size: 11px; white-space: nowrap; }}
  .stone {{ display: inline-block; background: #fff5cc; color: #7a5c00; border-radius: 4px;
            padding: 1px 6px; margin: 1px 2px; font-size: 11px; }}
  .legend {{ margin-top: 18px; font-size: 11px; color: #6e7681; }}
</style>
</head>
<body>
<h1>CSA Table of Attack <small>· {system_name}</small></h1>
<p class="muted">Threat library in the CSA Singapore <em>Guide to Cyber Threat Modelling</em>
(Feb 2021) Table-of-Attack format. {row_count} attack path(s). Generated by ATMS v{version}.</p>
<div class="intro">
  Each row is one attack path: where an adversary enters (<strong>Point of Entry</strong>),
  who they are (<strong>Threat Actor</strong>), how they pivot through
  <strong>stepping stones</strong> (<span class="stone">amber</span>) toward the
  <strong>crown jewel</strong> (<span class="crown"><span class="star">★</span></span>),
  and the techniques that anchor each step (<strong>Examples</strong>).
</div>
<table>
  <thead>
    <tr>
      <th>S/N</th>
      <th>Point of Entry</th>
      <th>Threat Actor(s)</th>
      <th>Sequence of Attack</th>
      <th>Threat Description</th>
      <th>Examples</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
<p class="legend">
  <strong>Legend.</strong>
  <span class="crown"><span class="star">★</span> crown jewel</span> — high-value asset the path
  terminates on (data store, secrets, model, identity, or OT controller).
  <span class="stone">stepping stone</span> — intermediate component pivoted through.
  Difficulty / business-impact are 1–5 (5 = highest).
</p>
</body>
</html>
"""

_ROW_TEMPLATE = """    <tr>
      <td class="sn">{sn}</td>
      <td><strong>{entry}</strong>{entry_type}</td>
      <td>{actors}</td>
      <td>
        <div class="seq">{sequence}</div>
        <div class="tactics">{tactics}</div>
        {stones}
      </td>
      <td>{description}<div class="muted" style="margin-top:4px;">Difficulty {difficulty}/5 · Impact {impact}/5</div></td>
      <td>{examples}</td>
    </tr>"""


def render_csa_table_html(model: ThreatModel) -> str:
    """Render the CSA Table of Attack as a self-contained HTML document."""
    from .. import __version__

    rows = build_table_of_attack(model)
    body: list[str] = []
    for r in rows:
        actors = "".join(
            f'<span class="actor">{_esc(a)}</span>' for a in r["threat_actors"]
        )
        # Crown jewel marker appended to the sequence's last hop.
        seq_parts = [_esc(hop["name"]) for hop in r["sequence"]]
        if seq_parts and r["is_crown_jewel"]:
            seq_parts[-1] = (
                f'<span class="crown"><span class="star">★</span> {seq_parts[-1]}</span>'
            )
        sequence = " &rarr; ".join(seq_parts) if seq_parts else "&mdash;"
        stones = ""
        if r["stepping_stones"]:
            stones = (
                '<div style="margin-top:3px;">'
                + "".join(f'<span class="stone">{_esc(s)}</span>' for s in r["stepping_stones"])
                + "</div>"
            )
        examples = "".join(
            f'<span class="ex">{_esc(x)}</span>' for x in r["examples"]
        ) or '<span class="muted">&mdash;</span>'
        entry_type = (
            f'<div class="muted" style="font-size:11px;">{_esc(r["point_of_entry_type"])}</div>'
            if r["point_of_entry_type"] else ""
        )
        body.append(_ROW_TEMPLATE.format(
            sn=r["sn"],
            entry=_esc(r["point_of_entry"]),
            entry_type=entry_type,
            actors=actors,
            sequence=sequence,
            tactics=_esc(r["tactics_str"]),
            stones=stones,
            description=_esc(r["threat_description"]),
            difficulty=r["difficulty"],
            impact=r["business_impact"],
            examples=examples,
        ))

    return _HTML_TEMPLATE.format(
        system_name=_esc(model.system.name),
        version=_esc(__version__),
        row_count=len(rows),
        rows="\n".join(body) or (
            '    <tr><td colspan="6" class="muted" '
            'style="text-align:center;">No attack paths discovered.</td></tr>'
        ),
    )


__all__ = [
    "build_table_of_attack",
    "render_csa_table_csv",
    "render_csa_table_html",
]
