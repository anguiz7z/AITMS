"""CSA Singapore "Risk Assessment for CII" risk model + Risk Register (v1.0.6).

The Cyber Security Agency of Singapore's *Guide to Conducting Cybersecurity
Risk Assessment for Critical Information Infrastructure* (Feb 2021) prescribes
a specific risk-scoring method and a Risk Register deliverable that local
clients (and CSA audits) expect:

  * **Likelihood = average(Discoverability, Exploitability, Reproducibility)**
    — the D-E-R triad, drawn from DREAD. Each sub-score is 1-5.
  * **Impact = max(Confidentiality, Integrity, Availability)** — the C-I-A
    triad. Each sub-score is 1-5. CSA uses the *worst* dimension, not an
    average, because a single catastrophic C/I/A breach defines the impact.
  * **Risk = f(Likelihood, Impact)** placed on a 5x5 matrix with the CSA
    bands: Low / Medium / Medium-High / High / Very High.
  * **Risk Register** with the 8 mandatory elements: risk scenario,
    identification date, existing measures, current risk level, treatment
    plan, treatment progress, residual risk level, risk owner.

DEFENSIBILITY PRINCIPLE
-----------------------
This is an ADDITIVE re-projection of ATMS's existing, already-audited
signals into the CSA shape. It does NOT invent numbers and does NOT change
ATMS's own risk_score / severity. Every CSA sub-score traces to a real
existing field with a documented derivation (see each helper's docstring),
so any value can be justified to an auditor:

  Discoverability  <- ATMS likelihood, +1 if the component is external-facing
                      (internet/public/untrusted zone — a real exposure signal)
  Exploitability   <- ATMS likelihood, lowered when mitigating controls are
                      recorded on the threat (control:* tags the controls
                      engine already wrote), raised when scanner/red-team
                      evidence exists
  Reproducibility  <- ATMS likelihood, raised to 5 on a CISA KEV hit
                      (actively-exploited == reliably reproducible)
  Confidentiality  <- ATMS impact, scaled by whether the threat's STRIDE-LM
                      categories touch confidentiality
  Integrity        <- ATMS impact, scaled by integrity-touching STRIDE-LM
  Availability     <- ATMS impact, scaled by availability-touching STRIDE-LM

The result is the CSA method computed honestly from ATMS's own evidence —
not a parallel guess.
"""

from __future__ import annotations

import io

from ..models import StrideAI, System, Threat, ThreatModel
from .csv_export import safe_csv_writer  # audit F047: formula-injection-safe CSV

# ─── STRIDE-LM -> C / I / A mapping ─────────────────────────────────
# Each STRIDE-LM category primarily threatens one or more of the C-I-A
# security properties. Drawn from the classic STRIDE<->CIA correspondence
# (Confidentiality / Integrity / Availability), extended for the AI-native
# and lateral-movement categories. A category may touch more than one.
_STRIDE_CIA: dict[str, tuple[str, ...]] = {
    "Spoofing": ("C", "I"),            # identity falsification -> unauthorised access (C) + forged actions (I)
    "Tampering": ("I",),               # unauthorised modification -> integrity
    "Repudiation": ("I",),             # deniability undermines the integrity of the audit record
    "Information_Disclosure": ("C",),  # confidentiality, by definition
    "Denial_of_Service": ("A",),       # availability, by definition
    "Elevation_of_Privilege": ("C", "I"),  # gains read (C) + write/control (I)
    "Defense_Evasion": ("C", "I"),     # hiding activity protects an ongoing C/I compromise
    "Lateral_Movement": ("C", "I", "A"),   # pivot toward a crown jewel can hit any property
    "Bias_Fairness": ("I",),           # discriminatory/incorrect output is an integrity-of-outcome failure
    "Emergent_Behavior": ("I", "A"),   # out-of-spec actions corrupt outputs (I) or destabilise service (A)
}

# CSA 5x5 risk bands. risk = likelihood * impact (1..25). The CSA guide
# uses five qualitative bands rather than four; these cut-points reproduce
# the guide's 5x5 colouring (Low / Medium / Medium-High / High / Very High).
_CSA_BANDS = (
    (1, 4, "Low"),
    (5, 9, "Medium"),
    (10, 14, "Medium-High"),
    (15, 19, "High"),
    (20, 25, "Very High"),
)


def _clamp(v: int) -> int:
    return max(1, min(5, int(v)))


def _is_external_component(system: System, component_id: str) -> bool:
    """Real exposure signal: is the threat's component external-facing?
    Reuses the same zone-aware logic the architectural rules use."""
    from ..engines.architectural_rules import _is_external_facing  # noqa: PLC0415

    comp = next((c for c in system.components if c.id == component_id), None)
    return bool(comp and _is_external_facing(comp))


# ─── D-E-R likelihood triad ─────────────────────────────────────────


def discoverability(threat: Threat, external: bool) -> int:
    """How easily an attacker finds the weakness. Base = ATMS likelihood
    (its DREAD lineage already maps likelihood -> discoverability); +1 when
    the affected component is external-facing (internet-reachable surfaces
    are easier to discover)."""
    base = _clamp(threat.likelihood)
    if external:
        base = min(5, base + 1)
    return base


def exploitability(threat: Threat) -> int:
    """Effort/skill to exploit. Base = ATMS likelihood. Lowered when the
    controls engine recorded a mitigating control on this threat
    (control:* reference tags), raised when scanner/red-team evidence
    proves a working exploit path."""
    base = _clamp(threat.likelihood)
    has_control = any(str(r).startswith("control:") for r in (threat.references or []))
    if has_control:
        base = max(1, base - 1)
    # Confirmed exploitation evidence raises exploitability.
    if threat.evidence_status in ("observed", "exploited"):
        base = min(5, base + 1)
    return base


def reproducibility(threat: Threat) -> int:
    """How reliably the attack works. Base = ATMS likelihood; forced to 5
    on a CISA KEV hit (actively-exploited-in-the-wild == reliably
    reproducible)."""
    base = _clamp(threat.likelihood)
    if any(getattr(e, "kev", False) for e in (threat.evidence or [])):
        return 5
    if threat.evidence_status == "exploited":
        base = min(5, base + 1)
    return base


def csa_likelihood(threat: Threat, external: bool) -> tuple[int, int, int, float]:
    """Return (D, E, R, likelihood) where likelihood = round(avg(D,E,R))."""
    d = discoverability(threat, external)
    e = exploitability(threat)
    r = reproducibility(threat)
    avg = (d + e + r) / 3.0
    return d, e, r, avg


# ─── C-I-A impact triad ─────────────────────────────────────────────


def cia_impact(threat: Threat) -> tuple[int, int, int, int]:
    """Return (C, I, A, impact) where impact = max(C, I, A).

    Each dimension is ATMS impact when the threat's STRIDE-LM categories
    touch that property, else a reduced floor (a threat that doesn't touch
    a property still carries a small residual on it). CSA takes the MAX —
    a single catastrophic dimension defines the impact."""
    base = _clamp(threat.impact)
    touched: set[str] = set()
    for cat in (threat.stride_ai or []):
        touched.update(_STRIDE_CIA.get(cat, ()))
    # A property the threat touches gets the full impact; an untouched one
    # gets a residual floor (impact minus 2, never below 1) so the register
    # never shows a hard zero but the dominant dimension stands out.
    floor = max(1, base - 2)
    c = base if "C" in touched else floor
    i = base if "I" in touched else floor
    a = base if "A" in touched else floor
    # If STRIDE was empty (shouldn't happen — 100% coverage), fall back to
    # the ATMS impact across the board so we never under-report.
    if not touched:
        c = i = a = base
    return c, i, a, max(c, i, a)


# ─── Risk band ──────────────────────────────────────────────────────


def csa_risk_band(likelihood: float, impact: int) -> tuple[int, str]:
    """Return (risk_value, band_label). risk_value = round(likelihood)*impact
    on the CSA 5x5 grid (1..25)."""
    lv = _clamp(round(likelihood))
    iv = _clamp(impact)
    risk = lv * iv
    band = next((label for lo, hi, label in _CSA_BANDS if lo <= risk <= hi), "Low")
    return risk, band


# ─── Per-threat CSA row ─────────────────────────────────────────────


def build_csa_rows(model: ThreatModel) -> list[dict]:
    """One CSA-scored row per threat, ranked by CSA risk value desc.

    Excludes threats whose disposition closes them (mitigated / false-
    positive / duplicate) from the *active* register, matching how ATMS
    rolls up severity — but keeps them available via the `closed` flag."""
    from ..models import is_closed  # noqa: PLC0415

    system = model.system
    comp_name = {c.id: c.name for c in system.components}
    rows: list[dict] = []
    for t in model.threats:
        external = _is_external_component(system, t.component_id)
        d, e, r, like = csa_likelihood(t, external)
        c, i, a, imp = cia_impact(t)
        risk, band = csa_risk_band(like, imp)
        rows.append({
            "threat_id": t.id,
            "component_id": t.component_id,
            "component_name": comp_name.get(t.component_id, t.component_id),
            "title": t.title,
            "stride_lm": list(t.stride_ai or []),
            # D-E-R
            "discoverability": d,
            "exploitability": e,
            "reproducibility": r,
            "likelihood": round(like, 2),
            "likelihood_int": _clamp(round(like)),
            # C-I-A
            "confidentiality": c,
            "integrity": i,
            "availability": a,
            "impact": imp,
            # risk
            "risk_value": risk,
            "risk_band": band,
            # register linkage
            "atms_severity": t.severity,
            "atms_risk_score": t.risk_score,
            "evidence_status": t.evidence_status,
            "external_facing": external,
            # audit F011: a REAL signal of a recorded control (control:* tags
            # added by apply_component_controls), not the exploitability <
            # discoverability heuristic that the external-facing discoverability
            # bump confounds into a false 'control recorded' on every
            # external-facing threat.
            "has_control": any(str(ref).startswith("control:") for ref in (t.references or [])),
            "mitigation_ids": list(t.mitigation_ids or []),
            "disposition": t.disposition,
            "owner": t.owner or "",
            "due_date": t.due_date or "",
            "closed": is_closed(t.disposition),
        })
    rows.sort(key=lambda x: (x["risk_value"], x["impact"], x["likelihood"]), reverse=True)
    return rows


# ─── 8-element CSA Risk Register ────────────────────────────────────
# The CSA CII guide mandates exactly these eight columns per risk.


def build_risk_register(model: ThreatModel, generated_date: str = "") -> list[dict]:
    """Project the CSA rows into the 8 mandatory Risk-Register elements.

    1. Risk scenario      = Asset + Threat event + Vulnerability + Consequence
    2. Identification date = when the risk was identified (analysis date)
    3. Existing measures  = controls/mitigations already linked
    4. Current risk level = CSA band from likelihood x impact (pre-treatment)
    5. Treatment plan     = recommended mitigations (the response)
    6. Treatment progress = derived from disposition lifecycle
    7. Residual risk level = band after planned treatment (one band lower if
       a treatment plan exists / disposition shows progress, else unchanged)
    8. Risk owner         = threat.owner (or 'Unassigned')
    """
    mit_by_id = {m.id: m for m in model.mitigations}
    rows = build_csa_rows(model)
    register: list[dict] = []
    for idx, rr in enumerate(rows, start=1):
        # 5. treatment plan — the linked mitigations' titles.
        treatments = [
            mit_by_id[mid].title for mid in rr["mitigation_ids"] if mid in mit_by_id
        ]
        # 6. progress from disposition.
        progress = _treatment_progress(rr["disposition"])
        # 7. residual = current, dropped one band when a treatment exists or
        #    the disposition shows acknowledged progress. Never below Low.
        residual_band = _residual_band(
            rr["risk_band"], bool(treatments), rr["disposition"]
        )
        # 1. risk scenario sentence.
        scenario = _risk_scenario(rr)
        register.append({
            "sn": idx,
            "risk_scenario": scenario,
            "identification_date": generated_date or "(analysis date)",
            "existing_measures": _existing_measures(rr),
            "current_risk_level": rr["risk_band"],
            "current_risk_value": rr["risk_value"],
            "treatment_plan": "; ".join(treatments) if treatments else "(no control linked — assign treatment)",
            "treatment_progress": progress,
            "residual_risk_level": residual_band,
            "risk_owner": rr["owner"] or "Unassigned",
            # carry the scoring detail for the HTML view
            "_detail": rr,
        })
    return register


def _risk_scenario(rr: dict) -> str:
    """CSA risk scenario = Asset + Threat event + Vulnerability + Consequence."""
    worst = max(
        (("Confidentiality", rr["confidentiality"]),
         ("Integrity", rr["integrity"]),
         ("Availability", rr["availability"])),
        key=lambda kv: kv[1],
    )[0]
    return (
        f"{rr['component_name']}: {rr['title']} "
        f"(STRIDE-LM: {', '.join(rr['stride_lm']) or 'n/a'}) "
        f"-> {worst} impact {rr['impact']}/5, likelihood {rr['likelihood_int']}/5."
    )


def _existing_measures(rr: dict) -> str:
    parts = []
    if rr["external_facing"]:
        parts.append("component is external-facing")
    if rr["evidence_status"] != "hypothetical":
        parts.append(f"evidence: {rr['evidence_status']}")
    # audit F011: report a recorded control only when the threat actually
    # declares one (control:* tag), not from the exploitability<discoverability
    # comparison (which the external-facing discoverability bump always trips).
    if rr.get("has_control"):
        parts.append("mitigating control(s) recorded")
    return "; ".join(parts) if parts else "none recorded"


def _treatment_progress(disposition: str) -> str:
    return {
        "open": "Not started",
        "accepted": "Risk accepted",
        "accepted_with_compensating_control": "Compensating control in place",
        "mitigated": "Completed",
        "transferred": "Transferred",
        "deferred": "Deferred",
        "false_positive": "Closed (false positive)",
        "duplicate": "Closed (duplicate)",
    }.get(disposition or "open", "Not started")


def _residual_band(current: str, has_treatment: bool, disposition: str) -> str:
    order = ["Low", "Medium", "Medium-High", "High", "Very High"]
    idx = order.index(current) if current in order else 0
    # audit F012: residual risk = risk remaining AFTER treatment is APPLIED.
    # A completed/transferred treatment drops two bands; a real compensating
    # control drops one. An OPEN threat with only a *suggested* (KB-linked)
    # mitigation has had no treatment applied, so its residual stays at current
    # -- crediting a band drop there overstated the client's posture.
    if disposition in ("mitigated", "transferred", "false_positive", "duplicate"):
        idx = max(0, idx - 2)
    elif disposition == "accepted_with_compensating_control":
        idx = max(0, idx - 1)
    return order[idx]


# ─── CSV renderer (the auditable register spreadsheet) ──────────────


def render_csa_risk_register_csv(model: ThreatModel, generated_date: str = "") -> str:
    register = build_risk_register(model, generated_date=generated_date)
    buf = io.StringIO()
    w = safe_csv_writer(buf, lineterminator="\n")
    w.writerow([
        "S/N",
        "Risk Scenario",
        "Identification Date",
        "Existing Measures",
        "Discoverability", "Exploitability", "Reproducibility", "Likelihood",
        "Confidentiality", "Integrity", "Availability", "Impact",
        "Current Risk Level", "Current Risk Value",
        "Treatment Plan",
        "Treatment Progress",
        "Residual Risk Level",
        "Risk Owner",
    ])
    for e in register:
        d = e["_detail"]
        w.writerow([
            e["sn"],
            e["risk_scenario"],
            e["identification_date"],
            e["existing_measures"],
            d["discoverability"], d["exploitability"], d["reproducibility"], d["likelihood_int"],
            d["confidentiality"], d["integrity"], d["availability"], d["impact"],
            e["current_risk_level"], e["current_risk_value"],
            e["treatment_plan"],
            e["treatment_progress"],
            e["residual_risk_level"],
            e["risk_owner"],
        ])
    return buf.getvalue()


# ─── Standalone HTML renderer ───────────────────────────────────────


def _esc(s) -> str:
    return (
        str(s)
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;").replace("'", "&#39;")
    )


_BAND_COLOR = {
    "Low": "#1a7f37",
    "Medium": "#9a6700",
    "Medium-High": "#bc4c00",
    "High": "#cf222e",
    "Very High": "#a40e26",
}


_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CSA Risk Register — {system_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 1320px; margin: 28px auto; padding: 0 24px; color: #0e1116; background: #fff; line-height: 1.5; }}
  h1 {{ font-size: 24px; margin: 0; }}
  h1 small {{ color: #6e7681; font-size: 14px; font-weight: 400; }}
  .muted {{ color: #6e7681; }}
  .intro {{ background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px 16px; margin: 14px 0 18px; font-size: 13px; }}
  .intro code {{ background: #eaeef2; padding: 0 4px; border-radius: 3px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12px; }}
  th, td {{ border: 1px solid #d0d7de; padding: 6px 8px; text-align: left; vertical-align: top; }}
  th {{ background: #0e1116; color: #fff; font-weight: 600; position: sticky; top: 0; }}
  tr:nth-child(even) td {{ background: #f6f8fa; }}
  td.c {{ text-align: center; white-space: nowrap; }}
  .band {{ display: inline-block; padding: 1px 8px; border-radius: 999px; color: #fff; font-weight: 600; font-size: 11px; white-space: nowrap; }}
  .triad {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11px; color: #57606a; }}
  .legend {{ margin-top: 16px; font-size: 11px; color: #6e7681; }}
  .matrix {{ border-collapse: collapse; margin: 8px 0 18px; }}
  .matrix td {{ width: 46px; height: 38px; text-align: center; font-weight: 600; color: #fff; }}
  .matrix th {{ background: #fff; color: #57606a; font-weight: 600; border: none; position: static; }}
</style>
</head>
<body>
<h1>CSA Risk Register <small>· {system_name}</small></h1>
<p class="muted">Risk model + register per the CSA Singapore <em>Guide to Conducting Cybersecurity
Risk Assessment for CII</em> (Feb 2021). {n} risk(s). Generated by ATMS v{version}.</p>
<div class="intro">
  <strong>Method.</strong> <code>Likelihood = avg(Discoverability, Exploitability, Reproducibility)</code>;
  <code>Impact = max(Confidentiality, Integrity, Availability)</code>; each sub-score 1–5.
  <code>Risk = Likelihood × Impact</code> placed on the CSA 5×5 bands.
  Every sub-score is derived from ATMS's own analysis signals (component exposure,
  recorded controls, scanner/KEV evidence, STRIDE-LM category) — see the column tooltips.
</div>
{matrix}
<table>
  <thead><tr>
    <th>S/N</th><th>Risk Scenario</th><th>Existing Measures</th>
    <th class="c" title="Discoverability / Exploitability / Reproducibility → Likelihood">D·E·R → L</th>
    <th class="c" title="Confidentiality / Integrity / Availability → Impact (max)">C·I·A → I</th>
    <th class="c">Current Risk</th>
    <th>Treatment Plan</th><th class="c">Progress</th><th class="c">Residual</th><th>Owner</th>
  </tr></thead>
  <tbody>
{rows}
  </tbody>
</table>
<p class="legend">
  <strong>Bands.</strong>
  <span class="band" style="background:{c_low}">Low</span> 1–4 ·
  <span class="band" style="background:{c_med}">Medium</span> 5–9 ·
  <span class="band" style="background:{c_mh}">Medium-High</span> 10–14 ·
  <span class="band" style="background:{c_high}">High</span> 15–19 ·
  <span class="band" style="background:{c_vh}">Very High</span> 20–25.
  Residual risk reflects planned treatment (a completed/transferred control drops two bands; a planned one drops one).
</p>
</body>
</html>
"""

_ROW = """    <tr>
      <td class="c">{sn}</td>
      <td>{scenario}</td>
      <td>{measures}</td>
      <td class="c">{d}·{e}·{r} <strong>→ {L}</strong></td>
      <td class="c">{C}·{I}·{A} <strong>→ {Imp}</strong></td>
      <td class="c"><span class="band" style="background:{band_color}">{band}</span><div class="triad">{risk_value}/25</div></td>
      <td>{treatment}</td>
      <td class="c">{progress}</td>
      <td class="c"><span class="band" style="background:{res_color}">{residual}</span></td>
      <td>{owner}</td>
    </tr>"""


def _matrix_html(rows: list[dict]) -> str:
    """A small 5x5 heat grid summarising how many risks land in each cell."""
    counts = [[0] * 6 for _ in range(6)]  # 1-based L,I
    for rr in rows:
        lv = _clamp(rr["likelihood_int"])
        iv = _clamp(rr["impact"])
        counts[lv][iv] += 1
    cells = ['<table class="matrix"><tr><th></th>'
             + "".join(f"<th>I={i}</th>" for i in range(1, 6)) + "</tr>"]
    for lv in range(5, 0, -1):
        row = [f"<th>L={lv}</th>"]
        for iv in range(1, 6):
            risk = lv * iv
            band = next((lbl for lo, hi, lbl in _CSA_BANDS if lo <= risk <= hi), "Low")
            n = counts[lv][iv]
            row.append(
                f'<td style="background:{_BAND_COLOR[band]}" title="L={lv} x I={iv} = {risk} ({band})">{n or ""}</td>'
            )
        cells.append("<tr>" + "".join(row) + "</tr>")
    cells.append("</table>")
    return "".join(cells)


def render_csa_risk_register_html(model: ThreatModel, generated_date: str = "") -> str:
    from .. import __version__  # noqa: PLC0415

    register = build_risk_register(model, generated_date=generated_date)
    detail_rows = [e["_detail"] for e in register]
    body: list[str] = []
    for e in register:
        d = e["_detail"]
        body.append(_ROW.format(
            sn=e["sn"],
            scenario=_esc(e["risk_scenario"]),
            measures=_esc(e["existing_measures"]),
            d=d["discoverability"], e=d["exploitability"], r=d["reproducibility"], L=d["likelihood_int"],
            C=d["confidentiality"], I=d["integrity"], A=d["availability"], Imp=d["impact"],
            band=_esc(e["current_risk_level"]),
            band_color=_BAND_COLOR.get(e["current_risk_level"], "#57606a"),
            risk_value=e["current_risk_value"],
            treatment=_esc(e["treatment_plan"]),
            progress=_esc(e["treatment_progress"]),
            residual=_esc(e["residual_risk_level"]),
            res_color=_BAND_COLOR.get(e["residual_risk_level"], "#57606a"),
            owner=_esc(e["risk_owner"]),
        ))
    return _HTML.format(
        system_name=_esc(model.system.name),
        version=_esc(__version__),
        n=len(register),
        matrix=_matrix_html(detail_rows),
        rows="\n".join(body) or '    <tr><td colspan="10" class="c muted">No risks.</td></tr>',
        c_low=_BAND_COLOR["Low"], c_med=_BAND_COLOR["Medium"], c_mh=_BAND_COLOR["Medium-High"],
        c_high=_BAND_COLOR["High"], c_vh=_BAND_COLOR["Very High"],
    )


__all__ = [
    "build_csa_rows",
    "build_risk_register",
    "csa_likelihood",
    "cia_impact",
    "csa_risk_band",
    "render_csa_risk_register_csv",
    "render_csa_risk_register_html",
]

# Re-export so `StrideAI`/`Threat`/`System` import lint stays satisfied if the
# module is imported for its types alone.
_ = (StrideAI, System, Threat)
