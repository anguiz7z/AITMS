"""Open Threat Model (OTM) export (v0.13).

Round-trips an ATMS System back to OTM v0.2.0 JSON so the model can be
shared with IriusRisk / Threat Dragon / pyTM. Threats are emitted as
``threats[]`` entries with risk and category fields populated from the
ATMS analysis.

Spec: https://github.com/iriusrisk/OpenThreatModel
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ..models import ThreatModel


def render_otm(model: ThreatModel) -> str:
    """Return an OTM v0.2.0 JSON string for the given ThreatModel."""
    sys = model.system
    project_id = (sys.name or "atms-export").lower().replace(" ", "-")[:64]

    trust_zones = []
    seen = set()
    for c in sys.components:
        z = c.trust_zone or "default"
        if z in seen:
            continue
        seen.add(z)
        trust_zones.append({"id": z, "name": z, "type": "trustZone", "risk": {"trustRating": 5}})

    components = []
    for c in sys.components:
        attrs = dict(c.metadata or {})
        attrs["atms_component_type"] = c.type
        components.append({
            "id": c.id,
            "name": c.name,
            "type": c.type,
            "description": c.description or "",
            "parent": {"trustZone": c.trust_zone or "default"},
            "attributes": attrs,
        })

    dataflows = []
    for i, df in enumerate(sys.dataflows or []):
        dataflows.append({
            "id": f"df-{i+1}",
            "name": df.label or f"flow-{i+1}",
            "source": df.source,
            "destination": df.target,
            "attributes": {
                "crosses_boundary": bool(df.crosses_boundary),
                "classification": df.data_classification,
            },
        })

    threats = []
    for t in model.threats:
        threats.append({
            "id": t.id,
            "name": t.title,
            "categories": list(t.stride_ai),
            "description": t.description,
            "risk": {
                "likelihood": t.likelihood,
                "likelihoodComment": "",
                "impact": t.impact,
                "impactComment": "",
            },
            "attributes": {
                "atms_severity": t.severity,
                "atms_risk_score": t.risk_score,
                "atms_evidence_status": t.evidence_status,
                "atms_kill_chain_phase": t.kill_chain_phase,
                "atms_owasp_llm": list(t.owasp_llm),
                "atms_owasp_agentic": list(t.owasp_agentic),
                "atms_owasp_api": list(t.owasp_api),
                "atms_owasp_ml": list(t.owasp_ml),
                "atms_atlas": list(t.atlas_techniques),
                "atms_attack_cloud": list(t.attack_cloud),
                "atms_attack_enterprise": list(t.attack_enterprise),
                "atms_linddun": list(t.linddun),
                "atms_nist_ai_100_2": list(t.nist_ai_100_2),
                "atms_nist_ai_rmf": list(t.nist_ai_rmf),
                "atms_maestro_threats": list(t.maestro_threats),
                "atms_compliance_controls": list(t.compliance_controls),
                "atms_disposition": t.disposition,
                "atms_ale_low": t.ale_low,
                "atms_ale_high": t.ale_high,
            },
            "componentIds": [t.component_id],
        })

    mitigations = []
    for m in model.mitigations:
        mitigations.append({
            "id": m.id,
            "name": m.title,
            "description": m.description,
            "riskReduction": m.risk_reduction,
            "attributes": {
                "atms_effort": m.effort,
                "atms_addresses_threat_ids": list(m.addresses_threat_ids),
                "atms_framework_refs": list(m.framework_refs),
            },
        })

    out = {
        "otmVersion": "0.2.0",
        "project": {
            "id": project_id,
            "name": sys.name,
            "description": sys.description or "",
            "owner": "atms-export",
        },
        "representations": [{
            "name": "ATMS",
            "id": "atms-rep",
            "type": "code",
            "attributes": {
                "atms_version": model.tool_version,
                "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "methodology": model.summary.get("methodology", "stride-ai"),
            },
        }],
        "trustZones": trust_zones,
        "components": components,
        "dataflows": dataflows,
        "threats": threats,
        "mitigations": mitigations,
    }
    return json.dumps(out, indent=2, default=str)


__all__ = ["render_otm"]
