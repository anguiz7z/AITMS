"""STIX 2.1 bundle export.

Maps:
  - Threat → attack-pattern (with x_atms_owasp_llm and external_references for ATLAS)
  - Mitigation → course-of-action
  - AttackPath → relationship chain (predecessor → successor of attack-patterns)

This is a minimal, self-consistent STIX 2.1 bundle. It validates structurally but
isn't intended to substitute for a full STIX 2.1 producer; the goal is interop with
threat-intel platforms that ingest STIX bundles.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from ..models import AttackPath, Mitigation, Threat, ThreatModel

STIX_VERSION = "2.1"
ATMS_NS = uuid.UUID("00000000-0000-0000-0000-000000a17150")


def _stix_id(prefix: str, seed: str) -> str:
    digest = hashlib.sha256(seed.encode()).digest()
    return f"{prefix}--{uuid.UUID(bytes=digest[:16], version=5)}"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _attack_pattern(threat: Threat, now: str) -> dict[str, Any]:
    """STIX attack-pattern. Every framework ID we know about appears as
    an `external_references` entry AND is stashed in an `x_atms_*`
    custom property — the former is the standard STIX traversal key,
    the latter survives round-trip into ATMS-aware tools."""
    refs: list[dict[str, Any]] = []
    for atlas_id in threat.atlas_techniques:
        refs.append({
            "source_name": "mitre-atlas",
            "external_id": atlas_id,
            "url": f"https://atlas.mitre.org/techniques/{atlas_id}/",
        })
    for tech_id in threat.attack_cloud:
        refs.append({
            "source_name": "mitre-attack-cloud",
            "external_id": tech_id,
            "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
        })
    for tech_id in threat.attack_enterprise:
        refs.append({
            "source_name": "mitre-attack",
            "external_id": tech_id,
            "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
        })
    for owasp_id in threat.owasp_llm:
        refs.append({
            "source_name": "owasp-llm-top-10-2025",
            "external_id": owasp_id,
            "url": "https://genai.owasp.org/llm-top-10/",
        })
    for agt_id in threat.owasp_agentic:
        refs.append({
            "source_name": "owasp-agentic-asi-2026",
            "external_id": agt_id,
            "url": "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
        })
    for api_id in threat.owasp_api:
        refs.append({
            "source_name": "owasp-api-top-10-2023",
            "external_id": api_id,
            "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
        })
    for ml_id in threat.owasp_ml:
        refs.append({
            "source_name": "owasp-ml-top-10-2023",
            "external_id": ml_id,
            "url": "https://owasp.org/www-project-machine-learning-security-top-10/",
        })
    for ld_id in threat.linddun:
        refs.append({
            "source_name": "linddun",
            "external_id": ld_id,
            "url": "https://linddun.org/",
        })
    for n_id in threat.nist_ai_100_2:
        refs.append({
            "source_name": "nist-ai-100-2",
            "external_id": n_id,
            "url": "https://csrc.nist.gov/pubs/ai/100/2/e2025/final",
        })
    for cc_id in threat.compliance_controls:
        refs.append({
            "source_name": "atms-compliance",
            "external_id": cc_id,
            "url": "https://github.com/anguiz7z/AITMS/blob/main/kb/compliance/controls.yaml",
        })
    for maestro_id in threat.maestro_threats:
        refs.append({
            "source_name": "csa-maestro-2026",
            "external_id": maestro_id,
            "url": "https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro",
        })
    obj = {
        "type": "attack-pattern",
        "spec_version": STIX_VERSION,
        "id": _stix_id("attack-pattern", threat.id),
        "created": now,
        "modified": now,
        "name": threat.title,
        "description": threat.description,
        "external_references": refs,
        "x_atms_threat_id": threat.id,
        "x_atms_component_id": threat.component_id,
        "x_atms_severity": threat.severity,
        "x_atms_likelihood": threat.likelihood,
        "x_atms_impact": threat.impact,
        "x_atms_risk_score": threat.risk_score,
        "x_atms_stride_ai": threat.stride_ai,
        "x_atms_owasp_llm": threat.owasp_llm,
        "x_atms_owasp_agentic": threat.owasp_agentic,
        "x_atms_owasp_api": threat.owasp_api,
        "x_atms_owasp_ml": threat.owasp_ml,
        "x_atms_attack_cloud": threat.attack_cloud,
        "x_atms_attack_enterprise": threat.attack_enterprise,
        "x_atms_linddun": threat.linddun,
        "x_atms_nist_ai_100_2": threat.nist_ai_100_2,
        "x_atms_compliance_controls": threat.compliance_controls,
        "x_atms_kill_chain_phase": threat.kill_chain_phase,
        "x_atms_evidence_status": threat.evidence_status,
        "x_atms_evidence_count": len(threat.evidence),
        "x_atms_evidence_kev": any(e.kev for e in threat.evidence),
        "x_atms_evidence_cves": sorted({c for e in threat.evidence for c in e.cve}),
        "x_atms_disposition": threat.disposition,
        "x_atms_owner": threat.owner,
        "x_atms_due_date": threat.due_date,
        "x_atms_ale_low": threat.ale_low,
        "x_atms_ale_high": threat.ale_high,
        "x_atms_maestro_layers": threat.maestro_layers,
        "x_atms_maestro_threats": threat.maestro_threats,
    }
    # audit F018: STIX 2.1 requires external_references to have minItems:1 when
    # present. A threat with no framework refs would otherwise emit an invalid
    # `"external_references": []`; omit the key entirely instead.
    if not refs:
        obj.pop("external_references", None)
    return obj


def _course_of_action(mit: Mitigation, now: str) -> dict[str, Any]:
    refs = [
        {"source_name": ref.split(":", 1)[0], "external_id": ref.split(":", 1)[1] if ":" in ref else ref}
        for ref in mit.framework_refs
    ]
    # v0.14.3: surface the v0.14 actionability fields so downstream
    # tools can read the D3FEND mapping + validation test without
    # parsing the description.
    for d in mit.d3fend:
        refs.append({
            "source_name": "mitre-d3fend",
            "external_id": d,
            "url": f"https://d3fend.mitre.org/technique/{d}/",
        })
    obj = {
        "type": "course-of-action",
        "spec_version": STIX_VERSION,
        "id": _stix_id("course-of-action", mit.id),
        "created": now,
        "modified": now,
        "name": mit.title,
        "description": mit.description,
        "external_references": refs,
        "x_atms_mitigation_id": mit.id,
        "x_atms_effort": mit.effort,
        "x_atms_risk_reduction": mit.risk_reduction,
        "x_atms_control_family": mit.control_family,
        "x_atms_automatable": mit.automatable,
        "x_atms_validation_test": mit.validation_test,
        "x_atms_d3fend": mit.d3fend,
        "x_atms_vendor_examples": mit.vendor_examples,
    }
    # audit F018: omit external_references entirely when empty (STIX 2.1 minItems:1).
    if not refs:
        obj.pop("external_references", None)
    return obj


def _relationship(src_id: str, rel_type: str, tgt_id: str, now: str) -> dict[str, Any]:
    return {
        "type": "relationship",
        "spec_version": STIX_VERSION,
        "id": _stix_id("relationship", f"{src_id}|{rel_type}|{tgt_id}"),
        "created": now,
        "modified": now,
        "source_ref": src_id,
        "relationship_type": rel_type,
        "target_ref": tgt_id,
    }


def _campaign(path: AttackPath, now: str) -> dict[str, Any]:
    return {
        "type": "campaign",
        "spec_version": STIX_VERSION,
        "id": _stix_id("campaign", path.id),
        "created": now,
        "modified": now,
        "name": path.title,
        "description": path.narrative,
        "x_atms_path_id": path.id,
        "x_atms_difficulty": path.estimated_difficulty,
        "x_atms_business_impact": path.business_impact,
        "x_atms_tactics": path.tactics_traversed,
    }


def render_stix(model: ThreatModel) -> str:
    # v0.14.3 perf: compute the timestamp once instead of per-object.
    now = _now()
    objects: list[dict[str, Any]] = []
    threat_to_stix: dict[str, str] = {}
    mit_to_stix: dict[str, str] = {}

    for t in model.threats:
        obj = _attack_pattern(t, now)
        objects.append(obj)
        threat_to_stix[t.id] = obj["id"]

    for m in model.mitigations:
        obj = _course_of_action(m, now)
        objects.append(obj)
        mit_to_stix[m.id] = obj["id"]
        for tid in m.addresses_threat_ids:
            if tid in threat_to_stix:
                objects.append(_relationship(obj["id"], "mitigates", threat_to_stix[tid], now))

    for path in model.attack_paths:
        camp = _campaign(path, now)
        objects.append(camp)
        for tid in path.threat_ids:
            if tid in threat_to_stix:
                objects.append(_relationship(camp["id"], "uses", threat_to_stix[tid], now))

    bundle = {
        "type": "bundle",
        # Deterministic bundle id derived from the (already-deterministic)
        # object ids -- uuid.uuid4() gave every export a different id and broke
        # byte-identical output (audit F044).
        "id": _stix_id("bundle", "|".join(sorted(str(o.get("id", "")) for o in objects))),
        "spec_version": STIX_VERSION,
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, default=str)
