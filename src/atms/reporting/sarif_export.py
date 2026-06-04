"""SARIF 2.1.0 output for `atms ci` (v0.13).

Renders the threat model as a SARIF report so GitHub code-scanning,
Azure DevOps, GitLab, and any SARIF-aware viewer can consume it.

We emit one rule per ATMS threat-id pattern (so duplicates collapse
neatly across components) and one result per concrete threat.
SARIF level is mapped from ATMS severity:

    info     → "note"
    low      → "note"
    medium   → "warning"
    high     → "error"
    critical → "error"

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ..models import ThreatModel

_SEV_TO_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def render_sarif(model: ThreatModel) -> str:
    """Return a SARIF 2.1.0 JSON string for the threat model."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    # Severity ranking so we can keep the *most severe* rule definition
    # when several threats share a local id across components. v0.14.0
    # used first-occurrence-wins, which silently overrode high/critical
    # rule details with whatever the first-encountered threat had.
    _SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for t in model.threats:
        rule_id = t.id.split(".", 1)[-1] if "." in t.id else t.id
        existing = rules.get(rule_id)
        # GitHub code-scanning rejects any SARIF rule whose
        # `shortDescription.text` exceeds 1024 chars, and the
        # ECMAScript-style truncation kicks in well before that for
        # sensible UX. We cap at 256 to match the convention used by
        # CodeQL / Semgrep / Trivy. `fullDescription` already capped at
        # 1000 below.
        short_text = (t.title or rule_id)[:256]
        candidate = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": short_text},
            "fullDescription": {"text": (t.description or t.title)[:1000]},
            "defaultConfiguration": {"level": _SEV_TO_LEVEL.get(t.severity, "warning")},
            "properties": {
                "tags": (
                    list(t.stride_ai)
                    + list(t.owasp_llm)
                    + list(t.owasp_agentic)
                    + list(t.atlas_techniques)
                    + ["security", "atms"]
                ),
                "severity": t.severity,
            },
        }
        if existing is None:
            rules[rule_id] = candidate
        else:
            # Promote on strictly higher severity.
            existing_sev = existing.get("properties", {}).get("severity", "medium")
            if _SEV_RANK.get(t.severity, 0) > _SEV_RANK.get(existing_sev, 0):
                rules[rule_id] = candidate
            else:
                # Even if not promoting, merge tags so we don't lose
                # framework references that only appear on one variant.
                existing_tags = set(existing["properties"].get("tags") or [])
                existing_tags.update(candidate["properties"].get("tags") or [])
                existing["properties"]["tags"] = sorted(existing_tags)
        results.append({
            "ruleId": rule_id,
            "level": _SEV_TO_LEVEL.get(t.severity, "warning"),
            "message": {
                "text": (
                    f"{t.title} (component: {t.component_name or t.component_id}; "
                    f"likelihood={t.likelihood}, impact={t.impact}, "
                    f"risk_score={t.risk_score}, status={t.evidence_status})"
                ),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"system://component/{t.component_id}"},
                },
                "logicalLocations": [{
                    "name": t.component_name or t.component_id,
                    "kind": "component",
                }],
            }],
            "properties": {
                "atms_severity": t.severity,
                "atms_likelihood": t.likelihood,
                "atms_impact": t.impact,
                "atms_risk_score": t.risk_score,
                "atms_evidence_status": t.evidence_status,
                "atms_kill_chain": t.kill_chain_phase,
                "atms_compliance_controls": list(t.compliance_controls),
                "cve": [c for e in t.evidence for c in e.cve],
                "kev": any(e.kev for e in t.evidence),
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ATMS",
                    "version": model.tool_version,
                    "informationUri": "https://github.com/anguiz7z/AITMS",
                    "rules": list(rules.values()),
                },
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(UTC).isoformat(timespec="seconds"),
            }],
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, default=str)


__all__ = ["render_sarif"]
