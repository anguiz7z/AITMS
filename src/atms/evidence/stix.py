"""STIX 2.1 bundle parser.

STIX 2.1 (https://oasis-open.github.io/cti-documentation/stix/intro) is
the open standard for sharing threat intelligence. ATMS already exports
STIX (see reporting/stix.py); this is the inverse path — ingest a feed
and convert each indicator / vulnerability / attack-pattern object into
an `Evidence` row.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..features import gated
from ..models import Evidence


# Map STIX 2.1 score-extension indicators to ATMS severity buckets.
# Falls back to medium when nothing useful is set.
def _severity_from(obj: dict) -> str:
    confidence = obj.get("confidence")
    if isinstance(confidence, int):
        if confidence >= 90:
            return "critical"
        if confidence >= 70:
            return "high"
        if confidence >= 40:
            return "medium"
        return "low"
    labels = [str(l).lower() for l in obj.get("labels", []) or []]
    for l in labels:
        if l in ("critical", "high", "medium", "low", "info"):
            return l
    return "medium"


@gated("evidence")
def parse_stix(path: Path) -> list[Evidence]:
    """Parse a STIX 2.1 bundle (.json) into Evidence objects."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    objects = raw.get("objects") if isinstance(raw, dict) else raw
    if objects is None:
        objects = [raw]
    out: list[Evidence] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        otype = obj.get("type", "")
        if otype not in ("indicator", "vulnerability", "attack-pattern", "malware", "tool"):
            continue
        title = obj.get("name") or obj.get("pattern") or otype
        desc = obj.get("description", "")
        severity = _severity_from(obj)
        cve_list: list[str] = []
        for ext in obj.get("external_references", []) or []:
            ref_id = (ext or {}).get("external_id", "")
            if isinstance(ref_id, str) and ref_id.upper().startswith("CVE-"):
                cve_list.append(ref_id.upper())
        affected = obj.get("indicator_types") or obj.get("malware_types") or []
        out.append(
            Evidence(
                source="ti",
                source_type=f"stix:{otype}",
                source_id=obj.get("id", ""),
                title=str(title)[:200],
                description=str(desc)[:1000],
                severity=severity,
                cve=cve_list,
                affected_asset=", ".join(str(x) for x in affected[:4]),
                observed_at=str(obj.get("created", ""))[:25],
                references=[
                    e.get("url", "") for e in obj.get("external_references", []) or []
                    if isinstance(e, dict) and e.get("url")
                ][:6],
            )
        )
    return out


__all__ = ["parse_stix"]
