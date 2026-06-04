"""Nessus / Tenable `.nessus` XML parser.

The `.nessus` format is XML-on-the-wire; defusedxml parses it safely.
We extract a flat list of `Evidence` items, one per ReportItem element,
preserving CVE list, CVSS, hostname and severity.

Reference: https://docs.tenable.com/nessus/Content/NessusFileFormat.htm
"""

from __future__ import annotations

from pathlib import Path

import defusedxml.ElementTree as DET  # type: ignore[import-untyped]

from ..features import gated
from ..models import Evidence

# Nessus severity codes 0..4
_SEV_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}


@gated("evidence")
def parse_nessus(path: Path) -> list[Evidence]:
    """Parse a `.nessus` file into a list of `Evidence` objects."""
    tree = DET.parse(str(path))
    root = tree.getroot()
    out: list[Evidence] = []
    for host in root.iter("ReportHost"):
        host_name = host.attrib.get("name", "")
        for item in host.iter("ReportItem"):
            sev_code = item.attrib.get("severity", "0")
            severity = _SEV_MAP.get(sev_code, "info")
            plugin_name = item.attrib.get("pluginName", "")
            plugin_id = item.attrib.get("pluginID", "")
            cves: list[str] = []
            cvss_score: float | None = None
            description = ""
            references: list[str] = []
            for child in item:
                tag = child.tag.lower()
                txt = (child.text or "").strip()
                if tag == "cve" and txt:
                    cves.append(txt)
                elif tag in ("cvss_base_score", "cvss3_base_score") and txt:
                    try:
                        cvss_score = float(txt)
                    except ValueError:
                        pass
                elif tag == "description":
                    description = txt
                elif tag == "see_also" and txt:
                    references.extend(line.strip() for line in txt.splitlines() if line.strip())
            out.append(
                Evidence(
                    source="vapt",
                    source_type="nessus",
                    source_id=plugin_id,
                    title=plugin_name or "Nessus finding",
                    description=description[:1000],  # cap to keep reports readable
                    severity=severity,
                    cve=cves,
                    cvss=cvss_score,
                    affected_asset=host_name,
                    references=references[:8],
                )
            )
    return out


__all__ = ["parse_nessus"]
