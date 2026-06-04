"""SARIF 2.1.0 parser.

SARIF (Static Analysis Results Interchange Format) is the format GitHub
code-scanning + most modern SAST/DAST tools (CodeQL, Semgrep, Trivy,
Snyk, Bandit, Brakeman) export. One file may contain multiple "runs",
each with its own tool + results.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path

from ..features import gated
from ..models import Evidence

# SARIF severity / level mapping → ATMS severity
_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _severity_from(rule: dict | None, result: dict) -> str:
    # SARIF "level" is the result-level; "defaultConfiguration.level" is rule-level.
    level = result.get("level") or (rule or {}).get("defaultConfiguration", {}).get("level", "warning")
    return _LEVEL_MAP.get(str(level).lower(), "medium")


@gated("evidence")
def parse_sarif(path: Path) -> list[Evidence]:
    """Parse a SARIF .sarif / .json file into a list of `Evidence` objects."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: list[Evidence] = []
    for run in raw.get("runs", []) or []:
        tool = run.get("tool", {}).get("driver", {})
        tool_name = tool.get("name", "sarif")
        rules_by_id = {r.get("id"): r for r in tool.get("rules", []) or [] if r.get("id")}
        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId", "")
            rule = rules_by_id.get(rule_id)
            sev = _severity_from(rule, result)
            msg = result.get("message", {}).get("text", "")
            # Affected asset: first physical-location URI
            asset = ""
            locs = result.get("locations") or []
            if locs:
                phys = (locs[0] or {}).get("physicalLocation", {})
                asset = (phys.get("artifactLocation") or {}).get("uri", "")
            cve_list: list[str] = []
            for tag in (rule or {}).get("properties", {}).get("tags", []) or []:
                if isinstance(tag, str) and tag.upper().startswith("CVE-"):
                    cve_list.append(tag.upper())
            references: list[str] = []
            help_uri = (rule or {}).get("helpUri")
            if help_uri:
                references.append(help_uri)
            out.append(
                Evidence(
                    source="vapt",
                    source_type=f"sarif:{tool_name}".lower(),
                    source_id=rule_id,
                    title=(rule or {}).get("shortDescription", {}).get("text") or rule_id or "SARIF finding",
                    description=msg[:1000],
                    severity=sev,
                    cve=cve_list,
                    affected_asset=asset,
                    references=references,
                )
            )
    return out


__all__ = ["parse_sarif"]
