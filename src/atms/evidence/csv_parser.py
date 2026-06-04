"""Generic CSV parser for findings dumps.

Many shops export their pentest / vuln-scan findings to CSV. The schema
is never standardised, so we sniff column headers from a small set of
common conventions:

  CVE / cve / CVE-ID            → Evidence.cve
  Severity / severity / Risk    → Evidence.severity
  CVSS / cvss / cvss_score      → Evidence.cvss
  Asset / asset / Host / IP     → Evidence.affected_asset
  Description / description     → Evidence.description
  Title / Name / plugin_name    → Evidence.title
  ID / id / finding_id          → Evidence.source_id
  References / url              → Evidence.references

Severity strings are normalised case-insensitively to info / low /
medium / high / critical. Numeric severities (1..5 or CVSS 0..10) are
mapped via simple cutoffs.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..features import gated
from ..models import Evidence


def _norm(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


# Column-alias map: (set of normalised headers we recognise) -> output field.
_ALIASES: list[tuple[str, set[str]]] = [
    ("cve", {"cve", "cveid", "cves"}),
    ("severity", {"severity", "risk", "risklevel", "criticality"}),
    ("cvss", {"cvss", "cvssscore", "cvssbasescore", "cvss3", "cvss3basescore"}),
    ("epss", {"epss", "epssscore", "epssprobability"}),
    ("asset", {"asset", "host", "hostname", "ip", "ipaddress", "target", "url"}),
    ("description", {"description", "desc", "details", "summary", "synopsis"}),
    ("title", {"title", "name", "pluginname", "vulnerability", "issue", "finding"}),
    ("id", {"id", "findingid", "ruleid", "pluginid", "cveid"}),
    ("references", {"references", "url", "see_also", "seealso", "links"}),
]


def _resolve_columns(fieldnames: list[str]) -> dict[str, str]:
    """Map output field → original column name, picking the first alias match."""
    norm_to_orig = {_norm(c): c for c in fieldnames}
    out: dict[str, str] = {}
    for field, alias_set in _ALIASES:
        for alias in alias_set:
            if alias in norm_to_orig and field not in out:
                out[field] = norm_to_orig[alias]
                break
    return out


def _normalise_severity(value: str) -> str:
    if not value:
        return "medium"
    v = value.strip().lower()
    if v in ("critical", "crit", "5"):
        return "critical"
    if v in ("high", "h", "4"):
        return "high"
    if v in ("medium", "med", "moderate", "m", "3"):
        return "medium"
    if v in ("low", "l", "2"):
        return "low"
    if v in ("info", "informational", "informational only", "1", "0", "none"):
        return "info"
    # Try parsing as CVSS score (0..10)
    try:
        f = float(v)
        if f >= 9.0:
            return "critical"
        if f >= 7.0:
            return "high"
        if f >= 4.0:
            return "medium"
        if f > 0:
            return "low"
        return "info"
    except ValueError:
        return "medium"


@gated("evidence")
def parse_csv(path: Path) -> list[Evidence]:
    """Parse a generic findings CSV into a list of Evidence."""
    text = path.read_text(encoding="utf-8-sig")
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return []
    cols = _resolve_columns(list(reader.fieldnames))
    out: list[Evidence] = []
    for row in reader:
        cve_field = (row.get(cols.get("cve", "")) or "").strip()
        cve_list = [c.strip().upper() for c in cve_field.replace(";", ",").split(",") if c.strip()]
        cvss_raw = (row.get(cols.get("cvss", "")) or "").strip()
        cvss_score: float | None = None
        try:
            cvss_score = float(cvss_raw) if cvss_raw else None
        except ValueError:
            cvss_score = None
        epss_raw = (row.get(cols.get("epss", "")) or "").strip()
        epss_score: float | None = None
        try:
            epss_score = float(epss_raw) if epss_raw else None
        except ValueError:
            epss_score = None
        title = (row.get(cols.get("title", "")) or "").strip() or "CSV finding"
        out.append(
            Evidence(
                source="vapt",
                source_type="csv",
                source_id=(row.get(cols.get("id", "")) or "").strip(),
                title=title,
                description=(row.get(cols.get("description", "")) or "").strip()[:1000],
                severity=_normalise_severity(row.get(cols.get("severity", "")) or ""),
                cve=cve_list,
                cvss=cvss_score,
                epss=epss_score,
                affected_asset=(row.get(cols.get("asset", "")) or "").strip(),
                references=[
                    s.strip() for s in (row.get(cols.get("references", "")) or "").split(",")
                    if s.strip()
                ][:4],
            )
        )
    return out


__all__ = ["parse_csv"]
