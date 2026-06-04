"""On-demand CVE lookup via NVD or OSV (v0.13).

Strict opt-in network call. The deterministic core never invokes this;
users run ``atms cve-lookup CVE-2024-3400`` explicitly.

Tries NVD 2.0 first (richer metadata, no key needed), falls back to
OSV.dev for OSS-package coverage. Returns a normalised
``CveLookupResult`` regardless of source so callers don't branch on
upstream format.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .refresh import DEFAULT_TIMEOUT, USER_AGENT

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
OSV_URL = "https://api.osv.dev/v1/vulns/{cve}"


@dataclass
class CveLookupResult:
    cve: str
    source: str = ""  # "nvd" | "osv" | ""
    title: str = ""
    description: str = ""
    severity: str = ""  # info | low | medium | high | critical
    cvss: float | None = None
    cvss_vector: str = ""
    cwe: list[str] = field(default_factory=list)
    affected: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published: str = ""
    last_modified: str = ""

    def to_dict(self) -> dict:
        return {
            "cve": self.cve, "source": self.source, "title": self.title,
            "description": self.description, "severity": self.severity,
            "cvss": self.cvss, "cvss_vector": self.cvss_vector,
            "cwe": list(self.cwe), "affected": list(self.affected),
            "references": list(self.references),
            "published": self.published, "last_modified": self.last_modified,
        }


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _http_get_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _from_nvd(cve: str, raw: dict) -> CveLookupResult:
    res = CveLookupResult(cve=cve, source="nvd")
    vulns = raw.get("vulnerabilities") or []
    if not vulns:
        return res
    cve_obj = (vulns[0] or {}).get("cve") or {}
    descriptions = cve_obj.get("descriptions") or []
    res.description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )
    res.title = res.description.split(".")[0][:200]
    metrics = cve_obj.get("metrics") or {}
    # Prefer CVSS 3.1 → 3.0 → 2.0
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(k) or []
        if rows:
            data = rows[0].get("cvssData") or {}
            try:
                res.cvss = float(data.get("baseScore", 0))
                res.cvss_vector = data.get("vectorString", "")
                res.severity = (rows[0].get("baseSeverity") or _cvss_to_severity(res.cvss)).lower()
            except (TypeError, ValueError):
                pass
            break
    weaknesses = cve_obj.get("weaknesses") or []
    cwe_ids: list[str] = []
    for w in weaknesses:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-"):
                cwe_ids.append(v)
    res.cwe = sorted(set(cwe_ids))
    res.references = [
        ref.get("url", "")
        for ref in (cve_obj.get("references") or [])
        if isinstance(ref, dict) and ref.get("url")
    ][:8]
    cpe_set: set[str] = set()
    for cfg in cve_obj.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if isinstance(match, dict) and match.get("criteria"):
                    cpe_set.add(match["criteria"])
    res.affected = sorted(cpe_set)[:12]
    res.published = cve_obj.get("published", "")
    res.last_modified = cve_obj.get("lastModified", "")
    return res


def _from_osv(cve: str, raw: dict) -> CveLookupResult:
    res = CveLookupResult(cve=cve, source="osv")
    res.title = raw.get("summary", "")
    res.description = raw.get("details", "")
    res.published = raw.get("published", "")
    res.last_modified = raw.get("modified", "")
    res.references = [
        r.get("url", "") for r in raw.get("references") or []
        if isinstance(r, dict) and r.get("url")
    ][:8]
    affected: list[str] = []
    for a in raw.get("affected") or []:
        pkg = a.get("package") or {}
        ecosys = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        if ecosys and name:
            affected.append(f"{ecosys}:{name}")
    res.affected = sorted(set(affected))[:12]
    sevs = raw.get("severity") or []
    for s in sevs:
        score_text = str(s.get("score", ""))
        if "/" in score_text:
            res.cvss_vector = score_text
        # Try base-score sniff
        for tok in score_text.split("/"):
            if tok.startswith(("CVSS:3.1:", "CVSS:3.0:")):
                continue
            try:
                v = float(tok)
                res.cvss = v
                res.severity = _cvss_to_severity(v)
                break
            except ValueError:
                continue
    return res


def cve_lookup(cve: str, *, timeout: int = DEFAULT_TIMEOUT) -> CveLookupResult:
    """Look up a CVE via NVD; fall back to OSV.

    Raises ``RuntimeError`` if both sources fail; never returns ``None``.
    """
    cve = cve.strip().upper()
    if not cve.startswith("CVE-"):
        raise ValueError(f"Not a CVE id: {cve!r}")
    last_err: Exception | None = None
    try:
        raw = _http_get_json(NVD_URL.format(cve=urllib.parse.quote(cve)), timeout=timeout)
        res = _from_nvd(cve, raw)
        if res.description or res.cvss is not None:
            return res
    except urllib.error.URLError as e:
        last_err = e
    try:
        raw = _http_get_json(OSV_URL.format(cve=urllib.parse.quote(cve)), timeout=timeout)
        res = _from_osv(cve, raw)
        if res.description or res.cvss is not None or res.affected:
            return res
    except urllib.error.URLError as e:
        last_err = e
    if last_err:
        raise RuntimeError(f"Could not look up {cve}: {last_err}")
    # Both sources reachable but neither knew the CVE.
    return CveLookupResult(cve=cve, source="", description="(not found in NVD or OSV)")


__all__ = ["cve_lookup", "CveLookupResult", "NVD_URL", "OSV_URL"]
