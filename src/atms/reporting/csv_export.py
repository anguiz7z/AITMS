"""CSV exports — risk register + mitigation matrix."""

from __future__ import annotations

import csv
from io import StringIO

from ..models import ThreatModel


def csv_safe(value):
    """Neutralise CSV / spreadsheet formula injection (audit F047).

    A downloadable CSV deliverable embeds user-controlled component / threat
    text. A cell whose text begins with ``=``, ``+``, ``-``, ``@`` (or a tab /
    CR) is interpreted as a formula by Excel / Google Sheets -- e.g. a
    component named ``=cmd|'/c calc'!A1``. Prefix such cells with a single
    quote so they render as literal text. Non-string cells pass through.
    """
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


class _SafeWriter:
    """csv.writer wrapper that runs every cell through csv_safe (audit F047)."""

    def __init__(self, writer):
        self._w = writer

    def writerow(self, row):
        self._w.writerow([csv_safe(c) for c in row])

    def writerows(self, rows):
        for r in rows:
            self.writerow(r)


def safe_csv_writer(buf, **kwargs):
    """A csv.writer whose every cell is formula-injection sanitised (F047)."""
    return _SafeWriter(csv.writer(buf, **kwargs))


def write_csv(model: ThreatModel, kind: str = "risk_register") -> str:
    if kind == "risk_register":
        return _risk_register(model)
    if kind == "mitigations":
        return _mitigations(model)
    raise ValueError(f"unknown CSV kind: {kind}")


def _risk_register(model: ThreatModel) -> str:
    buf = StringIO()
    w = safe_csv_writer(buf, lineterminator="\n")
    w.writerow(
        [
            "threat_id",
            "component_id",
            "component_name",
            "title",
            "severity",
            "likelihood",
            "impact",
            "risk_score",
            "stride_ai",
            "owasp_llm",
            "owasp_agentic",
            "owasp_api",
            "atlas",
            "attack_cloud",
            "attack_enterprise",
            "linddun",
            "nist_ai_100_2",
            "kill_chain_phase",
            "evidence_status",
            "evidence_count",
            "evidence_kev",
            "evidence_cves",
            "owasp_ml",
            "compliance_controls",
            "disposition",
            "reviewed_by",
            "reviewed_at",
            "due_date",
            "owner",
            "ale_low",
            "ale_high",
            "maestro_layers",
            "maestro_threats",
            "mitigation_count",
        ]
    )
    for t in model.threats:
        evidence_cves: list[str] = []
        for e in t.evidence:
            evidence_cves.extend(e.cve)
        kev_hit = "yes" if any(e.kev for e in t.evidence) else ""
        w.writerow(
            [
                t.id,
                t.component_id,
                t.component_name,
                t.title,
                t.severity,
                t.likelihood,
                t.impact,
                t.risk_score,
                "|".join(t.stride_ai),
                "|".join(t.owasp_llm),
                "|".join(t.owasp_agentic),
                "|".join(t.owasp_api),
                "|".join(t.atlas_techniques),
                "|".join(t.attack_cloud),
                "|".join(t.attack_enterprise),
                "|".join(t.linddun),
                "|".join(t.nist_ai_100_2),
                t.kill_chain_phase or "",
                t.evidence_status,
                len(t.evidence),
                kev_hit,
                "|".join(sorted(set(evidence_cves))),
                "|".join(t.owasp_ml),
                "|".join(t.compliance_controls),
                t.disposition,
                t.reviewed_by,
                t.reviewed_at,
                t.due_date,
                t.owner,
                t.ale_low,
                t.ale_high,
                "|".join(t.maestro_layers),
                "|".join(t.maestro_threats),
                len(t.mitigation_ids),
            ]
        )
    return buf.getvalue()


def _mitigations(model: ThreatModel) -> str:
    buf = StringIO()
    w = safe_csv_writer(buf, lineterminator="\n")
    w.writerow([
        "mitigation_id", "title", "effort", "risk_reduction", "frameworks",
        "addresses_count",
        # v0.14 actionability columns
        "control_family", "automatable", "d3fend", "vendor_examples", "validation_test",
    ])
    for m in model.mitigations:
        w.writerow(
            [
                m.id,
                m.title,
                m.effort,
                m.risk_reduction,
                "|".join(m.framework_refs),
                len(m.addresses_threat_ids),
                m.control_family or "",
                "yes" if m.automatable else "",
                "|".join(m.d3fend),
                "|".join(m.vendor_examples),
                m.validation_test or "",
            ]
        )
    return buf.getvalue()
