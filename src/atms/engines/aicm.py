"""CSA AI Controls Matrix (AICM) alignment — control-domain + shared-responsibility
ownership mapping.

AICM v1.0.3 (CSA, 2025-07, updated 2025-10) defines 243 control objectives across
18 domains, extending the CSA Cloud Controls Matrix, and tags each control across
5 dimensions — including Control Applicability & Ownership across the AI
shared-responsibility actors. ATMS maps each threat to the relevant AICM control
DOMAIN and the responsible ACTOR, so a reviewer sees which party owns the control
for each risk.

Honest scope: this maps to AICM's *domain + ownership structure*, not the
proprietary 243 control objective texts/IDs (those are in the official AICM
download). Deterministic, no LLM.
"""

from __future__ import annotations

from ..models import Component, Threat

# AICM control domains relevant to AI systems. CCM-base abbreviations (CSA CCM v4)
# plus MOS = the AI/model-security control group AICM adds.
DOMAINS: dict[str, str] = {
    "MOS": "Model & Output Security",
    "AIS": "Application & Interface Security",
    "DSP": "Data Security & Privacy",
    "IAM": "Identity & Access Management",
    "LOG": "Logging & Monitoring",
    "TVM": "Threat & Vulnerability Management",
    "STA": "Supply Chain, Transparency & Accountability",
    "GRC": "Governance, Risk & Compliance",
}

# AI shared-responsibility actors (AICM ownership dimension) by component type.
_OWNER_BY_TYPE: dict[str, str] = {
    "llm_inference": "Model Provider",
    "model_registry": "Model Provider",
    "agent": "Orchestrated Service Provider",
    "container_runtime": "Orchestrated Service Provider",
    "container_orchestrator": "Orchestrated Service Provider",
    "rag_vector_store": "Application Provider",
    "tool": "Application Provider",
    "serverless_function": "Application Provider",
    "api_gateway": "Application Provider",
    "object_storage": "Cloud Service Provider",
    "cloud_compute": "Cloud Service Provider",
    "batch_compute": "Cloud Service Provider",
    "load_balancer": "Cloud Service Provider",
    "network_segment": "Cloud Service Provider",
    "database": "AI Customer",
    "nosql_database": "AI Customer",
    "data_source": "AI Customer",
    "user": "AI Customer",
}


def _domains_for_threat(threat: Threat) -> list[str]:
    owasp = set(threat.owasp_llm or [])
    stride = {str(s).lower() for s in (threat.stride_ai or [])}
    out: set[str] = set()
    # OWASP LLM is the most reliable signal.
    if owasp & {"LLM01:2025", "LLM05:2025", "LLM07:2025"}:   # injection / output handling / sys-prompt
        out |= {"AIS", "MOS"}
    if owasp & {"LLM02:2025", "LLM08:2025"}:                  # sensitive disclosure / vector weaknesses
        out |= {"DSP"}
    if owasp & {"LLM03:2025", "LLM04:2025"}:                  # supply chain / poisoning
        out |= {"STA", "DSP"}
    if owasp & {"LLM06:2025"}:                                # excessive agency
        out |= {"IAM", "MOS"}
    if owasp & {"LLM09:2025"}:                                # misinformation
        out |= {"MOS", "GRC"}
    if owasp & {"LLM10:2025"}:                                # unbounded consumption
        out |= {"TVM", "LOG"}
    # STRIDE-AI fallbacks.
    if "information_disclosure" in stride:
        out |= {"DSP"}
    if "elevation_of_privilege" in stride or "spoofing" in stride:
        out |= {"IAM"}
    if "denial_of_service" in stride:
        out |= {"TVM"}
    if "tampering" in stride:
        out |= {"AIS"}
    if not out:
        out |= {"TVM"}  # default: threat-and-vuln management
    return sorted(out)


def compute_aicm(threats: list[Threat], components: list[Component]) -> dict:
    """Map threats to AICM control domains + the responsible shared-responsibility actor."""
    type_by_id = {c.id: c.type for c in components}
    domain_counts: dict[str, int] = {}
    owner_counts: dict[str, int] = {}
    for t in threats:
        for d in _domains_for_threat(t):
            domain_counts[d] = domain_counts.get(d, 0) + 1
        owner = _OWNER_BY_TYPE.get(type_by_id.get(t.component_id, ""), "AI Customer")
        owner_counts[owner] = owner_counts.get(owner, 0) + 1
    return {
        "method": "CSA AI Controls Matrix (AICM) v1.0.3",
        "domains": [
            {"id": d, "name": DOMAINS[d], "threats": n}
            for d, n in sorted(domain_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "ownership": [
            {"actor": a, "threats": n}
            for a, n in sorted(owner_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "note": "Mapped to AICM's 18-domain / 5-dimension structure incl. shared-responsibility ownership; the canonical 243 control objective IDs are in the official AICM v1.0.3 download.",
        "source": "CSA AI Controls Matrix v1.0.3 (2025-07, updated 2025-10)",
    }
