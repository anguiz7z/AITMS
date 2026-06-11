"""End-to-end ATMS workflow orchestrator.

Pure-Python pipeline that takes a `System` description and produces a `ThreatModel`.
No LLM required. Each step is independently re-runnable.

Pipeline stages:
  1. Threat enumeration  (engines.stride_ai.enumerate_threats)
  2. ATLAS enrichment    (engines.mapping.enrich_with_atlas)
  3. Risk scoring        (engines.risk.score_threats)
  4. Attack-path search  (engines.attack_paths.find_attack_paths)
  5. Mitigation roll-up  (engines.mitigations.collect_mitigations)
  6. Cross-link threats ↔ mitigations
  7. Build summary statistics
"""

from __future__ import annotations

from collections import Counter

from .engines.ai_scope import (
    NoAIComponentsError,
    ai_provenance,
    ai_relevance,
    compute_ai_blast_radius,
    find_ai_components,
)
from .engines.aicm import compute_aicm
from .engines.attack_paths import find_attack_paths, find_choke_points
from .engines.boundaries import annotate_dataflow_boundaries, infer_boundaries
from .engines.cbra import compute_cbra
from .engines.cloud import enrich_with_cloud
from .engines.compliance import enrich_with_compliance
from .engines.controls import apply_component_controls
from .engines.d3fend import apply_d3fend_actionability
from .engines.evidence import apply_evidence
from .engines.kill_chain import assign_kill_chain_phases
from .engines.linddun import enrich_with_linddun
from .engines.maestro import enrich_with_maestro
from .engines.mapping import enrich_with_atlas
from .engines.mitigations import collect_mitigations, prioritise_mitigations
from .engines.nist_ai_100_2 import enrich_with_nist_ai_100_2
from .engines.owasp_ml import enrich_with_owasp_ml
from .engines.quantitative import portfolio_ale, score_quantitative
from .engines.reference_patterns import enrich_with_reference_patterns
from .engines.risk import recompute_risk_scores, risk_matrix_counts, score_threats
from .engines.stride_ai import enumerate_threats
from .engines.structural import propose_structural_recommendations
from .evidence.matcher import match_evidence
from .kb import get_kb
from .models import Evidence, System, ThreatModel

# v0.17.2 — type-safe stage pipeline. Importing the module triggers
# `enforce_stage_order(STAGE_ORDER)`, so any reorder mistake fails
# at import time, not under an unlucky test run.
from .pipeline import validate_threats as _validate_threats  # noqa: F401

# Methodologies the user can request from the CLI / web UI.
# - stride-ai (default): full end-to-end pipeline.
# - linddun:             privacy-only filter (drops threats without a LINDDUN tag).
# - pasta:               attacker-simulation lens — keeps threats that participate
#                        in attack paths or have likelihood >= 4, ordered by phase.
SUPPORTED_METHODOLOGIES = ("stride-ai", "linddun", "pasta")


def analyze(
    system: System,
    methodology: str = "stride-ai",
    evidence: list[Evidence] | None = None,
    prior_run: str | None = None,
    require_ai_components: bool = True,
) -> ThreatModel:
    """Run the analysis pipeline.

    Args:
        system: User-supplied system description.
        methodology: Which lens to apply.
          * ``stride-ai`` (default) — full pipeline.
          * ``pasta`` — attacker-simulation filter.
          * ``linddun`` — privacy-only lens.
        evidence: Optional list of `Evidence` rows (VAPT / red-team / TI)
          to apply over the threat model after enrichment. See
          ``atms.evidence.parse_any`` for parsing helpers.
        prior_run: Optional path to a previously-saved ThreatModel JSON
          file. When provided, dispositions + lifecycle context fields
          from the prior run are carried forward to matching threats
          by ``threat.id``. Threats marked ``mitigated`` /
          ``false_positive`` / ``duplicate`` on the prior run will
          retain that disposition and drop out of the severity_breakdown
          + ALE rollups in the summary — closes the "30 critical findings
          we already triaged keep firing every Monday" pain point. v0.17.2.
        require_ai_components: when True (default), the analysis raises
          NoAIComponentsError on systems with zero AI primaries — that's
          the legacy v0.15+ behaviour (AI-anchored scope). When False
          (v0.17.4+), pure-IT and pure-OT systems are accepted; every
          component is considered "in scope" (no blast-radius filtering)
          and threats fire from playbooks for every component type.
          This is the foundation for ATMS becoming a general-purpose
          threat modeler that just-happens-to-be-strong on AI surfaces.
    """
    if methodology not in SUPPORTED_METHODOLOGIES:
        raise ValueError(
            f"Unknown methodology {methodology!r}; expected one of {SUPPORTED_METHODOLOGIES}"
        )
    kb = get_kb()
    # Fail loud on an empty/unresolved KB instead of silently emitting a
    # worthless threat model (generic STRIDE stubs, 0/10 OWASP, 0 ATLAS,
    # junk ALE). Happens when the bundled kb/ doesn't resolve at runtime —
    # a wheel install where shared-data landed off the import path, or a
    # stale install shadowing the source. (audit 2026-06: a stale v1.0.4
    # global install produced exactly this silent-junk output.)
    if not kb.playbooks:
        from .kb import EmptyKnowledgeBaseError
        from .paths import kb_dir as _kb_dir

        raise EmptyKnowledgeBaseError(
            f"ATMS knowledge base is empty (0 playbooks) — cannot produce a "
            f"threat model. The bundled kb/ was not found at {_kb_dir()}. "
            f"Reinstall ATMS or set ATMS_KB_DIR to a valid kb/ directory; "
            f"run `atms info` to diagnose."
        )

    # 0a-pre. v0.16.3 — Bedrock Agent KB auto-synthesis. When an AWS
    # Bedrock agent component is present without an associated
    # rag_vector_store / Knowledge Base, the user is likely modelling
    # an incomplete diagram. The cross-tool comparator found that
    # missing-KB-on-Bedrock-Agent silently drops the KB-confused-deputy
    # threat class. We synthesise a placeholder `kb_auto` rag_vector_store
    # component with a dataflow from agent → kb_auto so the engine emits
    # the right threats. The placeholder is tagged in metadata so the
    # report can surface "auto-synthesised — verify on diagram."
    _maybe_synthesize_bedrock_kb(system)

    # v0.16.9 (Bug-012): empty-components case gets its own clear error.
    # Previously surfaced as the generic NoAIComponentsError, which is
    # confusing for the YAML-typo "components: []" mistake.
    if not system.components:
        raise ValueError(
            "System has no components. Add at least one component "
            "(e.g. an `llm_inference`) before calling analyze()."
        )

    # 0a. AI-scope gate (v0.15.0 — relaxed v0.17.4). When
    # `require_ai_components` is True (default), pure-IT systems are
    # rejected to keep the v0.15+ AI-anchored contract. When False,
    # the gate is bypassed and EVERY component is treated as in-scope
    # (no blast-radius filtering). General-purpose-threat-model mode.
    ai_components = find_ai_components(system)
    if require_ai_components and not ai_components:
        raise NoAIComponentsError()
    if ai_components:
        ai_blast_radius = compute_ai_blast_radius(system)
    else:
        # General-purpose mode (v0.17.4): every component maps to an
        # empty AI-provenance list. `ai_relevance` returns "adjacent"
        # for everything (component.id is in the dict's keys), so no
        # filtering kicks in. `ai_provenance` returns [] which is
        # semantically correct in pure-IT/pure-OT mode — no AI
        # component is responsible for the threat. Must be a dict, not
        # a set: downstream ai_provenance() calls .get() on it.
        ai_blast_radius = {c.id: [] for c in system.components}

    # 0b. Augment the system with inferred trust boundaries + cross-boundary
    #     dataflow flags, so the user gets reasonable defaults when they
    #     haven't explicitly modelled boundaries (especially common after
    #     .vsdx ingestion).
    inferred = infer_boundaries(system)
    if inferred:
        system.trust_boundaries.extend(inferred)
    annotate_dataflow_boundaries(system)

    # 1. Enumerate threats from playbooks per component, BUT only for
    #    components that are AI-primary (the AI/ML/agentic primitives) or
    #    AI-adjacent (in the dataflow blast radius of an AI component).
    #    Out-of-scope components emit zero threats.
    in_scope_components = [
        c for c in system.components
        if ai_relevance(c, ai_blast_radius) != "out_of_scope"
    ]
    threats = enumerate_threats(in_scope_components, kb=kb, system=system)
    # Tag each threat with the AI provenance — which AI component(s)
    # made this threat in scope. Surfaced in the report so a reviewer
    # can immediately see "this firewall threat exists because of
    # llm_inference 'gpt4_endpoint'", not as a generic IT finding.
    _component_lookup = {c.id: c for c in system.components}
    for t in threats:
        comp = _component_lookup.get(t.component_id)
        if comp is None:
            continue
        relevance = ai_relevance(comp, ai_blast_radius)
        if relevance == "out_of_scope":
            continue  # shouldn't happen — we filtered above — but defensive
        t.ai_relevance = relevance
        prov = ai_provenance(comp, ai_blast_radius)
        # Drop self-reference for AI primaries.
        prov = [p for p in prov if p != comp.id]
        t.ai_caused_by = prov

    # 1a. Deduplicate by Threat.id. Threat IDs are `{component_id}.{playbook_id}`
    #     so a duplicate here means two components share `id` (caught earlier by
    #     Pydantic) or a playbook author copy-pasted a threat without changing
    #     the inner ID. Either way we drop later occurrences and emit a warning
    #     — STIX export collapses duplicate UUIDs silently, so a duplicate
    #     downstream means lost rows in dashboards.
    seen_ids: set[str] = set()
    deduped: list = []
    dropped: list[str] = []
    for t in threats:
        if t.id in seen_ids:
            dropped.append(t.id)
            continue
        seen_ids.add(t.id)
        deduped.append(t)
    if dropped:
        import logging
        logging.getLogger(__name__).warning(
            "Dropped %d threat(s) with duplicate IDs: %s",
            len(dropped), ", ".join(sorted(set(dropped))[:5])
            + (" ..." if len(set(dropped)) > 5 else ""),
        )
    threats = deduped

    # 1b. v0.17.2 (Cycle C) — disposition carry-forward. Load the prior
    # run's ThreatModel JSON and copy disposition + lifecycle-context
    # fields onto matching threats by id. The threat still appears in
    # the new model (so a reviewer can see "previously mitigated, fired
    # again"), but its disposition stays "mitigated" and it drops out
    # of the severity_breakdown + ALE rollups via _is_active(...) below.
    if prior_run:
        _carry_forward_dispositions(threats, prior_run)

    # 2. Add suggested ATLAS techniques based on keywords
    threats = enrich_with_atlas(threats, system.components, kb=kb)

    # 2b. Add MAESTRO layer + threat IDs and OWASP-Agentic IDs
    threats = enrich_with_maestro(threats, system.components, kb=kb)

    # 2c. Add OWASP API Top 10 + MITRE ATT&CK Cloud + ATT&CK Enterprise IDs
    #     (v0.9 added cloud; v0.10 added enterprise+ICS)
    threats = enrich_with_cloud(threats, system.components, kb=kb)

    # 2d. Add LINDDUN privacy IDs (v0.10)
    threats = enrich_with_linddun(threats, system.components, kb=kb)

    # 2e. Add NIST AI 100-2 adversarial-ML taxonomy IDs (v0.11)
    threats = enrich_with_nist_ai_100_2(threats, system.components, kb=kb)

    # 2f. Tag each threat with a Cyber Kill Chain phase (v0.11)
    threats = assign_kill_chain_phases(threats)

    # 2g. OWASP ML Top 10 (2023) for non-LLM ML systems (v0.13)
    threats = enrich_with_owasp_ml(threats, system.components, kb=kb)

    # 2h. Compliance-control mapping (v0.13) — NIS2/DORA/EU AI Act/PCI/HIPAA/...
    threats = enrich_with_compliance(threats, system.components, kb=kb, system=system)

    # 2i. v0.18.5 Cycle R — Architectural-pattern rules. Per-component
    # playbooks miss topology-level threats (Internet-reachable
    # datastore, web tier without WAF, orphan vault, etc.). Evaluate
    # the rule registry against the current System and append any new
    # threats. Each rule emits at most one threat per affected
    # component; rule-derived threats use id prefix `A_` to avoid
    # collision with playbook `T_` ids.
    #
    # Scope: arch threats inherit the AI-scope contract. When require_
    # ai_components is True we only KEEP arch threats whose component
    # is in scope (no AI-out-of-scope threats leak into reports).
    from .engines.architectural_rules import evaluate_arch_rules
    arch_threats = evaluate_arch_rules(system)
    in_scope_ids = {c.id for c in in_scope_components}
    arch_threats = [
        t for t in arch_threats
        if t.component_id in in_scope_ids
    ]
    # Tag with AI provenance like the playbook threats above (preserves
    # the contract that every threat carries ai_relevance + ai_caused_by).
    for t in arch_threats:
        comp = _component_lookup.get(t.component_id)
        if comp is None:
            continue
        relevance = ai_relevance(comp, ai_blast_radius)
        if relevance == "out_of_scope":
            continue
        t.ai_relevance = relevance
        prov = ai_provenance(comp, ai_blast_radius)
        prov = [p for p in prov if p != comp.id]
        t.ai_caused_by = prov
    # audit F065: the enrichment block (2..2h above) ran BEFORE arch threats
    # existed, so a HIGH arch finding (e.g. Internet-reachable datastore)
    # shipped with empty atlas/maestro/linddun/nist/compliance + a blank
    # kill-chain phase, looking un-traceable next to fully-mapped playbook
    # threats. Run the same passes over the arch threats so they are enriched
    # identically before they join the model.
    arch_threats = enrich_with_atlas(arch_threats, system.components, kb=kb)
    arch_threats = enrich_with_maestro(arch_threats, system.components, kb=kb)
    arch_threats = enrich_with_cloud(arch_threats, system.components, kb=kb)
    arch_threats = enrich_with_linddun(arch_threats, system.components, kb=kb)
    arch_threats = enrich_with_nist_ai_100_2(arch_threats, system.components, kb=kb)
    arch_threats = assign_kill_chain_phases(arch_threats)
    arch_threats = enrich_with_owasp_ml(arch_threats, system.components, kb=kb)
    arch_threats = enrich_with_compliance(arch_threats, system.components, kb=kb, system=system)
    threats.extend(arch_threats)

    # v0.18.5 Cycle R — re-run disposition carry-forward AFTER arch
    # rules so newly-emitted A_* threats also pick up prior-run
    # dispositions. Cheap and idempotent (re-applying a disposition
    # is a no-op).
    if prior_run:
        _carry_forward_dispositions(threats, prior_run)

    # If the user asked for the privacy-only lens, drop threats that didn't
    # pick up any LINDDUN tag — they're not privacy-relevant for this run.
    if methodology == "linddun":
        threats = [t for t in threats if t.linddun]

    # 3a. Initial qualitative scoring with DREAD-AI + 5x5 severity bucket.
    threats = score_threats(threats, system.components)

    # 3b. Lower likelihood for threats already covered by deployed
    #     Component.controls (v0.13). Re-bucket severity afterwards.
    threats = apply_component_controls(threats, system.components)
    threats = score_threats(threats, system.components)

    # 3c. Apply VAPT / red-team / threat-intel evidence (v0.12). A KEV CVE the
    #     threat references, or a demonstrated red-team exploit, OVERRIDES the
    #     qualitative severity bucket above and that override survives by design.
    #     **Maintainers: do not RE-BUCKET severity after this step.** We DO
    #     refresh the numeric risk_score (recompute_risk_scores) so it stays
    #     consistent with the evidence-adjusted likelihood/impact (audit F040);
    #     that recompute deliberately does not touch severity.
    evidence_unmatched_count = 0
    if evidence:
        pairs = match_evidence(evidence, system.components)
        evidence_unmatched_count = sum(1 for _, matched in pairs if not matched)
        apply_evidence(threats, system.components, evidence, kb=kb)
        recompute_risk_scores(threats, system.components)
        # audit F068: a threat carried forward as closed (false_positive /
        # mitigated / duplicate) that THIS run's evidence now shows
        # observed/exploited must not stay hidden -- reopen it so it re-enters
        # the active severity / risk-matrix / ALE rollups.
        from .models import is_closed as _is_closed
        for t in threats:
            if _is_closed(t.disposition) and t.evidence_status in ("observed", "exploited"):
                t.disposition = "open"

    # 3d. FAIR-lite quantitative ALE per threat (v0.13).
    threats = score_quantitative(threats, system=system)

    # 3e. v0.17.2 — Pydantic re-validation checkpoint. The 12+ engine
    # calls above mutate threats in place; if any of them produced an
    # out-of-Literal value (e.g. wrong-case severity) the bug would
    # otherwise survive until report rendering. Costs <10 ms on a
    # 100-threat sample. See atms.pipeline.STAGE_ORDER for the
    # declarative ordering invariants this checkpoint anchors.
    _validate_threats(threats)

    # 4. Build attack paths. Architectural-rule threats (id prefix `A_`)
    # are FINDINGS about topology, not steps in a kill chain — exclude
    # them from path discovery. They still surface in the report; they
    # just don't get woven into multi-step attack narratives where
    # they'd warp the path selection.
    _path_threats = [t for t in threats if ".A_" not in t.id]
    attack_paths = find_attack_paths(_path_threats, system.components, system.dataflows, kb=kb)

    # PASTA lens: keep only threats that participate in attack paths or have
    # likelihood >= 4 (the attacker-priority subset). Run AFTER attack paths
    # so we can filter against the actual chains, not just per-threat heuristics.
    if methodology == "pasta":
        path_threat_ids = {tid for p in attack_paths for tid in p.threat_ids}
        threats = [
            t for t in threats
            if t.id in path_threat_ids or t.likelihood >= 4 or t.severity in ("high", "critical")
        ]
        # Re-derive paths from the surviving threat set so downstream stages see
        # a consistent picture. Same arch-exclusion as above.
        _path_threats = [t for t in threats if ".A_" not in t.id]
        attack_paths = find_attack_paths(_path_threats, system.components, system.dataflows, kb=kb)

    # 5. Collect mitigations
    mitigations = collect_mitigations(threats, system.components, kb=kb)

    # 5b. Decorate mitigations with D3FEND mapping + actionability metadata
    #     (control_family, automatable, validation_test, vendor_examples). v0.14.
    mitigations = apply_d3fend_actionability(mitigations, kb=kb)

    # 5c. v0.16.4 — Tag mitigations with reference-architecture pattern
    #     IDs (AWS SRA / AWS GenAI Lens / Azure LZA / Azure WAF AI workloads).
    #     Lets a reviewer see "this mitigation is part of AWS SRA pattern X"
    #     rather than "another generic security tip."
    mitigations = enrich_with_reference_patterns(mitigations, threats, system.components, kb=kb)

    # 6. Backlink: threat.mitigation_ids should reference Mitigation.id where applicable
    threat_to_mits: dict[str, list[str]] = {}
    for m in mitigations:
        for tid in m.addresses_threat_ids:
            threat_to_mits.setdefault(tid, []).append(m.id)
    for t in threats:
        # Replace the playbook AML.M* refs with concrete Mitigation IDs from this run
        derived = threat_to_mits.get(t.id, [])
        # Keep both: AML.M* as references in citation, derived IDs in mitigation_ids
        # sorted() not list(set()) -- set iteration order varies across
        # processes (PYTHONHASHSEED), which leaked into the report and broke
        # byte-identical output (audit F045).
        t.references = sorted(set((t.references or []) + [f"ATLAS-MIT:{x}" for x in t.mitigation_ids if x.startswith("AML.")]))
        t.mitigation_ids = derived

    # 7. Summary
    #
    # v0.17.2 (Cycle C) — `active_threats` filters out closed
    # dispositions (mitigated / false_positive / duplicate). Rollups
    # below use the active set so a reviewer who triaged 30 things last
    # week doesn't see them count as "critical" again this week. The
    # full threats[] list is preserved on the ThreatModel so reports
    # can still show closed threats (visibly marked).
    from .models import is_closed
    active_threats = [t for t in threats if not is_closed(t.disposition)]
    closed_count = len(threats) - len(active_threats)
    sev_counts = Counter(t.severity for t in active_threats)
    top_mitigations = prioritise_mitigations(mitigations, active_threats, top_n=10)
    summary = {
        "components": len(system.components),
        "threats": len(threats),
        "threats_active": len(active_threats),
        "threats_closed": closed_count,
        "attack_paths": len(attack_paths),
        "mitigations": len(mitigations),
        "severity_breakdown": dict(sev_counts),
        "risk_matrix": risk_matrix_counts(active_threats),
        # audit F066: framework coverage must be computed over the SAME active
        # set as severity_breakdown / risk_matrix / ALE -- otherwise a threat
        # the analyst marked false_positive still inflates "ATLAS techniques
        # covered" / "OWASP LLM 8/10" in the headline, contradicting the
        # active-only numbers in the same report.
        "owasp_coverage": sorted({owasp for t in active_threats for owasp in t.owasp_llm}),
        "owasp_agentic_coverage": sorted({a for t in active_threats for a in t.owasp_agentic}),
        "owasp_api_coverage": sorted({a for t in active_threats for a in t.owasp_api}),
        "atlas_coverage": sorted({a for t in active_threats for a in t.atlas_techniques}),
        "attack_cloud_coverage": sorted({a for t in active_threats for a in t.attack_cloud}),
        "attack_enterprise_coverage": sorted({a for t in active_threats for a in t.attack_enterprise}),
        "linddun_coverage": sorted({a for t in active_threats for a in t.linddun}),
        "nist_ai_100_2_coverage": sorted({a for t in active_threats for a in t.nist_ai_100_2}),
        # audit F073: surface NIST AI 600-1 (GenAI Profile) coverage. The
        # catalogue was loaded and the feature marketed, but no rollup consumed
        # threat.nist_ai_rmf, so it was always empty (structurally dead).
        "nist_ai_rmf_coverage": sorted({a for t in active_threats for a in t.nist_ai_rmf}),
        "maestro_layers": sorted({layer for t in active_threats for layer in t.maestro_layers}),
        "maestro_threats": sorted({m for t in active_threats for m in t.maestro_threats}),
        "kill_chain_breakdown": dict(Counter(t.kill_chain_phase for t in threats if t.kill_chain_phase)),
        "evidence_status_breakdown": dict(Counter(t.evidence_status for t in threats)),
        "evidence_total": sum(len(t.evidence) for t in threats),
        # Count DISTINCT physical KEV evidence rows, not (threat x evidence)
        # pairs -- one KEV finding attached to N threats is ONE hit, not N
        # (audit F008). Evidence objects are shared by reference across the
        # threats they touch, so identity de-dupes the physical rows.
        "evidence_kev_hits": len({id(e) for t in threats for e in t.evidence if e.kev}),
        "evidence_unmatched": evidence_unmatched_count,
        "owasp_ml_coverage": sorted({a for t in active_threats for a in t.owasp_ml}),
        "compliance_coverage": sorted({c for t in active_threats for c in t.compliance_controls}),
        "compliance_frameworks": sorted({
            kb.compliance_controls.get(c, {}).get("framework", "")
            for t in active_threats for c in t.compliance_controls
            if kb.compliance_controls.get(c)
        } - {""}),
        "disposition_breakdown": dict(Counter(t.disposition for t in threats)),
        "kev_meta": kb.kev_meta or {},
        "epss_meta": kb.epss_meta or {},
        "choke_points": find_choke_points(attack_paths, system.components),
        "cbra": compute_cbra(system),
        "aicm": compute_aicm(active_threats, system.components),
        "ale": portfolio_ale(active_threats),
        "priority_mitigation_ids": [m.id for m in top_mitigations],
        "methodology": methodology,
    }

    # audit F067: a general-purpose / pure-IT estate (no AI component) must not
    # advertise AI-only taxonomy coverage. Individual dual-use threats may still
    # carry an OWASP-LLM/ATLAS cross-walk tag, but presenting headline
    # "OWASP LLM 8/10 covered" / "MITRE ATLAS techniques: N" for a non-AI system
    # is a factual error a client/auditor would reject.
    if not ai_components:
        for _k in ("owasp_coverage", "owasp_agentic_coverage", "atlas_coverage",
                   "maestro_layers", "maestro_threats", "nist_ai_100_2_coverage",
                   "nist_ai_rmf_coverage"):
            summary[_k] = []

    # v0.16.5 — Propose structural architecture edits where clusters of
    # threats on the same component share a root cause that one new
    # component would close. Capped at 5; emitted as a separate report
    # section, not folded into per-component mitigations.
    structural_recs = propose_structural_recommendations(threats, system)

    return ThreatModel(
        system=system,
        threats=threats,
        attack_paths=attack_paths,
        mitigations=mitigations,
        summary=summary,
        structural_recommendations=structural_recs,
    )


def _maybe_synthesize_bedrock_kb(system: System) -> None:
    """v0.16.3: when the system has an AWS Bedrock agent but no
    `rag_vector_store` component, synthesise a placeholder Knowledge
    Base so the KB-confused-deputy threat class isn't silently
    dropped on incomplete diagrams.

    Scope is deliberately narrow:
      - Only fires when at least one ``agent`` component has
        ``metadata.vendor`` in {aws, amazon} AND
        ``metadata.product`` in {bedrock_agent, bedrock_agents}.
      - Only fires when no ``rag_vector_store`` component already
        exists (don't double-synthesise if the user modelled one).
      - The synthesised component carries
        ``metadata.auto_synthesized=True`` so report templates can
        surface "this was auto-added; verify on the diagram" and the
        component is excluded from end-user mitigation roadmaps.
    """
    from .models import Component, Dataflow

    # Find Bedrock agents
    bedrock_agents = [
        c for c in system.components
        if c.type == "agent"
        and str(c.metadata.get("vendor", "")).lower() in {"aws", "amazon"}
        and str(c.metadata.get("product", "")).lower() in {
            "bedrock_agent", "bedrock_agents", "bedrock-agent", "amazon-bedrock-agent",
        }
    ]
    if not bedrock_agents:
        return
    # Don't synthesise if any RAG store already exists
    if any(c.type == "rag_vector_store" for c in system.components):
        return

    # Synthesise a placeholder KB component + dataflow per Bedrock agent
    auto_id = "kb_auto"
    counter = 2
    existing_ids = {c.id for c in system.components}
    while auto_id in existing_ids:
        auto_id = f"kb_auto_{counter}"
        counter += 1
    kb_comp = Component(
        id=auto_id,
        name="Knowledge Base (auto-synthesised — verify on diagram)",
        type="rag_vector_store",
        trust_zone=bedrock_agents[0].trust_zone,
        description=(
            "ATMS auto-synthesised this component because a Bedrock Agent was "
            "present without a paired Knowledge Base. The KB-confused-deputy "
            "threat class would otherwise be silently dropped from analysis. "
            "If your real diagram has the KB modelled, ignore this; if not, "
            "add it so the auto-synthesis disappears on next run."
        ),
        metadata={
            "vendor": "aws",
            "product": "bedrock_knowledge_base",
            "auto_synthesized": True,
        },
    )
    system.components.append(kb_comp)
    for agent in bedrock_agents:
        # v0.16.9 (Bug-010): dropped the inert `id=...` keyword — Dataflow
        # has no `id` field and Pydantic was silently discarding it. The
        # `label` carries the auto-synthesised provenance.
        system.dataflows.append(Dataflow(
            source=agent.id,
            target=auto_id,
            label="auto-synthesised RAG dataflow — verify",
        ))


# v0.17.2 (Cycle C) — fields carried forward from a prior run.
# Keep this list tight: only the human-curated lifecycle context.
# Engine-derived fields (severity, confidence, risk_score, ale_*) are
# re-derived from scratch each run, so we don't copy those over.
_DISPOSITION_CARRY_FIELDS = (
    "disposition",
    "compensating_control_id",
    "transferred_to_vendor",
    "mitigated_by_commit",
    "deferred_until",
)

# Valid disposition values a prior-run JSON may carry (audit F058 guard).
from typing import get_args as _get_args  # noqa: E402

from .models import Disposition as _Disposition  # noqa: E402

_VALID_DISPOSITIONS = frozenset(_get_args(_Disposition))


def _carry_forward_dispositions(threats: list, prior_run_path: str) -> None:
    """Load a saved ThreatModel JSON and copy disposition + lifecycle
    context fields onto matching threats in the current run by ID.

    Threats absent from the prior run are untouched; new threats keep
    their default `open` disposition. The function logs a one-line
    summary so re-runs make the carry-forward visible to the user.

    Silently no-ops if the file can't be read / parsed — the analysis
    must not fail because a prior-run path was wrong.
    """
    import json
    import logging
    from pathlib import Path

    log = logging.getLogger(__name__)
    path = Path(prior_run_path)
    if not path.exists() or not path.is_file():
        log.warning("prior_run=%s does not exist; skipping carry-forward", path)
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("prior_run=%s could not be loaded (%s); skipping carry-forward", path, exc)
        return

    prior_threats = data.get("threats") if isinstance(data, dict) else None
    if not isinstance(prior_threats, list):
        log.warning("prior_run=%s has no `threats` list; skipping carry-forward", path)
        return

    prior_by_id: dict[str, dict] = {}
    for raw in prior_threats:
        if isinstance(raw, dict) and isinstance(raw.get("id"), str):
            prior_by_id[raw["id"]] = raw

    carried = 0
    for t in threats:
        prev = prior_by_id.get(t.id)
        if prev is None:
            continue
        # Only carry NON-DEFAULT disposition context. A prior threat
        # left at `open` doesn't need to override our default `open`.
        if prev.get("disposition", "open") == "open" and not any(
            prev.get(f) for f in _DISPOSITION_CARRY_FIELDS[1:]
        ):
            continue
        for field in _DISPOSITION_CARRY_FIELDS:
            if field not in prev or prev[field] is None:
                continue
            val = prev[field]
            # audit F058: honour the documented "must not fail" contract -- a
            # prior-run JSON with a disposition outside the current Literal (or
            # a non-string lifecycle value) must be skipped with a warning, not
            # carried onto a live threat where it aborts the run at the
            # _validate_threats checkpoint (the model has no validate_assignment).
            if field == "disposition" and val not in _VALID_DISPOSITIONS:
                log.warning("prior_run=%s: ignoring unknown disposition %r on %s", path.name, val, t.id)
                continue
            if field != "disposition" and not isinstance(val, str):
                log.warning("prior_run=%s: ignoring non-string %s=%r on %s", path.name, field, val, t.id)
                continue
            setattr(t, field, val)
        carried += 1

    if carried:
        log.info("Carried forward %d disposition(s) from %s", carried, path.name)
