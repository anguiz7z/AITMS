"""Cross-walk mitigations to CSP reference-architecture patterns (v0.16.4).

ATMS produces structured mitigations per threat. The security-architect
expert critique of v0.15.1 (finding A-04) flagged that none of these
mitigations were tagged with the equivalent reference-architecture
control:

> "Every AWS component has a canonical control in AWS Security Reference
> Architecture (SRA), AWS Well-Architected GenAI Lens, or Bedrock-secure-
> by-default. Every Azure component has a counterpart in Azure Landing
> Zone Architecture / Azure Well-Architected AI workloads. ATMS tags
> none of its mitigations with the equivalent SRA / LZA ID, so a
> reviewer can't tell which mitigations are the delta versus what the
> platform already gives them by default."

This enricher closes that gap. It reads `kb/reference_patterns/*.yaml`
and tags each Mitigation with the matching reference-architecture
pattern IDs. The match is keyword-based + component-type overlap +
optional vendor-context filtering (AWS patterns only apply to threats
on components with `metadata.vendor` in {AWS, Amazon} or component
type that's intrinsically AWS-bearing).
"""

from __future__ import annotations

from ..kb import KnowledgeBase, get_kb
from ..models import Component, Mitigation, Threat


def enrich_with_reference_patterns(
    mitigations: list[Mitigation],
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
    max_per_mitigation: int = 3,
) -> list[Mitigation]:
    """Tag each Mitigation with up to ``max_per_mitigation`` reference-
    architecture pattern IDs that materially relate to it.

    The match is "reasonable hit" rather than "perfect overlap":
      - Mitigation's title + description tokens overlap the pattern's
        keyword list, AND
      - Some component in the threats the mitigation addresses has a
        component_type listed in the pattern's `applies_to_component_types`.

    AWS patterns are filtered to AWS-bearing components; Azure to
    Azure-bearing — using either component_type heuristics (AKS / EKS /
    VPC etc.) or `metadata.vendor`. We bias toward false negatives
    (missing a tag) rather than false positives (tagging the wrong
    cloud), because the latter erodes trust faster.
    """
    kb = kb or get_kb()
    if not kb.reference_patterns:
        return mitigations

    threats_by_id = {t.id: t for t in threats}
    components_by_id = {c.id: c for c in components}

    # Pre-compute per-mitigation context: addressed threats + components
    for mit in mitigations:
        if mit.reference_patterns:
            continue  # author has populated explicitly — preserve
        haystack = (mit.title + " " + mit.description).lower()
        ctx_threats = [threats_by_id.get(tid) for tid in mit.addresses_threat_ids
                       if tid in threats_by_id]
        ctx_components = [components_by_id.get(t.component_id) for t in ctx_threats
                          if t is not None and t.component_id in components_by_id]
        ctx_components = [c for c in ctx_components if c is not None]
        if not ctx_components:
            continue
        ctx_types = {c.type for c in ctx_components}

        # Vendor of the threat's components — used to filter AWS-only
        # patterns out of Azure-only architectures and vice versa.
        ctx_vendors: set[str] = set()
        for c in ctx_components:
            v = str((c.metadata or {}).get("vendor", "")).lower()
            if v:
                ctx_vendors.add(v)

        scored: list[tuple[str, int]] = []
        for pattern in kb.reference_patterns:
            pid = pattern.get("id")
            if not pid or pid in mit.reference_patterns:
                continue
            applies = set(pattern.get("applies_to_component_types") or [])
            if applies and not (applies & ctx_types):
                continue

            framework = (pattern.get("framework") or "").lower()
            # Cloud-specific filtering: don't tag AWS_SRA on a system
            # whose components only declare Azure vendor, and vice versa.
            if ctx_vendors:
                aws_vendors = {"aws", "amazon"}
                azure_vendors = {"azure", "microsoft", "ms"}
                gcp_vendors = {"gcp", "google"}
                if framework.startswith("aws_") and ctx_vendors & (azure_vendors | gcp_vendors) and not (ctx_vendors & aws_vendors):
                    continue
                if framework.startswith("azure_") and ctx_vendors & (aws_vendors | gcp_vendors) and not (ctx_vendors & azure_vendors):
                    continue
            else:
                # v0.16.9 (Bug-009): when no explicit vendor metadata exists,
                # infer vendor from the haystack tokens so we don't tag
                # AWS+Azure patterns on the SAME mitigation. Bias to false-
                # negative: if no token hits, skip cloud-specific patterns.
                has_aws_tokens = any(
                    tok in haystack for tok in ("bedrock", "sagemaker", "aws ", " iam ", "kendra", "s3 ", "kms")
                )
                has_azure_tokens = any(
                    tok in haystack for tok in ("azure", "foundry", "openai service", "entra", "synapse")
                )
                has_gcp_tokens = any(
                    tok in haystack for tok in ("vertex", "bigquery", "gcp ", " gke ")
                )
                # Each cloud family must match its own tokens AND not the others'.
                if framework.startswith("aws_") and not (has_aws_tokens and not (has_azure_tokens or has_gcp_tokens)):
                    continue
                if framework.startswith("azure_") and not (has_azure_tokens and not (has_aws_tokens or has_gcp_tokens)):
                    continue
                if framework.startswith("gcp_") and not (has_gcp_tokens and not (has_aws_tokens or has_azure_tokens)):
                    continue

            # Keyword match — at least one keyword in haystack
            keywords = pattern.get("keywords") or []
            matches = 0
            for kw in keywords:
                if not isinstance(kw, str) or len(kw) < 3:
                    continue
                if kw.lower() in haystack:
                    matches += 1
            if matches >= 1:
                # AI-specific patterns score higher when the threat is
                # an AI primary; generic security patterns score equal.
                score = matches + (1 if pattern.get("ai_specific") else 0)
                scored.append((pid, score))

        scored.sort(key=lambda t: -t[1])
        for pid, _ in scored[:max_per_mitigation]:
            if pid not in mit.reference_patterns:
                mit.reference_patterns.append(pid)
    return mitigations


__all__ = ["enrich_with_reference_patterns"]
