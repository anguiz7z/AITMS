"""Trust-boundary inference.

A 'trust boundary' is the line between two zones with different security
properties — different network segments, identity contexts, tenancy models, etc.
.vsdx diagrams don't carry the concept directly, so users either declare
boundaries by hand in the YAML, or rely on this engine to derive them from
component `trust_zone` fields.

Rule: for every pair of distinct `trust_zone` values present on components, we
infer one boundary, with `components_inside` = the smaller side and
`components_outside` = the larger side. Boundary type is chosen from the zone
labels via heuristics (network / identity / deployment_zone).

Derived boundaries are appended to the system's existing list — never replace.
The original user-declared boundaries always take precedence.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import Component, System, TrustBoundary, TrustBoundaryType

# Map common trust-zone labels to boundary types
ZONE_TYPE_HINTS: dict[str, TrustBoundaryType] = {
    "internet": "network",
    "dmz": "network",
    "corp_dmz": "network",
    "corp_internal": "network",
    "external_provider": "network",
    "vpc": "network",
    "training_vpc": "deployment_zone",
    "production": "deployment_zone",
    "staging": "deployment_zone",
    "default": "network",
}


def _boundary_type_for(zone_a: str, zone_b: str) -> TrustBoundaryType:
    a = ZONE_TYPE_HINTS.get(zone_a, "network")
    b = ZONE_TYPE_HINTS.get(zone_b, "network")
    # If both sides have a deployment-zone hint, call it deployment_zone
    if a == "deployment_zone" or b == "deployment_zone":
        return "deployment_zone"
    return a


def infer_boundaries(system: System) -> list[TrustBoundary]:
    """Return a list of inferred TrustBoundary objects (does NOT mutate `system`)."""
    by_zone: dict[str, list[str]] = defaultdict(list)
    for comp in system.components:
        by_zone[comp.trust_zone].append(comp.id)

    if len(by_zone) < 2:
        return []

    # Skip zones the user already declared boundaries around — avoid duplicates.
    declared_pairs = set()
    for tb in system.trust_boundaries:
        inside = frozenset(tb.components_inside)
        outside = frozenset(tb.components_outside)
        declared_pairs.add((inside, outside))

    inferred: list[TrustBoundary] = []
    zones = sorted(by_zone.keys())
    for i, zone in enumerate(zones):
        inside_ids = sorted(by_zone[zone])
        outside_ids = sorted(
            cid for other_zone, cids in by_zone.items() if other_zone != zone for cid in cids
        )
        if not outside_ids:
            continue
        if (frozenset(inside_ids), frozenset(outside_ids)) in declared_pairs:
            continue
        # Pick the dominant 'opposite' zone for the boundary-type hint
        biggest_other = max(
            (z for z in zones if z != zone), key=lambda z: len(by_zone[z])
        )
        bt = _boundary_type_for(zone, biggest_other)
        inferred.append(
            TrustBoundary(
                id=f"tb_inferred_{zone}",
                type=bt,
                components_inside=inside_ids,
                components_outside=outside_ids,
                description=(
                    f"Auto-derived from trust_zone='{zone}' vs '{biggest_other}'. "
                    "Refine by hand if the wrong components ended up on each side."
                ),
            )
        )
    return inferred


def annotate_dataflow_boundaries(system: System) -> int:
    """Set `crosses_boundary=True` on any dataflow whose source.trust_zone differs
    from target.trust_zone. Returns the number of dataflows updated."""
    by_id: dict[str, Component] = {c.id: c for c in system.components}
    updated = 0
    for df in system.dataflows:
        src = by_id.get(df.source)
        tgt = by_id.get(df.target)
        if src is None or tgt is None:
            continue
        if src.trust_zone != tgt.trust_zone and not df.crosses_boundary:
            df.crosses_boundary = True
            updated += 1
    return updated


__all__ = ["infer_boundaries", "annotate_dataflow_boundaries"]
