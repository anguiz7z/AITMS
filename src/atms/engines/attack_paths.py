"""Attack-path generation via NetworkX graph traversal.

Build a directed graph where:
  - Nodes are (component, threat) pairs
  - Edges connect (a, b) if `a.component` has a dataflow to `b.component`,
    AND the ATLAS tactics traversed are in valid kill-chain order.

Then enumerate top-N paths ranked by `exploitability * impact`, where
exploitability ≈ likelihood and impact ≈ business impact along the path.
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx

from ..kb import KnowledgeBase, get_kb
from ..models import AttackPath, Component, Dataflow, Threat
from ._ids import stable_id

# Canonical ATLAS tactic kill-chain ordering (authoritative MITRE atlas-data
# matrix order, verified 2026-05-30; missing tactics treated as wildcard).
TACTIC_ORDER = [
    "AML.TA0002",  # Reconnaissance
    "AML.TA0003",  # Resource Development
    "AML.TA0004",  # Initial Access
    "AML.TA0000",  # AI Model Access
    "AML.TA0005",  # Execution
    "AML.TA0006",  # Persistence
    "AML.TA0012",  # Privilege Escalation
    "AML.TA0007",  # Defense Evasion
    "AML.TA0013",  # Credential Access
    "AML.TA0008",  # Discovery
    "AML.TA0009",  # Collection
    "AML.TA0001",  # AI Attack Staging
    "AML.TA0014",  # Command and Control
    "AML.TA0010",  # Exfiltration
    "AML.TA0011",  # Impact
    "AML.TA0015",  # Lateral Movement
]
TACTIC_RANK = {tid: i for i, tid in enumerate(TACTIC_ORDER)}


def _tactics_for_threat(threat: Threat, kb: KnowledgeBase) -> list[str]:
    tactics: set[str] = set()
    for tech_id in threat.atlas_techniques:
        tech = kb.get_atlas_technique(tech_id)
        if tech:
            tactics.update(tech.get("tactics", []))
    return sorted(tactics, key=lambda t: TACTIC_RANK.get(t, 999))


def _min_tactic_rank(tactics: list[str]) -> int:
    if not tactics:
        return 999
    return min(TACTIC_RANK.get(t, 999) for t in tactics)


def _max_tactic_rank(tactics: list[str]) -> int:
    if not tactics:
        return -1
    return max(TACTIC_RANK.get(t, -1) for t in tactics)


def find_attack_paths(
    threats: list[Threat],
    components: list[Component],
    dataflows: list[Dataflow],
    kb: KnowledgeBase | None = None,
    top_n: int = 10,
    max_path_length: int = 5,
) -> list[AttackPath]:
    """Generate ranked attack paths."""
    kb = kb or get_kb()
    comp_index = {c.id: c for c in components}
    threat_tactics = {t.id: _tactics_for_threat(t, kb) for t in threats}

    # Component-level adjacency from dataflows (directed, both directions optional)
    comp_adj: dict[str, set[str]] = defaultdict(set)
    for df in dataflows:
        comp_adj[df.source].add(df.target)

    # Build threat-level graph
    g: nx.DiGraph = nx.DiGraph()
    threats_by_comp: dict[str, list[Threat]] = defaultdict(list)
    for t in threats:
        threats_by_comp[t.component_id].append(t)
        g.add_node(
            t.id,
            threat=t,
            tactics=threat_tactics[t.id],
            likelihood=t.likelihood,
            impact=t.impact,
        )

    # Edges: same component (intra-component pivot) OR adjacent component (via dataflow)
    for src in threats:
        src_max = _max_tactic_rank(threat_tactics[src.id])
        # sorted() -- iterating a set union directly varies across processes
        # (PYTHONHASHSEED) and changed the selected top-N attack paths, their
        # ids, narratives and threat_ids run-to-run (audit F041).
        for nbr_comp in sorted(comp_adj.get(src.component_id, set()) | {src.component_id}):
            for dst in threats_by_comp.get(nbr_comp, []):
                if dst.id == src.id:
                    continue
                dst_min = _min_tactic_rank(threat_tactics[dst.id])
                # Allow if dst is "later" in kill chain OR same rank but different threat
                if dst_min >= src_max:
                    g.add_edge(src.id, dst.id)

    # Enumerate paths starting from "early" tactics
    seeds = [
        t.id
        for t in threats
        if any(TACTIC_RANK.get(tac, 999) <= TACTIC_RANK["AML.TA0006"] for tac in threat_tactics[t.id])
    ]
    if not seeds:
        # No early-tactic threats — start from any threat
        seeds = [t.id for t in threats]

    raw_paths: list[list[str]] = []
    for seed in seeds:
        # DFS to length max_path_length
        for path in _dfs_paths(g, seed, max_path_length):
            if len(path) >= 2:
                raw_paths.append(path)

    # Score and dedup
    seen: set[tuple[str, ...]] = set()
    scored: list[tuple[float, list[str]]] = []
    for path in raw_paths:
        key = tuple(path)
        if key in seen:
            continue
        seen.add(key)
        score = _path_score(path, g)
        scored.append((score, path))
    scored.sort(key=lambda x: x[0], reverse=True)

    # v0.16.6 — Diversity selection. The red-team expert noted that
    # v0.15.1 emitted 10 paths that were permutations of the same chain.
    # Take the highest-scoring path, then iteratively select the next
    # path that differs MOST from those already chosen. Diff metric:
    # symmetric-difference size between the threat-class signature
    # (component_type × first-tactic). This produces paths with
    # different entry points and different lateral-movement classes.
    scored = _select_diverse_paths(scored, top_n, g, threat_tactics)

    # Build AttackPath objects
    out: list[AttackPath] = []
    for score, path in scored:
        threat_objs = [g.nodes[tid]["threat"] for tid in path]
        # audit F059: collapse only ADJACENT duplicate components, not every
        # revisit. A global de-dup dropped a legitimately re-visited component
        # (A->B->A->C became A->B->C), printing a hop B->C between two
        # components with no dataflow between them. Adjacent-only keeps every
        # printed hop corresponding to a real edge / intra-component pivot.
        components_list = []
        for t in threat_objs:
            if not components_list or components_list[-1] != t.component_id:
                components_list.append(t.component_id)
        tactics_traversed: list[str] = []
        for t in threat_objs:
            for tac in threat_tactics[t.id]:
                if tac not in tactics_traversed:
                    tactics_traversed.append(tac)
        difficulty = round(sum(6 - g.nodes[tid]["likelihood"] for tid in path) / len(path))
        biz_impact = max(g.nodes[tid]["impact"] for tid in path)
        narrative = _narrative(threat_objs, comp_index, kb)
        out.append(
            AttackPath(
                id=stable_id("PATH", *path),
                title=_path_title(threat_objs, comp_index),
                threat_ids=path,
                components=components_list,
                tactics_traversed=tactics_traversed,
                estimated_difficulty=max(1, min(5, difficulty)),
                business_impact=max(1, min(5, biz_impact)),
                narrative=narrative,
            )
        )
    return out


# Hard cap on the total number of DFS paths we'll enumerate from any
# single source. Big systems (200+ threats) can produce a combinatorial
# explosion; this keeps `atms analyze` bounded and predictable.
MAX_DFS_PATHS_PER_SOURCE = 5000


def _dfs_paths(g: nx.DiGraph, source: str, max_length: int) -> list[list[str]]:
    paths: list[list[str]] = []

    def _dfs(node: str, path: list[str]) -> None:
        if len(paths) >= MAX_DFS_PATHS_PER_SOURCE:
            return
        if len(path) >= max_length:
            paths.append(list(path))
            return
        successors = list(g.successors(node))
        if not successors:
            paths.append(list(path))
            return
        # Always record the path-so-far at each branch to also collect short paths
        paths.append(list(path))
        for nxt in successors:
            if len(paths) >= MAX_DFS_PATHS_PER_SOURCE:
                return
            if nxt in path:
                continue
            path.append(nxt)
            _dfs(nxt, path)
            path.pop()

    _dfs(source, [source])
    return paths


def _path_score(path: list[str], g: nx.DiGraph) -> float:
    if not path:
        return 0.0
    avg_likelihood = sum(g.nodes[n]["likelihood"] for n in path) / len(path)
    max_impact = max(g.nodes[n]["impact"] for n in path)
    length_bonus = min(len(path), 5) * 0.1
    return avg_likelihood * max_impact + length_bonus


def _path_signature(path: list[str], g: nx.DiGraph, threat_tactics: dict[str, list[str]]) -> tuple:
    """v0.16.6: canonical signature for a path used by diversity selection.

    Captures (entry_threat_id, first_tactic, terminal_threat_id,
    set_of_intermediate_tactics). Two paths with the same entry +
    terminal + intermediate tactics are considered "the same chain
    permuted" even if their node order differs.
    """
    if not path:
        return ()
    entry = path[0]
    terminal = path[-1]
    first_tactic = threat_tactics.get(entry, ["?"])[:1]
    intermediate_tactics = set()
    for node in path[1:-1]:
        intermediate_tactics.update(threat_tactics.get(node, []))
    return (entry, first_tactic[0] if first_tactic else "?", terminal, frozenset(intermediate_tactics))


def _select_diverse_paths(
    scored: list[tuple[float, list[str]]],
    top_n: int,
    g: nx.DiGraph,
    threat_tactics: dict[str, list[str]],
) -> list[tuple[float, list[str]]]:
    """v0.16.6: diversity selection. Take the top-scoring path, then
    iteratively select the next path whose signature differs MOST from
    those already chosen. Prevents the "10 paths that are the same
    chain permuted" failure mode (red-team expert finding A-08).
    """
    if not scored:
        return []
    # v0.16.9 (Bug-005): pre-compute signatures once and bound the
    # candidate pool. Previous O(N×M×S) re-scan made a 100-LLM dense
    # graph blow the 60s budget (61s observed). New strategy:
    #   1. Pre-compute signatures for every candidate (single pass).
    #   2. Cap candidate pool at top 200 by raw score before selecting.
    #   3. Cache sig→min-distance updates per iteration.
    MAX_CANDIDATES = 200
    truncated = scored[:MAX_CANDIDATES] if len(scored) > MAX_CANDIDATES else scored
    sigs: list[tuple] = [_path_signature(p, g, threat_tactics) for _, p in truncated]
    selected: list[tuple[float, list[str]]] = [truncated[0]]
    selected_sig_list: list[tuple] = [sigs[0]]
    # Track min-distance for each remaining candidate, updated in place.
    # Start by computing distance from each remaining candidate to
    # selected[0]; then on each iteration only update against the
    # newest-selected sig — that's the only way min_dist can change.
    min_dist: list[float] = [
        _signature_distance(sigs[i], selected_sig_list[0])
        for i in range(1, len(truncated))
    ]
    # Index map: remaining candidate j  -> original index in truncated
    remaining_indices = list(range(1, len(truncated)))
    while len(selected) < top_n and remaining_indices:
        # Pick the candidate with maximum (score + 5 * min_dist).
        best_pos = 0
        best_combined = -1.0
        for pos, idx in enumerate(remaining_indices):
            score = truncated[idx][0]
            combined = score + 5.0 * min_dist[pos]
            if combined > best_combined:
                best_combined = combined
                best_pos = pos
        chosen_idx = remaining_indices.pop(best_pos)
        del min_dist[best_pos]
        chosen_score, chosen_path = truncated[chosen_idx]
        chosen_sig = sigs[chosen_idx]
        selected.append((chosen_score, chosen_path))
        selected_sig_list.append(chosen_sig)
        # Update min_dist with distance to the newly-chosen signature.
        for pos, idx in enumerate(remaining_indices):
            d = _signature_distance(sigs[idx], chosen_sig)
            if d < min_dist[pos]:
                min_dist[pos] = d
    return selected


def _signature_distance(a: tuple, b: tuple) -> float:
    """Distance between two path signatures (0 = identical, higher = more different)."""
    if not a or not b:
        return 4.0
    d = 0.0
    if a[0] != b[0]:
        d += 1.0
    if a[1] != b[1]:
        d += 1.0
    if a[2] != b[2]:
        d += 1.0
    # Tactic-set distance: normalised symmetric difference
    set_a, set_b = a[3], b[3]
    if set_a or set_b:
        union_size = max(1, len(set_a | set_b))
        d += len(set_a ^ set_b) / union_size
    return d


def _path_title(threats: list[Threat], comp_index: dict[str, Component]) -> str:
    if len(threats) == 1:
        return threats[0].title
    head = comp_index.get(threats[0].component_id)
    tail = comp_index.get(threats[-1].component_id)
    head_name = head.name if head else threats[0].component_id
    tail_name = tail.name if tail else threats[-1].component_id
    return f"{head_name} → {tail_name}: {threats[-1].title}"


def _narrative(threats: list[Threat], comp_index: dict[str, Component], kb: KnowledgeBase) -> str:
    """Generate a deterministic adversary narrative — no LLM."""
    lines = []
    for i, t in enumerate(threats, 1):
        comp = comp_index.get(t.component_id)
        comp_name = comp.name if comp else t.component_id
        atlas_pretty = ", ".join(t.atlas_techniques) if t.atlas_techniques else "(no ATLAS mapping)"
        owasp_pretty = ", ".join(t.owasp_llm) if t.owasp_llm else "(no OWASP mapping)"
        lines.append(
            f"Step {i} — {comp_name} | {t.title}\n"
            f"  ATLAS: {atlas_pretty}\n"
            f"  OWASP LLM: {owasp_pretty}\n"
            f"  {t.description.strip()[:300]}"
        )
    return "\n\n".join(lines)
