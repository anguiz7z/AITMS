"""find_choke_points ranks the components the most attack paths traverse.

Adopted from ChokeHound (GitHub TM survey, 2026-06): the most-shared node is the
highest-leverage mitigation — answers "what do I fix first?" over the path set.
"""

from __future__ import annotations

from atms.engines.attack_paths import find_choke_points
from atms.models import AttackPath, Component


def _path(pid: str, comps: list[str]) -> AttackPath:
    return AttackPath(
        id=pid, title="t", threat_ids=["x"], components=comps,
        tactics_traversed=[], estimated_difficulty=2, business_impact=3,
    )


def test_choke_point_ranks_most_traversed_component_first():
    comps = [Component(id=c, name=c.upper(), type="tool") for c in ("a", "b", "c", "hub")]
    paths = [
        _path("p1", ["a", "hub"]),
        _path("p2", ["b", "hub"]),
        _path("p3", ["c", "hub"]),
        _path("p4", ["a", "b"]),
    ]
    cps = find_choke_points(paths, comps)
    assert cps[0]["component_id"] == "hub"
    assert cps[0]["component_name"] == "HUB"
    assert cps[0]["paths_through"] == 3
    assert cps[0]["total_paths"] == 4
    assert cps[0]["coverage"] == 0.75


def test_choke_points_empty_on_no_paths():
    assert find_choke_points([], []) == []


def test_choke_points_counts_each_path_once_per_component():
    # a component appearing twice in one path still counts that path once
    comps = [Component(id="x", name="X", type="tool")]
    assert find_choke_points([_path("p1", ["x", "x"])], comps)[0]["paths_through"] == 1
