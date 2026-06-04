"""Trust-boundary inference + cross-boundary dataflow flagging."""

from __future__ import annotations

from atms.engines.boundaries import annotate_dataflow_boundaries, infer_boundaries
from atms.models import Component, Dataflow, System, TrustBoundary
from atms.workflow import analyze


def _system(*zones_for_components: tuple[str, str]) -> System:
    components = [
        Component(id=f"c{i}", name=f"c{i}", type=ctype, trust_zone=zone)
        for i, (ctype, zone) in enumerate(zones_for_components)
    ]
    return System(name="t", components=components)


def test_no_boundary_when_single_zone():
    s = _system(("user", "default"), ("agent", "default"))
    assert infer_boundaries(s) == []


def test_two_zones_yield_two_inferred_boundaries():
    s = _system(("user", "internet"), ("agent", "corp_dmz"))
    tbs = infer_boundaries(s)
    assert len(tbs) == 2
    assert {tb.id for tb in tbs} == {"tb_inferred_internet", "tb_inferred_corp_dmz"}
    for tb in tbs:
        assert tb.type in {"network", "identity", "data_classification", "tenancy", "deployment_zone"}


def test_three_zones_yield_three_inferred_boundaries():
    s = _system(
        ("user", "internet"),
        ("agent", "corp_dmz"),
        ("llm_inference", "external_provider"),
    )
    tbs = infer_boundaries(s)
    assert len(tbs) == 3


def test_inference_does_not_duplicate_declared():
    s = _system(("user", "internet"), ("agent", "corp_dmz"))
    declared = TrustBoundary(
        id="tb_user_explicit",
        type="network",
        components_inside=["c0"],
        components_outside=["c1"],
        description="explicit",
    )
    s.trust_boundaries.append(declared)
    tbs = infer_boundaries(s)
    # Inference may still produce a boundary for the *other* side,
    # but the (inside, outside) pair we already declared must not be re-inferred.
    inside_outside = {(frozenset(tb.components_inside), frozenset(tb.components_outside)) for tb in tbs}
    assert (frozenset(["c0"]), frozenset(["c1"])) not in inside_outside


def test_dataflow_crosses_boundary_auto_flag():
    s = _system(("user", "internet"), ("agent", "corp_dmz"))
    s.dataflows = [Dataflow(source="c0", target="c1", label="msg", crosses_boundary=False)]
    n = annotate_dataflow_boundaries(s)
    assert n == 1
    assert s.dataflows[0].crosses_boundary is True


def test_dataflow_same_zone_not_flagged():
    s = _system(("user", "default"), ("agent", "default"))
    s.dataflows = [Dataflow(source="c0", target="c1", label="msg")]
    n = annotate_dataflow_boundaries(s)
    assert n == 0
    assert s.dataflows[0].crosses_boundary is False


def test_workflow_runs_inference_automatically():
    """analyze() should auto-derive boundaries even when the user provided none."""
    s = _system(("user", "internet"), ("agent", "corp_dmz"))
    tm = analyze(s)
    assert len(tm.system.trust_boundaries) >= 2
