"""Phase G property-based tests for the four most-used parsers.

Hand-authored fixtures catch the cases the author thought of.
Hypothesis generates random valid inputs and tries to break the
parser with edge cases the author didn't. Each test pins an
invariant that should hold across a wide input space.

Targets (descending order of blast radius):
  1. System YAML round-trip — System → YAML → System parses
  2. Pulumi YAML — synthesised resources don't crash the ingester
  3. OTM round-trip — render → parse stays consistent
  4. drawio — well-formed mxGraph XML doesn't crash the ingester

`hypothesis` is a dev-only dep (declared in `[project.optional-dependencies].dev`).
"""

from __future__ import annotations

import string
import typing

import pytest
import yaml

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from atms.models import Component, ComponentType, Dataflow, System  # noqa: E402

# Realistic component-type pool (the literals declared in models.ComponentType).
_VALID_COMPONENT_TYPES = list(typing.get_args(ComponentType))

# IDs must be 1-64 chars, alnum + _ + -
_ID_ALPHA = st.text(
    alphabet=string.ascii_letters + string.digits + "_-",
    min_size=1, max_size=32,
).filter(lambda s: s[0] in string.ascii_letters + "_")

# Names: any non-empty printable string ≤ 200 chars.
_NAME = st.text(
    alphabet=string.ascii_letters + string.digits + " -._",
    min_size=1, max_size=80,
)

_TRUST_ZONE = st.sampled_from([
    "default", "external", "perimeter", "app", "data", "secrets",
    "observability", "identity", "internet", "cloud",
])


@st.composite
def _component(draw) -> Component:
    return Component(
        id=draw(_ID_ALPHA),
        name=draw(_NAME),
        type=draw(st.sampled_from(_VALID_COMPONENT_TYPES)),
        description=draw(st.text(min_size=0, max_size=200)),
        trust_zone=draw(_TRUST_ZONE),
    )


@st.composite
def _system(draw) -> System:
    n = draw(st.integers(min_value=2, max_value=12))
    # Generate distinct IDs.
    ids: set[str] = set()
    while len(ids) < n:
        ids.add(draw(_ID_ALPHA))
    ids_list = list(ids)
    components = [
        Component(
            id=cid,
            name=draw(_NAME),
            type=draw(st.sampled_from(_VALID_COMPONENT_TYPES)),
            description=draw(st.text(min_size=0, max_size=200)),
            trust_zone=draw(_TRUST_ZONE),
        )
        for cid in ids_list
    ]
    # 0..n*2 dataflows between existing component ids.
    edge_count = draw(st.integers(min_value=0, max_value=n * 2))
    dataflows = []
    seen_edges: set[tuple[str, str]] = set()
    for _ in range(edge_count):
        src, tgt = draw(st.tuples(
            st.sampled_from(ids_list),
            st.sampled_from(ids_list),
        ))
        if src == tgt or (src, tgt) in seen_edges:
            continue
        seen_edges.add((src, tgt))
        dataflows.append(Dataflow(
            source=src, target=tgt,
            label=draw(st.text(max_size=80)),
        ))
    return System(name=draw(_NAME), components=components, dataflows=dataflows)


# ─── System YAML round-trip ────────────────────────────────────────
@settings(max_examples=40, deadline=2000,
          suppress_health_check=[HealthCheck.too_slow])
@given(_system())
def test_system_yaml_round_trip(sys_obj: System):
    """For any well-formed System, dumping to YAML and loading back
    produces an equivalent System (same id set, same edge set)."""
    serialised = yaml.safe_dump(sys_obj.model_dump(),
                                 sort_keys=False, default_flow_style=False)
    re_parsed = yaml.safe_load(serialised)
    rebuilt = System.model_validate(re_parsed)

    assert {c.id for c in rebuilt.components} == {c.id for c in sys_obj.components}
    assert {c.type for c in rebuilt.components} == {c.type for c in sys_obj.components}
    assert (
        {(df.source, df.target) for df in rebuilt.dataflows}
        == {(df.source, df.target) for df in sys_obj.dataflows}
    )


# ─── Pulumi YAML — pure function on random resource graphs ────────
@st.composite
def _pulumi_yaml_text(draw) -> str:
    """Synthesise a Pulumi-YAML body with random resources from the
    types we know about."""
    from atms.ingest.pulumi_yaml import _RESOURCE_MAP
    pulumi_types = list(_RESOURCE_MAP.keys())
    n = draw(st.integers(min_value=1, max_value=8))
    sym_ids: set[str] = set()
    while len(sym_ids) < n:
        sym_ids.add(draw(_ID_ALPHA))
    sym_list = list(sym_ids)
    lines = ["name: hypo-stack", "runtime: yaml", "resources:"]
    for sym in sym_list:
        rtype = draw(st.sampled_from(pulumi_types))
        lines.append(f"  {sym}:")
        lines.append(f"    type: {rtype}")
        # Random number of properties — sometimes refer to other syms.
        n_props = draw(st.integers(min_value=0, max_value=2))
        if n_props > 0:
            lines.append("    properties:")
            other_sym = draw(st.sampled_from(sym_list))
            lines.append(f"      ref: ${{{other_sym}.id}}")
    return "\n".join(lines) + "\n"


@settings(max_examples=25, deadline=2000,
          suppress_health_check=[HealthCheck.too_slow])
@given(_pulumi_yaml_text())
@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4
def test_pulumi_yaml_parser_does_not_crash(text: str):
    """The Pulumi YAML parser must handle any valid synthesised
    resource graph without raising — only `no resources` is an
    acceptable rejection."""
    from atms.ingest.pulumi_yaml import pulumi_to_system
    try:
        sys_obj = pulumi_to_system(text=text)
    except ValueError as exc:
        # Acceptable: explicit "no resources" rejection.
        assert "no `resources" in str(exc).lower() or "no resources" in str(exc).lower()
        return
    # If parsing succeeded, the System must be valid.
    assert len(sys_obj.components) >= 1
    # Every dataflow endpoint must resolve to a component (the parser
    # is responsible for filtering dangling refs).
    valid_ids = {c.id for c in sys_obj.components}
    for df in sys_obj.dataflows:
        assert df.source in valid_ids
        assert df.target in valid_ids


# ─── OTM round-trip ────────────────────────────────────────────────
@settings(max_examples=20, deadline=2000,
          suppress_health_check=[HealthCheck.too_slow])
@given(_system())
@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4
def test_otm_round_trip_preserves_topology(sys_obj: System):
    """Render an arbitrary System as OTM, then parse it back. The
    component set must round-trip 1:1; the type mapping is allowed to
    coarsen (some ATMS types collapse to the OTM vocabulary) but the
    ID set is preserved."""
    from atms.ingest.otm import parse_otm

    # Build a minimal ThreatModel-shaped wrapper for the OTM exporter.
    # render_otm only needs the system shape + an empty threats list.
    from atms.models import ThreatModel
    from atms.reporting.otm_export import render_otm
    tm = ThreatModel(system=sys_obj, threats=[], attack_paths=[],
                      mitigations=[], summary={})
    otm_text = render_otm(tm)
    # Write to a temp file because parse_otm expects a path.
    import os
    import tempfile
    fd, tp = tempfile.mkstemp(suffix=".otm", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(otm_text)
        rebuilt = parse_otm(tp)
    finally:
        try:
            os.unlink(tp)
        except OSError:
            pass

    assert {c.id for c in rebuilt.components} == {c.id for c in sys_obj.components}


# ─── drawio — minimal mxfile XML doesn't crash ────────────────────
@st.composite
def _drawio_mxfile(draw) -> str:
    """Synthesise a minimal mxfile with a small handful of cells."""
    n = draw(st.integers(min_value=1, max_value=6))
    cell_ids: list[str] = []
    cells: list[str] = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    safe_styles = [
        "shape=actor",
        "shape=mxgraph.aws4.api_gateway",
        "shape=mxgraph.aws4.bedrock",
        "shape=mxgraph.aws4.lambda",
        "shape=mxgraph.aws4.s3",
        "shape=mxgraph.azure.cosmos_db",
        "shape=cylinder3",
    ]
    for i in range(n):
        cid = f"n{i}"
        cell_ids.append(cid)
        style = draw(st.sampled_from(safe_styles))
        name = draw(st.text(
            alphabet=string.ascii_letters + " ",
            min_size=1, max_size=20,
        ))
        cells.append(
            f'<mxCell id="{cid}" value="{name.strip() or "Node"}" '
            f'style="{style}" vertex="1" parent="1"/>'
        )
    # 0..n edges.
    n_edges = draw(st.integers(min_value=0, max_value=n))
    for i in range(n_edges):
        if len(cell_ids) < 2:
            break
        src = draw(st.sampled_from(cell_ids))
        tgt = draw(st.sampled_from(cell_ids))
        if src == tgt:
            continue
        cells.append(f'<mxCell id="e{i}" edge="1" source="{src}" target="{tgt}" parent="1"/>')
    body = (
        "<mxfile><diagram><mxGraphModel><root>"
        + "".join(cells)
        + "</root></mxGraphModel></diagram></mxfile>"
    )
    return body


@settings(max_examples=25, deadline=2000,
          suppress_health_check=[HealthCheck.too_slow])
@given(_drawio_mxfile())
def test_drawio_parser_handles_random_mxfiles(mxfile: str):
    """Any well-formed mxfile XML with a handful of cells must parse
    without raising. Output may have 0 components (Mermaid-like
    diagrams with no recognised stencils); that's fine."""
    import os
    import tempfile

    from atms.ingest.drawio import drawio_to_system
    fd, tp = tempfile.mkstemp(suffix=".drawio", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(mxfile)
        sys_obj = drawio_to_system(tp)
    finally:
        try:
            os.unlink(tp)
        except OSError:
            pass

    # Every dataflow endpoint must resolve to a component the parser kept.
    valid = {c.id for c in sys_obj.components}
    for df in sys_obj.dataflows:
        assert df.source in valid
        assert df.target in valid
