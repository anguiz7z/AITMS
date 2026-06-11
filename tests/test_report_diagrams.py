"""Report-diagram contract: the standalone HTML report must render its
diagrams OFFLINE (Mermaid inlined, no CDN), and the attack-path section must
carry a visual combined attack graph — not just text.

These guard the fixes for the owner's 2026-06-11 demo feedback ("where is the
attack path? diagrams? ... I need 1 comprehensive one"): the report used a
jsDelivr CDN for Mermaid (blank diagram offline) and rendered attack paths as
text only.
"""

from __future__ import annotations

from atms.models import AttackPath, Component, Dataflow, System
from atms.reporting.mermaid import render_attack_path_graph


def _system() -> System:
    return System(
        name="t",
        components=[
            Component(id="ext", name="User", type="user", trust_zone="internet"),
            Component(id="api", name="API", type="api_gateway", trust_zone="dmz"),
            Component(id="agent", name="Agent", type="agent", trust_zone="app"),
            Component(id="db", name="DB", type="database", trust_zone="app"),
        ],
        dataflows=[Dataflow(source="ext", target="api", label="req")],
    )


def _paths() -> list[AttackPath]:
    return [
        AttackPath(
            id="P1", title="ext to db", threat_ids=["T1"],
            components=["ext", "api", "agent", "db"],
            tactics_traversed=["AML.TA0004"], estimated_difficulty=2, business_impact=5,
        ),
        AttackPath(
            id="P2", title="ext to agent", threat_ids=["T2"],
            components=["ext", "agent", "db"],
            tactics_traversed=["AML.TA0005"], estimated_difficulty=3, business_impact=4,
        ),
    ]


def test_attack_path_graph_renders_flowchart_with_role_classes():
    g = render_attack_path_graph(_paths(), _system(), choke_ids={"agent"})
    assert g.startswith("flowchart")
    # Every component in the chains is a node.
    for nid in ("ext", "api", "agent", "db"):
        assert nid in g
    # Role colouring is present.
    assert "classDef entry" in g and "classDef target" in g and "classDef choke" in g
    # The shared node 'agent' is marked a choke point and funnel arrows (==>) lead into it.
    assert "class agent choke;" in g
    assert "==> agent" in g
    # Entry seed and final target are coloured.
    assert "class ext entry;" in g
    assert "class db target;" in g


def test_attack_path_graph_empty_when_no_paths():
    assert render_attack_path_graph([], _system(), set()) == ""
    # Paths with no components are skipped, not crashed on.
    empty = [AttackPath(id="P", title="x", threat_ids=[], components=[],
                        tactics_traversed=[], estimated_difficulty=1, business_impact=1)]
    assert render_attack_path_graph(empty, _system(), set()) == ""


def test_single_component_paths_are_not_floating_nodes():
    """A path localised to one component has no edge to draw — it must be
    skipped so it doesn't render as a disconnected dot (the 2026-06-11 demo
    bug: 'Simple Sentiment Tool' floated unconnected)."""
    only_singletons = [
        AttackPath(id="S1", title="x", threat_ids=["T"], components=["agent"],
                   tactics_traversed=[], estimated_difficulty=1, business_impact=1),
        AttackPath(id="S2", title="y", threat_ids=["T"], components=["db"],
                   tactics_traversed=[], estimated_difficulty=1, business_impact=1),
    ]
    assert render_attack_path_graph(only_singletons, _system(), set()) == ""
    # A mix: only the multi-component path contributes nodes.
    mixed = only_singletons + _paths()
    g = render_attack_path_graph(mixed, _system(), set())
    # 'api' only exists in the multi-component path, proving it was drawn.
    assert "api[" in g


def test_html_report_is_offline_self_contained_with_both_diagrams():
    """The full HTML report inlines Mermaid (no CDN) and embeds BOTH the
    architecture DFD and the attack-path graph as mermaid blocks."""
    from atms.reporting.html import render_html
    from atms.workflow import analyze

    model = analyze(_system())
    # Force at least one path so the attack-graph block renders.
    model.attack_paths = _paths()
    model.summary["choke_points"] = [
        {"component_id": "agent", "component_name": "Agent",
         "paths_through": 2, "total_paths": 2, "coverage": 1.0}
    ]
    html = render_html(model)

    # Offline contract: no external CDN script anywhere.
    assert "jsdelivr" not in html and "cdn." not in html, "report must not pull Mermaid from a CDN"
    # Mermaid library is inlined (its API surface appears in the document).
    assert "mermaid" in html.lower()
    assert html.count('<pre class="mermaid">') >= 2, "expected architecture + attack-path diagrams"
    # The attack-path graph's role styling made it into the page.
    assert "classDef choke" in html
