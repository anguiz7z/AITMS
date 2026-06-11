"""Mermaid Data Flow Diagram renderer.

Produces a Mermaid `flowchart` definition from an ATMS `System`. Mermaid is
JS-rendered in browsers and on GitHub, so embedding the markup in a Markdown
report or HTML report gives reviewers a real visual diagram of the system —
no separate diagram file required.

Component-type → node shape mapping is chosen to be visually distinct in a
black-and-white printout (rectangles, stadiums, hexagons, cylinders).
"""

from __future__ import annotations

from ..models import Component, System

# Mermaid node-shape syntax per component type. Values are (open, close) brackets
# so we can format `id<open>"label"<close>`.
_SHAPE: dict[str, tuple[str, str]] = {
    # AI / agentic primitives
    "user":                   ("([",  "])"),    # stadium
    "agent":                  ("{{",  "}}"),    # hexagon
    "tool":                   ("[/",  "/]"),    # parallelogram
    "mcp_server":             ("[\\", "\\]"),   # parallelogram-alt
    "llm_inference":          ("[(",  ")]"),    # cylinder
    "rag_vector_store":       ("[(",  ")]"),    # cylinder
    "embedding_service":      ("([",  "])"),    # stadium
    "training_pipeline":      ("[",   "]"),     # rectangle
    "fine_tuning_pipeline":   ("[",   "]"),     # rectangle
    "prompt_template_store":  ("[",   "]"),     # rectangle
    "model_registry":         ("[(",  ")]"),    # cylinder
    "guardrails":             ("{",   "}"),     # rhombus
    "output_filter":          ("{",   "}"),     # rhombus
    "data_source":            ("[(",  ")]"),    # cylinder
    "external_api":           ("([",  "])"),    # stadium
    # Cloud-infrastructure components — distinguish by shape so reviewers
    # can spot cloud vs AI elements at a glance.
    "iam_principal":          ("(",   ")"),     # circle (identity → person-shaped)
    "secrets_vault":          ("[[",  "]]"),    # subroutine (vault → walls)
    "object_storage":         ("[(",  ")]"),    # cylinder (storage)
    "network_segment":        ("[",   "]"),     # rectangle (zone)
    "serverless_function":    (">",   "]"),     # asymmetric (function trigger)
    "api_gateway":            ("[/",  "\\]"),   # trapezoid (gateway funnel)
    "container_runtime":      ("[[",  "]]"),    # subroutine (container box)
    "kms_key":                ("(",   ")"),     # circle (key)
    "message_queue":          ("[(",  ")]"),    # cylinder (queue -> store)
    "observability_stack":    ("{",   "}"),     # rhombus (filter / decision)
    # IT / Network / OT / Legacy / Identity components (added v0.10).
    "database":               ("[(",  ")]"),    # cylinder
    "firewall":               ("{",   "}"),     # rhombus (filter)
    "directory_service":      ("(",   ")"),     # circle (identity)
    "web_application":        ("([",  "])"),    # stadium (web)
    "endpoint":               ("[",   "]"),     # rectangle (workstation)
    "legacy_mainframe":       ("[[",  "]]"),    # subroutine (boxy mainframe)
    "plc":                    ("[/",  "/]"),    # parallelogram (input/output device)
    "scada":                  ("[/",  "\\]"),   # trapezoid (control plane)
    "iot_device":             (">",   "]"),     # asymmetric (sensor)
    "load_balancer":          ("{",   "}"),     # rhombus (router)
    "vpn_gateway":            ("[/",  "\\]"),   # trapezoid (gateway)
    "network_switch":         ("[",   "]"),     # rectangle (network gear)
    "email_server":           ("[(",  ")]"),    # cylinder (mail store)
    "mfa_service":            ("(",   ")"),     # circle (identity-adjacent)
    "industrial_protocol":    ("[",   "]"),     # rectangle (bus)
    # Fallback
    "other":                  ("[",   "]"),     # rectangle
}


def _safe_id(raw: str) -> str:
    """Mermaid IDs must be alnum + underscore. Sanitise + append a short
    hash when the input is non-ASCII to avoid collisions like
    ``"ユーザー"`` and ``"ユーザ"`` both collapsing to ``"_____"``.
    """
    if raw is None:
        return "node"
    s = str(raw)
    out = []
    has_non_ascii = False
    for ch in s:
        if ch.isalnum() and ch.isascii():
            out.append(ch)
        elif ch == "_":
            out.append("_")
        else:
            has_non_ascii = has_non_ascii or not ch.isascii()
            out.append("_")
    sid = "".join(out)
    if sid and sid[0].isdigit():
        sid = "n_" + sid
    if has_non_ascii:
        # Stable suffix derived from the original string so two
        # different non-ASCII names produce different ids.
        import hashlib
        digest = hashlib.sha1(s.encode("utf-8")).hexdigest()[:6]
        sid = (sid or "u") + "_" + digest
    return sid or "node"


def _label(text: str) -> str:
    """Sanitise text for use as a Mermaid node / edge label.

    Mermaid renders labels as HTML, so user-supplied names with `<`, `>`,
    `&` need escaping. We also escape characters Mermaid itself treats
    specially (`"`, `|`, `\\`). When `securityLevel: 'strict'` is set
    in `static/atms-mermaid.js` Mermaid won't execute embedded JS even
    without this — but defence-in-depth: a future report renderer may
    not load atms-mermaid.js, and we never want a System YAML name to
    drive client-side script execution.
    """
    if not text:
        return ""
    # Escape `&` first so subsequent replacements don't double-encode.
    safe = text.replace("&", "&amp;")
    safe = safe.replace("<", "&lt;").replace(">", "&gt;")
    safe = safe.replace("\\", "\\\\").replace('"', "&quot;")
    safe = safe.replace("\n", "<br/>")
    safe = safe.replace("|", "&#124;")  # pipe is reserved in edge labels
    return safe


def _node_line(comp: Component) -> str:
    open_b, close_b = _SHAPE.get(comp.type, ("[", "]"))
    sid = _safe_id(comp.id)
    label_text = f"{_label(comp.name)}<br/><i>{_label(comp.type)}</i>"
    return f'  {sid}{open_b}"{label_text}"{close_b}'


def render_mermaid(system: System) -> str:
    """Return a Mermaid flowchart string. Group components by `trust_zone` into
    subgraphs so reviewers can see boundaries visually."""
    by_zone: dict[str, list[Component]] = {}
    for c in system.components:
        by_zone.setdefault(c.trust_zone, []).append(c)

    lines: list[str] = []
    lines.append("flowchart LR")
    lines.append("  classDef internet fill:#3a1a1a,stroke:#cf222e,color:#fff")
    lines.append("  classDef external fill:#3a2a14,stroke:#db6d28,color:#fff")
    lines.append("  classDef training fill:#1a2a3a,stroke:#58a6ff,color:#fff")
    lines.append("  classDef prod fill:#1f2630,stroke:#30363d,color:#e6edf3")

    # Subgraphs per trust zone
    zone_classes = {
        "internet": "internet",
        "external_provider": "external",
        "training_vpc": "training",
    }
    for zone in sorted(by_zone.keys()):
        members = by_zone[zone]
        cls = zone_classes.get(zone, "prod")
        zone_safe = _safe_id(zone)
        lines.append(f'  subgraph zone_{zone_safe}["{_label(zone)}"]')
        lines.append("    direction LR")
        for comp in members:
            lines.append("  " + _node_line(comp))
        lines.append("  end")
        # Attach class after subgraph close to colour every node in that zone
        for comp in members:
            lines.append(f"  class {_safe_id(comp.id)} {cls};")

    # Edges — between components, possibly across subgraphs
    for df in system.dataflows:
        src = _safe_id(df.source)
        tgt = _safe_id(df.target)
        label = _label(df.label or "")
        if df.crosses_boundary:
            # Use thick double-line arrow to call out boundary crossings
            if label:
                lines.append(f'  {src} ==>|"{label}"| {tgt}')
            else:
                lines.append(f"  {src} ==> {tgt}")
        else:
            if label:
                lines.append(f'  {src} -->|"{label}"| {tgt}')
            else:
                lines.append(f"  {src} --> {tgt}")

    return "\n".join(lines)


def render_attack_path_graph(
    attack_paths: list,
    system: System,
    choke_ids: set[str] | None = None,
) -> str:
    """Return a Mermaid flowchart of the *combined* attack graph.

    Every attack path is an ordered chain of component IDs
    (``path.components``: entry → … → target). We merge the chains into one
    graph so shared nodes line up — a component many paths run through becomes
    a visible hub, which is exactly the choke point the table names. Colour
    coding: green = external entry seed, red = a path's final target, amber +
    thick border = a choke point, slate = an intermediate step. Edges are the
    step-to-step transitions; a thick ``==>`` marks a transition into a choke
    point so the "everything funnels here" story reads at a glance.

    Returns ``""`` when there are no paths (template then skips the block).
    """
    if not attack_paths:
        return ""
    choke_ids = choke_ids or set()
    name_by_id = {c.id: c.name for c in system.components}

    node_order: list[str] = []          # preserve first-seen order, stable output
    seen_nodes: set[str] = set()
    edges: list[tuple[str, str]] = []
    seen_edges: set[tuple[str, str]] = set()
    entry_ids: set[str] = set()
    target_ids: set[str] = set()

    for p in attack_paths:
        comps = [c for c in getattr(p, "components", []) if c]
        # The graph visualises cross-component *traversal*. A path that stays
        # within a single component (a localised multi-threat chain — the
        # engine collapses adjacent duplicate component IDs) has no edge to
        # draw and would render as a floating node, so it's skipped here; it
        # still appears as a text path-card below.
        if len(comps) < 2:
            continue
        entry_ids.add(comps[0])
        target_ids.add(comps[-1])
        for cid in comps:
            if cid not in seen_nodes:
                seen_nodes.add(cid)
                node_order.append(cid)
        for a, b in zip(comps, comps[1:], strict=False):
            if (a, b) not in seen_edges:
                seen_edges.add((a, b))
                edges.append((a, b))

    if not node_order:
        return ""

    lines: list[str] = ["flowchart LR"]
    lines.append("  classDef entry fill:#16321a,stroke:#3fb950,color:#fff")
    lines.append("  classDef target fill:#3a1a1a,stroke:#cf222e,color:#fff")
    lines.append("  classDef choke fill:#3a2f14,stroke:#d29922,color:#fff,stroke-width:3px")
    lines.append("  classDef step fill:#1f2630,stroke:#30363d,color:#e6edf3")

    for cid in node_order:
        sid = _safe_id(cid)
        label = _label(name_by_id.get(cid, cid))
        lines.append(f'  {sid}["{label}"]')

    for a, b in edges:
        # Thicker arrow into a choke point so the funnel is obvious.
        arrow = "==>" if b in choke_ids else "-->"
        lines.append(f"  {_safe_id(a)} {arrow} {_safe_id(b)}")

    # Class priority: choke > entry > target > step. A node that is both an
    # entry seed and a choke still reads as a choke (the more useful signal).
    for cid in node_order:
        sid = _safe_id(cid)
        if cid in choke_ids:
            cls = "choke"
        elif cid in entry_ids and cid not in target_ids:
            cls = "entry"
        elif cid in target_ids and cid not in entry_ids:
            cls = "target"
        elif cid in entry_ids:           # both entry and target (single-hop)
            cls = "entry"
        else:
            cls = "step"
        lines.append(f"  class {sid} {cls};")

    return "\n".join(lines)


__all__ = ["render_mermaid", "render_attack_path_graph"]
