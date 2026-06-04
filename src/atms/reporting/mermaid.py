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


__all__ = ["render_mermaid"]
