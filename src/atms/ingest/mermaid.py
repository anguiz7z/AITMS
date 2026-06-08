r"""Mermaid flowchart → ATMS System (v0.18.1 Cycle P).

Adds Mermaid `flowchart` / `graph` syntax as a 7th ingest format.
Common in markdown docs + GitHub READMEs; many teams write
architecture diagrams in Mermaid before they ever open a drawing
tool.

Supported grammar (covers >95% of real-world flowcharts):

  flowchart LR | TD | TB | RL | BT          (orientation, ignored)

  A                                          (bare node)
  A[Label]                                   (rectangle)
  A(Label)                                   (rounded)
  A((Label))                                 (circle  → user)
  A[(Label)]                                 (cylinder → database)
  A[[Label]]                                 (subroutine)
  A{Label}                                   (rhombus → decision/external)
  A{{Label}}                                 (hexagon → process/agent)
  A>Label]                                   (asymmetric)
  A[/Label/]                                 (parallelogram → input/output)
  A[\Label\]                                 (trapezoid)

  A --> B                                    (arrow)
  A --- B                                    (line, no arrow)
  A -.-> B                                   (dotted arrow)
  A ==> B                                    (thick arrow)
  A -->|label| B                             (arrow with edge label)
  A -- label --> B                           (alt edge-label syntax)

Subgraphs:
  subgraph "VPC: production"
    direction LR
    apigw
    lambda
  end

Each subgraph becomes a TrustBoundary if its label looks like a
container (VPC / subnet / DMZ / etc.) — reuses _is_boundary_cell
from drawio.py.

Pure-Python regex parser, zero external deps, fully offline.
Heavy / weird Mermaid features (clickable nodes, subroutines with
links, class definitions, styling directives) are tolerated but
ignored.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..features import gated
from ..models import Component, Dataflow, System, TrustBoundary
from .drawio import _classify_boundary_type, _classify_label, _is_boundary_cell

# ────────────────────────────────────────────────────────────────────
# Node-shape → ATMS component type hints (when label doesn't help).
# Mermaid shape encodes semantic role surprisingly often: cylinders
# are databases, circles are actors, rhombi are decision points, etc.
# ────────────────────────────────────────────────────────────────────
_SHAPE_HINTS: dict[str, str] = {
    "cylinder": "database",        # A[(Label)]
    "circle": "user",              # A((Label))
    "diamond": "external_api",     # A{Label} — often "external decision" / 3rd party
    "hexagon": "agent",            # A{{Label}}
    "parallelogram": "data_source",  # A[/Label/]
    "trapezoid": "iot_device",     # A[\Label\] — rare; loose mapping
    "subroutine": "web_application",  # A[[Label]]
    "rect": "web_application",     # A[Label]
    "round": "web_application",    # A(Label)
    "asym": "external_api",        # A>Label]
}


# Node line patterns (ordered: most specific first).
# Each captures (id, label, shape_hint).
_NODE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Cylinder: A[(Label)]
    (re.compile(r"([A-Za-z0-9_]+)\[\(([^\)]*)\)\]"), "cylinder"),
    # Subroutine: A[[Label]]
    (re.compile(r"([A-Za-z0-9_]+)\[\[([^\]]*)\]\]"), "subroutine"),
    # Hexagon: A{{Label}}
    (re.compile(r"([A-Za-z0-9_]+)\{\{([^\}]*)\}\}"), "hexagon"),
    # Parallelogram: A[/Label/] or A[\Label\]
    (re.compile(r"([A-Za-z0-9_]+)\[/([^/]*)/\]"), "parallelogram"),
    (re.compile(r"([A-Za-z0-9_]+)\[\\([^\\]*)\\\]"), "trapezoid"),  # noqa: W605
    # Circle: A((Label))
    (re.compile(r"([A-Za-z0-9_]+)\(\(([^\)]*)\)\)"), "circle"),
    # Diamond / rhombus: A{Label}
    (re.compile(r"([A-Za-z0-9_]+)\{([^\}]*)\}"), "diamond"),
    # Asymmetric: A>Label]
    (re.compile(r"([A-Za-z0-9_]+)>([^\]]*)\]"), "asym"),
    # Rectangle: A[Label]
    (re.compile(r"([A-Za-z0-9_]+)\[([^\]]*)\]"), "rect"),
    # Rounded: A(Label)
    (re.compile(r"([A-Za-z0-9_]+)\(([^\)]*)\)"), "round"),
]


# Edge patterns. Applied to a CLEANED line (node decorators stripped
# to just their IDs — so `A[user] --> B[api]` becomes `A --> B`).
# Order: most specific (with label) first.
_EDGE_PIPE_LABEL = re.compile(
    # A -->|label| B   or   A ==>|label| B   or   A -.->|label| B
    r"\b([A-Za-z0-9_]+)\b\s*(?:-{2,}|={2,}|-\.+-)>\s*\|([^\|]*)\|\s*"
    r"\b([A-Za-z0-9_]+)\b"
)
_EDGE_INLINE_LABEL = re.compile(
    # A -- label --> B   (label in the middle of the arrow)
    r"\b([A-Za-z0-9_]+)\b\s*-{2,}\s+([^->\n|][^->\n|]*?)\s+-{2,}>\s*"
    r"\b([A-Za-z0-9_]+)\b"
)
_EDGE_BARE = re.compile(
    # A --> B   or   A ==> B   or   A -.-> B
    r"\b([A-Za-z0-9_]+)\b\s*(?:-{2,}|={2,}|-\.+-)>\s*\b([A-Za-z0-9_]+)\b"
)
# audit F056: leftward (A <-- B  => B->A) and bidirectional (A <--> B => both)
# arrows were silently dropped, losing dataflows and (via the bare-endpoint
# recorder) sometimes fabricating a phantom node from the unparsed line.
_EDGE_BIDIR = re.compile(
    r"\b([A-Za-z0-9_]+)\b\s*<(?:-{2,}|={2,}|-\.+-)>\s*\b([A-Za-z0-9_]+)\b"
)
_EDGE_LEFT = re.compile(
    r"\b([A-Za-z0-9_]+)\b\s*<(?:-{2,}|={2,}|-\.+-)\s*\b([A-Za-z0-9_]+)\b"
)


def _strip_node_decorators(line: str) -> str:
    """Replace `A[label]` → `A` so the edge regex sees bare IDs.

    Walks all node patterns in order (most-specific first) and
    substitutes each match with just the captured ID. Idempotent
    (running twice changes nothing because the second pass has no
    decorators left).
    """
    for pat, _ in _NODE_PATTERNS:
        line = pat.sub(lambda m: m.group(1), line)
    return line


_SUBGRAPH_OPEN = re.compile(r'^\s*subgraph\s+"?([^"\n]+?)"?\s*$')
_SUBGRAPH_END = re.compile(r"^\s*end\s*$")
_DIRECTIVE = re.compile(r"^\s*(?:flowchart|graph)\s+\w+", re.I)


_STRONG_SHAPES = {"cylinder", "circle", "hexagon", "parallelogram"}


def _classify_node(label: str, shape: str) -> tuple[str, str]:
    """Classify a Mermaid node. Returns (component_type, source-tag).

    Priority:
      1. Strong shape (cylinder/circle/hexagon/parallelogram) wins —
         these encode semantic role unambiguously in Mermaid culture.
      2. Label regex.
      3. Weak shape (rect / round / asym).
      4. 'other' fallback.

    Without rule 1, a label like "Customer DB" would match the user-
    regex's "customer" token and beat the cylinder shape — wrong.
    """
    if shape in _STRONG_SHAPES:
        return (_SHAPE_HINTS[shape], "shape")
    if label:
        by_label = _classify_label(label)
        if by_label:
            return (by_label, "label")
    if shape in _SHAPE_HINTS:
        return (_SHAPE_HINTS[shape], "shape")
    return ("other", "fallback")


def _strip_comments_and_trim(text: str) -> list[str]:
    """Remove Mermaid `%%` comments and return non-empty lines."""
    out: list[str] = []
    for line in text.splitlines():
        # Mermaid line comment: %%
        if "%%" in line:
            line = line.split("%%", 1)[0]
        line = line.rstrip()
        if line.strip():
            out.append(line)
    return out


@gated("ingest_mermaid")
def mermaid_to_system(
    source: str | Path,
    system_name: str | None = None,
) -> System:
    """Parse Mermaid flowchart source into an ATMS System.

    Args:
        source: either a filesystem Path to a `.mmd` / `.mermaid` /
                `.md` file, OR an inline Mermaid source string.
        system_name: override; defaults to filename stem or "mermaid".

    Returns: System draft (review before analyze()).
    """
    if isinstance(source, Path) or (
        isinstance(source, str) and "\n" not in source and len(source) < 300
        and (source.endswith(".mmd") or source.endswith(".mermaid")
             or source.endswith(".md"))
    ):
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        default_name = path.stem
    else:
        text = str(source)
        default_name = "mermaid"

    # If embedded in markdown, extract the first ```mermaid ... ``` block.
    fence = re.search(r"```\s*mermaid\s*\n(.*?)```", text, re.S)
    if fence:
        text = fence.group(1)

    lines = _strip_comments_and_trim(text)

    # First pass: identify subgraph blocks (boundary candidates).
    # Each subgraph stack-entry is (raw_label, member_node_ids).
    subgraphs: list[dict] = []  # {label, members}
    sg_stack: list[dict] = []
    nodes_by_id: dict[str, dict] = {}  # id → {label, shape, subgraph_idx}

    def _record_node(node_id: str, label: str, shape: str) -> None:
        existing = nodes_by_id.get(node_id)
        if existing:
            # First mention with a shape/label wins; subsequent bare
            # references just attach to the existing node.
            if not existing["label"] and label:
                existing["label"] = label
            if existing["shape"] == "rect" and shape != "rect":
                existing["shape"] = shape
        else:
            nodes_by_id[node_id] = {
                "id": node_id,
                "label": label,
                "shape": shape,
                "subgraph_idx": len(subgraphs) - 1 if sg_stack else None,
            }
        # If we're inside a subgraph, also tag membership on the topmost.
        if sg_stack:
            top = sg_stack[-1]
            if node_id not in top["members"]:
                top["members"].append(node_id)

    edges: list[tuple[str, str, str]] = []  # (source, target, label)

    for raw_line in lines:
        # Skip directive / class / style lines.
        if _DIRECTIVE.match(raw_line):
            continue
        if raw_line.strip().startswith(("classDef", "class ", "style ", "linkStyle", "direction ")):
            continue

        m = _SUBGRAPH_OPEN.match(raw_line)
        if m:
            label = m.group(1).strip()
            entry = {"label": label, "members": []}
            sg_stack.append(entry)
            subgraphs.append(entry)
            continue
        if _SUBGRAPH_END.match(raw_line):
            if sg_stack:
                sg_stack.pop()
            continue

        # Phase A: walk node patterns to record decorator-style nodes
        # (most specific first; consumed positions are masked so a less-
        # specific pattern can't re-match the same span).
        consumed = bytearray(len(raw_line))
        for pat, shape in _NODE_PATTERNS:
            for nm in pat.finditer(raw_line):
                if any(consumed[nm.start():nm.end()]):
                    continue
                node_id, label = nm.group(1), nm.group(2).strip()
                _record_node(node_id, label, shape)
                for i in range(nm.start(), nm.end()):
                    consumed[i] = 1

        # Phase B: edge extraction on a CLEANED copy of the line.
        # `A[user] --> B[api]` becomes `A --> B` so the edge regexes see
        # bare IDs at both ends.
        cleaned = _strip_node_decorators(raw_line)
        # Bidirectional / leftward arrows first (audit F056) -- they would
        # otherwise be missed by the rightward patterns below.
        bidir = _EDGE_BIDIR.search(cleaned)
        left = None if bidir else _EDGE_LEFT.search(cleaned)
        if bidir or left:
            a, b = (bidir or left).groups()
            pairs = ((a, b), (b, a)) if bidir else ((b, a),)
            for s, t in pairs:
                edges.append((s, t, ""))
            for raw_id in (a, b):
                if raw_id not in nodes_by_id:
                    _record_node(raw_id, "", "rect")
            continue
        edge_match = None
        for pat in (_EDGE_PIPE_LABEL, _EDGE_INLINE_LABEL, _EDGE_BARE):
            edge_match = pat.search(cleaned)
            if edge_match:
                groups = edge_match.groups()
                if len(groups) == 3:
                    src, edge_label, tgt = groups
                else:
                    src, tgt = groups
                    edge_label = ""
                edges.append((src, tgt, (edge_label or "").strip()))
                # Record bare endpoints if not already known.
                for raw_id in (src, tgt):
                    if raw_id not in nodes_by_id:
                        _record_node(raw_id, "", "rect")
                break

    # Build components.
    used_ids: set[str] = set()
    raw_to_comp_id: dict[str, str] = {}
    components: list[Component] = []
    for nid, info in nodes_by_id.items():
        label = info["label"] or nid
        shape = info["shape"]
        ctype, src = _classify_node(label, shape)
        comp_id = re.sub(r"[^A-Za-z0-9_]+", "_", nid).strip("_") or "node"
        original = comp_id
        n = 2
        while comp_id in used_ids:
            comp_id = f"{original}_{n}"
            n += 1
        used_ids.add(comp_id)
        raw_to_comp_id[nid] = comp_id

        # Trust zone from enclosing subgraph (if any).
        zone_label = "default"
        idx = info.get("subgraph_idx")
        if idx is not None and 0 <= idx < len(subgraphs):
            zone_label = re.sub(r"[^a-z0-9_]+", "_",
                                subgraphs[idx]["label"].lower())[:60] or "default"

        components.append(Component(
            id=comp_id,
            name=label,
            type=ctype,  # type: ignore[arg-type]
            trust_zone=zone_label,
            metadata={"source": f"mermaid:{src}", "shape": shape},
        ))

    # Build dataflows.
    dataflows: list[Dataflow] = []
    component_zone: dict[str, str] = {c.id: c.trust_zone for c in components}
    for src_raw, tgt_raw, edge_label in edges:
        src_id = raw_to_comp_id.get(src_raw)
        tgt_id = raw_to_comp_id.get(tgt_raw)
        if not (src_id and tgt_id):
            continue
        crosses = component_zone.get(src_id) != component_zone.get(tgt_id)
        dataflows.append(Dataflow(
            source=src_id, target=tgt_id,
            label=edge_label, crosses_boundary=crosses,
        ))

    # Build TrustBoundary objects (only for subgraphs whose label looks
    # like a boundary — VPC / subnet / DMZ / tenant / etc.).
    boundary_used: set[str] = set()
    trust_boundaries: list[TrustBoundary] = []
    for idx, sg in enumerate(subgraphs):
        if not _is_boundary_cell("", sg["label"]):
            continue
        member_comp_ids = [
            raw_to_comp_id[m] for m in sg["members"] if m in raw_to_comp_id
        ]
        if not member_comp_ids:
            continue
        b_id = re.sub(r"[^A-Za-z0-9_]+", "_", sg["label"].lower())[:60] or f"b{idx}"
        original = b_id
        n = 2
        while b_id in boundary_used:
            b_id = f"{original}_{n}"
            n += 1
        boundary_used.add(b_id)
        trust_boundaries.append(TrustBoundary(
            id=b_id,
            type=_classify_boundary_type(sg["label"], ""),  # type: ignore[arg-type]
            components_inside=member_comp_ids,
            description=sg["label"],
        ))

    name = system_name or default_name
    return System(
        name=name,
        components=components,
        dataflows=dataflows,
        trust_boundaries=trust_boundaries,
    )


__all__ = ["mermaid_to_system"]
