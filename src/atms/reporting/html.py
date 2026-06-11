"""HTML report renderer (self-contained, dark-mode default, print-friendly)."""

from __future__ import annotations

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ThreatModel
from ..paths import static_dir, templates_dir
from .csa_table import build_table_of_attack
from .mermaid import render_attack_path_graph, render_mermaid

_TEMPLATE_DIR = templates_dir()


def _bundled_mermaid_js() -> str:
    """Read the Mermaid library bundled in ``static/mermaid.min.js`` so the
    standalone HTML report renders its diagrams with **no network** — matching
    the tool's offline-first promise. Returns ``""`` if the asset is missing
    (the report then falls back to showing the Mermaid source, as before).
    """
    src = static_dir() / "mermaid.min.js"
    try:
        return src.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _choke_ids(model: ThreatModel) -> set[str]:
    cps = (model.summary or {}).get("choke_points") or []
    return {cp.get("component_id") for cp in cps if isinstance(cp, dict)}


def render_html(model: ThreatModel) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(
        system=model.system,
        threats=model.threats,
        attack_paths=model.attack_paths,
        mitigations=model.mitigations,
        summary=model.summary,
        tool_version=model.tool_version,
        generated_at=model.generated_at.isoformat(timespec="seconds"),
        mermaid_dfd=render_mermaid(model.system),
        mermaid_paths=render_attack_path_graph(
            model.attack_paths, model.system, _choke_ids(model)
        ),
        mermaid_js=_bundled_mermaid_js(),
        csa_table=build_table_of_attack(model),
    )
