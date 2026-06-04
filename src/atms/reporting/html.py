"""HTML report renderer (self-contained, dark-mode default, print-friendly)."""

from __future__ import annotations

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ThreatModel
from ..paths import templates_dir
from .csa_table import build_table_of_attack
from .mermaid import render_mermaid

_TEMPLATE_DIR = templates_dir()


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
        csa_table=build_table_of_attack(model),
    )
