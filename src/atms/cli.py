"""ATMS command-line interface.

Commands:
  atms analyze <system.yaml> [--out DIR] [--format md,html,stix,navigator,csv,sarif,otm]
  atms ci <system.yaml> [--max-severity high|critical] [--sarif-out PATH]
  atms kb-search <query> [--framework ...] [--limit N]
  atms list-playbooks
  atms validate <system.yaml>
  atms web [--host 127.0.0.1] [--port 8765]
  atms ingest-evidence <evidence.{nessus,sarif,csv,json}> <system.yaml>
  atms ingest-otm <otm.{json,yaml}> [--out system.yaml]
  atms refresh-feeds [--kev | --epss | --all]
  atms cve-lookup CVE-YYYY-NNNN
  atms devices [--type <component_type>] [--query Q]
  atms compliance [--framework NIS2|DORA|EU_AI_Act|GDPR|PCI_DSS|HIPAA|...]
  atms version
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.table import Table

from . import __version__
from .kb import get_kb
from .models import System
from .paths import samples_dir
from .reporting import render_html, render_markdown, render_navigator, render_stix, write_csv

# v0.14.4: force UTF-8 on stdout / stderr so the smoke-tester's CJK
# component-name crash doesn't reproduce. On Windows the PyInstaller-
# frozen binary defaults to cp1252 via rich's `legacy_windows_render`
# path, which crashes on any non-Latin-1 character (Chinese, Japanese,
# Korean, Arabic, Cyrillic, even a curly quote). This must happen
# BEFORE the rich Console is constructed.
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (OSError, ValueError):
    # Some hosts (notably PyInstaller boot when stdout is not a tty)
    # don't expose .reconfigure. Tolerate; the worst case is the
    # legacy code-page path is still in effect, which we now mitigate
    # with the explicit force_terminal=False below.
    pass
from .features import cli_gated, graceful_hibernation
from .reporting.otm_export import render_otm
from .reporting.sarif_export import render_sarif
from .workflow import analyze as _raw_run_analysis


def run_analysis(*args, **kwargs):
    """Wrapper around `workflow.analyze` that turns a NoAIComponentsError
    into a friendly CLI error + exit. Every other exception passes
    through unchanged."""
    from .engines.ai_scope import NoAIComponentsError
    try:
        return _raw_run_analysis(*args, **kwargs)
    except NoAIComponentsError as e:
        console.print(f"[red]ATMS rejects this system:[/red] {e}")
        sys.exit(2)

# v0.14.4: force_terminal=None lets rich detect; legacy_windows=False
# avoids the cp1252 codec path that previously crashed on CJK names.
console = Console(legacy_windows=False, soft_wrap=True)


def _load_system_yaml(system_path: Path):
    """Read + parse a System YAML file with friendly errors.

    The bare `yaml.safe_load(path.read_text(encoding="utf-8"))` pattern
    leaks two unhandled exceptions: ``UnicodeDecodeError`` on a non-
    UTF-8 file and ``yaml.YAMLError`` on malformed YAML. Both produce
    a stack trace from a frozen PyInstaller binary — terrible UX. This
    wrapper catches them and exits with a one-line message.

    Validation errors from `System.model_validate` (Pydantic) are also
    caught here so the user sees the failing field, not a Pydantic
    traceback.
    """
    try:
        text = system_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        console.print(
            f"[red]Could not read {system_path}:[/red] file is not UTF-8 ({e})."
        )
        sys.exit(2)
    except OSError as e:
        console.print(f"[red]Could not read {system_path}:[/red] {e}")
        sys.exit(2)
    try:
        # alias-free loader: bans YAML anchors/aliases so an alias-expansion
        # 'billion laughs' file can't OOM the CLI (audit F051).
        from .yaml_autocorrect import safe_load_system_yaml
        raw = safe_load_system_yaml(text)
    except yaml.YAMLError as e:
        console.print(
            f"[red]Malformed YAML in {system_path}:[/red] {str(e).splitlines()[0]}"
        )
        sys.exit(2)
    if raw is None:
        console.print(f"[red]Empty YAML file:[/red] {system_path}")
        sys.exit(2)
    # v0.14.9: best-effort autocorrect free-text component types so a
    # hand-edited YAML with `type: 'IoT Device'` doesn't bounce the user
    # out of the analysis. Surface what we changed so the reviewer can
    # decide whether to accept it.
    from .yaml_autocorrect import autocorrect_system_yaml, format_validation_error
    raw, corrections = autocorrect_system_yaml(raw)
    if corrections:
        console.print(
            f"[yellow]Auto-corrected {len(corrections)} value(s):[/yellow] "
            + "; ".join(corrections[:5])
            + (" ..." if len(corrections) > 5 else "")
        )
    try:
        sys_obj = System.model_validate(raw)
    except Exception as e:  # noqa: BLE001 (Pydantic ValidationError + odd shapes)
        console.print(
            f"[red]Invalid System YAML in {system_path}:[/red] "
            + format_validation_error(e, raw)
        )
        sys.exit(2)
    # v0.15.0: surface a clear AI-scope warning at LOAD time so commands
    # like `kb-search` or `validate` that don't run analyze() still flag
    # the issue. analyze() itself raises NoAIComponentsError; the CLI
    # catches that in run_analysis() callers.
    from .engines.ai_scope import find_ai_components
    if not find_ai_components(sys_obj):
        console.print(
            "[yellow]Note:[/yellow] this system has no AI components. "
            "ATMS evaluates AI-induced risk only — `analyze` will reject it. "
            "Add an AI component (`agent`, `llm_inference`, `rag_vector_store`, ...) "
            "or set `metadata.ai_integration: true` on a non-AI-typed component."
        )
    return sys_obj


@click.group(help="AI Threat Modeling Studio — workflow tool.")
def cli() -> None:  # pragma: no cover
    pass


@cli.command()
def version() -> None:
    """Print the ATMS version."""
    click.echo(f"ATMS v{__version__}")


@cli.command()
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output as machine-readable JSON (for scripting / bug reports).",
)
def info(as_json: bool) -> None:
    """Print diagnostic info: version, KB stats, Python + platform.

    Useful for bug reports — paste the output into the issue. With
    `--json` the output is machine-readable so you can include it in
    CI logs without parsing.
    """
    import json as _json
    import platform
    import sys as _sys
    import typing

    from .engines.architectural_rules import ARCHITECTURAL_RULES
    from .features import enabled_features
    from .kb import get_kb
    from .models import ComponentType

    kb = get_kb()
    ct_count = len(typing.get_args(ComponentType))
    # `compliance_controls` is a flat {control_id: {framework, ...}} dict;
    # count distinct frameworks via the embedded `framework` field.
    frameworks = {
        c.get("framework", "unknown") for c in kb.compliance_controls.values()
    }

    # v0.18.72 Hibernation Phase 6 — surface the feature-flag snapshot
    # so bug reports include the hibernation profile of the build that
    # produced them.
    flags = enabled_features()
    enabled_flag_names = sorted(k for k, v in flags.items() if v)
    disabled_flag_names = sorted(k for k, v in flags.items() if not v)

    data = {
        "atms_version": __version__,
        "python_version": _sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "frozen": bool(getattr(_sys, "frozen", False)),
        "kb": {
            "playbooks": len(kb.playbooks),
            "frameworks": len(frameworks),
            "controls": len(kb.compliance_controls),
            "architecture_rules": len(ARCHITECTURAL_RULES),
            "component_types": ct_count,
        },
        "features": {
            "enabled_count": len(enabled_flag_names),
            "disabled_count": len(disabled_flag_names),
            "enabled": enabled_flag_names,
            "disabled": disabled_flag_names,
        },
    }

    if as_json:
        click.echo(_json.dumps(data, indent=2, sort_keys=True))
        return

    # Human-readable form — Rich-style table without the Rich dep
    # (this command runs at install diagnostic time; minimal imports).
    click.echo(f"ATMS v{data['atms_version']}")
    click.echo("")
    click.echo(f"  Python      {data['python_version']} ({data['python_implementation']})")
    click.echo(f"  Platform    {data['platform']}")
    click.echo(f"  Frozen exe  {'yes' if data['frozen'] else 'no'}")
    click.echo("")
    click.echo("Knowledge base:")
    click.echo(f"  Playbooks            {data['kb']['playbooks']}")
    click.echo(f"  Frameworks           {data['kb']['frameworks']}")
    click.echo(f"  Compliance controls  {data['kb']['controls']}")
    click.echo(f"  Architecture rules   {data['kb']['architecture_rules']}")
    click.echo(f"  Component types      {data['kb']['component_types']}")
    click.echo("")
    click.echo("Features:")
    click.echo(
        f"  {data['features']['enabled_count']} enabled · "
        f"{data['features']['disabled_count']} hibernated"
    )
    click.echo(
        f"  Hibernated:  {', '.join(disabled_flag_names) if disabled_flag_names else '(none)'}"
    )
    click.echo("")
    click.echo("Re-enable a hibernated feature:")
    click.echo("  ATMS_FEATURE_<NAME>=1 atms <command>")
    click.echo("  e.g. ATMS_FEATURE_EVIDENCE=1 atms web")
    click.echo("  See README 'Re-enabling hibernated features' for details.")


@cli.command()
@click.option(
    "--out", "out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write to FILE instead of stdout.",
)
@click.option(
    "--indent",
    type=int,
    default=2,
    help="JSON indent (default: 2). Set to 0 for compact output.",
)
def schema(out_path: Path | None, indent: int) -> None:
    """Print the JSON Schema describing ATMS System YAML.

    The schema is generated from `atms.models.System` and matches what
    `docs/system.schema.json` ships. Use this command for offline access
    or when scripting:

    \b
        atms schema                      # print to stdout
        atms schema --out my.schema.json # write to file
        atms schema --indent 0           # compact form (no whitespace)

    Editor users: pin the canonical URL instead — it's stable across
    releases (see README "Editor autocomplete on system YAML").
    """
    import json as _json

    from .models import System
    s = System.model_json_schema()
    # Match the docs/system.schema.json header so tooling can pick up
    # the canonical $schema / $id even when this command is the source.
    s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    s["$id"] = (
        "https://raw.githubusercontent.com/anguiz7z/AITMS/"
        "main/docs/system.schema.json"
    )
    text = _json.dumps(
        s,
        indent=indent if indent > 0 else None,
        sort_keys=True,
        separators=(",", ":") if indent == 0 else (",", ": "),
    )
    if out_path is None:
        click.echo(text)
    else:
        out_path.write_text(text + ("\n" if indent > 0 else ""), encoding="utf-8")
        click.echo(f"Wrote {out_path}")


@cli.command()
@click.argument("system_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path), default=Path("output"),
              help="Output directory (default: ./output)")
@click.option(
    "--format",
    "formats",
    multiple=True,
    type=click.Choice(["md", "html", "stix", "navigator", "csv", "json", "sarif", "otm", "exec", "compliance", "jira", "roadmap", "sbom", "all"]),
    default=("all",),
    help=("Output format. REPEAT the flag for multiple formats: "
          "`--format md --format html`. Use `--format all` for every "
          "format (md, html, stix, navigator, csv, json, sarif, otm). "
          "Comma-separated values like `--format md,html` are NOT supported."),
)
@click.option("--strict", is_flag=True,
              help="Fail (exit 3) if any component has type='other'. Forces a clean review.")
@click.option(
    "--methodology",
    type=click.Choice(["stride-ai", "linddun", "pasta"]),
    default="stride-ai",
    show_default=True,
    help=(
        "Threat-modelling lens. 'stride-ai' = full pipeline; 'pasta' = "
        "attacker-simulation filter (threats in attack paths or likelihood >= 4); "
        "'linddun' = privacy-only filter."
    ),
)
@click.option(
    "--prior-run",
    type=click.Path(exists=False, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Path to a previously-saved ThreatModel JSON. Dispositions "
        "(mitigated / false_positive / duplicate / accepted / etc.) "
        "are carried forward to matching threats by ID. Closed-state "
        "threats stop counting toward severity_breakdown + ALE rollups "
        "— so a triaged threat doesn't keep firing as a fresh 'critical' "
        "on every re-run. v0.17.2."
    ),
)
@click.option(
    "--deployment-stage",
    type=click.Choice(["poc", "pilot", "production"]),
    default=None,
    help=(
        "Override System.deployment_stage from the command line. "
        "Lets you re-run the same YAML in POC / pilot / production "
        "scale-tier modes without editing the file. Drives the "
        "scale-aware FAIR loss priors (POC caps frequency at 1/yr). v0.17.3."
    ),
)
@click.option(
    "--industry",
    type=click.Choice([
        "tier1_bank", "regional_bank", "fintech", "insurer",
        "healthcare_provider", "pharma_biotech",
        "tech_saas", "ecommerce", "media_entertainment", "telecom",
        "manufacturing", "energy_utility", "critical_infrastructure",
        "government_defense", "education", "smb_other",
        "midmarket_other",
    ]),
    default=None,
    help="Override System.industry (drives FAIR loss-prior tier selection). v0.17.3.",
)
@click.option(
    "--revenue-bucket",
    type=click.Choice([
        "under_50m", "50m_to_500m", "500m_to_5b", "over_5b", "unknown",
    ]),
    default=None,
    help="Override System.revenue_bucket (drives FAIR loss-prior tier selection). v0.17.3.",
)
@click.option(
    "--allow-pure-it", is_flag=True, default=False,
    help=(
        "Allow analysis of systems with zero AI components (pure-IT, "
        "pure-OT, hybrid). Lifts the v0.15+ AI-anchored scope gate. "
        "Every component is treated as in-scope; threats fire from "
        "every playbook. ATMS becomes a general-purpose threat "
        "modeler. v0.17.4."
    ),
)
def analyze(
    system_path: Path,
    out_dir: Path,
    formats: tuple[str, ...],
    strict: bool,
    methodology: str,
    prior_run: Path | None,
    deployment_stage: str | None,
    industry: str | None,
    revenue_bucket: str | None,
    allow_pure_it: bool,
) -> None:
    """Analyze an AI system YAML and write reports."""
    system = _load_system_yaml(system_path)
    # v0.17.3 Cycle E: apply CLI overrides for scale-tier knobs. Lets
    # users re-run the same YAML across POC / pilot / production
    # without editing it (closes the "POC is not automated" pain point
    # — POC is now a single `--deployment-stage poc` flag).
    overrides_applied: list[str] = []
    if deployment_stage:
        system.deployment_stage = deployment_stage  # type: ignore[assignment]
        overrides_applied.append(f"stage={deployment_stage}")
    if industry:
        system.industry = industry  # type: ignore[assignment]
        overrides_applied.append(f"industry={industry}")
    if revenue_bucket:
        system.revenue_bucket = revenue_bucket  # type: ignore[assignment]
        overrides_applied.append(f"revenue={revenue_bucket}")
    console.print(f"[bold]Analyzing:[/bold] {system.name}  [dim](methodology={methodology})[/dim]")
    console.print(f"  components={len(system.components)}  dataflows={len(system.dataflows)}")
    if overrides_applied:
        console.print(f"  [dim]CLI overrides applied: {', '.join(overrides_applied)}[/dim]")

    others = [c for c in system.components if c.type == "other"]
    if others:
        console.print(
            f"  [yellow]warning:[/yellow] {len(others)} component(s) have type='other' "
            "(low-confidence stubs only). Use [cyan]atms review[/cyan] to fix."
        )
        for c in others:
            console.print(f"    - {c.id}: {c.name!r}")
        if strict:
            console.print("[red]--strict: aborting because system has 'other' components.[/red]")
            sys.exit(3)

    model = run_analysis(
        system, methodology=methodology,
        prior_run=str(prior_run) if prior_run else None,
        require_ai_components=not allow_pure_it,
    )
    if prior_run:
        carried = model.summary.get("threats_closed", 0)
        console.print(f"  [dim]carried forward dispositions from {prior_run.name}: "
                      f"{carried} threat(s) now closed[/dim]")

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = system_path.stem
    fmts = set(formats)
    if "all" in fmts:
        fmts = {"md", "html", "stix", "navigator", "csv", "json", "sarif", "otm", "exec", "compliance", "jira", "roadmap", "sbom"}

    written: list[Path] = []
    if "md" in fmts:
        p = out_dir / f"{stem}.md"
        p.write_text(render_markdown(model), encoding="utf-8")
        written.append(p)
    if "html" in fmts:
        p = out_dir / f"{stem}.html"
        p.write_text(render_html(model), encoding="utf-8")
        written.append(p)
    if "stix" in fmts:
        p = out_dir / f"{stem}.stix.json"
        p.write_text(render_stix(model), encoding="utf-8")
        written.append(p)
    if "navigator" in fmts:
        p = out_dir / f"{stem}.navigator.json"
        p.write_text(render_navigator(model), encoding="utf-8")
        written.append(p)
    if "csv" in fmts:
        p = out_dir / f"{stem}.risk_register.csv"
        p.write_text(write_csv(model, "risk_register"), encoding="utf-8")
        written.append(p)
        p = out_dir / f"{stem}.mitigations.csv"
        p.write_text(write_csv(model, "mitigations"), encoding="utf-8")
        written.append(p)
    if "json" in fmts:
        p = out_dir / f"{stem}.json"
        p.write_text(model.model_dump_json(indent=2), encoding="utf-8")
        written.append(p)
    if "sarif" in fmts:
        p = out_dir / f"{stem}.sarif"
        p.write_text(render_sarif(model), encoding="utf-8")
        written.append(p)
    if "otm" in fmts:
        p = out_dir / f"{stem}.otm.json"
        p.write_text(render_otm(model), encoding="utf-8")
        written.append(p)
    if "exec" in fmts:
        # v0.18.10 Cycle Z: one-page leadership-friendly summary.
        from .reporting.exec_summary import render_exec_summary
        p = out_dir / f"{stem}.exec.html"
        p.write_text(render_exec_summary(model), encoding="utf-8")
        written.append(p)
    if "compliance" in fmts:
        # v0.18.15 Cycle EE: per-framework compliance coverage matrix.
        from .reporting.compliance_matrix import (
            render_compliance_matrix_csv,
            render_compliance_matrix_html,
        )
        p = out_dir / f"{stem}.compliance.html"
        p.write_text(render_compliance_matrix_html(model), encoding="utf-8")
        written.append(p)
        p = out_dir / f"{stem}.compliance.csv"
        p.write_text(render_compliance_matrix_csv(model), encoding="utf-8")
        written.append(p)
    if "jira" in fmts:
        # v0.18.17 Cycle GG: JIRA-compatible CSV + REST JSON for backlog import.
        from .reporting.jira_export import render_jira_csv, render_jira_json
        p = out_dir / f"{stem}.jira.csv"
        p.write_text(render_jira_csv(model), encoding="utf-8")
        written.append(p)
        p = out_dir / f"{stem}.jira.json"
        p.write_text(render_jira_json(model), encoding="utf-8")
        written.append(p)
    if "roadmap" in fmts:
        # v0.18.23 Cycle MM: prioritised mitigation roadmap for planning.
        from .reporting.roadmap_export import render_roadmap_json, render_roadmap_md
        p = out_dir / f"{stem}.roadmap.md"
        p.write_text(render_roadmap_md(model), encoding="utf-8")
        written.append(p)
        p = out_dir / f"{stem}.roadmap.json"
        p.write_text(render_roadmap_json(model), encoding="utf-8")
        written.append(p)
    if "sbom" in fmts:
        # v0.18.29 Cycle SS: CycloneDX 1.5 SBOM artefact.
        from .reporting.sbom_export import render_sbom_cdx
        p = out_dir / f"{stem}.sbom.cdx.json"
        p.write_text(render_sbom_cdx(model), encoding="utf-8")
        written.append(p)

    sb = model.summary["severity_breakdown"]
    console.print()
    console.print("[bold green]Analysis complete.[/bold green]")
    console.print(
        f"  threats={len(model.threats)}  attack_paths={len(model.attack_paths)}  "
        f"mitigations={len(model.mitigations)}"
    )
    console.print(
        f"  severity:  critical={sb.get('critical', 0)}  high={sb.get('high', 0)}  "
        f"medium={sb.get('medium', 0)}  low={sb.get('low', 0)}"
    )
    console.print(
        f"  OWASP coverage: {len(model.summary['owasp_coverage'])}/10  "
        f"ATLAS techniques referenced: {len(model.summary['atlas_coverage'])}"
    )
    console.print()
    console.print("[bold]Written:[/bold]")
    for p in written:
        console.print(f"  {p}")


@cli.command(name="ci")
@click.argument("system_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--max-severity", "max_sev",
              type=click.Choice(["info", "low", "medium", "high", "critical"]),
              default="critical", show_default=True,
              help="Fail the run with non-zero exit if any threat has severity >= this.")
@click.option("--sarif-out", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write a SARIF 2.1.0 report to this path (for GitHub code-scanning, etc.).")
@click.option("--methodology",
              type=click.Choice(["stride-ai", "linddun", "pasta"]),
              default="stride-ai", show_default=True)
def ci(system_path: Path, max_sev: str, sarif_out: Path | None, methodology: str) -> None:
    """Run analysis in CI mode. Exits non-zero when threats >= --max-severity exist.

    Suitable for blocking PRs in GitHub Actions / GitLab CI / Jenkins.
    Always emits a SARIF report when --sarif-out is given so the result
    can be uploaded to code-scanning dashboards.
    """
    system = _load_system_yaml(system_path)
    model = run_analysis(system, methodology=methodology)

    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = sev_rank[max_sev]
    over = [t for t in model.threats if sev_rank.get(t.severity, 0) >= threshold]
    sb = model.summary["severity_breakdown"]
    console.print(f"[bold]CI run:[/bold] {system.name}")
    console.print(
        f"  threats={len(model.threats)}  "
        f"critical={sb.get('critical', 0)} high={sb.get('high', 0)} "
        f"medium={sb.get('medium', 0)} low={sb.get('low', 0)}"
    )
    console.print(f"  evidence rows: {model.summary.get('evidence_total', 0)}  "
                  f"KEV hits: {model.summary.get('evidence_kev_hits', 0)}  "
                  f"unmatched: {model.summary.get('evidence_unmatched', 0)}")

    if sarif_out:
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(render_sarif(model), encoding="utf-8")
        console.print(f"  SARIF written: {sarif_out}")

    if over:
        console.print(
            f"[red]FAIL:[/red] {len(over)} threat(s) at severity >= {max_sev}."
        )
        for t in over[:10]:
            console.print(f"    {t.severity} {t.id} — {t.title}")
        sys.exit(2)
    console.print("[green]PASS.[/green]")


@cli.command(name="refresh-feeds")
@click.option("--kev/--no-kev", default=True, show_default=True,
              help="Refresh the bundled CISA KEV catalog from cisa.gov.")
@click.option("--epss/--no-epss", default=True, show_default=True,
              help="Refresh the bundled EPSS top-N from first.org.")
@click.option("--top-n", default=200, show_default=True,
              help="EPSS rows to keep (sorted by score).")
@click.option("--timeout", default=30, show_default=True,
              help="HTTP timeout per feed (seconds).")
@cli_gated("feeds_refresh")
def refresh_feeds(kev: bool, epss: bool, top_n: int, timeout: int) -> None:
    """Refresh the bundled threat-intel snapshots from canonical live feeds.

    Strict opt-in network call. The deterministic core never reaches the
    internet; this command exists so security teams can keep KEV / EPSS
    fresh on demand. Honours HTTP_PROXY / HTTPS_PROXY env vars.
    """
    from atms.feeds.refresh import refresh_epss as _refresh_epss
    from atms.feeds.refresh import refresh_kev as _refresh_kev
    from atms.paths import kb_dir

    ti_dir = kb_dir() / "threat_intel"
    ti_dir.mkdir(parents=True, exist_ok=True)
    if kev:
        try:
            n = _refresh_kev(ti_dir / "cisa_kev.yaml", timeout=timeout)
            console.print(f"[green]KEV refreshed:[/green] {n} rows -> {ti_dir / 'cisa_kev.yaml'}")
        except RuntimeError as e:
            console.print(f"[red]KEV refresh failed:[/red] {e}")
    if epss:
        try:
            n = _refresh_epss(ti_dir / "epss_top.yaml", top_n=top_n, timeout=timeout)
            console.print(f"[green]EPSS refreshed:[/green] {n} rows -> {ti_dir / 'epss_top.yaml'}")
        except RuntimeError as e:
            console.print(f"[red]EPSS refresh failed:[/red] {e}")


@cli.command(name="cve-lookup")
@click.argument("cve")
@click.option("--timeout", default=30, show_default=True)
@cli_gated("cve_lookup")
def cve_lookup_cmd(cve: str, timeout: int) -> None:
    """Look up a CVE via NVD (with OSV fallback).

    Strict opt-in network call. Cross-references against the bundled
    KEV / EPSS snapshots so the user sees the local view alongside the
    upstream CVE details.
    """
    from atms.feeds.cve_lookup import cve_lookup as _lookup
    try:
        res = _lookup(cve, timeout=timeout)
    except (RuntimeError, ValueError) as e:
        console.print(f"[red]Lookup failed:[/red] {e}")
        sys.exit(1)

    kb = get_kb()
    on_kev = res.cve in kb.kev_cves
    epss_score = next((float(e.get("epss")) for e in kb.epss_scores if e.get("cve", "").upper() == res.cve), None)

    console.print(f"\n[bold]{res.cve}[/bold]   ([dim]{res.source or 'no source'}[/dim])")
    if res.title:
        console.print(f"  {res.title}")
    if res.cvss is not None:
        console.print(f"  severity:    [bold]{res.severity or '-'}[/bold]   "
                      f"CVSS: {res.cvss}   {res.cvss_vector}")
    console.print(f"  on KEV:      {'[red]YES — actively exploited[/red]' if on_kev else 'no'}")
    if epss_score is not None:
        console.print(f"  EPSS (local snapshot): {epss_score:.4f}")
    if res.cwe:
        console.print(f"  CWE:         {', '.join(res.cwe[:5])}")
    if res.affected:
        console.print(f"  affected:    {', '.join(res.affected[:4])}")
    if res.published:
        console.print(f"  published:   {res.published}")
    if res.description:
        console.print(f"\n  {res.description[:600]}")
    if res.references:
        console.print("\n  references:")
        for r in res.references[:6]:
            console.print(f"    {r}")


@cli.command(name="compliance")
@click.option("--framework", default=None,
              help="Filter to one framework (NIS2, DORA, EU_AI_Act, GDPR, "
                   "PCI_DSS, HIPAA, NIST_800_53, NIST_CSF, ISO27001, SEC_CYBER).")
@click.option("--query", "-q", default="", help="Substring search across title / description.")
@click.option("--limit", default=80, type=int)
@cli_gated("cli_kb_browsers")
def compliance_cmd(framework: str | None, query: str, limit: int) -> None:
    """Browse the bundled compliance-control library."""
    kb = get_kb()
    rows = list(kb.compliance_controls.values())
    if framework:
        wanted = framework.strip()
        rows = [r for r in rows if r.get("framework", "").lower() == wanted.lower()]
    if query:
        ql = query.lower()
        rows = [r for r in rows
                if ql in str(r.get("title", "")).lower()
                or ql in str(r.get("description", "")).lower()]
    if not rows:
        console.print("[yellow]No matching compliance controls.[/yellow]")
        return
    table = Table(show_header=True)
    table.add_column("Framework", style="cyan")
    table.add_column("ID")
    table.add_column("Title", style="bold")
    table.add_column("Applies to")
    for r in rows[:limit]:
        applies = ", ".join((r.get("applies_to") or [])[:3]) or "any"
        table.add_row(
            r.get("framework", ""),
            r.get("id", ""),
            r.get("title", "")[:80],
            applies,
        )
    console.print(table)
    console.print(f"\n  [dim]Showing {min(len(rows), limit)} of {len(rows)} matching controls.[/dim]")


@cli.command(name="ingest-k8s")
@click.argument("manifest_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write the converted System YAML to this file (default: stdout).")
@click.option("--name", default=None, help="Override the system name (default: file stem).")
@click.option("--analyze", "do_analyze", is_flag=True,
              help="Also run analysis on the converted system (with --allow-pure-it auto-detection).")
@cli_gated("ingest_k8s")
def ingest_k8s_cmd(manifest_path: Path, out_path: Path | None, name: str | None, do_analyze: bool) -> None:
    """Convert Kubernetes manifests YAML into ATMS System YAML.

    Multi-document YAML supported (the common case — Helm output,
    `kubectl get all -o yaml`). 20+ kinds mapped:
      Workload   Deployment / StatefulSet / DaemonSet / Pod / Job / CronJob
      Network    Service / Ingress / NetworkPolicy / Gateway / HTTPRoute
      Identity   ServiceAccount / Role / RoleBinding / ClusterRole(Binding)
      Storage    PersistentVolume / PersistentVolumeClaim / StorageClass
      Config     ConfigMap / Secret

    Service.spec.selector → workload edges, Ingress → Service edges,
    workload → Secret/ConfigMap/PVC edges. Namespaces become tenancy
    trust boundaries.

    v0.18.7 Cycle W.
    """
    from atms.ingest.kubernetes import kubernetes_to_system
    system = kubernetes_to_system(manifest_path, system_name=name)
    out_text = yaml.safe_dump(system.model_dump(), sort_keys=False, default_flow_style=False, width=100)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        console.print(f"[green]Wrote:[/green] {out_path}  "
                      f"[dim]({len(system.components)} resources, "
                      f"{len(system.trust_boundaries)} namespaces)[/dim]")
    else:
        click.echo(out_text)
    if do_analyze:
        from .engines.ai_scope import find_ai_components
        has_ai = bool(find_ai_components(system))
        model = run_analysis(system, require_ai_components=has_ai)
        console.print(f"[bold]Analyzed:[/bold] {len(model.threats)} threats, "
                      f"{len(model.attack_paths)} paths, {len(model.mitigations)} mitigations"
                      + ("" if has_ai else " [dim](pure-IT mode)[/dim]"))


@cli.command(name="scan")
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path),
              default=Path("output"),
              help="Output directory for reports (default: ./output).")
@click.option(
    "--format", "formats", multiple=True,
    type=click.Choice(["md", "html", "stix", "navigator", "csv", "json", "sarif", "otm", "exec", "compliance", "jira", "roadmap", "sbom", "all"]),
    default=("all",),
    help="Output format. Use --format all for every format.",
)
@click.option("--methodology",
              type=click.Choice(["stride-ai", "linddun", "pasta"]),
              default="stride-ai", show_default=True,
              help="Threat-modelling lens.")
@graceful_hibernation
def scan_cmd(
    input_path: Path,
    out_dir: Path,
    formats: tuple[str, ...],
    methodology: str,
) -> None:
    """Auto-detect format, ingest, and analyze in one step.

    Replaces the two-step `atms ingest-X` → `atms analyze` flow with
    a single command. Format detection is by suffix first, then by
    content for ambiguous .yaml / .json files. Pure-IT systems
    auto-route through --allow-pure-it.

    Supported inputs (auto-detected):
      .drawio, .xml            draw.io / mxGraph
      .mmd, .mermaid           Mermaid flowchart
      .md                      markdown with ```mermaid``` fence
      .vsdx                    Microsoft Visio
      .tf                      Terraform HCL
      .bicep                   Azure Bicep DSL
      .tm7                     Microsoft Threat Modeling Tool (12th format)
      .yaml, .yml              System YAML (default) or:
                                 CloudFormation (if AWSTemplateFormatVersion or
                                                  Resources.X.Type: AWS::...)
                                 Kubernetes manifest (if apiVersion + kind)
                                 OTM (if otmVersion or otm: in keys)
                                 docker-compose (if version + services)
                                 Pulumi YAML (if runtime: yaml or
                                              aws:|azure-native:|gcp:|kubernetes: types)
      .json                    System JSON / OTM JSON / ARM template
                                 (auto-detects ARM via $schema=deploymentTemplate)
      .otm                     OTM (forced)

    v0.18.8 Cycle X.
    """
    suffix = input_path.suffix.lower()
    text = input_path.read_text(encoding="utf-8") if suffix not in {".vsdx", ".png", ".jpg"} else ""
    system_obj = None
    chosen = ""

    # Direct-by-suffix dispatch (most common case).
    if suffix in (".drawio", ".xml"):
        from .ingest.drawio import drawio_to_system
        system_obj = drawio_to_system(input_path)
        chosen = "drawio"
    elif suffix in (".mmd", ".mermaid"):
        from .ingest.mermaid import mermaid_to_system
        system_obj = mermaid_to_system(input_path)
        chosen = "mermaid"
    elif suffix == ".md":
        from .ingest.mermaid import mermaid_to_system
        system_obj = mermaid_to_system(input_path)
        chosen = "mermaid (extracted from markdown)"
    elif suffix == ".vsdx":
        from .ingest.vsdx import vsdx_to_system
        system_obj = vsdx_to_system(input_path)
        chosen = "visio"
    elif suffix == ".tf":
        from .ingest.terraform import parse_terraform
        system_obj = parse_terraform(input_path)
        chosen = "terraform"
    elif suffix == ".bicep":
        from .ingest.azure_arm import azure_to_system_from_path
        system_obj = azure_to_system_from_path(input_path)
        chosen = "bicep"
    elif suffix == ".tm7":
        from .ingest.tm7 import tm7_to_system
        system_obj = tm7_to_system(path=input_path)
        chosen = "tm7 (Microsoft Threat Modeling Tool)"
    elif suffix == ".otm":
        from .ingest.otm import parse_otm
        system_obj = parse_otm(input_path)
        chosen = "otm"
    elif suffix in (".yaml", ".yml", ".json"):
        # Content-sniff: look for distinguishing keys / markers.
        # NOTE: CDK is checked BEFORE plain CFN because CDK output IS
        # CFN with extra annotations; the more specific match wins.
        sniff = text[:4000]  # cheap prefix check
        if ('cdk_nag' in sniff or 'aws-cdk:' in sniff or
                '"aws:cdk:path"' in sniff or '"aws:cdk:asset' in sniff):
            from .ingest.cloudformation import cloudformation_to_system
            system_obj = cloudformation_to_system(input_path)
            chosen = "cdk (via CloudFormation)"
        elif ("AWSTemplateFormatVersion" in sniff
                or "AWS::" in sniff and "Resources:" in sniff
                or '"AWS::' in sniff and '"Resources"' in sniff):
            from .ingest.cloudformation import cloudformation_to_system
            system_obj = cloudformation_to_system(input_path)
            chosen = "cloudformation"
        elif ("apiVersion:" in sniff and "kind:" in sniff
                or '"apiVersion"' in sniff and '"kind"' in sniff):
            from .ingest.kubernetes import kubernetes_to_system
            system_obj = kubernetes_to_system(input_path)
            chosen = "kubernetes"
        elif "otmVersion" in sniff or '"otmVersion"' in sniff:
            from .ingest.otm import parse_otm
            system_obj = parse_otm(input_path)
            chosen = "otm"
        elif ("deploymentTemplate.json" in sniff
                or "armtemplates" in sniff.lower()
                or ("$schema" in sniff and "Microsoft." in sniff and "resources" in sniff.lower())):
            from .ingest.azure_arm import azure_to_system_from_path
            system_obj = azure_to_system_from_path(input_path)
            chosen = "arm-template"
        elif ("runtime: yaml" in sniff
                or ("runtime:\n" in sniff and "name: yaml" in sniff)
                or ("resources:" in sniff and re.search(r"type:\s*(?:aws|azure-native|gcp|kubernetes):", sniff))):
            from .ingest.pulumi_yaml import pulumi_to_system
            system_obj = pulumi_to_system(path=input_path)
            chosen = "pulumi-yaml"
        elif ('"deployment"' in sniff
                and ('"resources"' in sniff or '"urn"' in sniff)
                and ('urn:pulumi:' in sniff or '"type":"pulumi:' in sniff)):
            # Pulumi state JSON (`pulumi stack export`) — covers TS / Python /
            # Go stacks that don't have a parseable Pulumi.yaml.
            from .ingest.pulumi_yaml import pulumi_state_to_system
            system_obj = pulumi_state_to_system(path=input_path)
            chosen = "pulumi-state"
        elif (("services:" in sniff or '"services"' in sniff)
                and ("version:" in sniff or '"version"' in sniff)
                and "name:" not in sniff[:200]):
            # docker-compose — heuristic; "services" + "version" but
            # no top-level "name" (System YAML always has a name).
            try:
                from .ingest.docker_compose import parse_docker_compose
                system_obj = parse_docker_compose(input_path)
                chosen = "docker-compose"
            except Exception:  # noqa: BLE001
                system_obj = _load_system_yaml(input_path)
                chosen = "system-yaml"
        else:
            # Default: treat as System YAML/JSON.
            system_obj = _load_system_yaml(input_path)
            chosen = "system-yaml"
    else:
        console.print(f"[red]Unsupported file extension:[/red] {suffix}. "
                       "See `atms scan --help` for the supported list.")
        sys.exit(2)

    console.print(f"[bold]Scanned:[/bold] {input_path.name} → format=[cyan]{chosen}[/cyan]")
    console.print(f"  components={len(system_obj.components)}  "
                   f"dataflows={len(system_obj.dataflows)}  "
                   f"trust_boundaries={len(system_obj.trust_boundaries)}")

    # Auto-detect AI vs pure-IT — never bounce the user out on AI-scope.
    from .engines.ai_scope import find_ai_components
    has_ai = bool(find_ai_components(system_obj))
    if not has_ai:
        console.print("  [dim](pure-IT mode — no AI components detected)[/dim]")

    model = run_analysis(
        system_obj, methodology=methodology,
        require_ai_components=has_ai,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = input_path.stem
    fmts = set(formats)
    if "all" in fmts:
        fmts = {"md", "html", "stix", "navigator", "csv", "json", "sarif", "otm", "exec", "compliance", "jira", "roadmap", "sbom"}

    written: list[Path] = []
    if "md" in fmts:
        p = out_dir / f"{stem}.md"
        p.write_text(render_markdown(model), encoding="utf-8")
        written.append(p)
    if "html" in fmts:
        p = out_dir / f"{stem}.html"
        p.write_text(render_html(model), encoding="utf-8")
        written.append(p)
    if "stix" in fmts:
        p = out_dir / f"{stem}.stix.json"
        p.write_text(render_stix(model), encoding="utf-8")
        written.append(p)
    if "navigator" in fmts:
        p = out_dir / f"{stem}.navigator.json"
        p.write_text(render_navigator(model), encoding="utf-8")
        written.append(p)
    if "csv" in fmts:
        for kind in ("risk_register", "mitigations"):
            p = out_dir / f"{stem}.{kind}.csv"
            p.write_text(write_csv(model, kind), encoding="utf-8")
            written.append(p)
    if "json" in fmts:
        p = out_dir / f"{stem}.json"
        p.write_text(model.model_dump_json(indent=2), encoding="utf-8")
        written.append(p)
    if "sarif" in fmts:
        p = out_dir / f"{stem}.sarif"
        p.write_text(render_sarif(model), encoding="utf-8")
        written.append(p)
    if "otm" in fmts:
        p = out_dir / f"{stem}.otm.json"
        p.write_text(render_otm(model), encoding="utf-8")
        written.append(p)
    if "exec" in fmts:
        # v0.18.10 Cycle Z: exec summary also wired into scan.
        from .reporting.exec_summary import render_exec_summary
        p = out_dir / f"{stem}.exec.html"
        p.write_text(render_exec_summary(model), encoding="utf-8")
        written.append(p)
    if "compliance" in fmts:
        # v0.18.15 Cycle EE: compliance matrix also wired into scan.
        from .reporting.compliance_matrix import (
            render_compliance_matrix_csv,
            render_compliance_matrix_html,
        )
        p = out_dir / f"{stem}.compliance.html"
        p.write_text(render_compliance_matrix_html(model), encoding="utf-8")
        written.append(p)
        p = out_dir / f"{stem}.compliance.csv"
        p.write_text(render_compliance_matrix_csv(model), encoding="utf-8")
        written.append(p)
    if "jira" in fmts:
        # v0.18.17 Cycle GG: JIRA backlog export also wired into scan.
        from .reporting.jira_export import render_jira_csv, render_jira_json
        p = out_dir / f"{stem}.jira.csv"
        p.write_text(render_jira_csv(model), encoding="utf-8")
        written.append(p)
        p = out_dir / f"{stem}.jira.json"
        p.write_text(render_jira_json(model), encoding="utf-8")
        written.append(p)
    if "roadmap" in fmts:
        # v0.18.23 Cycle MM: mitigation roadmap also wired into scan.
        from .reporting.roadmap_export import render_roadmap_json, render_roadmap_md
        p = out_dir / f"{stem}.roadmap.md"
        p.write_text(render_roadmap_md(model), encoding="utf-8")
        written.append(p)
        p = out_dir / f"{stem}.roadmap.json"
        p.write_text(render_roadmap_json(model), encoding="utf-8")
        written.append(p)
    if "sbom" in fmts:
        # v0.18.29 Cycle SS: CycloneDX 1.5 SBOM also wired into scan.
        from .reporting.sbom_export import render_sbom_cdx
        p = out_dir / f"{stem}.sbom.cdx.json"
        p.write_text(render_sbom_cdx(model), encoding="utf-8")
        written.append(p)

    console.print()
    console.print("[bold green]Analysis complete.[/bold green]")
    console.print(f"  threats={len(model.threats)}  "
                   f"attack_paths={len(model.attack_paths)}  "
                   f"mitigations={len(model.mitigations)}")
    sev = model.summary.get("severity_breakdown", {})
    console.print("  severity:  "
                   + "  ".join(f"{k}={sev.get(k, 0)}" for k in ("critical", "high", "medium", "low")))
    console.print()
    console.print("[bold]Written:[/bold]")
    for p in written:
        console.print(f"  {p}")


@cli.command(name="ingest-cfn")
@click.argument("cfn_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write the converted System YAML to this file (default: stdout).")
@click.option("--name", default=None, help="Override the system name (default: file stem).")
@click.option("--analyze", "do_analyze", is_flag=True,
              help="Also run analysis on the converted system (with --allow-pure-it auto-detection).")
@cli_gated("ingest_cfn")
def ingest_cfn_cmd(cfn_path: Path, out_path: Path | None, name: str | None, do_analyze: bool) -> None:
    """Convert an AWS CloudFormation YAML/JSON template into ATMS System YAML.

    Pairs with `atms ingest-iac` (Terraform). 60+ AWS resource types
    mapped (compute, storage, DB, identity, network, AI/ML, security).
    Refs / Fn::GetAtt / DependsOn become dataflows; VPC/Subnet
    references become trust boundaries.

    Short-form intrinsic tags (!Ref, !GetAtt) aren't supported by the
    safe YAML loader — convert to long-form first via:
        aws cloudformation convert-template --template-body file://t.yaml

    v0.18.4 Cycle T.
    """
    from atms.ingest.cloudformation import cloudformation_to_system
    system = cloudformation_to_system(cfn_path, system_name=name)
    out_text = yaml.safe_dump(system.model_dump(), sort_keys=False, default_flow_style=False, width=100)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        console.print(f"[green]Wrote:[/green] {out_path}  "
                      f"[dim]({len(system.components)} resources, "
                      f"{len(system.trust_boundaries)} boundaries)[/dim]")
    else:
        click.echo(out_text)
    if do_analyze:
        from .engines.ai_scope import find_ai_components
        has_ai = bool(find_ai_components(system))
        model = run_analysis(system, require_ai_components=has_ai)
        console.print(f"[bold]Analyzed:[/bold] {len(model.threats)} threats, "
                      f"{len(model.attack_paths)} paths, {len(model.mitigations)} mitigations"
                      + ("" if has_ai else " [dim](pure-IT mode)[/dim]"))


@cli.command(name="ingest-tm7")
@click.argument("tm7_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write the converted System YAML to this file (default: stdout).")
@click.option("--name", default=None, help="Override the system name (default: file stem).")
@click.option("--analyze", "do_analyze", is_flag=True,
              help="Also run analysis on the converted system.")
@cli_gated("ingest_tm7")
def ingest_tm7_cmd(tm7_path: Path, out_path: Path | None, name: str | None, do_analyze: bool) -> None:
    """Convert a Microsoft Threat Modeling Tool (.tm7) file into ATMS System YAML.

    Microsoft Threat Modeling Tool is the de-facto threat-modelling
    tool inside many regulated organisations (banks, healthcare,
    defense). This command reads its native .tm7 XML format.

    Stencil shape conventions (Microsoft DFD primitives):
        StencilRectangle      → external entity (user / actor)
        StencilEllipse        → process (web_application / serverless_function / agent / …)
        StencilParallelLines  → data store (database / object_storage / secrets_vault / …)
        BorderBoundary        → trust boundary
        Connector             → dataflow

    Display-name keywords refine the type ("WAF" → waf,
    "Lambda" → serverless_function, "Secrets Manager" → secrets_vault,
    etc.). Pure stdlib + defusedxml; no Microsoft code borrowed.

    v0.18.41 Cycle EEE.
    """
    from atms.ingest.tm7 import tm7_to_system
    system = tm7_to_system(path=tm7_path, system_name=name)
    out_text = yaml.safe_dump(system.model_dump(), sort_keys=False, default_flow_style=False, width=100)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        console.print(f"[green]Wrote:[/green] {out_path}  "
                      f"[dim]({len(system.components)} elements, "
                      f"{len(system.dataflows)} dataflows, "
                      f"{len(system.trust_boundaries)} boundaries)[/dim]")
    else:
        click.echo(out_text)
    if do_analyze:
        from .engines.ai_scope import find_ai_components
        has_ai = bool(find_ai_components(system))
        model = run_analysis(system, require_ai_components=has_ai)
        console.print(f"[bold]Analyzed:[/bold] {len(model.threats)} threats, "
                      f"{len(model.attack_paths)} paths, {len(model.mitigations)} mitigations")


@cli.command(name="ingest-pulumi")
@click.argument("pulumi_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write the converted System YAML to this file (default: stdout).")
@click.option("--name", default=None, help="Override the system name (default: Pulumi stack name).")
@click.option("--analyze", "do_analyze", is_flag=True,
              help="Also run analysis on the converted system (with --allow-pure-it auto-detection).")
@cli_gated("ingest_pulumi")
def ingest_pulumi_cmd(pulumi_path: Path, out_path: Path | None, name: str | None, do_analyze: bool) -> None:
    """Convert a Pulumi YAML file (`Pulumi.yaml` / `*.pulumi.yaml`) into ATMS System YAML.

    Completes the IaC trifecta with `ingest-cfn` (AWS CloudFormation)
    and `ingest-azure` (Bicep / ARM). ~80 Pulumi resource types mapped
    across AWS / Azure / GCP / Kubernetes. `${name.attr}` references
    become dataflows; VPCs/VNets/Networks become trust boundaries.

    Pulumi TypeScript / Python / Go programs are NOT supported because
    they require code execution. Convert them first via:
        pulumi convert --language yaml
    or
        pulumi stack export > stack.json  (parse separately)

    v0.18.18 Cycle HH.
    """
    from atms.ingest.pulumi_yaml import pulumi_to_system
    system = pulumi_to_system(path=pulumi_path, system_name=name)
    out_text = yaml.safe_dump(system.model_dump(), sort_keys=False, default_flow_style=False, width=100)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        console.print(f"[green]Wrote:[/green] {out_path}  "
                      f"[dim]({len(system.components)} resources, "
                      f"{len(system.trust_boundaries)} boundaries)[/dim]")
    else:
        click.echo(out_text)
    if do_analyze:
        from .engines.ai_scope import find_ai_components
        has_ai = bool(find_ai_components(system))
        model = run_analysis(system, require_ai_components=has_ai)
        console.print(f"[bold]Analyzed:[/bold] {len(model.threats)} threats, "
                      f"{len(model.attack_paths)} paths, {len(model.mitigations)} mitigations"
                      + ("" if has_ai else " [dim](pure-IT mode)[/dim]"))


@cli.command(name="ingest-azure")
@click.argument("azure_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write the converted System YAML to this file (default: stdout).")
@click.option("--name", default=None, help="Override the system name (default: file stem).")
@click.option("--analyze", "do_analyze", is_flag=True,
              help="Also run analysis on the converted system (with --allow-pure-it auto-detection).")
@cli_gated("ingest_azure")
def ingest_azure_cmd(azure_path: Path, out_path: Path | None, name: str | None, do_analyze: bool) -> None:
    """Convert an Azure Bicep (`.bicep`) or ARM JSON template into ATMS System YAML.

    Pairs with `atms ingest-cfn` for AWS and `atms ingest-iac` for
    Terraform. ~60 Azure resource types mapped (compute, storage,
    SQL/Cosmos/Postgres/MySQL, KeyVault, App Service, AKS/ACI, AOAI,
    AML, Log Analytics, App Insights, App Gateway, Front Door, etc.).
    Symbolic references and `dependsOn` become dataflows;
    `Microsoft.Network/virtualNetworks` become trust boundaries.

    Auto-detects Bicep DSL vs ARM JSON from the file content.

    v0.18.14 Cycle DD.
    """
    from atms.ingest.azure_arm import azure_to_system_from_path
    system = azure_to_system_from_path(azure_path, name=name)
    out_text = yaml.safe_dump(system.model_dump(), sort_keys=False, default_flow_style=False, width=100)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        console.print(f"[green]Wrote:[/green] {out_path}  "
                      f"[dim]({len(system.components)} resources, "
                      f"{len(system.trust_boundaries)} boundaries)[/dim]")
    else:
        click.echo(out_text)
    if do_analyze:
        from .engines.ai_scope import find_ai_components
        has_ai = bool(find_ai_components(system))
        model = run_analysis(system, require_ai_components=has_ai)
        console.print(f"[bold]Analyzed:[/bold] {len(model.threats)} threats, "
                      f"{len(model.attack_paths)} paths, {len(model.mitigations)} mitigations"
                      + ("" if has_ai else " [dim](pure-IT mode)[/dim]"))


@cli.command(name="ingest-otm")
@click.argument("otm_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write the converted System YAML to this file (default: stdout).")
@click.option("--analyze", "do_analyze", is_flag=True,
              help="Also run analysis on the converted system (uses default formats).")
@cli_gated("ingest_otm")
def ingest_otm_cmd(otm_path: Path, out_path: Path | None, do_analyze: bool) -> None:
    """Convert an Open Threat Model (OTM v0.2) JSON/YAML file into ATMS System YAML.

    OTM is the open, vendor-neutral threat-model format used by IriusRisk,
    pyTM, and OWASP Threat Dragon. Use this command to import a model
    that started life in another tool.
    """
    from atms.ingest.otm import parse_otm
    system = parse_otm(otm_path)
    out_text = yaml.safe_dump(system.model_dump(), sort_keys=False, default_flow_style=False, width=100)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        console.print(f"[green]Wrote:[/green] {out_path}")
    else:
        click.echo(out_text)
    if do_analyze:
        model = run_analysis(system)
        console.print(f"[bold]Analyzed:[/bold] {len(model.threats)} threats, "
                      f"{len(model.attack_paths)} paths, {len(model.mitigations)} mitigations")


@cli.command(name="ingest-redteam")
@click.argument("artefact_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("system_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path),
              default=Path("output"), help="Output directory (default: ./output)")
@click.option("--format", "fmt",
              type=click.Choice(["auto", "caldera", "atomic", "bas_csv"]),
              default="auto", show_default=True)
@cli_gated("redteam")
def ingest_redteam(artefact_path: Path, system_path: Path, out_dir: Path, fmt: str) -> None:
    """Ingest a red-team / BAS artefact and run analysis with the chains applied.

    Caldera (.json), Atomic Red Team (.json/.jsonl), AttackIQ / Cymulate /
    SafeBreach BAS (.csv). Successful TTPs flip matched threats to status
    'exploited' and likelihood 5.
    """
    from atms.evidence.redteam import (
        parse_atomic_red_team,
        parse_bas_csv,
        parse_caldera,
        parse_redteam,
    )
    parsers = {"caldera": parse_caldera, "atomic": parse_atomic_red_team, "bas_csv": parse_bas_csv}
    rows = parse_redteam(artefact_path) if fmt == "auto" else parsers[fmt](artefact_path)
    system = _load_system_yaml(system_path)
    console.print(f"[bold]Red-team artefact:[/bold] {len(rows)} rows from {artefact_path.name}")
    model = run_analysis(system, evidence=rows)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = system_path.stem + "+redteam"
    md = out_dir / f"{stem}.md"
    md.write_text(render_markdown(model), encoding="utf-8")
    sb = model.summary["severity_breakdown"]
    console.print(f"  threats={len(model.threats)}  critical={sb.get('critical', 0)}  "
                  f"high={sb.get('high', 0)}  red-team rows attached: {model.summary.get('evidence_total', 0)}")
    console.print(f"  Written: {md}")


@cli.command(name="ingest-iac")
@click.argument("iac_path", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt",
              type=click.Choice(["auto", "compose", "terraform"]),
              default="auto", show_default=True,
              help="IaC format. 'auto' picks by extension / filename.")
@click.option("--out", "out_path", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write the converted System YAML here (default: stdout).")
@click.option("--analyze", "do_analyze", is_flag=True,
              help="Also run analysis on the converted system.")
@cli_gated("ingest_terraform")
def ingest_iac(iac_path: Path, fmt: str, out_path: Path | None, do_analyze: bool) -> None:
    """Convert Terraform (.tf / dir) or docker-compose YAML into ATMS System YAML.

    Pragmatic mappers — edit the result in the GUI editor before running
    analysis on it. Terraform supports AWS / Azure / GCP resource types
    out of the box; modules and count/for_each may need a `terraform show`
    expansion first.
    """
    from atms.ingest.docker_compose import parse_docker_compose
    from atms.ingest.terraform import parse_terraform

    if fmt == "auto":
        if iac_path.is_dir() or iac_path.suffix.lower() == ".tf":
            fmt = "terraform"
        elif iac_path.name.lower() in ("docker-compose.yml", "docker-compose.yaml",
                                        "compose.yml", "compose.yaml") or iac_path.suffix.lower() in (".yml", ".yaml"):
            fmt = "compose"
        else:
            fmt = "terraform"

    if fmt == "terraform":
        system = parse_terraform(iac_path)
    else:
        system = parse_docker_compose(iac_path)

    out_text = yaml.safe_dump(system.model_dump(), sort_keys=False,
                              default_flow_style=False, width=100)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text, encoding="utf-8")
        console.print(f"[green]Wrote:[/green] {out_path} ({len(system.components)} components, "
                      f"{len(system.dataflows)} dataflows)")
    else:
        click.echo(out_text)
    if do_analyze:
        model = run_analysis(system)
        console.print(f"[bold]Analyzed:[/bold] {len(model.threats)} threats, "
                      f"{len(model.attack_paths)} paths")


@cli.command(name="ingest-evidence")
@click.argument("evidence_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("system_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path),
              default=Path("output"), help="Output directory (default: ./output)")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["auto", "nessus", "sarif", "stix", "csv"]),
    default="auto",
    show_default=True,
    help="Evidence format. 'auto' picks by file extension.",
)
@click.option(
    "--methodology",
    type=click.Choice(["stride-ai", "linddun", "pasta"]),
    default="stride-ai",
    show_default=True,
    help="Threat-modelling lens.",
)
@cli_gated("evidence")
def ingest_evidence(
    evidence_path: Path,
    system_path: Path,
    out_dir: Path,
    fmt: str,
    methodology: str,
) -> None:
    """Ingest a VAPT / SARIF / STIX / CSV evidence file and run analysis.

    Each finding is matched to a component (by hostname / IP / product+version
    metadata, falling back to component-name substring match), attached as
    `Threat.evidence`, and used to upgrade severity / likelihood / confidence.
    CISA-KEV CVEs force severity to critical.
    """
    from atms.evidence import (
        parse_any,
        parse_csv,
        parse_nessus,
        parse_sarif,
        parse_stix,
    )

    # Pick the parser
    parsers = {"nessus": parse_nessus, "sarif": parse_sarif,
               "stix": parse_stix, "csv": parse_csv}
    if fmt == "auto":
        evidence_rows = parse_any(evidence_path)
    else:
        evidence_rows = parsers[fmt](evidence_path)

    system = _load_system_yaml(system_path)
    console.print(f"[bold]Evidence:[/bold] {len(evidence_rows)} rows from {evidence_path.name}")
    console.print(f"[bold]System:[/bold]   {system.name} ({len(system.components)} components)")
    console.print(f"[bold]Lens:[/bold]     {methodology}")

    model = run_analysis(system, methodology=methodology, evidence=evidence_rows)

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = system_path.stem + "+evidence"
    md_path = out_dir / f"{stem}.md"
    md_path.write_text(render_markdown(model), encoding="utf-8")
    html_path = out_dir / f"{stem}.html"
    html_path.write_text(render_html(model), encoding="utf-8")
    csv_path = out_dir / f"{stem}.csv"
    csv_path.write_text(write_csv(model, "risk_register"), encoding="utf-8")

    sb = model.summary["severity_breakdown"]
    sumtotal = model.summary.get("evidence_total", 0)
    kev_hits = model.summary.get("evidence_kev_hits", 0)
    console.print()
    console.print("[bold green]Evidence ingested.[/bold green]")
    console.print(f"  threats={len(model.threats)}  attack_paths={len(model.attack_paths)}  "
                  f"mitigations={len(model.mitigations)}")
    console.print(f"  severity:  critical={sb.get('critical', 0)}  high={sb.get('high', 0)}  "
                  f"medium={sb.get('medium', 0)}  low={sb.get('low', 0)}")
    console.print(f"  evidence rows attached: {sumtotal}   KEV hits: {kev_hits}")
    console.print()
    console.print("[bold]Written:[/bold]")
    for p in (md_path, html_path, csv_path):
        console.print(f"  {p}")


@cli.command(name="devices")
@click.option("--type", "ctype", default=None,
              help="Filter to one component type (e.g. directory_service, plc, llm_inference).")
@click.option("--query", "-q", default="", help="Substring search across vendor / product / description.")
@click.option("--limit", default=50, type=int)
def devices_cmd(ctype: str | None, query: str, limit: int) -> None:
    """Browse the bundled device & product catalog (v0.11)."""
    kb = get_kb()
    devs = kb.devices_for(ctype)
    if query:
        ql = query.lower()
        devs = [
            d for d in devs
            if ql in str(d.get("vendor", "")).lower()
            or ql in str(d.get("product", "")).lower()
            or ql in str(d.get("description", "")).lower()
            or any(ql in str(v).lower() for v in d.get("versions", []))
        ]
    if not devs:
        console.print("[yellow]No catalog entries match.[/yellow]")
        return
    table = Table(show_header=True)
    table.add_column("Category", style="cyan")
    table.add_column("Vendor")
    table.add_column("Product", style="bold")
    table.add_column("Versions")
    table.add_column("OS")
    for d in devs[:limit]:
        table.add_row(
            d.get("category", "other"),
            d.get("vendor", ""),
            d.get("product", ""),
            ", ".join(str(v) for v in (d.get("versions", []) or [])[:4]),
            d.get("os", "") or "—",
        )
    console.print(table)
    console.print(f"\n  [dim]Showing {min(len(devs), limit)} of {len(devs)} matching entries.[/dim]")


@cli.command(name="kb-search")
@click.argument("query")
@click.option(
    "--framework",
    type=click.Choice(
        [
            "all",
            "atlas",
            "attack",
            "attack_cloud",
            "attack_enterprise",
            "owasp",
            "owasp_llm",
            "owasp_agentic",
            "owasp_api",
            "owasp_ml",
            "linddun",
            "nist_ai_100_2",
            "compliance",
            "maestro",
            "nist",
        ]
    ),
    default="all",
    help="Filter to one framework. 'owasp' covers LLM Top 10 + Agentic + API; "
         "'attack' covers Cloud + Enterprise + ICS; use the explicit name "
         "for a single slice.",
)
@click.option("--limit", default=10, type=int)
def kb_search(query: str, framework: str, limit: int) -> None:
    """Keyword search across the knowledge base."""
    kb = get_kb()
    fw = None if framework == "all" else framework
    results = kb.search(query, framework=fw, limit=limit)
    if not results:
        console.print(f"[yellow]No results for: {query}[/yellow]")
        return
    table = Table(title=f"KB results for '{query}' (top {len(results)})")
    table.add_column("Framework", style="cyan", width=10)
    table.add_column("ID", style="magenta", width=18)
    table.add_column("Title", style="bold", width=42)
    table.add_column("Score", justify="right")
    table.add_column("Snippet", overflow="fold")
    for r in results:
        table.add_row(r["framework"], r["id"], r["title"], str(r["score"]), r["snippet"])
    console.print(table)


@cli.command(name="list-playbooks")
def list_playbooks() -> None:
    """List all per-component playbooks."""
    kb = get_kb()
    table = Table(title="Component playbooks")
    table.add_column("Component type", style="cyan")
    table.add_column("Threats", justify="right")
    table.add_column("Description", overflow="fold")
    for ctype, pb in sorted(kb.playbooks.items()):
        table.add_row(ctype, str(len(pb.get("threats", []))), pb.get("description", "").strip().split("\n")[0])
    console.print(table)


@cli.command()
@click.argument("system_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--in-place", is_flag=True, help="Overwrite the input YAML in place.")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None,
              help="Write reviewed YAML here (default: stdout).")
@cli_gated("cli_review")
def review(system_path: Path, in_place: bool, out_path: Path | None) -> None:
    """Walk every 'other'-typed component and prompt for the correct ATMS type.

    Useful after `atms ingest` when the heuristic classifier couldn't pick a
    type. Suggested types are listed; press Enter to keep 'other'.
    """

    # The full v0.13 component-type list (kept in sync with ComponentType
    # in models.py). Lacking entries here would make `atms review` unable
    # to fix anything beyond the original v0.7 types.
    valid_types = [
        # AI / agentic
        "llm_inference", "rag_vector_store", "agent", "tool", "mcp_server",
        "training_pipeline", "fine_tuning_pipeline", "embedding_service",
        "prompt_template_store", "model_registry", "guardrails", "output_filter",
        "data_source", "external_api", "user",
        # Cloud (v0.9)
        "iam_principal", "secrets_vault", "object_storage", "network_segment",
        "serverless_function", "api_gateway", "container_runtime", "kms_key",
        "message_queue", "observability_stack",
        # IT / OT / network / identity (v0.10)
        "database", "firewall", "directory_service", "web_application", "endpoint",
        "legacy_mainframe", "plc", "scada", "iot_device", "load_balancer",
        "vpn_gateway", "network_switch", "email_server", "mfa_service",
        "industrial_protocol",
        # Catch-all
        "other",
    ]

    system_obj = _load_system_yaml(system_path)

    others = [c for c in system_obj.components if c.type == "other"]
    if not others:
        console.print(f"[green]No 'other'-typed components in {system_path.name}. Nothing to review.[/green]")
        return

    console.print(f"[bold]{len(others)} component(s) need review.[/bold]")
    console.print(f"Valid types: {', '.join(valid_types)}\n")
    changed = 0
    for comp in others:
        console.print(f"[cyan]{comp.id}[/cyan]  name={comp.name!r}")
        if comp.description and comp.description != comp.name:
            console.print(f"  description: {comp.description[:120]}")
        new_type = click.prompt(
            "  type",
            default="other",
            show_default=True,
            type=click.Choice(valid_types, case_sensitive=False),
        )
        if new_type != comp.type:
            comp.type = new_type  # type: ignore[assignment]
            changed += 1
        console.print()

    out_yaml = yaml.safe_dump(system_obj.model_dump(), sort_keys=False, default_flow_style=False, width=100)
    if in_place:
        system_path.write_text(out_yaml, encoding="utf-8")
        console.print(f"[green]Wrote {changed} change(s) back to {system_path}[/green]")
    elif out_path:
        out_path.write_text(out_yaml, encoding="utf-8")
        console.print(f"[green]Wrote {changed} change(s) to {out_path}[/green]")
    else:
        console.print(out_yaml)


@cli.command()
@click.argument("system_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--strict", is_flag=True,
              help="Exit 3 if any component has type='other' (forces a clean review). v0.17.3.")
@click.option("--check-ai-scope/--no-check-ai-scope", default=True,
              help="Reject systems with zero AI components (default: on). "
                   "Exit 4 on failure. v0.17.3.")
@click.option("--json", "as_json", is_flag=True,
              help="Emit a machine-readable JSON report on stdout — useful "
                   "for CI pre-commit hooks. v0.17.3.")
def validate(system_path: Path, strict: bool, check_ai_scope: bool, as_json: bool) -> None:
    """Validate a system YAML against the System schema.

    Exit codes (CI-friendly):
      0 — valid (and AI-scope check passed if enabled)
      2 — invalid YAML / model validation failed
      3 — --strict and at least one component has type='other'
      4 — --check-ai-scope and zero AI components found

    The exit codes are stable across versions; safe to use in pre-commit
    hooks, GitHub-Actions guards, and similar CI gates.
    """

    # _load_system_yaml() prints its own diagnostic + sys.exit(2) on
    # validation failure, so reaching the next line means the YAML
    # validated successfully.
    sys_model = _load_system_yaml(system_path)

    others = [c for c in sys_model.components if c.type == "other"]
    no_ai = False
    if check_ai_scope:
        from .engines.ai_scope import find_ai_components
        no_ai = not find_ai_components(sys_model)

    report = {
        "path": str(system_path),
        "name": sys_model.name,
        "components": len(sys_model.components),
        "dataflows": len(sys_model.dataflows),
        "other_components": [c.id for c in others],
        "ai_components_present": not no_ai if check_ai_scope else None,
        "valid": True,
        "exit_code": 0,
    }

    # Determine final exit code (priority: ai-scope > strict > ok).
    if no_ai:
        report["valid"] = False
        report["exit_code"] = 4
        report["reason"] = "No AI/ML/agentic components found — out of ATMS scope."
    elif strict and others:
        report["valid"] = False
        report["exit_code"] = 3
        report["reason"] = (
            f"--strict: {len(others)} component(s) have type='other'. "
            "Run `atms review` and assign concrete types."
        )

    if as_json:
        click.echo(json.dumps(report, indent=2))
    else:
        if report["valid"]:
            console.print(
                f"[green]OK[/green] - {sys_model.name}: "
                f"{len(sys_model.components)} components, "
                f"{len(sys_model.dataflows)} dataflows"
            )
            if others:
                console.print(
                    f"  [yellow]warning:[/yellow] {len(others)} component(s) "
                    "have type='other' (use --strict to fail on this)."
                )
        else:
            console.print(f"[red]FAIL[/red] - {report.get('reason')}")

    sys.exit(report["exit_code"])


_INIT_TEMPLATES: dict[str, dict] = {
    "basic": {
        "description": "Minimal one-LLM scaffold (1 user → 1 LLM).",
        "system": {
            "deployment_stage": "poc",
            "components": [
                {"id": "u", "name": "User", "type": "user"},
                {"id": "llm", "name": "LLM inference",
                 "type": "llm_inference",
                 "description": "Replace with the actual model name + vendor (e.g. Bedrock / Claude)."},
            ],
            "dataflows": [
                {"source": "u", "target": "llm", "label": "prompt"},
            ],
        },
    },
    "rag": {
        "description": "RAG scaffold (user → LLM ⇄ vector store).",
        "system": {
            "deployment_stage": "poc",
            "components": [
                {"id": "u", "name": "User", "type": "user"},
                {"id": "llm", "name": "LLM inference", "type": "llm_inference"},
                {"id": "rag", "name": "RAG vector store",
                 "type": "rag_vector_store",
                 "description": "Replace with your vector DB (Kendra / Azure AI Search / Pinecone)."},
                {"id": "src", "name": "Document source",
                 "type": "data_source",
                 "description": "Where indexed documents come from."},
            ],
            "dataflows": [
                {"source": "u", "target": "llm", "label": "query"},
                {"source": "llm", "target": "rag", "label": "retrieve"},
                {"source": "rag", "target": "llm", "label": "chunks"},
                {"source": "src", "target": "rag", "label": "index"},
            ],
        },
    },
    "agentic": {
        "description": "Agentic scaffold (agent + tool + guardrails).",
        "system": {
            "deployment_stage": "poc",
            "components": [
                {"id": "u", "name": "User", "type": "user"},
                {"id": "ag", "name": "Agent", "type": "agent",
                 "metadata": {"tool_scope": "read"}},
                {"id": "guard", "name": "Guardrails", "type": "guardrails"},
                {"id": "tool", "name": "External tool", "type": "tool"},
            ],
            "dataflows": [
                {"source": "u", "target": "guard", "label": "request"},
                {"source": "guard", "target": "ag", "label": "filtered"},
                {"source": "ag", "target": "tool", "label": "invoke"},
            ],
        },
    },
    "chatbot": {
        "description": "Chatbot scaffold (user + LLM + output filter).",
        "system": {
            "deployment_stage": "poc",
            "components": [
                {"id": "u", "name": "End user", "type": "user"},
                {"id": "llm", "name": "Chat LLM", "type": "llm_inference"},
                {"id": "out", "name": "Output filter", "type": "output_filter",
                 "description": "PII / jailbreak-response redactor before the user sees the reply."},
            ],
            "dataflows": [
                {"source": "u", "target": "llm", "label": "prompt"},
                {"source": "llm", "target": "out", "label": "response"},
                {"source": "out", "target": "u", "label": "redacted"},
            ],
        },
    },
}


@cli.command(name="init")
@click.argument("name", required=False, default="my-system")
@click.option(
    "--template", type=click.Choice(list(_INIT_TEMPLATES.keys())),
    default="basic", show_default=True,
    help="Which starter scaffold to write.",
)
@click.option(
    "--out", "out_path", type=click.Path(path_type=Path), default=None,
    help="Output YAML path (default: <name>.yaml in cwd).",
)
@click.option(
    "--force", is_flag=True,
    help="Overwrite the output file if it already exists.",
)
def init_cmd(name: str, template: str, out_path: Path | None, force: bool) -> None:
    """Scaffold a starter System YAML.

    Writes a minimal, valid System YAML with placeholder components +
    dataflows that the user can edit. Default `deployment_stage` is
    `poc` so freshly-scaffolded systems get the POC FAIR-priors tier.

    Examples:

      atms init my-chatbot --template chatbot
      atms init aws-rag --template rag --out samples/aws-rag.yaml
    """
    target = out_path if out_path else Path(f"{name}.yaml")
    if target.exists() and not force:
        console.print(
            f"[red]{target} already exists.[/red] Use --force to overwrite, "
            f"or pass --out to write somewhere else."
        )
        sys.exit(2)

    tpl = _INIT_TEMPLATES[template]
    payload = {"name": name, **tpl["system"]}
    yaml_text = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml_text, encoding="utf-8")
    console.print(
        f"[green]Wrote[/green] {target}  "
        f"[dim]({template}: {tpl['description']})[/dim]"
    )
    console.print(f"  next: [cyan]atms validate {target}[/cyan] then "
                  f"[cyan]atms analyze {target}[/cyan]")


@cli.command()
@click.argument("diagram_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None,
              help="Write YAML to this path (default: stdout).")
@click.option("--name", default=None, help="Override the system name (default: file stem).")
@click.option("--analyze", "analyze_after", is_flag=True,
              help="Run analysis on the parsed system after writing the YAML.")
@graceful_hibernation
def ingest(diagram_path: Path, out_path: Path | None, name: str | None, analyze_after: bool) -> None:
    """Ingest an architecture diagram and emit a System YAML draft.

    Supported formats:
      - .vsdx              Microsoft Visio (since v0.6)
      - .drawio / .xml     draw.io / diagrams.net (since v0.17.4)
      - .mmd / .mermaid    Mermaid flowchart source (new in v0.18.1)
      - .md                markdown file with a ```mermaid fence (new in v0.18.1)

    The output is a *draft*. Review and edit before running analysis.
    Legacy binary .vsd is not supported — convert in Visio or LibreOffice first.
    """
    from .ingest.vsdx import vague_dataflows, vsdx_to_system

    suffix = diagram_path.suffix.lower()
    if suffix == ".vsd":
        console.print("[red]Legacy .vsd is not supported.[/red] Open in Visio (or LibreOffice "
                       "Draw) and 'Save As' .vsdx, then retry.")
        sys.exit(2)
    if suffix in (".drawio", ".xml"):
        # v0.17.4: draw.io / diagrams.net XML support.
        from .ingest.drawio import classification_summary, drawio_to_system
        system_obj = drawio_to_system(diagram_path, system_name=name)
        summary = classification_summary(system_obj)
        console.print(
            f"  [dim]classified: {summary['style']} via style, "
            f"{summary['label']} via label, "
            f"{summary['fallback']} fallback[/dim]"
        )
    elif suffix in (".mmd", ".mermaid"):
        # v0.18.1 Cycle P: Mermaid flowchart.
        from .ingest.mermaid import mermaid_to_system
        system_obj = mermaid_to_system(diagram_path, system_name=name)
        console.print(f"  [dim]parsed mermaid: {len(system_obj.components)} nodes, "
                       f"{len(system_obj.trust_boundaries)} subgraph boundaries[/dim]")
    elif suffix in (".cfn", ".cloudformation"):
        # v0.18.4 Cycle T: CloudFormation YAML/JSON.
        from .ingest.cloudformation import cloudformation_to_system
        system_obj = cloudformation_to_system(diagram_path, system_name=name)
        console.print(f"  [dim]parsed CloudFormation: {len(system_obj.components)} resources, "
                       f"{len(system_obj.trust_boundaries)} VPC/subnet boundaries[/dim]")
    elif suffix == ".md":
        # v0.18.1: extract first ```mermaid block from a markdown file.
        from .ingest.mermaid import mermaid_to_system
        system_obj = mermaid_to_system(diagram_path, system_name=name)
        if not system_obj.components:
            console.print(f"[red]No mermaid block found in {diagram_path}.[/red] "
                           "Expected a ```mermaid ... ``` fence containing flowchart syntax.")
            sys.exit(2)
        console.print(f"  [dim]extracted mermaid from markdown: "
                       f"{len(system_obj.components)} nodes[/dim]")
    elif suffix == ".vsdx":
        system_obj = vsdx_to_system(diagram_path, system_name=name)
    else:
        console.print(f"[red]Unsupported diagram format:[/red] {suffix} "
                       "(expected .vsdx / .drawio / .xml / .mmd / .mermaid / .md)")
        sys.exit(2)
    yaml_text = yaml.safe_dump(system_obj.model_dump(), sort_keys=False, default_flow_style=False, width=100)

    console.print(f"[bold]Parsed[/bold] {diagram_path.name}: {len(system_obj.components)} components, "
                   f"{len(system_obj.dataflows)} dataflows")
    types = {c.type for c in system_obj.components}
    if "other" in types:
        n_other = sum(1 for c in system_obj.components if c.type == "other")
        console.print(f"  [yellow]{n_other} component(s) classified as 'other'[/yellow] — "
                       "run [cyan]atms review[/cyan] to fix.")
    vague = vague_dataflows(system_obj)
    if vague:
        console.print(f"  [yellow]{len(vague)} dataflow(s) have vague labels[/yellow] — "
                       "add verb-phrase labels for auto data-classification.")

    if out_path:
        out_path.write_text(yaml_text, encoding="utf-8")
        console.print(f"  YAML written to {out_path}")
    else:
        console.print()
        console.print(yaml_text)

    if analyze_after:
        if not out_path:
            console.print("[yellow]--analyze requires --out so the system YAML is persisted.[/yellow]")
            return
        console.print()
        console.print("[bold]Running analysis on the parsed system...[/bold]")
        ctx = click.get_current_context()
        ctx.invoke(analyze, system_path=out_path, out_dir=Path("output"), formats=("all",))


@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
@click.option("--reload", is_flag=True, help="Enable autoreload (dev mode)")
def web(host: str, port: int, reload: bool) -> None:
    """Run the ATMS web UI (FastAPI)."""
    import uvicorn  # local import to keep startup fast

    # In a PyInstaller-frozen build, sys.frozen is set. Uvicorn's import-string
    # path doesn't work in frozen mode (no module search path), so we pass the
    # app object directly — at the cost of disabling --reload, which in any
    # case requires a writable source tree.
    if getattr(sys, "frozen", False):
        if reload:
            console.print("[yellow]--reload is not supported in the frozen .exe build.[/yellow]")
        from .web import app
        uvicorn.run(app, host=host, port=port)
    else:
        uvicorn.run("atms.web:app", host=host, port=port, reload=reload)


@cli.command()
@click.argument("old_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("new_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["table", "markdown", "json"]), default="table",
              help="Output format (default: table).")
@cli_gated("cli_diff")
def diff(old_path: Path, new_path: Path, fmt: str) -> None:
    """Diff two analysis runs (the JSON dumps written by `atms analyze`).

    Shows added / removed threats and any threat whose severity changed.
    Useful to track progress across iterations of the same system.
    """

    old_doc = json.loads(old_path.read_text(encoding="utf-8"))
    new_doc = json.loads(new_path.read_text(encoding="utf-8"))

    def _index(doc: dict) -> dict[str, dict]:
        return {t["id"]: t for t in doc.get("threats", [])}

    old_idx = _index(old_doc)
    new_idx = _index(new_doc)

    added_ids = sorted(set(new_idx) - set(old_idx))
    removed_ids = sorted(set(old_idx) - set(new_idx))
    common_ids = sorted(set(old_idx) & set(new_idx))
    severity_changed = [
        (tid, old_idx[tid]["severity"], new_idx[tid]["severity"])
        for tid in common_ids
        if old_idx[tid]["severity"] != new_idx[tid]["severity"]
    ]
    score_changed = [
        (tid, old_idx[tid].get("risk_score", 0), new_idx[tid].get("risk_score", 0))
        for tid in common_ids
        if abs(old_idx[tid].get("risk_score", 0) - new_idx[tid].get("risk_score", 0)) >= 5
    ]
    # v0.16.6 — disposition lifecycle changes. Surfaces threats that
    # moved from `open` → `accepted` / `mitigated` / `transferred` /
    # `accepted_with_compensating_control` / `deferred`. Lets a CISO see
    # "6 dispositions changed this quarter" instead of regenerating
    # 65 threats from scratch.
    disposition_changed = [
        (tid, old_idx[tid].get("disposition", "open"), new_idx[tid].get("disposition", "open"))
        for tid in common_ids
        if old_idx[tid].get("disposition", "open") != new_idx[tid].get("disposition", "open")
    ]

    summary_old = old_doc.get("summary", {})
    summary_new = new_doc.get("summary", {})

    if fmt == "json":
        click.echo(json.dumps({
            "added_threats": [new_idx[t] for t in added_ids],
            "removed_threats": [old_idx[t] for t in removed_ids],
            "severity_changed": [
                {"threat_id": t, "from": o, "to": n} for t, o, n in severity_changed
            ],
            "score_changed": [
                {"threat_id": t, "from": o, "to": n} for t, o, n in score_changed
            ],
            "disposition_changed": [
                {"threat_id": t, "from": o, "to": n} for t, o, n in disposition_changed
            ],
            "summary_old": summary_old,
            "summary_new": summary_new,
        }, indent=2))
        return

    if fmt == "markdown":
        lines: list[str] = []
        lines.append(f"# Diff: {old_path.name} -> {new_path.name}\n")
        lines.append(f"- Added threats: {len(added_ids)}")
        lines.append(f"- Removed threats: {len(removed_ids)}")
        lines.append(f"- Severity changes: {len(severity_changed)}")
        lines.append(f"- Risk-score changes (>=5): {len(score_changed)}\n")
        if added_ids:
            lines.append("## Added")
            for t in added_ids:
                th = new_idx[t]
                lines.append(f"- `{t}` **{th['severity']}** {th['title']} (risk {th.get('risk_score', 0)})")
            lines.append("")
        if removed_ids:
            lines.append("## Removed")
            for t in removed_ids:
                th = old_idx[t]
                lines.append(f"- `{t}` **{th['severity']}** {th['title']} (risk {th.get('risk_score', 0)})")
            lines.append("")
        if severity_changed:
            lines.append("## Severity changed")
            for t, o, n in severity_changed:
                lines.append(f"- `{t}` {o} -> **{n}**: {new_idx[t]['title']}")
            lines.append("")
        if disposition_changed:
            lines.append("## Disposition changed")
            for t, o, n in disposition_changed:
                ctx = ""
                # Surface lifecycle context fields if populated
                t_new = new_idx[t]
                bits = []
                if t_new.get("compensating_control_id"):
                    bits.append(f"control={t_new['compensating_control_id']}")
                if t_new.get("transferred_to_vendor"):
                    bits.append(f"vendor={t_new['transferred_to_vendor']}")
                if t_new.get("mitigated_by_commit"):
                    bits.append(f"commit={t_new['mitigated_by_commit']}")
                if t_new.get("deferred_until"):
                    bits.append(f"until={t_new['deferred_until']}")
                if bits:
                    ctx = f"  ({', '.join(bits)})"
                lines.append(f"- `{t}` {o} -> **{n}**{ctx}: {new_idx[t]['title']}")
            lines.append("")
        click.echo("\n".join(lines))
        return

    # Default: rich tables
    console.print(f"[bold]{old_path.name}[/bold] -> [bold]{new_path.name}[/bold]")
    console.print(
        f"  threats: {summary_old.get('threats', '?')} -> {summary_new.get('threats', '?')}  "
        f"mitigations: {summary_old.get('mitigations', '?')} -> {summary_new.get('mitigations', '?')}"
    )
    console.print(
        f"  added={len(added_ids)}  removed={len(removed_ids)}  "
        f"severity_changed={len(severity_changed)}  score_changed={len(score_changed)}  "
        f"disposition_changed={len(disposition_changed)}"
    )
    if added_ids:
        t = Table(title=f"Added ({len(added_ids)})")
        t.add_column("ID"); t.add_column("Severity"); t.add_column("Title")
        for tid in added_ids:
            th = new_idx[tid]
            t.add_row(tid, th["severity"], th["title"])
        console.print(t)
    if removed_ids:
        t = Table(title=f"Removed ({len(removed_ids)})")
        t.add_column("ID"); t.add_column("Severity"); t.add_column("Title")
        for tid in removed_ids:
            th = old_idx[tid]
            t.add_row(tid, th["severity"], th["title"])
        console.print(t)
    if severity_changed:
        t = Table(title=f"Severity changed ({len(severity_changed)})")
        t.add_column("ID"); t.add_column("From"); t.add_column("To"); t.add_column("Title")
        for tid, o, n in severity_changed:
            t.add_row(tid, o, n, new_idx[tid]["title"])
        console.print(t)


def compute_run_delta(prev_model, new_model) -> dict:
    """Pure-function comparator used by `atms watch` (v0.18.22 Cycle LL).

    Returns a dict summarising how the threat register changed between
    two analysis runs:

      {
        "threats_prev": int,
        "threats_now": int,
        "added_ids": [...],     # threat IDs present now but not before
        "removed_ids": [...],   # threat IDs that disappeared
        "severity_changed": [{"id":..., "from":..., "to":...}, ...],
        "severity_breakdown_now":  {critical:N, high:N, ...},
        "severity_breakdown_prev": {...},
        "severity_delta":          {critical:+N, high:-N, ...},
      }

    Factored out of the watch loop so it can be tested directly.
    """
    prev_threats = {t.id: t for t in (prev_model.threats if prev_model else [])}
    new_threats = {t.id: t for t in new_model.threats}
    added = sorted(set(new_threats) - set(prev_threats))
    removed = sorted(set(prev_threats) - set(new_threats))
    sev_changed = []
    for tid in set(prev_threats) & set(new_threats):
        if prev_threats[tid].severity != new_threats[tid].severity:
            sev_changed.append({
                "id": tid,
                "from": prev_threats[tid].severity,
                "to": new_threats[tid].severity,
            })
    from collections import Counter
    sb_prev = dict(Counter(t.severity for t in (prev_model.threats if prev_model else [])))
    sb_now = dict(Counter(t.severity for t in new_model.threats))
    all_sevs = set(sb_prev) | set(sb_now)
    sev_delta = {s: sb_now.get(s, 0) - sb_prev.get(s, 0) for s in all_sevs}
    return {
        "threats_prev": len(prev_threats),
        "threats_now": len(new_threats),
        "added_ids": added,
        "removed_ids": removed,
        "severity_changed": sev_changed,
        "severity_breakdown_prev": sb_prev,
        "severity_breakdown_now": sb_now,
        "severity_delta": sev_delta,
    }


@cli.command(name="watch")
@click.argument("system_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--interval", type=float, default=2.0, show_default=True,
              help="Seconds between mtime polls.")
@click.option("--methodology",
              type=click.Choice(["stride-ai", "linddun", "pasta"]),
              default="stride-ai", show_default=True)
@click.option("--max-iters", type=int, default=None, hidden=True,
              help="Internal: stop after N iterations (for tests).")
@cli_gated("cli_watch")
def watch_cmd(
    system_path: Path,
    interval: float,
    methodology: str,
    max_iters: int | None,
) -> None:
    """Watch a System YAML for changes and re-analyse on every edit.

    Polls `mtime` every `--interval` seconds; whenever the file
    changes, re-runs `analyze` and prints the delta (added /
    removed / severity-changed threats + severity breakdown).
    Ctrl-C to stop. v0.18.22 Cycle LL.
    """
    import time

    last_mtime = 0.0
    prev_model = None
    iters = 0
    console.print(f"[bold]Watching:[/bold] {system_path}  "
                   f"[dim](interval={interval}s, methodology={methodology})[/dim]")
    console.print("[dim]Press Ctrl-C to stop.[/dim]")

    try:
        while True:
            try:
                mtime = system_path.stat().st_mtime
            except OSError as exc:
                console.print(f"[red]watch: stat() failed: {exc}[/red]")
                break

            if mtime > last_mtime:
                last_mtime = mtime
                try:
                    system = _load_system_yaml(system_path)
                    has_ai = True  # default to AI-scope; can be parameterised later
                    from .engines.ai_scope import find_ai_components
                    if not find_ai_components(system):
                        has_ai = False
                    model = run_analysis(
                        system, methodology=methodology,
                        require_ai_components=has_ai,
                    )
                except (Exception, SystemExit) as exc:  # noqa: BLE001
                    # `_load_system_yaml` calls sys.exit(2) on parse errors;
                    # catch SystemExit too so the watch loop survives them.
                    console.print(f"[red]watch: analysis failed: {exc}[/red]")
                else:
                    delta = compute_run_delta(prev_model, model)
                    ts = time.strftime("%H:%M:%S")
                    console.print(
                        f"[green]{ts}[/green]  "
                        f"threats: {delta['threats_prev']} → {delta['threats_now']}  "
                        f"(+{len(delta['added_ids'])} -{len(delta['removed_ids'])})  "
                        f"sev-changed: {len(delta['severity_changed'])}"
                    )
                    breakdown = delta["severity_breakdown_now"]
                    console.print(
                        "  [dim]severity[/dim]: "
                        + "  ".join(f"{k}={breakdown.get(k, 0)}"
                                     for k in ("critical", "high", "medium", "low", "info"))
                    )
                    if delta["severity_changed"]:
                        for change in delta["severity_changed"][:5]:
                            console.print(
                                f"  [yellow]sev[/yellow] "
                                f"{change['id']}: {change['from']} → {change['to']}"
                            )
                    prev_model = model

            iters += 1
            if max_iters is not None and iters >= max_iters:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print()
        console.print("[bold]watch: stopped (Ctrl-C).[/bold]")


@cli.command(name="mcp")
@cli_gated("mcp_server")
def mcp_cmd() -> None:
    """Run ATMS as an MCP (Model Context Protocol) stdio server.

    Lets Claude Code (and any other MCP client) query the ATMS
    knowledge base and run analyses without invoking the CLI.

    Wire into Claude Code via .mcp.json:

        {
          "mcpServers": {
            "atms": {
              "command": "atms",
              "args": ["mcp"]
            }
          }
        }

    Exposed tools:
        atms_analyze            Analyze a System YAML, return ThreatModel
        atms_scan_text          Scan an inline diagram / IaC artefact
        atms_search_playbook    Get a playbook by ComponentType
        atms_search_compliance  Search compliance controls
        atms_metrics            KB inventory snapshot

    v0.18.43 Cycle GGG. Pure-stdlib stdio JSON-RPC 2.0; no new deps.
    """
    from .mcp_server import serve_stdio
    serve_stdio()


@cli.command()
def selftest() -> None:
    """Run sample analyses against bundled fixtures and assert basic invariants."""
    samples_path = samples_dir()
    failures: list[str] = []
    # audit F010: selftest is the official install-verification command (the
    # installer runs it post-install). If the package shipped without its
    # samples/, globbing yields zero files and the old code fell straight
    # through to "All sample analyses passed." -- a false GREEN on a broken
    # install. Fail loudly instead.
    yaml_samples = sorted(samples_path.glob("*.yaml"))
    if not yaml_samples:
        console.print(
            f"[red]selftest: no sample systems found at {samples_path}[/red]"
        )
        console.print(
            "[red]This install is missing its bundled samples/ -- the package "
            "is broken (see paths.samples_dir / wheel shared-data).[/red]"
        )
        sys.exit(1)
    # v0.17.4: auto-detect pure-IT samples so selftest covers them too.
    from .engines.ai_scope import find_ai_components
    for path in yaml_samples:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            system = System.model_validate(raw)
            has_ai = bool(find_ai_components(system))
            model = run_analysis(system, require_ai_components=has_ai)
            mode = "" if has_ai else " [pure-IT]"
            if len(model.threats) < 5:
                failures.append(f"{path.name}: only {len(model.threats)} threats")
            elif has_ai and not model.summary["owasp_coverage"]:
                # OWASP-LLM coverage assertion only applies to AI samples.
                failures.append(f"{path.name}: no OWASP coverage")
            else:
                console.print(
                    f"[green]OK[/green] {path.name}{mode}: "
                    f"{len(model.threats)} threats, {len(model.attack_paths)} paths, "
                    f"{len(model.mitigations)} mitigations"
                )
        except Exception as e:  # noqa: BLE001
            failures.append(f"{path.name}: {e}")
    if failures:
        console.print()
        console.print("[red]Failures:[/red]")
        for f in failures:
            console.print(f"  - {f}")
        sys.exit(1)
    console.print("[bold green]All sample analyses passed.[/bold green]")


if __name__ == "__main__":  # pragma: no cover
    cli()
