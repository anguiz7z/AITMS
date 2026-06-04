"""Roadmap V5 Phase 4 — report quality (HTML + Markdown).

The report is the deliverable a customer keeps. Phase 4 fixed a real
gap and pins report quality:

  * BUG (fixed): the HTML report template (`report.html.j2`) rendered
    per-threat pills for OWASP LLM / Agentic / API / ATLAS / ATT&CK /
    LINDDUN / NIST AI 100-2 / OWASP ML / MAESTRO — but NOT
    `csa_singapore`, even though CSA Singapore is named in the core
    promise and IS populated on threats (via the KB playbook refs).
    A threat carrying a CSA ref had its attribution silently dropped
    from the HTML report (the Markdown report already rendered it).
    Fixed by adding a CSA pill to the HTML template.

  * Pins that every core-promise framework present on a real analysed
    system renders in BOTH the HTML and the Markdown report.

  * Pins exec-summary count accuracy.

All assertions run against REAL `analyze()` output (which has a fully
populated summary), not hand-built ThreatModels. KEEP suite.
"""

from __future__ import annotations

import glob
from pathlib import Path

import yaml

from atms.engines.ai_scope import find_ai_components
from atms.models import System
from atms.reporting.html import render_html
from atms.reporting.markdown import render_markdown
from atms.workflow import analyze

ROOT = Path(__file__).resolve().parents[1]


def _analyze(name: str):
    s = System.model_validate(
        yaml.safe_load((ROOT / "samples" / name).read_text(encoding="utf-8")))
    has_ai = bool(find_ai_components(s))
    return analyze(s, require_ai_components=has_ai)


# ─── CSA Singapore renders in the HTML report (the fix) ─────────────


def test_csa_singapore_renders_in_html_report():
    """rag_system carries CSA Singapore refs; every one must appear in
    the HTML report (the gap Phase 4 closed)."""
    tm = _analyze("rag_system.yaml")
    csa_refs = sorted({c for t in tm.threats for c in t.csa_singapore})
    assert csa_refs, "expected rag_system threats to carry CSA Singapore refs"
    html = render_html(tm)
    for ref in csa_refs:
        assert ref in html, f"CSA ref {ref} missing from HTML report"


def test_csa_singapore_renders_in_markdown_report():
    tm = _analyze("rag_system.yaml")
    csa_refs = sorted({c for t in tm.threats for c in t.csa_singapore})
    assert csa_refs
    md = render_markdown(tm)
    for ref in csa_refs:
        assert ref in md, f"CSA ref {ref} missing from Markdown report"


def test_html_template_has_csa_pill():
    """Structural guard: the HTML template iterates t.csa_singapore."""
    tpl = (ROOT / "src" / "atms" / "templates" / "report.html.j2").read_text(
        encoding="utf-8")
    assert "t.csa_singapore" in tpl, (
        "report.html.j2 must render a csa_singapore pill"
    )


# ─── Every present core-promise framework renders in both formats ───


def test_core_promise_frameworks_render_in_both_reports():
    """For an agentic sample, every core-promise framework that appears
    on any threat must render in BOTH the HTML and Markdown report."""
    tm = _analyze("agentic_system.yaml")
    html = render_html(tm)
    md = render_markdown(tm)

    fields = {
        "owasp_llm": "OWASP LLM",
        "owasp_agentic": "OWASP Agentic",
        "atlas_techniques": "MITRE ATLAS",
        "maestro_threats": "MAESTRO",
        "csa_singapore": "CSA Singapore",
    }
    for field, label in fields.items():
        refs = sorted({r for t in tm.threats for r in getattr(t, field)})
        if not refs:
            continue  # framework not triggered by this sample — skip
        # Spot-check the first ref renders in both formats.
        ref = refs[0]
        assert ref in html, f"{label} ref {ref} missing from HTML report"
        assert ref in md, f"{label} ref {ref} missing from Markdown report"


def test_all_core_frameworks_represented_across_ai_fleet_reports():
    """Across the AI fleet, each core-promise framework renders in at
    least one HTML report (proves the templates wire every field)."""
    seen = {"owasp_llm": False, "owasp_agentic": False,
            "atlas_techniques": False, "maestro_threats": False,
            "csa_singapore": False}
    for f in sorted(glob.glob(str(ROOT / "samples" / "*.yaml"))):
        s = System.model_validate(yaml.safe_load(Path(f).read_text(encoding="utf-8")))
        if not find_ai_components(s):
            continue
        tm = analyze(s)
        html = render_html(tm)
        for field in seen:
            if seen[field]:
                continue
            refs = {r for t in tm.threats for r in getattr(t, field)}
            if refs and any(r in html for r in refs):
                seen[field] = True
    missing = [k for k, v in seen.items() if not v]
    assert not missing, f"frameworks never rendered in any HTML report: {missing}"


# ─── HTML report is a well-formed standalone document ───────────────


def test_html_report_is_wellformed_document():
    tm = _analyze("rag_system.yaml")
    html = render_html(tm)
    assert "<html" in html.lower() and "</html>" in html.lower()
    assert "<style" in html.lower()  # self-contained styled doc
    assert len(html) > 2000


# ─── Summary accuracy ───────────────────────────────────────────────


def test_summary_threat_count_matches_threats():
    for f in sorted(glob.glob(str(ROOT / "samples" / "*.yaml")))[:6]:
        s = System.model_validate(yaml.safe_load(Path(f).read_text(encoding="utf-8")))
        has_ai = bool(find_ai_components(s))
        tm = analyze(s, require_ai_components=has_ai)
        summary = tm.summary
        count = (summary.get("threats") if isinstance(summary, dict)
                 else getattr(summary, "threats", None))
        if count is not None:
            assert count == len(tm.threats), (
                f"{Path(f).name}: summary says {count} threats but there "
                f"are {len(tm.threats)}"
            )
