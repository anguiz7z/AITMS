"""Regression test pinning the v0.16.10 STRIDE-AI / DREAD-AI cleanup.

The rename from "STRIDE-AI" / "DREAD-AI" to "STRIDE for AI" /
"Likelihood × Impact (DREAD-derived)" must reach every user-facing
template. This test scans Jinja templates + the report templates and
fails if either literal string appears anywhere outside the allowlist.

The single allowlisted occurrence is `web/about.html`, where the
literal appears INSIDE a sentence explaining why we no longer use the
name — i.e. it's the disclaimer documenting the rename itself.

Also pins the methodology-provenance contract added in v0.16.10:
every StrideAI value must have a published-framework anchor in
kb/methodology_provenance.yaml, and the about page must render it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from atms.kb import get_kb
from atms.models import StrideAI

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src" / "atms" / "templates"

# Files where the literal "STRIDE-AI" / "DREAD-AI" is intentional —
# they document the legacy name as part of the disclaimer.
ALLOWLIST = {
    "web/about.html",
}

BANNED = ("STRIDE-AI", "DREAD-AI")


def _iter_template_files():
    for p in TEMPLATES.rglob("*"):
        if p.is_dir():
            continue
        if p.suffix not in (".html", ".j2"):
            continue
        rel = p.relative_to(TEMPLATES).as_posix()
        if rel in ALLOWLIST:
            continue
        yield p, rel


@pytest.mark.parametrize("banned_term", BANNED)
def test_no_legacy_branding_in_templates(banned_term: str):
    """No user-facing template may contain the legacy `STRIDE-AI` or
    `DREAD-AI` literal (except the about-page disclaimer)."""
    hits: list[tuple[str, int, str]] = []
    for path, rel in _iter_template_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if banned_term in text:
            for line_no, line in enumerate(text.splitlines(), start=1):
                if banned_term in line:
                    hits.append((rel, line_no, line.strip()))
    assert not hits, (
        f"Found {len(hits)} leak(s) of legacy {banned_term!r} in user-facing templates:\n"
        + "\n".join(f"  {rel}:{ln}: {line}" for rel, ln, line in hits)
    )


def test_every_stride_category_has_methodology_provenance():
    """Every value in the StrideAI Literal must have an entry in
    kb/methodology_provenance.yaml — otherwise the about page will
    silently leave a category un-anchored."""
    kb = get_kb()
    expected = set(StrideAI.__args__)
    actual = set(kb.methodology_provenance.keys())
    missing = expected - actual
    extra = actual - expected
    assert not missing, (
        f"StrideAI categories missing from methodology_provenance.yaml: "
        f"{sorted(missing)}"
    )
    assert not extra, (
        f"methodology_provenance.yaml has unknown categories: "
        f"{sorted(extra)}"
    )


def test_methodology_provenance_entries_have_required_fields():
    """Each entry must carry anchor + url + standing + summary."""
    kb = get_kb()
    for cat, info in kb.methodology_provenance.items():
        for field in ("anchor", "url", "standing", "summary"):
            assert field in info, f"{cat!r}: missing {field!r}"
        assert info["standing"] in ("standard", "atms_extension"), (
            f"{cat!r}: unknown standing {info['standing']!r}"
        )
        assert info["url"].startswith("http"), (
            f"{cat!r}: url should be a URL, got {info['url']!r}"
        )


def test_about_page_renders_provenance_table():
    """The /about route must include the provenance table in the
    rendered HTML, with both 'standard' and 'ATMS extension' pills."""
    from fastapi.testclient import TestClient

    from atms.web import app
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/about")
    assert r.status_code == 200
    html = r.text
    assert "Threat-category provenance" in html
    assert "Bias_Fairness" in html
    assert "NIST AI RMF" in html
    assert "ATMS extension" in html


def test_about_page_renders_every_stride_category():
    """EVERY StrideAI category must appear on the /about provenance table —
    not just the ones a hardcoded order list happens to name.

    Regression for v1.0.4: the /about route built its table from a literal
    9-item `order` list that omitted Lateral_Movement, so the new category
    was silently dropped from the page even though the KB carried it. The
    route now appends any provenance key not in the explicit order, and
    this test guards that every future category renders."""
    from fastapi.testclient import TestClient

    from atms.models import StrideAI
    from atms.web import app
    client = TestClient(app, raise_server_exceptions=False)
    html = client.get("/about").text
    missing = [c for c in StrideAI.__args__ if c not in html]
    assert not missing, (
        f"/about provenance table is missing STRIDE categories {missing}. "
        f"The route's `order` list probably needs the new category (or the "
        f"append-leftovers fallback regressed)."
    )


def test_methodology_route_empty_path():
    """`/methodology` with no path renders the empty-state page."""
    from fastapi.testclient import TestClient

    from atms.web import app
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/methodology")
    assert r.status_code == 200
    assert "No threat-model results loaded" in r.text


def test_methodology_route_with_real_threats(tmp_path, monkeypatch):
    """`/methodology` analyses a fresh System and renders per-threat
    framework citations. Uses an in-memory analyse to avoid depending
    on any specific output file."""
    from fastapi.testclient import TestClient

    from atms.models import Component, System
    from atms.web import app
    from atms.workflow import analyze

    sys_obj = System(name="t", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    tm = analyze(sys_obj)
    assert tm.threats, "analyze() must produce threats for the smoke test"

    # Save under output/ in a temp cwd and pass the basename: the route now
    # sandboxes ?path= to output//cwd (audit F049/F050), so an absolute temp
    # path is correctly rejected.
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "output"
    out_dir.mkdir()
    (out_dir / "smoke.json").write_text(tm.model_dump_json(), encoding="utf-8")

    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/methodology?path=smoke.json")
    assert r.status_code == 200
    html = r.text
    # Page must show STRIDE breakdown + per-threat table.
    assert "STRIDE breakdown" in html
    assert "Per-threat provenance" in html
