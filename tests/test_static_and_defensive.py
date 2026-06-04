"""Tests for the bundled-Mermaid + defensive-init hardening (v0.7.0)."""

from __future__ import annotations

from atms.paths import static_dir


def test_static_dir_exists_and_has_mermaid():
    sd = static_dir()
    assert sd.exists()
    files = {p.name for p in sd.iterdir()}
    assert "mermaid.min.js" in files
    assert "atms-mermaid.js" in files


def test_bundled_mermaid_is_substantial():
    """Catch a corrupted / truncated download."""
    sd = static_dir()
    js = sd / "mermaid.min.js"
    # Mermaid 10.x minified is ~3 MB; sanity-bound to catch a 0-byte dud
    assert js.stat().st_size > 1_000_000, "bundled mermaid.min.js looks truncated"


def test_atms_mermaid_helper_has_defensive_logic():
    """Verify the helper script actually contains the validation logic so a
    refactor doesn't silently regress to the old start-on-load behaviour."""
    sd = static_dir()
    helper = (sd / "atms-mermaid.js").read_text(encoding="utf-8")
    assert "isLikelyMermaid" in helper
    # Don't auto-start — we control init ourselves
    assert "startOnLoad: false" in helper
    # Vetted-only render
    assert "validBlocks" in helper
    # Friendly fallback message instead of bomb icon
    assert "Diagram unavailable" in helper or "unavailable" in helper


def test_static_files_served_via_fastapi(client_module_scope):
    c = client_module_scope
    r = c.get("/static/mermaid.min.js")
    assert r.status_code == 200
    assert "javascript" in (r.headers.get("content-type") or "").lower()
    assert len(r.content) > 1_000_000

    r2 = c.get("/static/atms-mermaid.js")
    assert r2.status_code == 200
    assert b"isLikelyMermaid" in r2.content


def test_unknown_static_404(client_module_scope):
    r = client_module_scope.get("/static/does-not-exist.js")
    assert r.status_code == 404


def test_inline_web_report_uses_local_mermaid(client_module_scope):
    """The inline web report must reference the local /static/ paths, not a CDN."""
    from pathlib import Path

    samples_dir_path = Path(__file__).resolve().parents[1] / "samples"
    yaml_text = (samples_dir_path / "chatbot.yaml").read_text(encoding="utf-8")
    r = client_module_scope.post("/analyze", data={"yaml": yaml_text})
    assert r.status_code == 200
    body = r.text
    assert "/static/mermaid.min.js" in body
    assert "/static/atms-mermaid.js" in body
    # No accidental CDN reference left in the inline path
    assert "cdn.jsdelivr.net/npm/mermaid" not in body


def test_downloadable_html_report_has_defensive_init():
    """The standalone HTML report (downloadable + emailable) keeps the CDN but
    must also have the defensive init guard so opening the raw template or
    viewing offline doesn't show the bomb-icon error."""
    from pathlib import Path

    import yaml

    from atms.models import System
    from atms.reporting import render_html
    from atms.workflow import analyze

    samples_dir_path = Path(__file__).resolve().parents[1] / "samples"
    raw = yaml.safe_load((samples_dir_path / "chatbot.yaml").read_text(encoding="utf-8"))
    html = render_html(analyze(System.model_validate(raw)))
    assert "isLikelyMermaid" in html
    assert "startOnLoad: false" in html
    assert "Diagram unavailable" in html
