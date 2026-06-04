"""Regression tests for v0.17.3 Cycle G — web /diff route.

Promotes the v0.17.0 stretch item out of CLI-only into the web UI.
Pins four contracts:
  1. `/diff` with no params renders the empty-state page.
  2. `/diff?a=...&b=...` with two valid saved-ThreatModel JSONs
     renders the structured delta (added / removed / severity-changed /
     disposition-changed sections).
  3. A missing or malformed path produces a friendly 200 with an
     error banner — never a 500.
  4. The new route appears in the global nav.
"""

from __future__ import annotations

# v0.18.70 Hibernation Phase 3 — entire file exercises a
# hibernated surface. Skipped by default; run with:
#     pytest -m hibernated tests/test_web_diff.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import json
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from atms.models import Component, System
from atms.web import app
from atms.workflow import analyze


def _write_tm_json(tm) -> str:
    """Dump a ThreatModel to a tempfile and return the path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8",
    )
    json.dump(json.loads(tm.model_dump_json()), f)
    f.close()
    return f.name


def _make_two_runs():
    """Two runs of the same system; mark a threat mitigated on run #1
    so the diff has both severity-changed and disposition-changed
    rows to render."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    tm1 = analyze(sys_obj)
    tm2 = analyze(sys_obj)
    # Mutate tm1 so the diff has visible differences.
    tm1.threats[0].disposition = "mitigated"
    tm1.threats[1].severity = "critical"  # type: ignore[assignment]
    return tm1, tm2


# ─── /diff route contracts ──────────────────────────────────────────
def test_diff_route_empty_state_renders_200():
    """Hitting /diff with no params shows the empty-state form."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/diff")
    assert r.status_code == 200
    assert "Diff between two runs" in r.text
    assert "Enter two paths above" in r.text


def test_diff_route_with_valid_paths_renders_delta():
    """Two real ThreatModel JSONs → diff sections populated."""
    tm1, tm2 = _make_two_runs()
    p1 = _write_tm_json(tm1)
    p2 = _write_tm_json(tm2)
    try:
        c = TestClient(app, raise_server_exceptions=False)
        r = c.get(f"/diff?a={p1}&b={p2}")
        assert r.status_code == 200
        html = r.text
        # Summary tile renders the counts
        assert "Added" in html
        assert "Removed" in html
        assert "Severity changed" in html
        assert "Disposition changed" in html
        # Disposition section actually appears (we mutated one threat).
        assert "mitigated" in html
    finally:
        Path(p1).unlink(missing_ok=True)
        Path(p2).unlink(missing_ok=True)


def test_diff_route_missing_path_is_a_friendly_error():
    """Bad path → 200 with error banner, not a 500 traceback."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/diff?a=/nonexistent/a.json&b=/nonexistent/b.json")
    assert r.status_code == 200
    assert "diff-error" in r.text or "not found" in r.text.lower()


def test_diff_route_malformed_json_is_a_friendly_error():
    """Garbage JSON → 200 with error banner."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8",
    )
    f.write("{ not valid json")
    f.close()
    try:
        c = TestClient(app, raise_server_exceptions=False)
        r = c.get(f"/diff?a={f.name}&b={f.name}")
        assert r.status_code == 200
        assert "Could not load" in r.text or "diff-error" in r.text
    finally:
        Path(f.name).unlink(missing_ok=True)


# v0.18.70 Hibernation Phase 3 — the nav-absence assertion that
# previously lived here moved to tests/test_hibernation_nav.py.
# Nav-absence is a DEFAULT-mode contract; this whole file is
# hibernated-mode (everything in it assumes the diff feature is
# enabled), so the assertion was a category mismatch.


def test_diff_route_identical_runs_show_no_differences():
    """Two unmutated runs of the same system → no diff rows."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    tm = analyze(sys_obj)
    p = _write_tm_json(tm)
    try:
        c = TestClient(app, raise_server_exceptions=False)
        r = c.get(f"/diff?a={p}&b={p}")
        assert r.status_code == 200
        # The "no differences" empty state shows
        assert "No differences detected" in r.text
    finally:
        Path(p).unlink(missing_ok=True)
