"""Regression tests for the v0.17.2 architecture-drift guard.

Pins three contracts:
  1. `scripts/check_architecture_drift.py` succeeds on the current
     repo state — the diagram is genuinely up to date.
  2. The standalone docs/architecture.html exactly equals the bundled
     template src/atms/templates/web/architecture.html.
  3. Every engine module (except the allowlisted ones) appears in the
     diagram somewhere.
"""

from __future__ import annotations

import filecmp
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_architecture_drift.py"
DOCS = ROOT / "docs" / "architecture.html"
TEMPLATE = ROOT / "src" / "atms" / "templates" / "web" / "architecture.html"
ENGINES_DIR = ROOT / "src" / "atms" / "engines"


def _import_guard():
    """Load the drift guard module by path (it's a script, not a
    package member)."""
    spec = importlib.util.spec_from_file_location(
        "check_architecture_drift", str(SCRIPT),
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_architecture_drift"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_drift_guard_passes_on_current_state():
    """The guard must succeed today. If this test fails, run
    `python scripts/check_architecture_drift.py` to see what drifted."""
    guard = _import_guard()
    missing = guard.check_engines_referenced()
    assert not missing, (
        f"engine modules not referenced in the architecture diagram: {missing}"
    )
    assert guard.check_docs_in_sync(), (
        "docs/architecture.html is out of sync with the bundled template. "
        "Run: cp src/atms/templates/web/architecture.html docs/architecture.html"
    )


def test_docs_copy_equals_bundled_template():
    """The two files MUST be byte-identical."""
    if DOCS.exists():
        assert filecmp.cmp(str(TEMPLATE), str(DOCS), shallow=False), (
            "docs/architecture.html ≠ src/atms/templates/web/architecture.html. "
            "Run: cp src/atms/templates/web/architecture.html docs/architecture.html"
        )


def test_every_engine_module_appears_in_diagram():
    """Same check as the guard, but as a unit test so a pytest run
    catches drift even when CI's explicit step is skipped."""
    guard = _import_guard()
    missing = guard.check_engines_referenced()
    assert not missing, f"missing from architecture diagram: {missing}"


def test_recent_v0172_additions_are_referenced():
    """Cycles A/B/C added specific files that MUST appear in the
    diagram. Pins the rule that future architectural changes get
    diagram updates."""
    text = TEMPLATE.read_text(encoding="utf-8")
    # Cycle A: pipeline.py
    assert "pipeline.py" in text, "Cycle A (pipeline.py) missing from diagram"
    # Cycle B: frameworks.py
    assert "frameworks.py" in text, "Cycle B (frameworks.py) missing from diagram"
    # Cycle C: prior_run carry-forward
    assert "_carry_forward_dispositions" in text, (
        "Cycle C (carry_forward_dispositions) missing from diagram"
    )
