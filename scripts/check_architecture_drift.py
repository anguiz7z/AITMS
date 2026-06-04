"""Architecture diagram drift guard (v0.17.2).

Fails CI if any of these inputs has drifted from the diagram:

  1. A `src/atms/engines/*.py` module that the diagram doesn't reference.
     (Adding a new engine without updating the diagram is the most
     common drift; we want CI to nudge the author to update it.)

  2. The standalone `docs/architecture.html` and the bundled
     `src/atms/templates/web/architecture.html` are out of sync. The
     two files MUST be identical — the standalone exists only as a
     convenient offline-double-clickable mirror.

Usage:
    python scripts/check_architecture_drift.py            # human-readable
    python scripts/check_architecture_drift.py --strict   # exits 1 on any drift (CI mode)
"""

from __future__ import annotations

import argparse
import filecmp
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINES_DIR = ROOT / "src" / "atms" / "engines"
DOCS_FILE = ROOT / "docs" / "architecture.html"
TEMPLATE_FILE = ROOT / "src" / "atms" / "templates" / "web" / "architecture.html"

# Engines that are intentionally NOT shown as discrete nodes in the
# diagram (e.g. internal helpers that don't run as standalone stages).
ALLOWLIST: set[str] = {
    "__init__",
    "ai_scope",       # rendered as wf_scope, not a standalone engine node
    "boundaries",     # rendered as wf_boundaries, not a standalone engine node
    # v0.18.5 Cycle R: architectural_rules is added as a NEW node
    # `eng_arch_rules` in the diagram below; the allowlist + the new
    # node together keep the drift guard happy.
    "_ids",           # v0.19.1: private ID helper (stable_id), not an engine node
}


def _engine_module_names() -> set[str]:
    """All `src/atms/engines/*.py` module names (sans `.py`)."""
    if not ENGINES_DIR.is_dir():
        return set()
    return {
        p.stem for p in ENGINES_DIR.glob("*.py")
        if p.is_file()
    } - ALLOWLIST


def _diagram_text() -> str:
    """Read the bundled-template diagram (the canonical version)."""
    if not TEMPLATE_FILE.exists():
        raise SystemExit(f"diagram template missing: {TEMPLATE_FILE}")
    return TEMPLATE_FILE.read_text(encoding="utf-8")


def check_engines_referenced() -> list[str]:
    """Return engine modules that are NOT mentioned anywhere in the diagram."""
    diagram = _diagram_text()
    missing: list[str] = []
    for name in sorted(_engine_module_names()):
        # We look for the exact module-name string. The diagram includes
        # `src/atms/engines/<name>.py` in the file lists or the bare
        # module name in descriptions — either is enough proof of
        # reference.
        if name not in diagram:
            missing.append(name)
    return missing


def check_docs_in_sync() -> bool:
    """The standalone docs/architecture.html must equal the bundled
    template. Returns True if in sync."""
    if not DOCS_FILE.exists():
        # Acceptable: someone may have removed the standalone copy
        # deliberately. CI only enforces template ↔ docs sync when
        # both exist.
        return True
    return filecmp.cmp(str(TEMPLATE_FILE), str(DOCS_FILE), shallow=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true",
                        help="Exit 1 on any drift (CI mode).")
    args = parser.parse_args()

    drift = 0

    missing = check_engines_referenced()
    if missing:
        drift += 1
        print(
            "ERROR: engine modules not referenced in "
            "src/atms/templates/web/architecture.html:",
            file=sys.stderr,
        )
        for name in missing:
            print(f"  - src/atms/engines/{name}.py", file=sys.stderr)
        print(
            "\n  Add a node for each missing engine to the NODES dict in "
            "the diagram (or, if it's an internal helper that shouldn't "
            "be shown, add it to ALLOWLIST in this script).",
            file=sys.stderr,
        )

    if not check_docs_in_sync():
        drift += 1
        print(
            "ERROR: docs/architecture.html is out of sync with "
            "src/atms/templates/web/architecture.html.\n"
            "  Run: cp src/atms/templates/web/architecture.html docs/architecture.html",
            file=sys.stderr,
        )

    if drift == 0:
        engines = sorted(_engine_module_names())
        print(
            f"OK  architecture diagram in sync ({len(engines)} engines "
            f"referenced; template == docs copy)."
        )
        return 0

    return 1 if args.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
