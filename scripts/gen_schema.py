"""Generate `docs/system.schema.json` from atms.models.System.

The output is the JSON Schema describing the YAML format users feed
to ATMS. VSCode users can pin it via `yaml.schemas` in settings to get
autocomplete + inline validation on `.system.yaml` files:

    # .vscode/settings.json
    {
      "yaml.schemas": {
        "https://raw.githubusercontent.com/anguiz7z/AITMS/main/docs/system.schema.json":
            ["**/*.system.yaml", "**/samples/*.yaml"]
      }
    }

Usage:
    python scripts/gen_schema.py             # regenerate (writes file)
    python scripts/gen_schema.py --check     # exit 1 if file is stale

The Makefile `schema` target wraps the first form. CI runs --check so
any edit to atms.models without re-running this script fails the
build (same drift-guard pattern as `scripts/gen_palette.py`).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_JSON = ROOT / "docs" / "system.schema.json"


def _generate() -> str:
    """Build the canonical JSON Schema text from `atms.models.System`.

    We pin the indent + sort_keys so the diff between runs is stable —
    this is critical for the --check drift guard.
    """
    # Lazy import so the script works in a fresh checkout before the
    # package is installed.
    sys.path.insert(0, str(ROOT / "src"))
    from atms.models import System  # type: ignore[import-not-found]

    schema = System.model_json_schema()
    # Add a `$schema` declaration + a `$id` matching the canonical URL
    # so VSCode / other JSON Schema clients can resolve refs sensibly.
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = (
        "https://raw.githubusercontent.com/anguiz7z/AITMS/"
        "main/docs/system.schema.json"
    )
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def _write(text: str) -> None:
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(text, encoding="utf-8")


def _check_stale() -> int:
    """Compare the generated text against the file on disk; exit 1 if
    they differ. Used by CI as a drift guard."""
    new = _generate()
    if not OUT_JSON.exists():
        print(f"FAIL: {OUT_JSON} does not exist. Run `make schema`.",
              file=sys.stderr)
        return 1
    current = OUT_JSON.read_text(encoding="utf-8")
    if current != new:
        print(
            f"FAIL: {OUT_JSON} is stale.\n"
            f"Run `make schema` to regenerate. "
            f"(Triggered by an edit to atms.models without re-running the generator.)",
            file=sys.stderr,
        )
        # Show a diff hint — first 200 chars of the new content for sanity.
        return 1
    print(f"OK: {OUT_JSON} is up to date.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="Don't write — exit 1 if the file on disk is stale.",
    )
    args = ap.parse_args()
    if args.check:
        return _check_stale()
    text = _generate()
    _write(text)
    print(f"Wrote {OUT_JSON} ({len(text)} bytes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
