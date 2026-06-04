"""Generate src/atms/static/palette-data.json from models.py + _SYNONYMS.

The web editor's component palette used to be a hand-maintained JS array
in `src/atms/static/atms-editor.js`. It drifted: 40/121 ComponentType
values were exposed (67% gap). This script is the new single source of
truth: it walks `models.py` for the `ComponentType` Literal + its
comment-header groupings, inverts `yaml_autocorrect._SYNONYMS` to derive
search aliases, applies the manual emoji_overrides from
`kb/palette_meta.yaml`, and writes a deterministic JSON file the
editor's JS fetches at load time.

Usage:
    python scripts/gen_palette.py            # regenerate (writes file)
    python scripts/gen_palette.py --check    # exit 1 if file is stale

The Makefile `palette` target wraps the first form. CI runs --check
so any edit to ComponentType without re-running this script fails the
build.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODELS_PY = ROOT / "src" / "atms" / "models.py"
PALETTE_META = ROOT / "kb" / "palette_meta.yaml"
OUT_JSON = ROOT / "src" / "atms" / "static" / "palette-data.json"


def _parse_component_groups() -> list[tuple[str, list[str]]]:
    """Walk models.py and emit [(group_name, [type1, type2, ...]), ...].

    Group names come from the comment-header lines that look like:
        # ─── AI / ML / agentic primitives ────────────────────────────
    The next set of quoted string literals (until the next header) are
    that group's members. Order is preserved from source order.
    """
    text = MODELS_PY.read_text(encoding="utf-8")
    # Slice from `ComponentType = Literal[` to the closing `]`.
    m = re.search(r"ComponentType\s*=\s*Literal\[(.*?)^\]", text, re.S | re.M)
    if not m:
        raise SystemExit("Could not locate ComponentType Literal in models.py")
    block = m.group(1)

    groups: list[tuple[str, list[str]]] = []
    current_group: str | None = None
    current_members: list[str] = []
    header_re = re.compile(r"#\s*[─-]+\s*(.+?)\s*[─-]+")
    type_re = re.compile(r'"([a-z0-9_]+)"')

    for line in block.splitlines():
        # Header line?
        h = header_re.search(line)
        if h:
            if current_group is not None:
                groups.append((current_group, current_members))
            current_group = h.group(1).strip()
            current_members = []
            continue
        # Type literal?
        t = type_re.search(line)
        if t and current_group is not None:
            current_members.append(t.group(1))
    if current_group is not None and current_members:
        groups.append((current_group, current_members))
    return groups


def _invert_synonyms() -> dict[str, list[str]]:
    """Invert atms.yaml_autocorrect._SYNONYMS into canonical → [aliases]."""
    # Import lazily so the script also works in a fresh checkout where
    # the package isn't installed yet (we add src/ to sys.path).
    sys.path.insert(0, str(ROOT / "src"))
    from atms.yaml_autocorrect import _SYNONYMS  # noqa: WPS433

    inv: dict[str, list[str]] = defaultdict(list)
    for alias, canon in _SYNONYMS.items():
        if alias != canon:  # skip identity entries
            inv[canon].append(alias)
    return {k: sorted(set(v)) for k, v in inv.items()}


def _abbrev(type_name: str) -> str:
    """Default 2-char abbreviation from a snake_case type name.

    Used when no emoji_override is provided. Deterministic so re-runs
    produce identical output.

      llm_inference            -> "Li"
      time_series_database     -> "Ts"
      ot_jumphost              -> "Oj"
      user                     -> "Us"
    """
    parts = type_name.split("_")
    if len(parts) >= 2:
        return (parts[0][:1] + parts[1][:1]).title()
    return type_name[:2].title()


def _load_meta() -> dict:
    if not PALETTE_META.exists():
        return {"emoji_overrides": {}, "group_order": []}
    return yaml.safe_load(PALETTE_META.read_text(encoding="utf-8")) or {}


def build_palette_data() -> dict:
    groups = _parse_component_groups()
    synonyms = _invert_synonyms()
    meta = _load_meta()
    emoji_overrides: dict[str, str] = meta.get("emoji_overrides") or {}
    group_order: list[str] = meta.get("group_order") or []

    # Optional: force a specific group display order.
    if group_order:
        order_map = {g: i for i, g in enumerate(group_order)}
        groups.sort(key=lambda g: order_map.get(g[0], 999))

    out_groups: list[dict] = []
    seen_types: set[str] = set()
    for group_name, types in groups:
        items: list[dict] = []
        for t in types:
            if t in seen_types:
                continue
            seen_types.add(t)
            items.append({
                "type": t,
                "emoji": emoji_overrides.get(t) or _abbrev(t),
                "synonyms": synonyms.get(t, []),
            })
        out_groups.append({"name": group_name, "items": items})

    # Sanity check: confirm every ComponentType is covered.
    sys.path.insert(0, str(ROOT / "src"))
    from atms.models import ComponentType  # noqa: WPS433

    expected = set(ComponentType.__args__)
    missing = expected - seen_types
    extra = seen_types - expected
    if missing or extra:
        raise SystemExit(
            f"Palette/ComponentType mismatch — missing={sorted(missing)}, "
            f"extra={sorted(extra)}"
        )

    return {
        "version": 1,
        "total": len(seen_types),
        "groups": out_groups,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if generated content differs from the on-disk file.",
    )
    args = parser.parse_args()

    data = build_palette_data()
    serialized = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        if not OUT_JSON.exists():
            print(f"ERROR: {OUT_JSON} does not exist — run `make palette`.", file=sys.stderr)
            return 1
        on_disk = OUT_JSON.read_text(encoding="utf-8")
        if on_disk != serialized:
            print(
                f"ERROR: {OUT_JSON} is stale.\n"
                f"  Expected {data['total']} types in {len(data['groups'])} groups.\n"
                f"  Run `make palette` to regenerate.",
                file=sys.stderr,
            )
            return 1
        print(f"OK  palette-data.json up-to-date ({data['total']} types, "
              f"{len(data['groups'])} groups)")
        return 0

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(serialized, encoding="utf-8")
    print(
        f"OK  wrote {OUT_JSON.relative_to(ROOT)} — {data['total']} types "
        f"in {len(data['groups'])} groups"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
