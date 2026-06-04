"""Regression tests pinning the v0.16.10 editor palette contract.

The palette JSON is generated from `models.py` + `_SYNONYMS` by
`scripts/gen_palette.py`. These tests guard against:
  (a) silently dropping ComponentType values from the editor,
  (b) palette JSON drifting out of sync with the Python source,
  (c) palette JSON having entries that don't correspond to a real
      ComponentType value (typos).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from atms.models import ComponentType

ROOT = Path(__file__).resolve().parents[1]
PALETTE_JSON = ROOT / "src" / "atms" / "static" / "palette-data.json"
GEN_SCRIPT = ROOT / "scripts" / "gen_palette.py"


def _load_palette() -> dict:
    return json.loads(PALETTE_JSON.read_text(encoding="utf-8"))


def test_palette_json_exists():
    assert PALETTE_JSON.exists(), (
        f"{PALETTE_JSON} missing — run `make palette` or "
        f"`python scripts/gen_palette.py`."
    )


def test_every_component_type_in_palette():
    """Every ComponentType Literal value must appear in the palette JSON."""
    data = _load_palette()
    palette_types = {
        item["type"]
        for group in data["groups"]
        for item in group["items"]
    }
    expected = set(ComponentType.__args__)
    missing = expected - palette_types
    extra = palette_types - expected

    assert not missing, f"ComponentType values missing from palette: {sorted(missing)}"
    assert not extra, f"Palette has unknown types: {sorted(extra)}"


def test_palette_total_matches_component_count():
    """The palette's `total` field equals len(ComponentType)."""
    data = _load_palette()
    assert data["total"] == len(ComponentType.__args__), (
        f"Palette declares {data['total']} types but ComponentType has "
        f"{len(ComponentType.__args__)}"
    )


def test_palette_groups_nonempty():
    """Each group must have at least one item (no orphan headers)."""
    data = _load_palette()
    empty = [g["name"] for g in data["groups"] if not g["items"]]
    assert not empty, f"Empty palette groups: {empty}"


def test_palette_no_duplicate_types_within_or_across_groups():
    """A ComponentType value must appear exactly once across the whole palette."""
    data = _load_palette()
    seen: dict[str, str] = {}
    for group in data["groups"]:
        for item in group["items"]:
            t = item["type"]
            if t in seen:
                pytest.fail(
                    f"{t!r} appears in both {seen[t]!r} and {group['name']!r}"
                )
            seen[t] = group["name"]


def test_palette_items_have_required_keys():
    """Each palette item must carry type, emoji, synonyms."""
    data = _load_palette()
    for group in data["groups"]:
        for item in group["items"]:
            assert "type" in item, f"item missing type: {item}"
            assert "emoji" in item, f"item missing emoji: {item}"
            assert "synonyms" in item, f"item missing synonyms: {item}"
            assert isinstance(item["synonyms"], list), (
                f"synonyms must be a list: {item}"
            )


def test_palette_generator_check_mode_passes():
    """`python scripts/gen_palette.py --check` must succeed — proving
    the on-disk JSON matches what the generator would produce now.
    Forces devs to re-run `make palette` after touching models.py."""
    result = subprocess.run(
        [sys.executable, str(GEN_SCRIPT), "--check"],
        cwd=str(ROOT),
        env={"PYTHONPATH": str(ROOT / "src"), **__import__("os").environ},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"palette JSON is stale.\nstdout: {result.stdout}\nstderr: {result.stderr}\n"
        f"Run `make palette` (or `python scripts/gen_palette.py`) to regenerate."
    )
