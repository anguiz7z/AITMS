"""Phase O — JSON Schema export for system YAML (v0.18.63).

ATMS users author `.system.yaml` files by hand. Without a published
JSON Schema, VSCode and other YAML tooling can't offer autocomplete
on `ComponentType` values, validate dataflow shapes, or warn when a
required field is missing. Phase O ships `docs/system.schema.json`
generated from `atms.models.System.model_json_schema()` and pins a
drift guard so any edit to the models without regenerating the schema
fails CI.

This test file pins:
  * The schema file exists and is well-formed JSON.
  * Generated schema matches the file on disk (calls
    `scripts/gen_schema.py --check` semantics directly).
  * Every `ComponentType` value is represented in the schema's enum.
  * The schema declares the canonical `$schema` + `$id` URLs (so
    VSCode can resolve it).
  * The Makefile exposes both `schema` (regenerate) and `schema-check`
    (drift guard) targets.
"""

from __future__ import annotations

import json
import typing
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "docs" / "system.schema.json"


def test_schema_file_exists():
    """The committed schema is the source of truth for downstream
    consumers (VSCode, JSON Schema validators). It must exist."""
    assert SCHEMA.exists(), (
        f"Missing {SCHEMA}. Run `python scripts/gen_schema.py` to generate it."
    )


def test_schema_is_valid_json():
    """The file must parse as JSON — guards against accidental
    truncation / encoding issues."""
    raw = SCHEMA.read_text(encoding="utf-8")
    schema = json.loads(raw)
    assert isinstance(schema, dict)
    assert schema.get("title") == "System"


def test_schema_declares_canonical_id_and_meta_schema():
    """`$schema` + `$id` must be set so VSCode can resolve the file
    from its URL pin."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
    # $id should point at the raw GitHub URL — that's what users pin.
    assert "raw.githubusercontent.com" in schema.get("$id", "")
    assert "system.schema.json" in schema.get("$id", "")


def test_schema_includes_every_component_type():
    """Every value of the runtime `ComponentType` Literal must be
    represented in the schema's `Component.type.enum` array.

    This is the load-bearing invariant for downstream YAML tooling —
    if a new ComponentType is added to models.py without rerunning
    `make schema`, this test fails and the drift guard catches it."""
    from atms.models import ComponentType

    runtime_types = set(typing.get_args(ComponentType))

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    defs = schema.get("$defs", {})
    component_def = defs.get("Component", {})
    type_field = component_def.get("properties", {}).get("type", {})
    schema_enum = set(type_field.get("enum", []))

    assert runtime_types == schema_enum, (
        f"ComponentType drift between runtime and schema.\n"
        f"In runtime but not schema: {sorted(runtime_types - schema_enum)}\n"
        f"In schema but not runtime: {sorted(schema_enum - runtime_types)}\n"
        f"Run `make schema` to regenerate."
    )


def test_schema_drift_check_passes():
    """Calling `gen_schema.py --check` exits 0 — meaning the committed
    file matches what fresh generation would produce. This is the
    same contract CI enforces."""
    import subprocess
    result = subprocess.run(
        ["python", "scripts/gen_schema.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"gen_schema.py --check failed:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}\n"
        f"Run `make schema` locally and commit the updated file."
    )


def test_schema_has_required_top_level_fields():
    """`name`, `components`, `dataflows` should all appear as
    `properties` of the root System object. `required` should list
    at least `name`."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    for key in ("name", "components", "dataflows"):
        assert key in props, f"missing System.{key} in schema"
    assert "name" in required, "name should be required at the System level"


def test_schema_size_is_reasonable():
    """The schema should be neither tiny (generation broke) nor huge
    (unbounded growth). Pin the order of magnitude as a smoke test."""
    raw = SCHEMA.read_text(encoding="utf-8")
    # ≥ 5KB (we have 121 ComponentType values + multiple nested defs)
    # ≤ 64KB (if it ever exceeds this, something has gone wrong)
    assert 5_000 < len(raw) < 64_000, (
        f"Schema size {len(raw)} bytes is outside the sanity window. "
        f"Check what's happening in atms.models."
    )


def test_makefile_has_schema_targets():
    """`make schema` and `make schema-check` must exist in the Makefile.
    Phase N's meta-test already verifies general Makefile hygiene; this
    test specifically pins the schema targets that landed in Phase O."""
    mkfile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "schema:" in mkfile, "Makefile is missing the `schema` target"
    assert "schema-check:" in mkfile, "Makefile is missing the `schema-check` target"
    # Both should be in .PHONY too.
    assert "schema schema-check" in mkfile or "schema-check" in mkfile.split(".PHONY")[1]


def test_gen_schema_writes_idempotently():
    """Running the generator twice produces identical output."""
    import subprocess
    # First run.
    r1 = subprocess.run(
        ["python", "scripts/gen_schema.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r1.returncode == 0, f"gen_schema.py failed: {r1.stderr}"
    text_after_1 = SCHEMA.read_text(encoding="utf-8")
    # Second run.
    r2 = subprocess.run(
        ["python", "scripts/gen_schema.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r2.returncode == 0
    text_after_2 = SCHEMA.read_text(encoding="utf-8")
    assert text_after_1 == text_after_2, "gen_schema.py is not idempotent"


def test_gen_schema_check_detects_drift(tmp_path, monkeypatch):
    """If the committed file is corrupted, `--check` returns non-zero.

    We test this by mutating a copy of the file to a different value
    and pointing the generator's OUT path at it via monkeypatch. The
    real on-disk file is untouched."""
    # Easier: test that the script's return code is non-zero when the
    # file doesn't match. Use a sandbox file.
    bogus = tmp_path / "system.schema.json"
    bogus.write_text("not the real schema", encoding="utf-8")
    # Monkeypatching the module global is the clean way.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gen_schema", ROOT / "scripts" / "gen_schema.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "OUT_JSON", bogus)
    rc = mod._check_stale()
    assert rc == 1, "expected --check to flag the mismatched file"


def test_schema_can_validate_a_real_sample():
    """Pick the bundled `samples/rag_system.yaml`, load it, and verify
    that the schema would accept it (via a lightweight jsonschema
    library validation if available; otherwise structural sanity).

    This catches the bug where the schema generator emits a schema
    so strict it would reject ATMS's own samples — which has happened
    before with Pydantic 2 schema generators when default values get
    serialised as required."""
    sample = ROOT / "samples" / "rag_system.yaml"
    if not sample.exists():
        pytest.skip("rag_system.yaml not present")

    import yaml as yaml_lib
    sample_data = yaml_lib.safe_load(sample.read_text(encoding="utf-8"))

    # Try jsonschema validation if the lib is installed.
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        # Fall back to a structural sanity check: just confirm the
        # sample has the keys the schema declares as required.
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        required = schema.get("required", [])
        for key in required:
            assert key in sample_data, (
                f"sample is missing required key `{key}` per schema"
            )
        return

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(instance=sample_data, schema=schema)
