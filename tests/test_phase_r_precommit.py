"""Phase R — pre-commit hook config (v0.18.66).

Contributors landing on the project without prior context kept hitting
ruff failures in CI that they could have caught locally — but the
project had no `.pre-commit-config.yaml`, so they had no obvious local
gate. Phase R adds the config and pins the hook set so a future
"cleanup" can't silently drop the local-CI parity.

Pinned hooks:
  * pre-commit-hooks (trailing-ws, eof-fixer, check-yaml, check-json,
    check-toml, check-merge-conflict, check-added-large-files,
    mixed-line-ending)
  * ruff-pre-commit with --fix (matches CI's ruff step)
  * Local hooks: gen_palette.py --check, gen_schema.py --check
    (drift guards trigger only on the relevant source files)

We do NOT actually run `pre-commit` from this test (that would
require the binary on the CI host). We parse the config as YAML and
assert structure.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".pre-commit-config.yaml"


def _load() -> dict:
    assert CONFIG.exists(), (
        f"Missing {CONFIG}. Run `git pull` or check `.pre-commit-config.yaml` "
        f"wasn't accidentally removed."
    )
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))


def test_precommit_config_exists_and_parses():
    """Sanity: the file is valid YAML and has the `repos` key."""
    data = _load()
    assert isinstance(data, dict)
    assert "repos" in data
    assert isinstance(data["repos"], list)


def test_precommit_includes_ruff_hook():
    """The ruff hook MUST be present — that's the local mirror of the
    CI lint step."""
    data = _load()
    repos = data["repos"]
    ruff_repo = next(
        (r for r in repos if "ruff" in r.get("repo", "")),
        None,
    )
    assert ruff_repo is not None, (
        "Missing ruff hook in .pre-commit-config.yaml. Without it, "
        "contributors can push lint failures that CI would have caught."
    )
    hook_ids = {h["id"] for h in ruff_repo.get("hooks", [])}
    assert "ruff" in hook_ids


def test_precommit_includes_drift_guards():
    """Both ATMS-specific drift guards (palette + schema) MUST be wired
    so a model edit without re-generating the artefact fails locally."""
    data = _load()
    repos = data["repos"]
    local_repos = [r for r in repos if r.get("repo") == "local"]
    assert local_repos, (
        "Missing the `local` repos section. The palette + schema "
        "drift guards live there."
    )
    local_hook_ids = {
        h["id"]
        for r in local_repos
        for h in r.get("hooks", [])
    }
    assert "palette-drift" in local_hook_ids, (
        "Missing palette-drift local hook — Phase 1 (palette) and "
        "Phase R (this) require it."
    )
    assert "schema-drift" in local_hook_ids, (
        "Missing schema-drift local hook — Phase O (schema) and "
        "Phase R (this) require it."
    )


def test_precommit_includes_file_hygiene_hooks():
    """Standard pre-commit-hooks: trailing-whitespace + end-of-file-fixer
    + check-yaml + check-merge-conflict. These cover 95% of "oops, I
    pushed a typo" failures."""
    data = _load()
    repos = data["repos"]
    hooks_repo = next(
        (r for r in repos if "pre-commit-hooks" in r.get("repo", "")),
        None,
    )
    assert hooks_repo is not None
    hook_ids = {h["id"] for h in hooks_repo.get("hooks", [])}
    for required in (
        "trailing-whitespace",
        "end-of-file-fixer",
        "check-yaml",
        "check-merge-conflict",
    ):
        assert required in hook_ids, (
            f"Missing standard hook `{required}` from pre-commit-hooks. "
            f"Current: {sorted(hook_ids)}"
        )


def test_precommit_check_json_excludes_generated_schema():
    """`docs/system.schema.json` is generated; the check-json hook
    must exclude it (otherwise an unrelated edit would trigger a
    false-positive on its formatting)."""
    text = CONFIG.read_text(encoding="utf-8")
    # Look for the exclude pattern alongside check-json.
    assert "system.schema.json" in text, (
        "Expected the check-json hook to explicitly exclude the "
        "generated schema file."
    )


def test_precommit_large_files_threshold_reasonable():
    """The `check-added-large-files` hook should be configured with a
    threshold that's tolerant of `samples/corpus/*` (~20 KB max) but
    catches accidental binary/vendor blobs."""
    data = _load()
    repos = data["repos"]
    for r in repos:
        for h in r.get("hooks", []):
            if h.get("id") == "check-added-large-files":
                args = h.get("args", [])
                # Expect something like "--maxkb=500"
                kb_arg = next((a for a in args if a.startswith("--maxkb=")), None)
                assert kb_arg, "check-added-large-files missing --maxkb arg"
                kb = int(kb_arg.split("=")[1])
                # 100 KB ≤ threshold ≤ 2 MB is a sensible range.
                assert 100 <= kb <= 2000, (
                    f"check-added-large-files maxkb={kb} is outside "
                    f"the sensible window [100, 2000]"
                )
                return
    raise AssertionError("check-added-large-files hook missing entirely")


def test_precommit_drift_guard_filter_on_models_change_only():
    """The schema-drift hook should ONLY fire when models.py changes —
    re-running gen_schema.py on every commit would be wasteful."""
    data = _load()
    repos = data["repos"]
    for r in repos:
        if r.get("repo") != "local":
            continue
        for h in r.get("hooks", []):
            if h.get("id") == "schema-drift":
                files_pattern = h.get("files", "")
                # Regex syntax means the literal `models.py` shows up as
                # `models\.py` after YAML parsing (the `.` is escaped to
                # match a literal dot, not any char). Check for both
                # parts.
                assert "models" in files_pattern and ".py" in files_pattern, (
                    f"schema-drift hook should filter on models.py "
                    f"changes; current `files` pattern: {files_pattern!r}"
                )
                return
    raise AssertionError("schema-drift hook missing")
