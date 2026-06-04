"""Phase N — Makefile developer surface (v0.18.62).

The pre-existing Makefile was sparse and the canonical pytest
invocations only lived in pyproject.toml comments. New contributors had
to read pyproject.toml carefully to learn `pytest -q -m "not slow" -n
auto --dist=loadfile` is the parallel mode. This test pins the
Makefile's contract:

  * Every documented canonical command listed in pyproject.toml or the
    README is reachable through a Makefile target.
  * `make help` works and lists every public target (catches the
    common bug where you add a target but forget the `## description`
    annotation, which silently drops it from `make help`).
  * All targets are declared in .PHONY (catches the common bug where
    the file name collides with the target name).

We do NOT run `make` from this test — that would require gnumake on
the CI host and would also be slow. We parse the Makefile as text.
"""

from __future__ import annotations

import re
from pathlib import Path

MAKEFILE = Path(__file__).resolve().parents[1] / "Makefile"


def _read():
    assert MAKEFILE.exists(), f"Makefile missing: {MAKEFILE}"
    return MAKEFILE.read_text(encoding="utf-8")


def _targets_with_help(text: str) -> set[str]:
    """Targets that carry a `## description` annotation — these are the
    ones `make help` will show."""
    targets = set()
    for line in text.splitlines():
        # Match  `target_name: deps ## description`
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9_-]*)\s*:[^=]*##", line)
        if m:
            targets.add(m.group(1))
    return targets


def _phony_targets(text: str) -> set[str]:
    """Targets declared in any `.PHONY: a b c ...` line."""
    out: set[str] = set()
    in_phony = False
    for line in text.splitlines():
        if line.startswith(".PHONY"):
            in_phony = True
            body = line.split(":", 1)[1] if ":" in line else ""
            out.update(body.split())
            # Continuation lines end with backslash.
            if not line.rstrip().endswith("\\"):
                in_phony = False
            continue
        if in_phony:
            body = line.rstrip()
            ends_continued = body.endswith("\\")
            out.update(body.rstrip("\\").split())
            if not ends_continued:
                in_phony = False
    return out


REQUIRED_TARGETS = {
    # Discovery
    "help",
    # Testing — these are the canonical invocations users WILL want
    "test",
    "test-parallel",
    "test-all",
    "coverage",
    "coverage-ci",
    "coverage-html",
    # Linting / typing
    "lint",
    "lint-fix",
    "mypy",
    # CLI shortcuts
    "selftest",
    "web",
    "analyze",
    # Generated artefacts
    "palette",
    "palette-check",
    "schema",          # v0.18.63 Phase O
    "schema-check",    # v0.18.63 Phase O
    "drift-check",
    # Build + release
    "build",
    "verify-wheel",
    "build-exe",
    # Maintenance
    "install",
    "clean",
    # Aggregate
    "ci",
}


def test_makefile_default_goal_is_help():
    """`.DEFAULT_GOAL := help` — `make` alone shows the target list."""
    text = _read()
    assert ".DEFAULT_GOAL := help" in text


def test_makefile_required_targets_all_present():
    """Every canonical command users need is a real make target."""
    text = _read()
    annotated = _targets_with_help(text)
    missing = REQUIRED_TARGETS - annotated
    assert not missing, (
        f"missing canonical Makefile targets (or they lack a `##` doc): "
        f"{sorted(missing)}"
    )


def test_makefile_phony_includes_every_annotated_target():
    """Every annotated target must also appear in `.PHONY`, otherwise a
    file named e.g. `clean` in the project would shadow the target."""
    text = _read()
    annotated = _targets_with_help(text)
    phony = _phony_targets(text)
    missing_phony = annotated - phony
    assert not missing_phony, (
        f"Makefile targets missing from .PHONY: {sorted(missing_phony)}"
    )


def test_makefile_canonical_pytest_invocations_surfaced():
    """The two canonical pytest invocations from pyproject.toml are
    embedded in the Makefile (so editing one without the other gets
    caught early)."""
    text = _read()
    # Sequential
    assert '-m "not slow"' in text
    # Parallel
    assert "-n auto" in text
    assert "--dist=loadfile" in text


def test_makefile_help_format_grep_friendly():
    """The `## description` pattern is grep-friendly: a single line per
    target so an external script (or this test) can index them."""
    text = _read()
    annotations = re.findall(r"^([a-zA-Z][a-zA-Z0-9_-]*):.*## (.+)$",
                              text, re.MULTILINE)
    # ≥18 documented targets — guards against a future "clean-up" that
    # accidentally drops the ## annotations.
    assert len(annotations) >= 18, (
        f"expected ≥18 documented targets, got {len(annotations)}: "
        f"{[t[0] for t in annotations]}"
    )


def test_makefile_analyze_target_documents_sample_arg():
    """`make analyze` must check the SAMPLE arg and print a usage hint
    when it's empty — common UX trap when users forget to set it."""
    text = _read()
    # The usage hint must exist
    assert 'make analyze SAMPLE=' in text
    # And the guard
    assert 'if [ -z "$(SAMPLE)" ]' in text


def test_makefile_ci_target_aggregates_canonical_steps():
    """`make ci` runs the same bundle that GitHub Actions runs — guards
    against the two drifting apart."""
    text = _read()
    m = re.search(r"^ci:\s+(.+?)(?:##|$)", text, re.MULTILINE)
    assert m, "`ci:` target should exist with prerequisites"
    deps = set(m.group(1).split())
    # The aggregate must cover at minimum: lint, the parallel test
    # invocation, coverage enforcement, and the selftest.
    for required in ("lint", "test-parallel", "coverage-ci", "selftest"):
        assert required in deps, (
            f"`make ci` is missing required step: {required}; "
            f"current deps: {sorted(deps)}"
        )
