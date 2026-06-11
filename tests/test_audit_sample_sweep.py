"""Fleet sweep: every bundled sample YAML must analyze cleanly.

Guards against a sample edit or a playbook change silently breaking
the bundled fleet of example systems shipped under ``samples/``.

The contract this locks in, for EVERY ``samples/*.yaml`` file:

  * The file loads through the *same* path the CLI ``analyze`` command
    uses — ``atms.cli._load_system_yaml`` (YAML safe-load + autocorrect
    + ``System.model_validate``). A malformed or schema-invalid sample
    would make that helper ``sys.exit(2)`` (→ ``SystemExit``), which
    fails the test loudly instead of going unnoticed.

  * Running ``analyze(system, require_ai_components=True)`` — the exact
    default the CLI uses (``require_ai_components = not allow_pure_it``)
    — either:
      (a) returns a ThreatModel with **>0 threats** and a populated
          ``.summary``, with no exception, OR
      (b) for ``pure_it_estate.yaml`` specifically — the one bundled
          sample with zero AI components by design — raises
          ``NoAIComponentsError`` (the v0.15+ AI-scope gate).

  * ``pure_it_estate.yaml`` is asserted to be the *only* AI-scope
    rejection in the fleet: a guard so that if a future edit strips the
    AI component out of another sample (or adds one to the pure-IT
    estate), this sweep flags the drift rather than silently passing.

Parametrization is over a live ``samples/*.yaml`` glob, so a newly
added sample is automatically swept — no edit to this file required.

Run:
    cd E:/Jarvis/builds/aitms && PYTHONPATH=src ATMS_KB_NO_CACHE=1 \
        python -m pytest tests/test_audit_sample_sweep.py -q -p no:cacheprovider
"""

from __future__ import annotations

from pathlib import Path

import pytest

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"

# The single bundled sample that has zero AI components by design and is
# therefore expected to be rejected by the AI-scope gate when analysed
# with the CLI's default ``require_ai_components=True``.
PURE_IT_SAMPLE = "pure_it_estate.yaml"

# Every top-level sample system YAML. ``samples/`` also contains the
# ``corpus/`` and ``iac/`` subdirectories and a ``.vsdx`` binary; the
# non-recursive ``glob`` keeps us to the System-YAML fleet the CLI's
# ``analyze`` command consumes directly.
SAMPLE_FILES = sorted(p for p in SAMPLES_DIR.glob("*.yaml"))


def test_samples_dir_is_populated() -> None:
    """Sanity guard: the glob actually found samples. A path/layout
    regression that empties this list would otherwise make every
    parametrized test vacuously 'pass' (0 collected)."""
    assert SAMPLE_FILES, f"no sample *.yaml found under {SAMPLES_DIR}"
    # The pure-IT estate must exist — the AI-scope branch below depends
    # on it.
    assert (SAMPLES_DIR / PURE_IT_SAMPLE).exists(), (
        f"expected bundled pure-IT sample missing: {PURE_IT_SAMPLE}"
    )


@pytest.mark.parametrize(
    "sample_path",
    SAMPLE_FILES,
    ids=[p.name for p in SAMPLE_FILES],
)
def test_sample_analyzes_or_is_pure_it_rejected(sample_path: Path) -> None:
    """Each bundled sample either produces >0 threats or (for the one
    pure-IT sample) is rejected by the AI-scope gate.

    Loads via the CLI's own ``_load_system_yaml`` so the test exercises
    the same parse + validate path the ``atms analyze`` command does;
    analyses with ``require_ai_components=True`` to match the CLI
    default (``not allow_pure_it``)."""
    from atms.cli import _load_system_yaml
    from atms.engines.ai_scope import NoAIComponentsError
    from atms.workflow import analyze

    # _load_system_yaml sys.exit(2)s on a malformed / schema-invalid
    # sample, surfacing as SystemExit — a loud, correct failure here.
    system = _load_system_yaml(sample_path)
    assert system.components, f"{sample_path.name} loaded with zero components"

    if sample_path.name == PURE_IT_SAMPLE:
        # (b) The pure-IT estate has no AI component — the gate must fire.
        with pytest.raises(NoAIComponentsError):
            analyze(system, require_ai_components=True)
        return

    # (a) Every other sample: full pipeline, >0 threats, no exception.
    model = analyze(system, require_ai_components=True)
    assert len(model.threats) > 0, (
        f"{sample_path.name} produced 0 threats — a sample or playbook "
        f"change likely broke threat enumeration for this system"
    )
    # The summary rollup must be consistent with the threat list. A
    # mismatch means a regression in the summary-building stage.
    assert isinstance(model.summary, dict) and model.summary, (
        f"{sample_path.name} produced an empty summary"
    )
    assert model.summary.get("threats") == len(model.threats), (
        f"{sample_path.name}: summary['threats']="
        f"{model.summary.get('threats')} != len(threats)={len(model.threats)}"
    )
    # Each emitted threat must carry the identity fields reports rely on.
    for t in model.threats:
        assert t.id, f"{sample_path.name}: a threat has an empty id"
        assert t.title, f"{sample_path.name}: threat {t.id} has an empty title"
        assert t.severity in ("info", "low", "medium", "high", "critical"), (
            f"{sample_path.name}: threat {t.id} has invalid severity "
            f"{t.severity!r}"
        )


def test_pure_it_is_the_only_ai_scope_rejection() -> None:
    """Drift guard: ``pure_it_estate.yaml`` must be the ONLY sample the
    AI-scope gate rejects.

    If a future edit removes the AI component from another sample (so it
    starts being rejected) or adds one to the pure-IT estate (so it
    stops being rejected), this catches it — the per-sample test above
    special-cases exactly one filename and would otherwise mask such a
    drift as a generic pass/fail on the wrong file."""
    from atms.cli import _load_system_yaml
    from atms.engines.ai_scope import NoAIComponentsError
    from atms.workflow import analyze

    rejected: list[str] = []
    for sample_path in SAMPLE_FILES:
        system = _load_system_yaml(sample_path)
        try:
            analyze(system, require_ai_components=True)
        except NoAIComponentsError:
            rejected.append(sample_path.name)

    assert rejected == [PURE_IT_SAMPLE], (
        f"expected only {PURE_IT_SAMPLE!r} to be AI-scope-rejected, "
        f"got {rejected!r}"
    )
