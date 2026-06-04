"""Performance smoke tests (v0.14.8).

These are NOT hard latency assertions — they're guards against
quadratic-blow-up regressions. A 100-component system should analyse
in seconds, not minutes. If this test takes more than 60s on CI, that
is itself the signal that someone introduced an O(n²) loop.
"""

from __future__ import annotations

import time

import pytest

from atms.models import Component, Dataflow, System
from atms.workflow import analyze


def _build_synthetic_system(n_components: int) -> System:
    """Build a system with `n_components` AI/cloud components and a
    dense-ish graph of dataflows so the engine has real work to do."""
    types_cycle = [
        "user", "agent", "llm_inference", "rag_vector_store",
        "embedding_service", "guardrails", "output_filter",
        "tool", "external_api", "object_storage", "kms_key",
        "iam_principal", "container_runtime", "serverless_function",
        "api_gateway", "database", "secrets_vault",
    ]
    components = []
    for i in range(n_components):
        t = types_cycle[i % len(types_cycle)]
        components.append(Component(
            id=f"c{i}",
            name=f"{t}-{i}",
            type=t,  # type: ignore[arg-type]
            trust_zone="prod" if i % 3 else "internet",
            description=f"Synthetic component {i} of type {t}.",
        ))
    # Sparse-ish dataflows: each component talks to ~3 successors.
    dataflows = []
    for i in range(n_components - 1):
        for j in range(1, 4):
            tgt = (i + j) % n_components
            if tgt != i:
                dataflows.append(Dataflow(
                    id=f"df_{i}_{tgt}",
                    source=f"c{i}", target=f"c{tgt}",
                    label=f"flow {i}→{tgt}",
                ))
    return System(name=f"perf-{n_components}", components=components, dataflows=dataflows)


@pytest.mark.slow
@pytest.mark.parametrize("size,budget_seconds", [
    (50, 20.0),
    (100, 45.0),
])
def test_analyze_finishes_within_budget(size: int, budget_seconds: float):
    """Regression guard: a `size`-component synthetic system must
    analyse end-to-end in under `budget_seconds`. Generous budget so
    flaky CI runners don't false-fire; the goal is catching a 10×
    blow-up, not measuring exact latency."""
    sys_obj = _build_synthetic_system(size)
    started = time.perf_counter()
    tm = analyze(sys_obj)
    elapsed = time.perf_counter() - started
    assert tm.threats, "engine produced zero threats — pipeline regression"
    assert elapsed < budget_seconds, (
        f"{size}-component system took {elapsed:.1f}s "
        f"(budget {budget_seconds}s) — likely O(n²) regression"
    )


@pytest.mark.slow
def test_analyze_produces_stable_output_on_re_run():
    """Determinism guard: analysing the same system twice produces the
    same threat IDs and counts. If a future change introduces a
    set-iteration order dependency, this test catches it."""
    sys_obj = _build_synthetic_system(30)
    tm1 = analyze(sys_obj)
    tm2 = analyze(sys_obj)
    ids1 = sorted(t.id for t in tm1.threats)
    ids2 = sorted(t.id for t in tm2.threats)
    assert ids1 == ids2
    assert len(tm1.attack_paths) == len(tm2.attack_paths)
    assert len(tm1.mitigations) == len(tm2.mitigations)
