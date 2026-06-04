"""Phase H performance-regression tests.

Phase 3 (v0.18.47) made KB cold-start go 920ms → 21ms with a pickle
cache. docs/PERFORMANCE.md documents the numbers. But if someone
breaks the cache later, only the doc gets stale — no test fails.
Phase H pins floor invariants so any regression that meaningfully
degrades startup or hot-path trips CI.

Marked `slow` so they don't run on every iteration; only `pytest -m slow`
or CI's nightly job exercises them. The floors are generous (3-5×
the local measurement) so they survive slow CI runners.

These tests SKIP automatically when running under pytest-xdist —
parallel workers race over the pickle cache file on disk, which
invalidates the warm-vs-cold timing premise.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

# Skip the entire module under xdist; the cache contention between
# workers makes timing assertions meaningless. Run with `-n 0` or
# without xdist installed to exercise these tests.
_XDIST_WORKER = os.environ.get("PYTEST_XDIST_WORKER")
pytestmark = pytest.mark.skipif(
    _XDIST_WORKER is not None,
    reason=(
        "Phase H perf tests require single-process execution to get "
        "honest cache hit/miss timing. Re-run with `pytest -m slow -n 0`."
    ),
)


@pytest.mark.slow
def test_kb_warm_load_under_1500ms():
    """Warm KB load (cache hit) measured at ~20ms locally. Floor:
    1500ms — leaves a 75× headroom for slow CI runners + accounts
    for xdist parallel workers fighting over the cache file."""
    from atms.kb import _cache_path, _kb_dir, get_kb

    # Ensure cache is warm: invoke once + clear lru.
    get_kb()
    get_kb.cache_clear()
    cache = _cache_path(_kb_dir())
    assert cache.exists(), "cache file should be present after first load"

    t0 = time.perf_counter()
    kb = get_kb()
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert kb.playbooks, "KB must load successfully"
    assert elapsed_ms < 1500, (
        f"KB warm load took {elapsed_ms:.0f}ms — exceeds 1500ms floor. "
        f"Phase 3 (v0.18.47) baseline was ~20ms. The pickle cache may "
        f"have been broken; investigate kb.py::get_kb."
    )


@pytest.mark.slow
def test_analyze_warm_path_under_500ms():
    """Warm analyze() on the standard rag_system.yaml: ~57ms locally.
    Floor: 500ms — leaves an 8× headroom."""
    import yaml

    from atms.models import System
    from atms.workflow import analyze

    sample = Path(__file__).resolve().parents[1] / "samples" / "rag_system.yaml"
    raw = yaml.safe_load(sample.read_text(encoding="utf-8"))
    sys_obj = System.model_validate(raw)

    # Warm-up call to populate the KB singleton.
    analyze(sys_obj)

    # Measure 3 consecutive runs; take the median.
    runs = []
    for _ in range(3):
        t0 = time.perf_counter()
        analyze(sys_obj)
        runs.append((time.perf_counter() - t0) * 1000)
    median_ms = sorted(runs)[1]

    assert median_ms < 500, (
        f"analyze(rag_system.yaml) median {median_ms:.0f}ms — exceeds "
        f"500ms floor. Phase 3 baseline was ~57ms. The hot path may "
        f"have grown a quadratic loop; profile with cProfile."
    )


@pytest.mark.slow
def test_full_suite_imports_under_1500ms():
    """Cold `import atms.cli` (with all its Click + Pydantic + KB
    deps) should stay under 1.5s. If it grows past that the CLI feels
    sluggish on every fresh invocation."""
    import subprocess
    import sys

    repo_src = Path(__file__).resolve().parents[1] / "src"

    # Use a fresh subprocess so we measure cold import, not the
    # already-loaded modules of the test process.
    t0 = time.perf_counter()
    result = subprocess.run(
        [sys.executable, "-c", "import atms.cli"],
        env={"PYTHONPATH": str(repo_src),
             **{k: v for k, v in __import__("os").environ.items()
                if k in ("PATH", "SYSTEMROOT", "LOCALAPPDATA", "USERPROFILE",
                         "APPDATA", "WINDIR")}},
        capture_output=True, text=True, timeout=30,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert result.returncode == 0, f"import atms.cli failed: {result.stderr[:300]}"
    assert elapsed_ms < 1500, (
        f"`import atms.cli` (subprocess) took {elapsed_ms:.0f}ms — "
        f"exceeds 1500ms floor. Baseline was ~334ms (Phase 3). "
        f"Investigate cli.py top-level imports."
    )


@pytest.mark.slow
def test_kb_cold_load_under_3s_with_cache_invalidated():
    """When the pickle cache is cold (or invalidated), KB load must
    still stay under 3 seconds. Phase 3 baseline was ~920ms; floor of
    3000ms gives 3.2× headroom."""
    from atms.kb import _cache_path, _kb_dir, get_kb

    cache = _cache_path(_kb_dir())
    if cache.exists():
        cache.unlink()
    get_kb.cache_clear()

    t0 = time.perf_counter()
    kb = get_kb()
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert kb.playbooks
    assert elapsed_ms < 3000, (
        f"KB cold load took {elapsed_ms:.0f}ms — exceeds 3000ms floor. "
        f"Phase 3 baseline was ~920ms. Either the YAML parsing has "
        f"slowed, OR the kb/ tree has grown substantially."
    )
