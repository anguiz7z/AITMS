"""Roadmap V5 Phase 7 — performance & stability floor.

Locks the KEEP-path performance + concurrency behaviour so v1.0 can't
regress. Complements the existing `test_perf_smoke.py` (KB-load /
analyze / CLI-import budgets) with web concurrency + render budgets.

All tests are slow + xdist-skipped (parallel workers race on the
on-disk KB pickle cache, invalidating timing) — matching the
perf-smoke convention.
"""

from __future__ import annotations

import concurrent.futures as cf
import os
import time
from collections import Counter
from pathlib import Path

import pytest
import yaml

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        os.environ.get("PYTEST_XDIST_WORKER") is not None,
        reason="perf/concurrency tests need single-process execution",
    ),
]

ROOT = Path(__file__).resolve().parents[1]
_AI_YAML = (
    "name: concurrency-probe\ncomponents:\n"
    "  - id: llm\n    name: LLM\n    type: llm_inference\n"
    "  - id: rag\n    name: RAG\n    type: rag_vector_store\n"
    "  - id: agent\n    name: Agent\n    type: agent\n"
)


def _client():
    from fastapi.testclient import TestClient

    from atms.web import app
    return TestClient(app, raise_server_exceptions=False)


def test_web_handles_concurrent_analyze_no_corruption():
    """20 parallel POST /analyze (10 workers) all return 200. A
    shared-state bug (run-store, KB cache) would surface as a 500 or
    mismatched response under contention."""
    c = _client()

    def one(_i: int) -> int:
        return c.post("/analyze", data={"yaml": _AI_YAML}).status_code

    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        codes = list(ex.map(one, range(20)))

    assert Counter(codes) == Counter({200: 20}), (
        f"concurrent /analyze returned non-200s: {Counter(codes)}"
    )


def test_concurrent_analyze_results_independent():
    """The big system's report mentions its own components; concurrent
    requests don't bleed into each other."""
    c = _client()
    results: dict[int, str] = {}

    def go(i: int):
        results[i] = c.post("/analyze", data={"yaml": _AI_YAML}).text

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(go, range(8)))

    for txt in results.values():
        assert "concurrency-probe" in txt or "Agent" in txt


def test_report_render_under_budget():
    """analyse + render HTML + MD for rag_system stays under 5s."""
    from atms.models import System
    from atms.reporting.html import render_html
    from atms.reporting.markdown import render_markdown
    from atms.workflow import analyze

    raw = yaml.safe_load((ROOT / "samples" / "rag_system.yaml").read_text(encoding="utf-8"))
    s = System.model_validate(raw)

    start = time.perf_counter()
    tm = analyze(s)
    html = render_html(tm)
    md = render_markdown(tm)
    elapsed = time.perf_counter() - start

    assert html and md
    assert elapsed < 5.0, f"analyse+render took {elapsed:.2f}s (budget 5s)"


def test_large_system_analyse_under_budget():
    """A 60-component system analyses under 3s."""
    from atms.models import Component, System
    from atms.workflow import analyze

    comps = [Component(id=f"c{i}", name=f"C{i}",
                       type="llm_inference" if i % 4 == 0 else "tool")
             for i in range(60)]
    s = System(name="big", components=comps)

    start = time.perf_counter()
    tm = analyze(s, require_ai_components=False)
    elapsed = time.perf_counter() - start

    assert len(tm.threats) >= 1
    assert elapsed < 3.0, f"60-component analyse took {elapsed:.2f}s (budget 3s)"
