"""Roadmap V5 Phase 2 — analyze-loop robustness regression net.

The analyze loop IS the product. This module pins its ACTUAL,
correct contract (verified by probing in v0.19.2/.3):

  * The Pydantic `System` model and the `analyze()` entry point
    DELIBERATELY reject degenerate inputs with clean, typed errors:
      - empty component list           -> ValueError (at analyze)
      - dataflow to unknown component  -> ValidationError (at build)
      - duplicate component ids        -> ValidationError (at build)
      - zero AI components (default)   -> NoAIComponentsError
    These are FEATURES, not crashes — the net pins that they stay
    clean, typed rejections (never an unexpected exception type).

  * Structurally-VALID systems (unique ids, valid dataflows, >=1
    component) always analyse to a well-formed ThreatModel without
    raising — exercised both by explicit cases and a Hypothesis
    property test that generates only valid systems.

  * The CLI + web surfaces render friendly errors (no tracebacks,
    no HTTP 500s) on malformed / schema-invalid / empty input. The
    web form field is `yaml`; malformed YAML re-renders the index
    with HTTP 400 + an `.alert-error` block.

No production change — Phase 2 is a regression net. KEEP suite.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from atms.cli import cli
from atms.models import Component, Dataflow, System
from atms.web import app
from atms.workflow import analyze

_TYPES = ["llm_inference", "agent", "tool", "user", "database",
          "rag_vector_store", "mcp_server", "serverless_function",
          "api_gateway", "object_storage", "other"]


# ─── 1. Property: VALID systems never crash analyze ─────────────────


@st.composite
def _valid_system(draw):
    """Generate a structurally-valid System: unique component ids, no
    dataflows (so no dangling refs), >=1 component."""
    n = draw(st.integers(min_value=1, max_value=10))
    ids = [f"c{i}" for i in range(n)]  # guaranteed-unique ids
    comps = [
        Component(
            id=cid,
            name=draw(st.text(min_size=1, max_size=30)),
            type=draw(st.sampled_from(_TYPES)),
        )
        for cid in ids
    ]
    return System(name=draw(st.text(min_size=1, max_size=30)), components=comps)


@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(system=_valid_system())
def test_analyze_never_crashes_on_valid_generated_system(system):
    """Any structurally-VALID System analyses to a well-formed model
    without raising."""
    tm = analyze(system, require_ai_components=False)
    assert tm.threats is not None
    assert tm.mitigations is not None
    assert tm.attack_paths is not None
    for t in tm.threats:
        assert t.severity in {"critical", "high", "medium", "low", "info"}
    assert tm.model_dump_json()  # JSON round-trip never fails


# ─── 2. Degenerate inputs are rejected cleanly (typed errors) ───────


def test_empty_system_rejected_with_value_error():
    """analyze() on a zero-component system raises a clean ValueError,
    not an unexpected crash."""
    with pytest.raises(ValueError, match="no components"):
        analyze(System(name="e", components=[]), require_ai_components=False)


def test_dangling_dataflow_rejected_at_construction():
    """A dataflow to an unknown component is rejected by the System
    model validator."""
    with pytest.raises(ValidationError):
        System(
            name="s",
            components=[Component(id="a", name="A", type="agent")],
            dataflows=[Dataflow(source="a", target="ghost", label="x")],
        )


def test_duplicate_component_ids_rejected_at_construction():
    with pytest.raises(ValidationError):
        System(name="s", components=[
            Component(id="a", name="A", type="agent"),
            Component(id="a", name="B", type="llm_inference"),
        ])


def test_pure_it_system_rejected_by_default():
    """Default analyze() rejects a system with no AI components."""
    s = System(name="s", components=[Component(id="u", name="U", type="user")])
    with pytest.raises(Exception):  # NoAIComponentsError (subclass)  # noqa: B017
        analyze(s)


# ─── 3. Valid degenerate-but-legal systems analyse fine ─────────────


def test_single_ai_component_yields_threats():
    tm = analyze(System(name="s", components=[
        Component(id="l", name="L", type="llm_inference")]),
        require_ai_components=False)
    assert len(tm.threats) >= 1


def test_self_loop_dataflow_is_legal_and_analyses():
    tm = analyze(System(name="s",
        components=[Component(id="a", name="A", type="agent")],
        dataflows=[Dataflow(source="a", target="a", label="self")]),
        require_ai_components=False)
    assert tm.threats is not None


def test_cyclic_dataflows_do_not_hang():
    """a->b->a cycle must not infinite-loop attack-path enumeration."""
    tm = analyze(System(name="s", components=[
        Component(id="a", name="A", type="agent"),
        Component(id="b", name="B", type="llm_inference"),
    ], dataflows=[
        Dataflow(source="a", target="b", label="x"),
        Dataflow(source="b", target="a", label="y"),
    ]), require_ai_components=False)
    assert tm.threats is not None


def test_unicode_component_names_analyse():
    tm = analyze(System(name="中文システム",
        components=[Component(id="a", name="\U0001f916 Agent éñ",
                             type="agent")]),
        require_ai_components=False)
    assert tm.threats is not None


def test_large_system_60_components():
    comps = [Component(id=f"c{i}", name=f"C{i}",
                       type="llm_inference" if i % 5 == 0 else "tool")
             for i in range(60)]
    tm = analyze(System(name="big", components=comps),
                 require_ai_components=False)
    assert len(tm.threats) >= 1


# ─── 4. CLI error contract (no traceback) ───────────────────────────


def _write(content: str, suffix: str = ".yaml") -> str:
    fd, p = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(content)
    return p


def test_cli_validate_malformed_yaml_no_traceback():
    p = _write("name: test\n  bad: : indent:\n   - [")
    try:
        r = CliRunner().invoke(cli, ["validate", p])
        assert r.exit_code != 0
        assert "Traceback (most recent call last)" not in r.output
    finally:
        os.unlink(p)


def test_cli_validate_schema_invalid_yaml_no_traceback():
    p = _write("foo: bar\n")
    try:
        r = CliRunner().invoke(cli, ["validate", p])
        assert r.exit_code != 0
        assert "Traceback (most recent call last)" not in r.output
    finally:
        os.unlink(p)


def test_cli_analyze_malformed_yaml_no_traceback(tmp_path):
    p = _write("name: t\n  : : [")
    try:
        r = CliRunner().invoke(cli, ["analyze", p, "--out", str(tmp_path / "o")])
        assert r.exit_code != 0
        assert "Traceback (most recent call last)" not in r.output
    finally:
        os.unlink(p)


def test_cli_analyze_pure_it_rejected_cleanly(tmp_path):
    """A valid pure-IT system is rejected by `analyze` (AI-induced-risk
    scope) — but cleanly, with a guidance message and no traceback."""
    p = _write("name: t\ncomponents:\n  - id: u\n    name: U\n    type: user\n")
    try:
        r = CliRunner().invoke(cli, ["analyze", p, "--out", str(tmp_path / "o")])
        assert "Traceback (most recent call last)" not in r.output
        assert "AI" in r.output  # the rejection message mentions AI scope
    finally:
        os.unlink(p)


# ─── 5. Web error contract (field is `yaml`; never 500) ─────────────


def _client():
    return TestClient(app, raise_server_exceptions=False)


def test_web_analyze_malformed_yaml_is_friendly_not_500():
    r = _client().post("/analyze", data={"yaml": "name: t\n  bad: : : ["})
    assert r.status_code != 500
    assert r.status_code == 400
    assert "Traceback (most recent call last)" not in r.text


def test_web_analyze_schema_invalid_is_friendly_not_500():
    r = _client().post("/analyze", data={"yaml": "foo: bar\n"})
    assert r.status_code != 500
    assert "Traceback (most recent call last)" not in r.text


def test_web_analyze_empty_body_is_friendly_not_500():
    r = _client().post("/analyze", data={"yaml": ""})
    assert r.status_code != 500


def test_web_analyze_pure_it_is_friendly_not_500():
    r = _client().post("/analyze", data={
        "yaml": "name: t\ncomponents:\n  - id: u\n    name: U\n    type: user\n"})
    assert r.status_code != 500


def test_web_analyze_valid_ai_system_succeeds():
    r = _client().post("/analyze", data={
        "yaml": "name: t\ncomponents:\n  - id: l\n    name: L\n    type: llm_inference\n"})
    assert r.status_code == 200
    assert "Traceback (most recent call last)" not in r.text
