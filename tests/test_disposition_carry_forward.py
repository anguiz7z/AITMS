"""Regression tests for v0.17.2 Cycle C — disposition carry-forward.

Pins three contracts:
  1. `analyze(system, prior_run=path)` copies disposition + lifecycle
     fields from a saved ThreatModel JSON onto matching new threats
     (by id).
  2. Threats with a closed disposition (mitigated / false_positive /
     duplicate) drop out of `summary.severity_breakdown` and the ALE
     totals, but remain in `tm.threats`.
  3. New threats absent from the prior run keep their default `open`
     disposition.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from atms.models import CLOSED_DISPOSITIONS, Component, System, is_closed
from atms.workflow import analyze


# ─── CLOSED_DISPOSITIONS constant + is_closed helper ─────────────────
def test_closed_dispositions_constant_shape():
    """The set is a finite frozenset of valid Disposition values."""
    assert isinstance(CLOSED_DISPOSITIONS, frozenset)
    assert frozenset({"mitigated", "false_positive", "duplicate"}) == CLOSED_DISPOSITIONS


def test_is_closed_classifies_correctly():
    for closed in ("mitigated", "false_positive", "duplicate"):
        assert is_closed(closed), f"{closed} should be closed"
    for open_state in ("open", "accepted", "transferred",
                       "accepted_with_compensating_control", "deferred",
                       None):
        assert not is_closed(open_state), f"{open_state} should be open"


# ─── End-to-end carry-forward ────────────────────────────────────────
def _build_sample_system() -> System:
    return System(name="t", components=[
        Component(id="u", name="U", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])


def test_carry_forward_copies_mitigated_disposition():
    sys_obj = _build_sample_system()
    # Run once, get a baseline ThreatModel.
    tm1 = analyze(sys_obj)
    assert tm1.threats, "baseline should produce threats"
    # Pick the first threat, mark it mitigated, save as prior-run JSON.
    target_id = tm1.threats[0].id
    tm1.threats[0].disposition = "mitigated"
    tm1.threats[0].mitigated_by_commit = "abc1234"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(json.loads(tm1.model_dump_json()), f)
        prior_path = f.name

    try:
        # Re-run with the prior path; the target should still be present
        # but carry the mitigated disposition.
        tm2 = analyze(sys_obj, prior_run=prior_path)
        matching = [t for t in tm2.threats if t.id == target_id]
        assert matching, "carried threat should still appear in the new run"
        assert matching[0].disposition == "mitigated"
        assert matching[0].mitigated_by_commit == "abc1234"
    finally:
        Path(prior_path).unlink(missing_ok=True)


def test_closed_threats_drop_from_severity_breakdown():
    """Threats with closed disposition stop counting toward
    severity_breakdown — that's the whole point of the feature."""
    sys_obj = _build_sample_system()
    tm1 = analyze(sys_obj)
    # Mark ALL threats mitigated on the prior run.
    for t in tm1.threats:
        t.disposition = "mitigated"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(json.loads(tm1.model_dump_json()), f)
        prior_path = f.name

    try:
        tm2 = analyze(sys_obj, prior_run=prior_path)
        # threats[] still contains everything (so the report can show it)
        assert tm2.summary["threats"] == len(tm1.threats)
        # severity_breakdown sums to 0 (all closed)
        sev_total = sum(tm2.summary["severity_breakdown"].values())
        assert sev_total == 0, (
            f"all threats closed; severity_breakdown should be empty, "
            f"got {tm2.summary['severity_breakdown']}"
        )
        # summary exposes both totals
        assert tm2.summary["threats_active"] == 0
        assert tm2.summary["threats_closed"] == len(tm1.threats)
    finally:
        Path(prior_path).unlink(missing_ok=True)


def test_new_threats_keep_default_open_disposition():
    """A threat in the new run that wasn't in the prior run must NOT
    inherit anything. It just keeps its default disposition."""
    sys_obj = _build_sample_system()
    tm1 = analyze(sys_obj)
    # Prior run has just one mitigated threat; the other 12 don't exist.
    # Simulate by saving a synthetic prior with only one entry.
    prior_data = {
        "system": json.loads(sys_obj.model_dump_json()),
        "threats": [{
            "id": "this_id_doesnt_exist_in_new_run",
            "disposition": "mitigated",
        }],
    }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(prior_data, f)
        prior_path = f.name

    try:
        tm2 = analyze(sys_obj, prior_run=prior_path)
        # All real threats keep their default disposition (open or the
        # playbook-declared value, which in practice is `open`).
        for t in tm2.threats:
            assert t.disposition == "open", (
                f"{t.id} got disposition={t.disposition!r}, expected open"
            )
    finally:
        Path(prior_path).unlink(missing_ok=True)


def test_missing_prior_run_file_is_a_warning_not_an_error():
    """An invalid prior_run path must NOT crash analyze() — it logs a
    warning and proceeds as if no prior was given."""
    sys_obj = _build_sample_system()
    tm = analyze(sys_obj, prior_run="/this/path/does/not/exist.json")
    assert tm.threats  # analysis proceeded
    assert tm.summary["threats_closed"] == 0


def test_malformed_prior_run_is_a_warning_not_an_error():
    sys_obj = _build_sample_system()
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        f.write("{ this is not valid json")
        bad_path = f.name
    try:
        tm = analyze(sys_obj, prior_run=bad_path)
        assert tm.threats  # analysis proceeded
        assert tm.summary["threats_closed"] == 0
    finally:
        Path(bad_path).unlink(missing_ok=True)


def test_carry_forward_preserves_full_threats_list():
    """The closed-disposition threats stay IN `tm.threats` — they only
    drop out of the rollup summaries. The report templates can then
    show them as 'previously closed' without losing the audit trail."""
    sys_obj = _build_sample_system()
    tm1 = analyze(sys_obj)
    n_threats = len(tm1.threats)
    for t in tm1.threats[:3]:
        t.disposition = "false_positive"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(json.loads(tm1.model_dump_json()), f)
        prior_path = f.name

    try:
        tm2 = analyze(sys_obj, prior_run=prior_path)
        assert len(tm2.threats) == n_threats, "no threats should be dropped"
        closed = [t for t in tm2.threats if is_closed(t.disposition)]
        assert len(closed) == 3, "3 threats should be marked closed"
    finally:
        Path(prior_path).unlink(missing_ok=True)


def test_summary_exposes_threats_active_and_closed_counts():
    """Even on a fresh run with no prior, the summary must expose the
    two new keys (with closed=0)."""
    sys_obj = _build_sample_system()
    tm = analyze(sys_obj)
    assert "threats_active" in tm.summary
    assert "threats_closed" in tm.summary
    assert tm.summary["threats_active"] == len(tm.threats)
    assert tm.summary["threats_closed"] == 0
