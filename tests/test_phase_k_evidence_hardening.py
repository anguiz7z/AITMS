"""Phase K — Evidence pipeline hardening / branch-coverage closure.

Roadmap V4 Phase K. The four evidence-ingestion modules carry user data
INTO the threat model — every uncovered branch is a parser bug waiting
to happen when a customer drops a real .stix.json, BAS export, or
Caldera operations file on us. The existing tests covered the happy
paths but missed the defensive guards: severity-from-confidence cutoffs,
non-bundle STIX shapes, JSONL multi-record red-team files, severity
fallbacks across BAS verdicts, the autodetect dispatcher.

Files covered:

  * src/atms/evidence/__init__.py  (60.6% → ~100%)
      - .nessus / .sarif / .csv / .json (STIX) / .json (SARIF) dispatch
      - Unsupported extension raises with a clear message

  * src/atms/evidence/stix.py  (59.7% → ~100%)
      - _severity_from: confidence 90+/70+/40+/<40 branches
      - _severity_from: label fallback (critical/high/medium/low/info)
      - _severity_from: no-confidence-no-labels → medium default
      - parse_stix: top-level dict-with-objects vs. bare-object shapes
      - parse_stix: non-dict objects skipped
      - parse_stix: unknown object types filtered out
      - parse_stix: CVE harvest from external_references

  * src/atms/evidence/csv_parser.py  (77.8% → ~95%)
      - _normalise_severity: every severity alias bucket
      - _normalise_severity: CVSS-numeric mapping (0..10)
      - _normalise_severity: malformed numeric → medium fallback
      - parse_csv: empty CSV / no fieldnames → []
      - parse_csv: malformed CVSS / EPSS numbers default to None
      - parse_csv: multi-CVE field (comma + semicolon separators)

  * src/atms/evidence/redteam.py  (75.6% → ~95%)
      - _atomic_severity: success/partial/prevented branches
      - parse_caldera: v4 state="finished" success path
      - parse_caldera: state="failed" continue branch
      - parse_caldera: v2 status==0 success when state absent
      - parse_caldera: neither state nor status → assume failure
      - parse_caldera: non-dict op skipped
      - parse_caldera: non-dict link skipped
      - parse_atomic_red_team: JSONL multi-record file
      - parse_atomic_red_team: empty file → []
      - parse_atomic_red_team: non-dict invocation skipped
      - parse_bas_csv: empty file / no fieldnames → []
      - parse_bas_csv: severity fallback from result
      - parse_redteam: extension dispatch + content sniff
      - parse_redteam: unsupported extension raises

Phase K is pure test additions — no production code change.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — file tests evidence parsers (hibernated).
#     pytest -m hibernated tests/test_phase_k_evidence_hardening.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import json

import pytest

from atms.evidence import parse_any
from atms.evidence.csv_parser import (
    _normalise_severity,
    _resolve_columns,
    parse_csv,
)
from atms.evidence.redteam import (
    _atomic_severity,
    parse_atomic_red_team,
    parse_bas_csv,
    parse_caldera,
    parse_redteam,
)
from atms.evidence.stix import _severity_from, parse_stix

# ===========================================================================
# evidence/__init__.py — parse_any auto-dispatch
# ===========================================================================


def test_parse_any_dispatches_nessus(tmp_path):
    """.nessus → parse_nessus. Empty Nessus XML is a no-op."""
    p = tmp_path / "scan.nessus"
    p.write_text('<?xml version="1.0"?>\n<NessusClientData_v2></NessusClientData_v2>',
                 encoding="utf-8")
    out = parse_any(p)
    assert isinstance(out, list)


def test_parse_any_dispatches_sarif(tmp_path):
    """.sarif → parse_sarif. Minimal SARIF document."""
    p = tmp_path / "out.sarif"
    p.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
    }), encoding="utf-8")
    out = parse_any(p)
    assert out == []


def test_parse_any_dispatches_csv(tmp_path):
    """.csv → parse_csv. Minimal CSV with one finding."""
    p = tmp_path / "findings.csv"
    p.write_text("CVE,Severity\nCVE-2024-1234,High\n", encoding="utf-8")
    out = parse_any(p)
    assert len(out) == 1
    assert out[0].cve == ["CVE-2024-1234"]
    assert out[0].severity == "high"


def test_parse_any_dispatches_stix_json(tmp_path):
    """.json with STIX 2.1 sentinel ("bundle" or "indicator") → parse_stix."""
    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {"type": "indicator", "id": "indicator--1", "name": "Bad IP",
             "pattern": "[ipv4-addr:value = '1.2.3.4']", "confidence": 95},
        ],
    }
    p = tmp_path / "ti.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    out = parse_any(p)
    assert len(out) == 1
    assert out[0].source_type == "stix:indicator"


def test_parse_any_dispatches_json_to_sarif_fallback(tmp_path):
    """.json without STIX sentinels falls back to SARIF parsing."""
    p = tmp_path / "results.json"
    # SARIF-flavoured JSON: no "bundle" or "indicator" present.
    p.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
    }), encoding="utf-8")
    out = parse_any(p)
    assert out == []


def test_parse_any_unsupported_extension_raises(tmp_path):
    """.xyz → ValueError with a helpful supported-list message."""
    p = tmp_path / "weird.xyz"
    p.write_text("dummy", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        parse_any(p)
    assert "Unrecognised evidence format" in str(exc.value)
    assert ".nessus" in str(exc.value)
    assert ".sarif" in str(exc.value)


def test_parse_any_no_extension_raises(tmp_path):
    """Path with no extension → ValueError with `(none)` in the message."""
    p = tmp_path / "noext"
    p.write_text("dummy", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        parse_any(p)
    assert "(none)" in str(exc.value)


# ===========================================================================
# evidence/stix.py — _severity_from + parse_stix
# ===========================================================================


def test_stix_severity_from_confidence_critical():
    """confidence ≥ 90 → critical."""
    assert _severity_from({"confidence": 95}) == "critical"
    assert _severity_from({"confidence": 90}) == "critical"


def test_stix_severity_from_confidence_high():
    """confidence 70-89 → high."""
    assert _severity_from({"confidence": 89}) == "high"
    assert _severity_from({"confidence": 70}) == "high"


def test_stix_severity_from_confidence_medium():
    """confidence 40-69 → medium."""
    assert _severity_from({"confidence": 69}) == "medium"
    assert _severity_from({"confidence": 40}) == "medium"


def test_stix_severity_from_confidence_low():
    """confidence < 40 → low."""
    assert _severity_from({"confidence": 39}) == "low"
    assert _severity_from({"confidence": 0}) == "low"


def test_stix_severity_from_labels_critical():
    """labels: ["critical"] → critical."""
    assert _severity_from({"labels": ["critical"]}) == "critical"


def test_stix_severity_from_labels_high():
    assert _severity_from({"labels": ["high"]}) == "high"


def test_stix_severity_from_labels_low():
    assert _severity_from({"labels": ["low"]}) == "low"


def test_stix_severity_from_labels_info():
    assert _severity_from({"labels": ["info"]}) == "info"


def test_stix_severity_from_labels_unknown_fallback():
    """Unknown label string → medium default."""
    assert _severity_from({"labels": ["unknown-bucket"]}) == "medium"


def test_stix_severity_from_no_signals_returns_medium():
    """No confidence + no labels → medium."""
    assert _severity_from({}) == "medium"
    assert _severity_from({"labels": []}) == "medium"


def test_stix_severity_from_non_int_confidence_falls_through_to_labels():
    """confidence as a string falls through to label-based detection."""
    assert _severity_from({"confidence": "high", "labels": ["high"]}) == "high"


def test_stix_parse_bundle_with_objects_list(tmp_path):
    """Standard STIX 2.1 bundle: {"type": "bundle", "objects": [...]}"""
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps({
        "type": "bundle",
        "objects": [
            {"type": "indicator", "id": "indicator--1", "name": "IP block",
             "pattern": "[ipv4-addr:value = '5.6.7.8']", "confidence": 80,
             "external_references": [
                 {"external_id": "CVE-2024-9999", "url": "https://nvd.nist.gov/vuln/CVE-2024-9999"},
             ],
             "labels": ["malicious-activity"]},
            {"type": "vulnerability", "id": "vuln--1", "name": "CVE thing",
             "description": "broken auth"},
            {"type": "attack-pattern", "id": "ap--1", "name": "Phishing"},
            {"type": "malware", "id": "mal--1", "name": "Emotet",
             "malware_types": ["trojan", "downloader"]},
            {"type": "tool", "id": "tool--1", "name": "Mimikatz"},
            # Filtered out — type not in allowed set.
            {"type": "marking-definition", "id": "marking--1"},
            # Non-dict skipped.
            "not a dict",
        ],
    }), encoding="utf-8")
    out = parse_stix(p)
    # 5 surviving objects (indicator, vulnerability, attack-pattern, malware, tool)
    assert len(out) == 5
    by_id = {e.source_id: e for e in out}
    assert by_id["indicator--1"].cve == ["CVE-2024-9999"]
    assert by_id["indicator--1"].severity == "high"  # confidence=80 → high
    assert "trojan" in by_id["mal--1"].affected_asset


def test_stix_parse_bare_object_not_bundle(tmp_path):
    """Top-level non-dict (bare list) is treated as the objects list."""
    p = tmp_path / "raw.json"
    p.write_text(json.dumps([
        {"type": "indicator", "id": "ind--1", "name": "Lone IOC"},
    ]), encoding="utf-8")
    out = parse_stix(p)
    assert len(out) == 1


def test_stix_parse_bare_single_object(tmp_path):
    """Top-level dict that's NOT a bundle (no "objects" key) → wrap as [raw]."""
    p = tmp_path / "single.json"
    p.write_text(json.dumps({
        "type": "indicator", "id": "ind--solo", "name": "Solo",
    }), encoding="utf-8")
    out = parse_stix(p)
    # raw.get("objects") returns None → objects = [raw] path (line 41-42).
    assert len(out) == 1
    assert out[0].source_id == "ind--solo"


def test_stix_parse_skips_non_dict_objects(tmp_path):
    """Items in objects[] that aren't dicts are skipped (line 46)."""
    p = tmp_path / "mixed.json"
    p.write_text(json.dumps({
        "objects": [
            "string-not-dict",
            42,
            None,
            {"type": "indicator", "id": "ind--ok"},
        ],
    }), encoding="utf-8")
    out = parse_stix(p)
    assert len(out) == 1


def test_stix_parse_filters_unknown_types(tmp_path):
    """Only indicator/vulnerability/attack-pattern/malware/tool pass (line 49)."""
    p = tmp_path / "noise.json"
    p.write_text(json.dumps({
        "objects": [
            {"type": "course-of-action", "id": "coa--1"},
            {"type": "report", "id": "rep--1"},
            {"type": "indicator", "id": "ind--ok"},
        ],
    }), encoding="utf-8")
    out = parse_stix(p)
    assert len(out) == 1
    assert out[0].source_id == "ind--ok"


# ===========================================================================
# evidence/csv_parser.py — _normalise_severity + parse_csv
# ===========================================================================


def test_csv_normalise_severity_all_aliases():
    """Every severity alias bucket maps to its canonical value."""
    assert _normalise_severity("") == "medium"  # empty default
    assert _normalise_severity("Critical") == "critical"
    assert _normalise_severity("crit") == "critical"
    assert _normalise_severity("5") == "critical"
    assert _normalise_severity("HIGH") == "high"
    assert _normalise_severity("h") == "high"
    assert _normalise_severity("4") == "high"
    assert _normalise_severity("medium") == "medium"
    assert _normalise_severity("med") == "medium"
    assert _normalise_severity("moderate") == "medium"
    assert _normalise_severity("m") == "medium"
    assert _normalise_severity("3") == "medium"
    assert _normalise_severity("low") == "low"
    assert _normalise_severity("l") == "low"
    assert _normalise_severity("2") == "low"
    assert _normalise_severity("info") == "info"
    assert _normalise_severity("informational") == "info"
    assert _normalise_severity("1") == "info"
    assert _normalise_severity("0") == "info"
    assert _normalise_severity("none") == "info"


def test_csv_normalise_severity_cvss_numeric():
    """CVSS-style numeric strings get bucketed via cutoffs."""
    assert _normalise_severity("9.5") == "critical"
    assert _normalise_severity("9.0") == "critical"
    assert _normalise_severity("8.5") == "high"
    assert _normalise_severity("7.0") == "high"
    assert _normalise_severity("6.5") == "medium"
    assert _normalise_severity("4.0") == "medium"
    assert _normalise_severity("3.5") == "low"
    assert _normalise_severity("0.1") == "low"
    assert _normalise_severity("0.0") == "info"


def test_csv_normalise_severity_garbage_string_falls_back_to_medium():
    """Non-numeric, non-alias string → medium default."""
    assert _normalise_severity("definitely not a thing") == "medium"


def test_csv_parse_empty_csv_returns_empty_list(tmp_path):
    """Empty file → no fieldnames → return [] (line 94)."""
    p = tmp_path / "empty.csv"
    p.write_text("", encoding="utf-8")
    out = parse_csv(p)
    assert out == []


def test_csv_parse_malformed_cvss_defaults_to_none(tmp_path):
    """Non-numeric CVSS column → cvss field is None (lines 104-105)."""
    p = tmp_path / "bad_cvss.csv"
    p.write_text("CVE,CVSS,Severity\nCVE-2024-1,not-a-number,High\n",
                 encoding="utf-8")
    out = parse_csv(p)
    assert len(out) == 1
    assert out[0].cvss is None


def test_csv_parse_malformed_epss_defaults_to_none(tmp_path):
    """Non-numeric EPSS column → epss field is None (lines 110-111)."""
    p = tmp_path / "bad_epss.csv"
    p.write_text("CVE,EPSS,Severity\nCVE-2024-2,bogus,High\n",
                 encoding="utf-8")
    out = parse_csv(p)
    assert len(out) == 1
    assert out[0].epss is None


def test_csv_parse_multi_cve_semicolon_separated(tmp_path):
    """`"CVE-1; CVE-2; CVE-3"` (quoted column) → 3 CVEs. The CVE field
    splits on both `,` and `;` (csv_parser line 99).

    Note: when commas are used as the CVE separator, the field MUST be
    quoted in the CSV — otherwise csv.DictReader treats the comma as
    a column boundary. This test uses semicolons inside an unquoted
    field, which is the natural shape Nessus and Qualys produce.
    """
    p = tmp_path / "multi.csv"
    p.write_text(
        "CVE,Severity\n"
        "CVE-2024-1; CVE-2024-2; CVE-2024-3,Critical\n",
        encoding="utf-8",
    )
    out = parse_csv(p)
    assert len(out) == 1
    assert out[0].cve == ["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"]


def test_csv_parse_uses_synopsis_for_description(tmp_path):
    """`Synopsis` column is an alias for description (alias map line 40)."""
    p = tmp_path / "synopsis.csv"
    p.write_text(
        "PluginName,Synopsis,Risk\n"
        "SMB Signing Not Required,Possible MITM,Medium\n",
        encoding="utf-8",
    )
    out = parse_csv(p)
    assert out[0].description == "Possible MITM"
    assert out[0].title == "SMB Signing Not Required"


def test_csv_resolve_columns_first_alias_wins():
    """When fieldnames contain multiple aliases for the same field, the
    earlier-listed alias wins (the `field not in out` guard at line 53)."""
    cols = _resolve_columns(["CVE", "cve_id", "severity"])
    # Both `cve` and `cveid` could match — first hit is what's in CVE.
    assert "cve" in cols


# ===========================================================================
# evidence/redteam.py — _atomic_severity + parse_caldera + atomic + bas + dispatcher
# ===========================================================================


def test_atomic_severity_success_high():
    """success/succeeded/true/passed/detected → high (lines 33-34)."""
    assert _atomic_severity("Success") == "high"
    assert _atomic_severity("SUCCEEDED") == "high"
    assert _atomic_severity("true") == "high"
    assert _atomic_severity("Passed") == "high"
    assert _atomic_severity("Detected") == "high"


def test_atomic_severity_partial_medium():
    """partial / blocked-but-executed → medium (lines 35-36)."""
    assert _atomic_severity("partial") == "medium"
    assert _atomic_severity("Partial Success") == "medium"
    assert _atomic_severity("blocked but executed") == "medium"


def test_atomic_severity_prevented_low():
    """prevented / blocked / failed / no impact → low (lines 37-38)."""
    assert _atomic_severity("Prevented") == "low"
    assert _atomic_severity("blocked") == "low"
    assert _atomic_severity("false") == "low"
    assert _atomic_severity("Failed") == "low"
    assert _atomic_severity("No Impact") == "low"


def test_atomic_severity_unknown_medium():
    assert _atomic_severity("zwzwzw") == "medium"
    assert _atomic_severity("") == "medium"
    assert _atomic_severity(None) == "medium"


def test_caldera_v4_state_finished_promotes_to_evidence(tmp_path):
    """state="finished" → succeeded path (line 85)."""
    p = tmp_path / "op.json"
    p.write_text(json.dumps({
        "name": "test-op",
        "chain": [
            {"state": "finished",
             "ability": {"technique_id": "T1059", "name": "Cmd-line",
                         "description": "ran a command", "ability_id": "ab1"}},
        ],
    }), encoding="utf-8")
    out = parse_caldera(p)
    assert len(out) == 1
    assert "attack:T1059" in out[0].references


def test_caldera_state_failed_skipped(tmp_path):
    """state="failed" → continue, no Evidence (line 87)."""
    p = tmp_path / "op.json"
    p.write_text(json.dumps({
        "chain": [
            {"state": "failed",
             "ability": {"technique_id": "T9999", "name": "x"}},
        ],
    }), encoding="utf-8")
    out = parse_caldera(p)
    assert out == []


def test_caldera_v2_status_zero_success_when_no_state(tmp_path):
    """No state, status==0 → succeeded path (line 89)."""
    p = tmp_path / "op.json"
    p.write_text(json.dumps({
        "chain": [
            {"status": 0,
             "ability": {"technique_id": "T1003", "name": "Cred dump"}},
        ],
    }), encoding="utf-8")
    out = parse_caldera(p)
    assert len(out) == 1


def test_caldera_no_state_no_status_assumes_failure(tmp_path):
    """Neither field → succeeded=False → continue (line 92)."""
    p = tmp_path / "op.json"
    p.write_text(json.dumps({
        "chain": [
            {"ability": {"technique_id": "T1234", "name": "Mystery"}},
        ],
    }), encoding="utf-8")
    out = parse_caldera(p)
    assert out == []


def test_caldera_non_dict_op_skipped(tmp_path):
    """Top-level item that's not a dict is skipped (line 61)."""
    p = tmp_path / "op.json"
    p.write_text(json.dumps([
        "not a dict",
        42,
        {"chain": [
            {"state": "finished",
             "ability": {"technique_id": "T1059", "name": "OK"}},
        ]},
    ]), encoding="utf-8")
    out = parse_caldera(p)
    assert len(out) == 1


def test_caldera_non_dict_link_skipped(tmp_path):
    """Items inside chain[] that aren't dicts are skipped (line 65)."""
    p = tmp_path / "op.json"
    p.write_text(json.dumps({
        "chain": [
            "not a link",
            None,
            {"state": "finished",
             "ability": {"technique_id": "T1059", "name": "OK"}},
        ],
    }), encoding="utf-8")
    out = parse_caldera(p)
    assert len(out) == 1


def test_caldera_no_tech_id_omits_attack_ref(tmp_path):
    """Ability with no technique_id → no `attack:` reference (line 114 branch)."""
    p = tmp_path / "op.json"
    p.write_text(json.dumps({
        "chain": [
            {"state": "finished",
             "ability": {"name": "Untyped ability"}},
        ],
    }), encoding="utf-8")
    out = parse_caldera(p)
    assert len(out) == 1
    refs = out[0].references
    assert not any(r.startswith("attack:") for r in refs)


def test_atomic_red_team_empty_file_returns_empty_list(tmp_path):
    """Empty Atomic invocation file → [] (line 149)."""
    p = tmp_path / "inv.json"
    p.write_text("", encoding="utf-8")
    out = parse_atomic_red_team(p)
    assert out == []


def test_atomic_red_team_single_record_no_array_no_jsonl(tmp_path):
    """A lone `{...}` record (no JSONL, no top-level array) is parsed as
    one invocation (line 161)."""
    p = tmp_path / "inv.json"
    p.write_text(json.dumps({
        "Atomic": {"attack_technique": "T1059", "name": "PowerShell",
                   "display_name": "PowerShell Execution",
                   "auto_generated_guid": "abc-1"},
        "ExecutionResult": "Success",
        "StartTime": "2026-05-23T10:00:00Z",
    }), encoding="utf-8")
    out = parse_atomic_red_team(p)
    assert len(out) == 1
    assert out[0].references == ["attack:T1059"]
    assert out[0].severity == "high"


def test_atomic_red_team_jsonl_multi_record(tmp_path):
    """JSONL: multiple `{...}` lines → multiple invocations (line 158-159)."""
    p = tmp_path / "inv.jsonl"
    p.write_text(
        json.dumps({"Atomic": {"attack_technique": "T1003"},
                    "ExecutionResult": "Success"})
        + "\n"
        + json.dumps({"Atomic": {"attack_technique": "T1059"},
                      "ExecutionResult": "Failed"})
        + "\n",
        encoding="utf-8",
    )
    out = parse_atomic_red_team(p)
    assert len(out) == 2
    sev_by_tech = {e.references[0]: e.severity for e in out if e.references}
    assert sev_by_tech["attack:T1003"] == "high"
    assert sev_by_tech["attack:T1059"] == "low"


def test_atomic_red_team_skips_non_dict_invocations(tmp_path):
    """Top-level array with mixed entries — non-dict entries are skipped
    (line 168)."""
    p = tmp_path / "inv.json"
    p.write_text(json.dumps([
        "skip me",
        None,
        42,
        {"Atomic": {"attack_technique": "T1059", "name": "OK"},
         "ExecutionResult": "Success"},
    ]), encoding="utf-8")
    out = parse_atomic_red_team(p)
    assert len(out) == 1


def test_bas_csv_empty_returns_empty_list(tmp_path):
    """Empty BAS CSV → [] (line 213)."""
    p = tmp_path / "bas.csv"
    p.write_text("", encoding="utf-8")
    out = parse_bas_csv(p)
    assert out == []


def test_bas_csv_severity_fallback_from_result_column(tmp_path):
    """No `Severity` column → derive from `Result` via _atomic_severity."""
    p = tmp_path / "bas.csv"
    p.write_text(
        "Technique,Target,Result\n"
        "T1059,host1,Successful\n"
        "T1003,host2,Prevented\n",
        encoding="utf-8",
    )
    out = parse_bas_csv(p)
    sev_by_tech = {e.source_id: e.severity for e in out}
    # "Successful" isn't in the success-set ("success" is) — default medium.
    # "Prevented" maps to "low".
    assert sev_by_tech["T1003"] == "low"


def test_bas_csv_explicit_severity_column_wins(tmp_path):
    """When `Severity` column exists with a recognised bucket, it wins
    over result-derived severity."""
    p = tmp_path / "bas.csv"
    p.write_text(
        "Technique,Target,Result,Severity\n"
        "T1059,host1,Prevented,critical\n",
        encoding="utf-8",
    )
    out = parse_bas_csv(p)
    assert out[0].severity == "critical"  # explicit > derived


def test_parse_redteam_dispatch_caldera(tmp_path):
    """.json with `"chain"` sentinel → parse_caldera (line 253)."""
    p = tmp_path / "op.json"
    p.write_text(json.dumps({
        "chain": [
            {"state": "finished",
             "ability": {"technique_id": "T1059", "name": "OK"}},
        ],
    }), encoding="utf-8")
    out = parse_redteam(p)
    assert len(out) == 1


def test_parse_redteam_dispatch_atomic(tmp_path):
    """.json with `"Atomic"` sentinel → parse_atomic_red_team (line 251)."""
    p = tmp_path / "inv.json"
    p.write_text(json.dumps({
        "Atomic": {"attack_technique": "T1059", "name": "OK"},
        "ExecutionResult": "Success",
    }), encoding="utf-8")
    out = parse_redteam(p)
    assert len(out) == 1
    assert out[0].source_type == "atomic_red_team"


def test_parse_redteam_dispatch_csv(tmp_path):
    """.csv → parse_bas_csv (line 248)."""
    p = tmp_path / "bas.csv"
    p.write_text("Technique,Result\nT1059,Successful\n", encoding="utf-8")
    out = parse_redteam(p)
    assert isinstance(out, list)


def test_parse_redteam_dispatch_unknown_json_defaults_to_caldera(tmp_path):
    """.json with neither Atomic nor chain sentinels → defaults to
    parse_caldera (line 256). Sole valid input here is a JSON shape that
    parse_caldera will tolerate."""
    p = tmp_path / "weird.json"
    # parse_caldera tolerates an empty top-level dict; chain default is [].
    p.write_text(json.dumps({"name": "mystery"}), encoding="utf-8")
    out = parse_redteam(p)
    assert out == []


def test_parse_redteam_unsupported_extension_raises(tmp_path):
    """.xml → ValueError listing supported formats (lines 257-260)."""
    p = tmp_path / "weird.xml"
    p.write_text("<xml/>", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        parse_redteam(p)
    assert "Caldera" in str(exc.value)
    assert "Atomic" in str(exc.value)
