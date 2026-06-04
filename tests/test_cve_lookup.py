"""Phase A coverage tests for src/atms/feeds/cve_lookup.py.

The module was at 44.8% coverage entering Phase A — entirely uncovered
because the legitimate path requires a live NVD/OSV call. These tests
mock urllib so we exercise every parse + fallback branch without
touching the network. Honest goal: ≥85% on the module.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from atms.feeds.cve_lookup import (
    CveLookupResult,
    _cvss_to_severity,
    _from_nvd,
    _from_osv,
    cve_lookup,
)


# ─── _cvss_to_severity — every band ────────────────────────────────
@pytest.mark.parametrize("score,expected", [
    (9.9, "critical"),
    (9.0, "critical"),
    (8.5, "high"),
    (7.0, "high"),
    (5.0, "medium"),
    (4.0, "medium"),
    (3.0, "low"),
    (0.1, "low"),
    (0.0, "info"),
])
def test_cvss_to_severity_buckets(score, expected):
    assert _cvss_to_severity(score) == expected


# ─── _from_nvd ─────────────────────────────────────────────────────
def _nvd_payload(*, cvss="9.8", severity="CRITICAL", vector="CVSS:3.1/AV:N/AC:L",
                 cwe=("CWE-79",), include_refs=True, include_cpe=True,
                 description="Test CVE description.") -> dict:
    """Synthetic NVD response shaped like the real API."""
    descriptions = [{"lang": "en", "value": description}]
    metrics = {"cvssMetricV31": [{
        "cvssData": {"baseScore": float(cvss), "vectorString": vector},
        "baseSeverity": severity,
    }]}
    weaknesses = [{"description": [{"value": c} for c in cwe]}]
    refs = [{"url": "https://nvd.example/ref1"},
             {"url": "https://nvd.example/ref2"}] if include_refs else []
    configs = [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
    ]}]}] if include_cpe else []
    return {"vulnerabilities": [{"cve": {
        "descriptions": descriptions,
        "metrics": metrics,
        "weaknesses": weaknesses,
        "references": refs,
        "configurations": configs,
        "published": "2024-01-15T00:00:00",
        "lastModified": "2024-02-01T00:00:00",
    }}]}


def test_nvd_parser_extracts_critical_findings():
    raw = _nvd_payload(cvss="9.8", severity="CRITICAL")
    res = _from_nvd("CVE-2024-12345", raw)
    assert res.source == "nvd"
    assert res.cvss == 9.8
    assert res.severity == "critical"
    assert "Test CVE description" in res.description
    assert "CWE-79" in res.cwe
    assert len(res.references) >= 1
    assert any("cpe:2.3" in a for a in res.affected)
    assert res.published == "2024-01-15T00:00:00"


def test_nvd_parser_no_vulnerabilities_returns_empty():
    res = _from_nvd("CVE-2099-99999", {"vulnerabilities": []})
    assert res.cve == "CVE-2099-99999"
    assert res.source == "nvd"
    assert res.description == ""
    assert res.cvss is None


def test_nvd_parser_falls_back_to_cvss30_then_v2():
    """CVSS 3.1 missing → falls back to 3.0; if 3.0 missing too → v2."""
    raw = {"vulnerabilities": [{"cve": {
        "descriptions": [{"lang": "en", "value": "Old vuln"}],
        "metrics": {"cvssMetricV2": [{
            "cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L"},
            "baseSeverity": "MEDIUM",
        }]},
    }}]}
    res = _from_nvd("CVE-2010-0001", raw)
    assert res.cvss == 5.0
    assert res.severity == "medium"


def test_nvd_parser_invalid_score_silently_continues():
    """A score that can't be parsed must NOT crash — just skip metrics."""
    raw = {"vulnerabilities": [{"cve": {
        "descriptions": [{"lang": "en", "value": "Bad metrics"}],
        "metrics": {"cvssMetricV31": [{
            "cvssData": {"baseScore": "not-a-number", "vectorString": ""},
        }]},
    }}]}
    res = _from_nvd("CVE-2024-99999", raw)
    assert res.cvss is None  # parse failed silently
    assert "Bad metrics" in res.description


def test_nvd_parser_skips_non_cwe_weaknesses():
    raw = _nvd_payload(cwe=("CWE-79", "NVD-CWE-noinfo", "CWE-200"))
    res = _from_nvd("CVE-2024-12345", raw)
    assert "CWE-79" in res.cwe
    assert "CWE-200" in res.cwe
    assert "NVD-CWE-noinfo" not in res.cwe


def test_nvd_parser_caps_references_at_8():
    raw = _nvd_payload()
    raw["vulnerabilities"][0]["cve"]["references"] = [
        {"url": f"https://r{i}.example/"} for i in range(20)
    ]
    res = _from_nvd("CVE-X", raw)
    assert len(res.references) == 8


def test_nvd_parser_caps_affected_at_12():
    raw = _nvd_payload()
    raw["vulnerabilities"][0]["cve"]["configurations"] = [{"nodes": [{
        "cpeMatch": [{"criteria": f"cpe:2.3:a:v:p{i}:1:*:*:*:*:*:*:*"}
                      for i in range(30)],
    }]}]
    res = _from_nvd("CVE-X", raw)
    assert len(res.affected) == 12


# ─── _from_osv ─────────────────────────────────────────────────────
def test_osv_parser_extracts_severity_from_score():
    raw = {
        "summary": "OSV-discovered issue",
        "details": "Long description here",
        "published": "2024-02-01",
        "modified": "2024-02-05",
        "references": [{"url": "https://osv.dev/ref"}],
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "requests"}},
            {"package": {"ecosystem": "npm", "name": "axios"}},
        ],
        "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/7.5"}],
    }
    res = _from_osv("CVE-2024-A", raw)
    assert res.source == "osv"
    assert res.title == "OSV-discovered issue"
    assert "PyPI:requests" in res.affected
    assert "npm:axios" in res.affected
    # 7.5 → high
    assert res.cvss == 7.5
    assert res.severity == "high"


def test_osv_parser_empty_inputs():
    res = _from_osv("CVE-X", {})
    assert res.source == "osv"
    assert res.description == ""
    assert res.cvss is None
    assert res.affected == []


def test_osv_parser_ignores_invalid_severity_tokens():
    raw = {"severity": [{"score": "weird:scoring/junk-tokens"}]}
    res = _from_osv("CVE-X", raw)
    assert res.cvss is None


def test_osv_parser_skips_affected_without_ecosystem():
    raw = {"affected": [
        {"package": {"name": "no-ecosystem"}},          # missing ecosystem
        {"package": {"ecosystem": "PyPI", "name": "ok"}},
    ]}
    res = _from_osv("CVE-X", raw)
    assert res.affected == ["PyPI:ok"]


# ─── cve_lookup orchestrator ───────────────────────────────────────
def test_cve_lookup_rejects_non_cve_id():
    with pytest.raises(ValueError, match="Not a CVE"):
        cve_lookup("vuln-2024-0001")


def test_cve_lookup_normalises_case():
    """Lowercase + leading/trailing whitespace must work — the
    normaliser uppercases + strips."""
    with patch("atms.feeds.cve_lookup._http_get_json") as get:
        get.return_value = _nvd_payload()
        res = cve_lookup("  cve-2024-12345  ")
    assert res.cve == "CVE-2024-12345"


def test_cve_lookup_uses_nvd_first():
    with patch("atms.feeds.cve_lookup._http_get_json") as get:
        get.return_value = _nvd_payload(cvss="9.8")
        res = cve_lookup("CVE-2024-12345")
    assert res.source == "nvd"
    assert res.severity == "critical"
    assert get.call_count == 1   # OSV not hit


def test_cve_lookup_falls_back_to_osv_when_nvd_empty():
    """NVD returns 200 with empty vulns → orchestrator tries OSV."""
    def fake_get(url, timeout=10):
        if "nvd" in url:
            return {"vulnerabilities": []}
        return {"summary": "From OSV",
                "details": "OSV details",
                "affected": [{"package": {"ecosystem": "PyPI", "name": "x"}}]}
    with patch("atms.feeds.cve_lookup._http_get_json", side_effect=fake_get):
        res = cve_lookup("CVE-2024-7777")
    assert res.source == "osv"
    assert res.title == "From OSV"


def test_cve_lookup_falls_back_to_osv_on_nvd_url_error():
    """Network error from NVD must trigger the OSV fallback."""
    import urllib.error

    def fake_get(url, timeout=10):
        if "nvd" in url:
            raise urllib.error.URLError("nvd unreachable")
        return {"summary": "OSV had it", "details": "yes",
                 "affected": [{"package": {"ecosystem": "PyPI", "name": "p"}}]}
    with patch("atms.feeds.cve_lookup._http_get_json", side_effect=fake_get):
        res = cve_lookup("CVE-2024-1111")
    assert res.source == "osv"


def test_cve_lookup_raises_runtime_error_when_both_sources_fail():
    """Both URLs throw → RuntimeError surfaces."""
    import urllib.error
    with (
        patch("atms.feeds.cve_lookup._http_get_json",
                side_effect=urllib.error.URLError("offline")),
        pytest.raises(RuntimeError, match="Could not look up"),
    ):
        cve_lookup("CVE-2024-9999")


def test_cve_lookup_unknown_cve_returns_not_found_marker():
    """Both NVD and OSV return 200 but neither has the CVE."""
    def fake_get(url, timeout=10):
        if "nvd" in url:
            return {"vulnerabilities": []}
        return {}  # OSV: empty
    with patch("atms.feeds.cve_lookup._http_get_json", side_effect=fake_get):
        res = cve_lookup("CVE-2099-12345")
    assert res.source == ""
    assert "not found" in res.description.lower()


# ─── CveLookupResult.to_dict ──────────────────────────────────────
def test_result_to_dict_round_trip():
    r = CveLookupResult(
        cve="CVE-X", source="nvd", title="t", description="d",
        severity="high", cvss=8.5, cvss_vector="V",
        cwe=["CWE-1"], affected=["a"], references=["http://r"],
        published="P", last_modified="L",
    )
    d = r.to_dict()
    assert d["cve"] == "CVE-X"
    assert d["cvss"] == 8.5
    assert d["cwe"] == ["CWE-1"]
    assert d["references"] == ["http://r"]
    # Verify the dict can be JSON-serialised (CLI uses --json).
    assert json.dumps(d)
