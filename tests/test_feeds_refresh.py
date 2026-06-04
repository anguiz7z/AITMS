"""Phase B coverage tests for src/atms/feeds/refresh.py.

Baseline: 29.7% — none of the parsing logic was exercised. These tests
mock `_http_get` to feed synthetic upstream responses and verify:
  - KEV CSV parsing (cveID/cveId column name variants, ransomware flag)
  - EPSS JSON parsing (top-N truncation, malformed score handling)
  - Output YAML structure + header comments
  - Network-error path returns a RuntimeError with helpful context
  - Non-CVE rows are filtered out (don't poison the snapshot)
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import yaml

from atms.feeds.refresh import (
    KEV_URL,
    USER_AGENT,
    _http_get,
    refresh_epss,
    refresh_kev,
)

# ─── KEV refresh ──────────────────────────────────────────────────
_KEV_CSV_SAMPLE = (
    b"\xef\xbb\xbf"  # UTF-8 BOM (CISA emits this)
    b"cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,"
    b"requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes\r\n"
    b'CVE-2024-12345,Microsoft,Exchange,Test Vuln,2024-01-15,'
    b'Short description of the vuln,Apply patch,2024-02-01,Known,n/a,CWE-79\r\n'
    b'CVE-2024-99999,VendorX,ProductY,Another Vuln,2024-03-20,'
    b'Another description,Mitigate,2024-04-01,Unknown,n/a,CWE-22\r\n'
    b'BAD-2024-0001,Junk,Junk,Not a CVE,2024-01-01,'
    b'Garbage row,n/a,n/a,n/a,n/a,n/a\r\n'
)


def test_refresh_kev_parses_csv_to_yaml(tmp_path):
    out = tmp_path / "kev.yaml"
    with patch("atms.feeds.refresh._http_get", return_value=_KEV_CSV_SAMPLE):
        n = refresh_kev(out)
    assert n == 2  # bad-prefix row filtered out
    text = out.read_text(encoding="utf-8")
    # Header comment block
    assert text.startswith("# CISA Known Exploited Vulnerabilities")
    assert f"Source: {KEV_URL}" in text
    assert "Rows: 2" in text
    # YAML body
    rows = yaml.safe_load("\n".join(
        l for l in text.splitlines() if not l.startswith("#")
    ))
    assert isinstance(rows, list) and len(rows) == 2
    by_cve = {r["cve"]: r for r in rows}
    assert "CVE-2024-12345" in by_cve
    e = by_cve["CVE-2024-12345"]
    assert e["vendor"] == "Microsoft"
    assert e["product"] == "Exchange"
    assert e["ransomware"] is True
    assert by_cve["CVE-2024-99999"]["ransomware"] is False


def test_refresh_kev_handles_alternate_cveId_column_name(tmp_path):
    """CISA has used both `cveID` and `cveId` historically. Either
    must round-trip."""
    csv_text = (
        b"cveId,vendorProject,product,shortDescription,dateAdded,dueDate,"
        b"knownRansomwareCampaignUse\r\n"
        b"CVE-2024-1,V,P,Desc,2024-01-01,2024-02-01,Known\r\n"
    )
    out = tmp_path / "kev.yaml"
    with patch("atms.feeds.refresh._http_get", return_value=csv_text):
        n = refresh_kev(out)
    assert n == 1


def test_refresh_kev_writes_zero_rows_on_empty_feed(tmp_path):
    """If the feed comes back with only a header (no data rows),
    refresh still writes a valid snapshot with 0 rows — not a crash."""
    csv_text = b"cveID,vendorProject,product\r\n"
    out = tmp_path / "kev.yaml"
    with patch("atms.feeds.refresh._http_get", return_value=csv_text):
        n = refresh_kev(out)
    assert n == 0
    assert "Rows: 0" in out.read_text(encoding="utf-8")


def test_refresh_kev_propagates_network_failure(tmp_path):
    out = tmp_path / "kev.yaml"
    with (
        patch("atms.feeds.refresh._http_get",
                side_effect=RuntimeError("Network error fetching X")),
        pytest.raises(RuntimeError, match="Network error"),
    ):
        refresh_kev(out)
    # No partial file written.
    assert not out.exists()


# ─── EPSS refresh ─────────────────────────────────────────────────
_EPSS_PAYLOAD = {
    "status": "OK",
    "total": 4,
    "data": [
        {"cve": "CVE-2024-1", "epss": "0.9876", "percentile": "0.9999"},
        {"cve": "CVE-2024-2", "epss": "0.5432", "percentile": "0.85"},
        {"cve": "CVE-2024-3", "epss": "not-a-number",  # bad score → filtered
         "percentile": "0.5"},
        {"cve": "not-a-cve",  "epss": "0.1", "percentile": "0.1"},  # filtered
    ],
}


def test_refresh_epss_parses_top_n(tmp_path):
    import json
    out = tmp_path / "epss.yaml"
    with patch("atms.feeds.refresh._http_get",
                return_value=json.dumps(_EPSS_PAYLOAD).encode("utf-8")):
        n = refresh_epss(out)
    assert n == 2  # 2 bad rows filtered out
    rows = yaml.safe_load("\n".join(
        l for l in out.read_text(encoding="utf-8").splitlines()
        if not l.startswith("#")
    ))
    assert {r["cve"] for r in rows} == {"CVE-2024-1", "CVE-2024-2"}
    # Percentile is multiplied by 100 (0.9999 → 99.99).
    e1 = next(r for r in rows if r["cve"] == "CVE-2024-1")
    assert e1["epss"] == 0.9876
    assert e1["percentile"] == 99.99


def test_refresh_epss_honours_top_n_cap(tmp_path):
    import json
    payload = {"data": [
        {"cve": f"CVE-2024-{i}", "epss": "0.5", "percentile": "0.5"}
        for i in range(20)
    ]}
    out = tmp_path / "epss.yaml"
    with patch("atms.feeds.refresh._http_get",
                return_value=json.dumps(payload).encode("utf-8")):
        n = refresh_epss(out, top_n=5)
    assert n == 5


def test_refresh_epss_handles_empty_data_array(tmp_path):
    import json
    out = tmp_path / "epss.yaml"
    with patch("atms.feeds.refresh._http_get",
                return_value=json.dumps({"data": []}).encode("utf-8")):
        n = refresh_epss(out)
    assert n == 0
    assert "Rows: 0" in out.read_text(encoding="utf-8")


def test_refresh_epss_propagates_network_failure(tmp_path):
    out = tmp_path / "epss.yaml"
    with (
        patch("atms.feeds.refresh._http_get",
                side_effect=RuntimeError("Network error fetching Y")),
        pytest.raises(RuntimeError, match="Network error"),
    ):
        refresh_epss(out)


# ─── _http_get error wrapping ─────────────────────────────────────
def test_http_get_wraps_urlerror_as_runtime_error():
    """The internal helper turns urllib.error.URLError into RuntimeError
    with a helpful proxy-hint message — important UX for offline users."""
    import urllib.error
    with (
        patch("urllib.request.urlopen",
                side_effect=urllib.error.URLError("connection refused")),
        pytest.raises(RuntimeError, match="proxy|Network error|offline"),
    ):
        _http_get("https://example.invalid/")


def test_http_get_sends_user_agent_header():
    """The User-Agent must include the ATMS version so server logs
    can identify us. Prevents bot-blocking heuristics from kicking us out."""
    from unittest.mock import MagicMock
    mock_resp = MagicMock()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read = MagicMock(return_value=b"ok")
    with patch("urllib.request.urlopen", return_value=mock_resp) as urlopen:
        result = _http_get("https://example.invalid/")
    assert result == b"ok"
    # Inspect the Request that was passed.
    req = urlopen.call_args[0][0]
    assert req.get_header("User-agent", "").startswith("ATMS/")
    assert USER_AGENT.startswith("ATMS/")
