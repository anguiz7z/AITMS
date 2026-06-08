"""Evidence-parser hardening regressions (audit F037/F038/F039)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.hibernated  # evidence parsers are hibernated


def _sarif(obj) -> Path:
    f = tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False, encoding="utf-8")
    f.write(json.dumps(obj))
    f.close()
    return Path(f.name)


def test_parse_sarif_tolerates_null_tool_rules_and_message():
    """F037/F038: a SARIF file with JSON-null tool / driver / rule entries /
    message / shortDescription / defaultConfiguration must not crash."""
    from atms.evidence.sarif import parse_sarif
    doc = {
        "runs": [
            {"tool": None, "results": [{"ruleId": "R1", "message": None, "level": "error"}]},
            {"tool": {"driver": {"rules": [None, {"id": "R2", "shortDescription": None,
                                                  "properties": None, "defaultConfiguration": None}]}},
             "results": [{"ruleId": "R2", "message": {"text": "finding"}}]},
        ]
    }
    rows = parse_sarif(_sarif(doc))
    assert len(rows) == 2  # both results parsed, neither crashed


def test_stix_confidence_float_or_string_is_not_under_rated():
    """F039: STIX confidence as a float / numeric string must map to the right
    bucket, not fall through to 'medium'/'low'."""
    from atms.evidence.stix import _severity_from
    assert _severity_from({"confidence": 95.0}) == "critical"
    assert _severity_from({"confidence": "92"}) == "critical"
    assert _severity_from({"confidence": 75.5}) == "high"
    # a bool is NOT a numeric confidence -> fall back to labels
    assert _severity_from({"confidence": True, "labels": ["low"]}) == "low"
