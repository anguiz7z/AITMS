"""Evidence ingestion package (v0.12).

Parses VAPT / scanner / red-team / threat-intel artefacts into a list of
`Evidence` objects, then matches them to ATMS components and updates the
threat model in place.

Pure-Python; uses defusedxml for XML, stdlib json/csv for the rest.
No network calls — feeds (CISA KEV / EPSS) ship as bundled snapshots.
"""

from __future__ import annotations

from ..features import gated
from .csv_parser import parse_csv
from .nessus import parse_nessus
from .redteam import parse_atomic_red_team, parse_bas_csv, parse_caldera, parse_redteam
from .sarif import parse_sarif
from .stix import parse_stix

__all__ = [
    "parse_csv",
    "parse_nessus",
    "parse_sarif",
    "parse_stix",
    "parse_caldera",
    "parse_atomic_red_team",
    "parse_bas_csv",
    "parse_redteam",
    "parse_any",
]


@gated("evidence")
def parse_any(path) -> list:
    """Auto-detect the format from the file extension and parse.

    Returns a list of `atms.models.Evidence`.
    """
    from pathlib import Path

    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".nessus":
        return parse_nessus(p)
    if suffix == ".sarif":
        return parse_sarif(p)
    if suffix == ".csv":
        return parse_csv(p)
    if suffix in (".json",):
        # STIX 2.1 bundles use .json — we sniff via top-level "type"
        text = p.read_text(encoding="utf-8")
        if '"type"' in text and ('"bundle"' in text or '"indicator"' in text):
            return parse_stix(p)
        # Otherwise assume SARIF-style JSON
        return parse_sarif(p)
    raise ValueError(
        f"Unrecognised evidence format: {suffix or '(none)'}. "
        "Supported: .nessus, .sarif, .csv, .json (STIX 2.1)."
    )
