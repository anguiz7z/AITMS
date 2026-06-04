"""Refresh bundled CISA KEV + EPSS snapshots from canonical live feeds.

Pulls the upstream CSV/JSON, transforms to ATMS' YAML schema, writes to
``kb/threat_intel/cisa_kev.yaml`` and ``kb/threat_intel/epss_top.yaml``.

Network-on-demand only. The deterministic core never calls these
functions at analysis time — this module is invoked exclusively by the
opt-in ``atms refresh-feeds`` CLI command.
"""

from __future__ import annotations

import csv
import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

from .. import __version__

USER_AGENT = f"ATMS/{__version__} (+https://github.com/anguiz7z/AITMS)"

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
EPSS_URL = "https://api.first.org/data/v1/epss?limit=200&order=!epss"

DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_TOP_EPSS = 200


def _http_get(url: str, timeout: int = DEFAULT_TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (validated URL)
            return resp.read()
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Network error fetching {url}: {e}. Set HTTP(S)_PROXY if behind a proxy, "
            "or run offline with the bundled snapshot."
        ) from e


def refresh_kev(out_path: Path, *, url: str = KEV_URL, timeout: int = DEFAULT_TIMEOUT) -> int:
    """Pull the live CISA KEV CSV and write a YAML snapshot.

    Returns the number of rows written.
    """
    body = _http_get(url, timeout=timeout)
    text = body.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    rows: list[dict] = []
    for r in reader:
        cve = (r.get("cveID") or r.get("cveId") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        rows.append({
            "cve": cve,
            "vendor": (r.get("vendorProject") or "").strip(),
            "product": (r.get("product") or "").strip(),
            "description": (r.get("shortDescription") or "").strip(),
            "date_added": (r.get("dateAdded") or "").strip(),
            "due_date": (r.get("dueDate") or "").strip(),
            "ransomware": (r.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
        })
    header = (
        "# CISA Known Exploited Vulnerabilities — refreshed snapshot.\n"
        f"# Source: {url}\n"
        f"# Refreshed: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"# Rows: {len(rows)}\n\n"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        header + yaml.safe_dump(rows, sort_keys=False, default_flow_style=False, width=100),
        encoding="utf-8",
    )
    return len(rows)


def refresh_epss(
    out_path: Path,
    *,
    url: str = EPSS_URL,
    top_n: int = DEFAULT_TOP_EPSS,
    timeout: int = DEFAULT_TIMEOUT,
) -> int:
    """Pull the live EPSS top-N JSON and write a YAML snapshot.

    Returns the number of rows written.
    """
    body = _http_get(url, timeout=timeout)
    payload = json.loads(body.decode("utf-8"))
    items = payload.get("data") or []
    rows: list[dict] = []
    for item in items[:top_n]:
        cve = str(item.get("cve", "")).upper()
        if not cve.startswith("CVE-"):
            continue
        try:
            epss_score = float(item.get("epss"))
            percentile = float(item.get("percentile"))
        except (TypeError, ValueError):
            continue
        rows.append({"cve": cve, "epss": round(epss_score, 4), "percentile": round(percentile * 100, 2)})
    header = (
        "# EPSS scores — refreshed top-N snapshot.\n"
        f"# Source: {url}\n"
        f"# Refreshed: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"# Rows: {len(rows)}\n\n"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        header + yaml.safe_dump(rows, sort_keys=False, default_flow_style=False, width=100),
        encoding="utf-8",
    )
    return len(rows)


__all__ = ["refresh_kev", "refresh_epss", "USER_AGENT", "KEV_URL", "EPSS_URL"]
