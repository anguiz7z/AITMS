"""Live-feed refresh + CVE-lookup helpers (v0.13).

Strict opt-in network module. The deterministic shipped product never
reaches the internet on its own; users invoke `atms refresh-feeds` or
`atms cve-lookup` explicitly. We use stdlib `urllib` (no new deps), set
a meaningful User-Agent, and respect HTTP_PROXY / HTTPS_PROXY env vars
out-of-the-box.

Sources:
- CISA KEV catalogue:   https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
- FIRST EPSS scores:    https://api.first.org/data/v1/epss
- NVD CVE 2.0 API:      https://services.nvd.nist.gov/rest/json/cves/2.0
- OSV.dev (fallback):   https://api.osv.dev/v1/vulns/{id}

All functions raise `RuntimeError` with a clear message when the network
is unreachable; never crash the surrounding workflow silently.
"""

from __future__ import annotations

from .cve_lookup import CveLookupResult, cve_lookup
from .refresh import (
    USER_AGENT,
    refresh_epss,
    refresh_kev,
)

__all__ = [
    "cve_lookup",
    "CveLookupResult",
    "refresh_kev",
    "refresh_epss",
    "USER_AGENT",
]
