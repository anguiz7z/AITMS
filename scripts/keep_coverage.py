"""Measure line coverage of the KEEP code paths ONLY.

The hibernation work (v0.18.68-73) narrowed ATMS to a focused product.
The default ``pytest --cov`` total is misleading because it includes
the 40 hibernated modules (evidence parsers, IaC ingesters, extra
exporters, MCP server, ...) which are intentionally NOT exercised in
the default run — they drag the number down even though every line
that ships in the default product is well covered.

This script runs the default (KEEP-only) test suite with coverage,
OMITTING every hibernated module, and reports the honest KEEP-path
coverage. Roadmap V5 uses it as the real floor.

Usage:
    python scripts/keep_coverage.py
    python scripts/keep_coverage.py --fail-under 75
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Hibernated-by-default modules → omit from the KEEP floor.
HIBERNATED_OMIT = [
    "src/atms/ingest/mermaid.py",
    "src/atms/ingest/vsdx.py",
    "src/atms/ingest/tm7.py",
    "src/atms/ingest/otm.py",
    "src/atms/ingest/terraform.py",
    "src/atms/ingest/pulumi_yaml.py",
    "src/atms/ingest/cloudformation.py",
    "src/atms/ingest/azure_arm.py",
    "src/atms/ingest/kubernetes.py",
    "src/atms/ingest/docker_compose.py",
    "src/atms/vision/*",
    "src/atms/evidence/*",
    "src/atms/engines/evidence.py",
    "src/atms/feeds/*",
    "src/atms/mcp_server.py",
    "src/atms/reporting/sbom_export.py",
    "src/atms/reporting/stix.py",
    "src/atms/reporting/sarif_export.py",
    "src/atms/reporting/navigator.py",
    "src/atms/reporting/jira_export.py",
    "src/atms/reporting/roadmap_export.py",
    "src/atms/reporting/otm_export.py",
    "src/atms/reporting/csv_export.py",
    "src/atms/reporting/compliance_matrix.py",
    "src/atms/engines/linddun.py",
    "src/atms/engines/nist_ai_100_2.py",
    "src/atms/engines/owasp_ml.py",
    "src/atms/__main__.py",
    "src/atms/static/*",
    "src/atms/templates/*",
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fail-under", type=float, default=None)
    args = ap.parse_args()

    rc = ROOT / ".coveragerc.keep"
    rc.write_text(
        "[run]\nsource = src/atms\nbranch = True\nomit =\n"
        + "".join(f"    {p}\n" for p in HIBERNATED_OMIT)
        + "\n[report]\nshow_missing = True\nskip_covered = True\nprecision = 1\n",
        encoding="utf-8",
    )
    try:
        cmd = [
            sys.executable, "-m", "pytest", "-q",
            "--cov=src/atms",
            f"--cov-config={rc}",
            "--cov-report=term-missing:skip-covered",
        ]
        if args.fail_under is not None:
            cmd.append(f"--cov-fail-under={args.fail_under}")
        env = {**os.environ, "PYTHONPATH": "src"}
        return subprocess.run(cmd, cwd=ROOT, env=env).returncode
    finally:
        rc.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
