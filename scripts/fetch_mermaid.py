"""Download a pinned Mermaid release into src/atms/static/ for offline use.

Run this once when you want to refresh the bundled Mermaid version. The
result is committed to the repo so end users never need internet to view
the diagrams in HTML reports or the inline web UI.

Usage:
    python scripts/fetch_mermaid.py [--version 10.9.5]
"""

from __future__ import annotations

import argparse
import hashlib
import urllib.request
from pathlib import Path

# Pin a specific Mermaid version. Update this number when refreshing.
DEFAULT_VERSION = "10.9.5"
URL_TEMPLATE = "https://cdn.jsdelivr.net/npm/mermaid@{version}/dist/mermaid.min.js"

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "src" / "atms" / "static" / "mermaid.min.js"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default=DEFAULT_VERSION)
    args = parser.parse_args()

    url = URL_TEMPLATE.format(version=args.version)
    print(f"Fetching {url}")
    with urllib.request.urlopen(url) as resp:
        body = resp.read()
    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    size_kb = len(body) / 1024
    print(f"Wrote {DEST} ({size_kb:.1f} KB, sha256={digest[:16]}...)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
