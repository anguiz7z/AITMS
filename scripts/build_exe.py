"""Build the ATMS portable Windows .exe via PyInstaller.

Usage:
    python scripts/build_exe.py [--clean]

Outputs:
    dist/atms.exe         the single-file thick-client binary
    build/                intermediate work dir (safe to delete)

After build:
    dist\\atms.exe version
    dist\\atms.exe selftest
    dist\\atms.exe analyze samples/rag_system.yaml --out output
    dist\\atms.exe ingest samples/test_diagram.vsdx
    dist\\atms.exe web                    # http://127.0.0.1:8765

Copy `dist\\atms.exe` to any Windows machine — no Python needed.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "atms.spec"
DIST = ROOT / "dist"
BUILD = ROOT / "build"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean", action="store_true", help="Remove build/ and dist/ first")
    args = parser.parse_args()

    if args.clean:
        for d in (BUILD, DIST):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
                print(f"Removed {d}")

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", str(SPEC)]
    print(">", " ".join(cmd))
    rc = subprocess.call(cmd, cwd=str(ROOT))
    if rc != 0:
        print(f"PyInstaller exited with {rc}")
        return rc

    exe = DIST / ("atms.exe" if sys.platform == "win32" else "atms")
    if not exe.exists():
        print(f"ERROR: expected output {exe} not found")
        return 1

    size_mb = exe.stat().st_size / (1024 * 1024)
    print()
    print(f"OK  Built {exe}  ({size_mb:.1f} MB)")
    print()
    print("Smoke checks you can run now:")
    print(f"  {exe} version")
    print(f"  {exe} selftest")
    print(f"  {exe} ingest samples/test_diagram.vsdx")
    print(f"  {exe} analyze samples/rag_system.yaml --out output")
    print(f"  {exe} web                    # http://127.0.0.1:8765")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
