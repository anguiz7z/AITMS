"""Phase C verification — build the wheel, install into a clean
venv, run `atms selftest`. Used by the Phase 6 GitHub Actions
release workflow and runnable locally before any tag push.

End-to-end:
  1. `python -m build --wheel`           — produces dist/atms-X.Y.Z-py3-none-any.whl
  2. `python -m venv <tmp>`              — clean Python with nothing installed
  3. `<tmp>/Scripts/pip install <wheel>` — installs ATMS + every dep
  4. `<tmp>/Scripts/atms version`        — sanity check
  5. `<tmp>/Scripts/atms selftest`       — exercises every bundled sample

The wheel must carry ALL of:
  - kb/*.yaml (166 files of compliance / playbooks / frameworks)
  - templates/web/*.html (Jinja templates)
  - templates/report.*.j2 (report templates)
  - static/*.{js,css}  (vendored mermaid + the editor JS)
  - samples/*.yaml + samples/corpus/* + samples/iac/*
  - kb/system.schema.json + kb/palette_meta.yaml + kb/methodology_provenance.yaml
  - kb/devices/catalog.yaml (274 entries)
  - kb/threat_intel/cisa_kev.yaml + epss_top.yaml

If any of those don't ship in the wheel, `atms selftest` fails
loudly. That's the Phase C contract.

Usage:
  python scripts/verify_wheel.py        # default: builds + verifies
  python scripts/verify_wheel.py --skip-build   # reuse existing wheel
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess, echo the command, raise on non-zero exit."""
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if res.returncode != 0:
        print(f"    stderr: {res.stderr.strip()[:500]}")
        raise SystemExit(f"command failed (exit {res.returncode})")
    return res


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true",
                        help="Reuse the existing dist/*.whl instead of rebuilding.")
    parser.add_argument("--keep-venv", action="store_true",
                        help="Leave the temp venv on disk for manual inspection.")
    args = parser.parse_args()

    print("Phase C — verify the wheel installs cleanly + selftest passes")
    print()

    # Step 1: wheel build.
    dist = ROOT / "dist"
    if not args.skip_build:
        print("Step 1: build wheel via python -m build --wheel")
        # Clean prior wheels of this version to avoid pip ambiguity.
        for old in dist.glob("atms-*-py3-none-any.whl"):
            old.unlink()
        run([sys.executable, "-m", "build", "--wheel"], cwd=ROOT)
        print()

    wheels = sorted(dist.glob("atms-*-py3-none-any.whl"))
    if not wheels:
        raise SystemExit("no wheel found in dist/ — run without --skip-build")
    wheel = wheels[-1]
    print(f"Using wheel: {wheel.name}")
    print()

    # Step 2: clean venv.
    venv = Path(tempfile.mkdtemp(prefix="atms-wheel-verify-"))
    print(f"Step 2: create clean venv at {venv}")
    try:
        run([sys.executable, "-m", "venv", str(venv)])
        scripts = venv / ("Scripts" if sys.platform == "win32" else "bin")
        pip = scripts / ("pip.exe" if sys.platform == "win32" else "pip")
        atms = scripts / ("atms.exe" if sys.platform == "win32" else "atms")

        # Step 3: pip install.
        print()
        print(f"Step 3: pip install {wheel.name}")
        run([str(pip), "install", "--quiet", str(wheel)])

        # Step 4: version probe.
        print()
        print("Step 4: atms version")
        ver = run([str(atms), "version"])
        print(f"    {ver.stdout.strip()}")

        # Step 5: selftest.
        print()
        print("Step 5: atms selftest (every bundled sample must analyse)")
        st = run([str(atms), "selftest"])
        print(f"    {st.stdout.strip()}")

        print()
        print("Phase C verification PASSED.")
        print(f"  Wheel:   {wheel.name}")
        print(f"  Version: {ver.stdout.strip()}")
        return 0
    finally:
        if args.keep_venv:
            print(f"\nVenv preserved at: {venv}")
        else:
            shutil.rmtree(venv, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
