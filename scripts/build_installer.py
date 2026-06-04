"""Build the ATMS Windows installer.

End-to-end:
  1. Run PyInstaller to produce dist/atms.exe.
  2. Read the version from src/atms/__init__.py.
  3. Find Inno Setup's ISCC.exe (winget install location, or PATH).
  4. Compile installer/atms.iss into dist/ATMS-Setup-X.Y.Z.exe.

Usage:
    python scripts/build_installer.py [--clean] [--skip-exe]

Outputs:
    dist/atms.exe                   the portable single-file binary
    dist/ATMS-Setup-X.Y.Z.exe       the installer to ship to testers
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ISS = ROOT / "installer" / "atms.iss"
DIST = ROOT / "dist"
BUILD_EXE = ROOT / "scripts" / "build_exe.py"

ISCC_CANDIDATES = [
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
    Path("C:/Program Files (x86)/Inno Setup 6/ISCC.exe"),
    Path("C:/Program Files/Inno Setup 6/ISCC.exe"),
]


def find_iscc() -> Path | None:
    on_path = shutil.which("ISCC")
    if on_path:
        return Path(on_path)
    for c in ISCC_CANDIDATES:
        if c.exists():
            return c
    return None


def read_version() -> str:
    """Read `__version__` from `src/atms/__init__.py` and verify it
    matches `pyproject.toml`'s `version`. v0.14.5 added the cross-check
    after a build-audit flagged that updating one and forgetting the
    other would silently ship a mislabeled installer."""
    init = (ROOT / "src" / "atms" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*[\'"]([^\'"]+)[\'"]', init)
    if not m:
        raise RuntimeError("Could not read __version__ from src/atms/__init__.py")
    pkg_version = m.group(1)

    proj_path = ROOT / "pyproject.toml"
    proj = proj_path.read_text(encoding="utf-8")
    pm = re.search(r'^\s*version\s*=\s*[\'"]([^\'"]+)[\'"]', proj, re.MULTILINE)
    if not pm:
        raise RuntimeError("Could not read version from pyproject.toml")
    proj_version = pm.group(1)
    if pkg_version != proj_version:
        raise RuntimeError(
            f"Version mismatch — refusing to build a mislabeled installer.\n"
            f"  src/atms/__init__.py: __version__ = {pkg_version!r}\n"
            f"  pyproject.toml:       version       = {proj_version!r}\n"
            f"Update both to the same value, then rerun."
        )
    return pkg_version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean", action="store_true", help="Wipe build/ and dist/ before starting")
    parser.add_argument("--skip-exe", action="store_true",
                        help="Reuse an existing dist/atms.exe; skip the PyInstaller step")
    args = parser.parse_args()

    iscc = find_iscc()
    if iscc is None:
        print("ERROR: Inno Setup 6 (ISCC.exe) not found.")
        print("Install via winget:")
        print("    winget install JRSoftware.InnoSetup")
        return 2

    print(f"Inno Setup compiler: {iscc}")

    if not args.skip_exe:
        print("> Building portable .exe via PyInstaller ...")
        cmd = [sys.executable, str(BUILD_EXE)]
        if args.clean:
            cmd.append("--clean")
        rc = subprocess.call(cmd, cwd=str(ROOT))
        if rc != 0:
            print(f"PyInstaller exited with {rc}")
            return rc

    exe = DIST / "atms.exe"
    if not exe.exists():
        print(f"ERROR: {exe} not found. Run without --skip-exe to build it.")
        return 1

    version = read_version()
    print(f"Version: {version}")
    print(f"> Compiling installer/atms.iss -> dist/ATMS-Setup-{version}.exe ...")

    cmd = [
        str(iscc),
        f"/DMyAppVersion={version}",
        str(ISS),
    ]
    print(">", " ".join(cmd))
    rc = subprocess.call(cmd, cwd=str(ROOT / "installer"))
    if rc != 0:
        print(f"ISCC exited with {rc}")
        return rc

    setup = DIST / f"ATMS-Setup-{version}.exe"
    if not setup.exists():
        print(f"ERROR: expected {setup} not found")
        return 1

    size_mb = setup.stat().st_size / (1024 * 1024)
    print()
    print(f"OK  Built {setup}  ({size_mb:.1f} MB)")
    print()
    print("Test the installer interactively:")
    print(f"  start {setup}")
    print()
    print("Or silently (no UI, useful in CI):")
    print(f"  {setup} /VERYSILENT /NORESTART /LOG=install.log")
    print()
    print("Default install location: %LOCALAPPDATA%\\Programs\\ATMS")
    print("Uninstall: Settings -> Apps -> ATMS  (or run Uninstall ATMS in the Start menu)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
