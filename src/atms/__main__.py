"""Entry point for `python -m atms` and the PyInstaller frozen executable.

Both run the Click CLI. Keep this file tiny so it's safe to use as the
PyInstaller entry script.
"""

from __future__ import annotations

import multiprocessing
import sys


def main() -> None:
    # PyInstaller-frozen executables need this as the very first thing for any
    # subprocess / multiprocessing usage (uvicorn workers, etc.) to work
    # correctly on Windows.
    multiprocessing.freeze_support()

    from atms.cli import cli

    cli(prog_name="atms")


if __name__ == "__main__":
    sys.exit(main() or 0)
