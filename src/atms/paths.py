"""Centralised resource-path lookup.

Resolves paths to the bundled `kb/`, `samples/`, and Jinja `templates/` folders
in three modes:

  1. **Development (editable install)**: source layout is
     `<repo>/src/atms/...` and resources live next to the source under
     `<repo>/kb`, `<repo>/samples`, `<repo>/src/atms/templates`.
  2. **Installed wheel**: data files installed under `<site-packages>/atms/...`.
  3. **PyInstaller frozen executable**: resources are extracted to
     `sys._MEIPASS` at runtime; paths are flattened under that root.

Set `ATMS_KB_DIR` / `ATMS_SAMPLES_DIR` env vars to override (handy for tests
and for users who want to point at a custom forked KB).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _meipass() -> Path | None:
    """If running under PyInstaller, return the temp extraction dir; else None."""
    base = getattr(sys, "_MEIPASS", None)
    return Path(base) if base else None


def _candidates(*relative: str) -> list[Path]:
    """Generate candidate resource locations in priority order."""
    here = Path(__file__).resolve()
    cands: list[Path] = []

    # 1. PyInstaller bundle (highest priority when frozen)
    mp = _meipass()
    if mp is not None:
        cands.append(mp.joinpath(*relative))
        cands.append(mp / "atms" / Path(*relative).name)  # flat layout fallback

    # 2. Repo / editable install: src/atms/__file__ → up two → repo root
    repo_root = here.parents[2]
    cands.append(repo_root.joinpath(*relative))

    # 3. Installed wheel: data files copied alongside the package
    cands.append(here.parent.joinpath(*relative))

    # 4. Installed wheel via hatch *shared-data*: top-level `kb` / `samples`
    #    are mapped to `atms/kb` / `atms/samples`, which pip places under
    #    <sys.prefix>/atms/... -- NOT inside the importable package. Without
    #    this candidate a plain `pip install <wheel>` / PyPI install resolves
    #    kb_dir()/samples_dir() to a nonexistent path and silently loads an
    #    EMPTY knowledge base. (audit F009/F010)
    cands.append(Path(sys.prefix).joinpath("atms", *relative))
    if sys.base_prefix != sys.prefix:  # inside a venv: also try the base install
        cands.append(Path(sys.base_prefix).joinpath("atms", *relative))

    return cands


def _first_existing(*relative: str, env: str | None = None) -> Path:
    if env:
        v = os.environ.get(env)
        if v:
            p = Path(v).expanduser()
            if p.exists():
                return p
    for p in _candidates(*relative):
        if p.exists():
            return p
    # Return the most likely path even if missing — caller can raise a clearer error.
    return _candidates(*relative)[0]


def kb_dir() -> Path:
    """Knowledge-base directory (`kb/`)."""
    return _first_existing("kb", env="ATMS_KB_DIR")


def samples_dir() -> Path:
    """Bundled sample systems directory (`samples/`)."""
    return _first_existing("samples", env="ATMS_SAMPLES_DIR")


def templates_dir() -> Path:
    """Jinja2 templates directory (`src/atms/templates` in dev)."""
    # Templates are package-internal; in dev they live next to this file's parent.
    here = Path(__file__).resolve().parent  # .../src/atms
    candidates = [
        here / "templates",
    ]
    mp = _meipass()
    if mp is not None:
        candidates.insert(0, mp / "atms" / "templates")
        candidates.insert(0, mp / "templates")
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


def static_dir() -> Path:
    """Static asset directory (`src/atms/static` in dev). Used for the bundled
    Mermaid library + the defensive init script. Found via the same three-mode
    lookup as templates_dir()."""
    here = Path(__file__).resolve().parent  # .../src/atms
    candidates = [here / "static"]
    mp = _meipass()
    if mp is not None:
        candidates.insert(0, mp / "atms" / "static")
        candidates.insert(0, mp / "static")
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


def output_dir(default: str = "output") -> Path:
    """Default output directory — relative to CWD so the user's invocation
    directory is the source of truth (consistent across dev / frozen)."""
    return Path.cwd() / default


__all__ = ["kb_dir", "samples_dir", "templates_dir", "static_dir", "output_dir"]
