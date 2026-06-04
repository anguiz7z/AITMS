# Building ATMS for Windows

ATMS ships in two Windows packaging formats:

1. **Portable .exe** — single 35 MB `atms.exe` you copy anywhere and run. PyInstaller-built, fully self-contained.
2. **Installer** — single 37 MB `ATMS-Setup-X.Y.Z.exe` that the end user double-clicks. Inno Setup wizard installs to `%LOCALAPPDATA%\Programs\ATMS`, drops Start Menu and (optional) Desktop shortcuts, optionally adds `atms.exe` to PATH, registers an uninstaller in Add/Remove Programs.

Both bundle the Python runtime, every dependency, the YAML knowledge base, the Jinja templates, and the bundled samples. **Neither requires Python or any AI/LLM SDK on the target machine** — see [AI_DEPENDENCIES.md](AI_DEPENDENCIES.md).

## Prerequisites (build machine only)

- Windows 10/11 64-bit (Linux/Mac builds are possible but produce non-portable binaries — PyInstaller doesn't cross-compile).
- Python 3.11+.
- Working ATMS dev environment: `pip install -r requirements.txt`.
- For the portable .exe: `pip install pyinstaller`.
- For the installer: **Inno Setup 6** (free). One-line install via winget:

  ```powershell
  winget install JRSoftware.InnoSetup
  ```

  The build script auto-discovers `ISCC.exe` from the standard winget install location (`%LOCALAPPDATA%\Programs\Inno Setup 6`).

The end user (tester laptop) needs nothing — not Python, not Inno Setup, not the build prerequisites.

## Build the portable .exe

```powershell
pip install pyinstaller
python scripts/build_exe.py --clean
```

`--clean` wipes `dist/` and `build/` first. The build takes 60-90 seconds on a typical laptop and produces `dist/atms.exe` (~35 MB).

## Build the installer

The recommended path. Produces `dist/ATMS-Setup-X.Y.Z.exe` (37 MB) — what you ship to testers.

```powershell
python scripts/build_installer.py --clean
```

Steps the script runs:

1. Run PyInstaller via `scripts/build_exe.py` to produce `dist/atms.exe`.
2. Read the version from `src/atms/__init__.py`.
3. Locate `ISCC.exe` (Inno Setup 6).
4. Compile `installer/atms.iss`, embedding the version into the output filename.

If you've already got a fresh `dist/atms.exe`, skip the slow PyInstaller step:

```powershell
python scripts/build_installer.py --skip-exe
```

## Test the installer locally

Interactive (UI wizard):

```powershell
start dist\ATMS-Setup-X.Y.Z.exe   # match the version of your local build
```

Silent / CI-style (no UI, log to file):

```powershell
.\dist\ATMS-Setup-X.Y.Z.exe /VERYSILENT /NORESTART /SUPPRESSMSGBOXES /LOG=install.log
```

Default install location: `%LOCALAPPDATA%\Programs\ATMS\` (no admin needed).

After install, the end user has:

- `%LOCALAPPDATA%\Programs\ATMS\atms.exe` — the binary
- `%LOCALAPPDATA%\Programs\ATMS\samples\` — bundled sample systems + test_diagram.vsdx
- `%LOCALAPPDATA%\Programs\ATMS\README.md`, `USAGE.md`, `AI_DEPENDENCIES.md`, `LICENSE`, `CHANGELOG.md`
- Start Menu folder `ATMS`:
  - **ATMS Web UI** — runs `atms.exe web`, opens local server on port 8765
  - **ATMS Command Prompt** — opens cmd.exe in the install dir for CLI use
  - **Documentation (README)**
  - **Open Samples Folder**
  - **Uninstall ATMS**
- Optional Desktop shortcut (off by default; user opts in during install)
- Optional `atms` on PATH (off by default; user opts in during install)
- Add/Remove Programs entry: **AI Threat Modeling Studio X.Y.Z** (matches the build's `__version__`) with publisher `anguiz7z`

## Uninstall

Two equivalent paths:

- Settings → Apps → "AI Threat Modeling Studio" → Uninstall
- Start Menu → ATMS → Uninstall ATMS
- Silent: `%LOCALAPPDATA%\Programs\ATMS\unins000.exe /VERYSILENT /NORESTART`

Removes the install dir, all Start Menu entries, the Add/Remove Programs registration, and the PATH entry (if it was added).

The driver is the spec file [`atms.spec`](atms.spec). It explicitly bundles:

- `kb/` — every YAML in the knowledge base (OWASP LLM, OWASP Agentic, MAESTRO, MITRE ATLAS, NIST AI RMF, STRIDE-AI matrix, all 15 component playbooks).
- `samples/` — every bundled sample system + the test_diagram.vsdx.
- `src/atms/templates/` — Markdown + HTML report templates and the web UI templates.
- `vsdx` package data (its built-in template .vsdx).
- All `uvicorn` / `fastapi` / `starlette` / `pydantic` submodules (PyInstaller can't auto-detect dynamic imports).

## Test the .exe

After build, run from the repo root:

```powershell
.\dist\atms.exe version
.\dist\atms.exe selftest                                 # runs all 4 bundled samples
.\dist\atms.exe ingest .\samples\test_diagram.vsdx       # parse a Visio diagram
.\dist\atms.exe analyze .\samples\rag_system.yaml --out .\dist\output
.\dist\atms.exe web                                      # http://127.0.0.1:8765
```

You can also run from any CWD as long as the input files exist there.

## Deploy to a tester laptop

1. Copy `dist\atms.exe` (single file) to the laptop. Anywhere — `C:\Tools\atms.exe`, a USB stick, OneDrive, anywhere.
2. The first run is slightly slower (~3 seconds) because PyInstaller extracts to a temp directory. Subsequent runs are fast.
3. No Python install needed on the target machine. No .NET. No registry edits.

## Limitations of the frozen build

- The optional `--reload` flag on `atms web` is disabled (no live source tree).
- The optional vision module (`vision/analyzer.py`, requires `anthropic`) is **excluded** from the .exe by design — adding ~50 MB for an opt-in feature you can run from a Python install instead.
- Output files are still written to the CWD (e.g., `output/`) — the .exe doesn't bundle them.
- WeasyPrint PDF rendering is not bundled (Windows GTK install requirement); use the HTML output instead.

## Roll back to a prior release

ATMS uses annotated git tags for every release. To roll back:

```powershell
git fetch --tags
git checkout v0.3.0    # or v0.2.0, v0.1.0
```

To rebuild a previous release as an .exe:

```powershell
git checkout v0.3.0
python scripts/build_exe.py --clean
git checkout main
```

## CI build (future)

A GitHub Actions workflow could be added to publish `dist/atms.exe` on every tag push. Skipped for now — local build is reliable and the .exe is too large to commit to the repo.
