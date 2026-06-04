# PyInstaller spec for the ATMS Windows portable build.
# Run from the repo root: `pyinstaller atms.spec`
# Outputs `dist/atms.exe` (single file).
#
# What we bundle:
#   - src/atms/                         the package source
#   - kb/                               YAML knowledge base
#   - samples/                          sample systems + test_diagram.vsdx
#   - src/atms/templates/               Jinja2 templates (markdown + html + web/)
#
# What's loaded by importlib at runtime that PyInstaller can't auto-detect
# (so we declare them in `hiddenimports`):
#   - uvicorn workers and protocol implementations
#   - fastapi internals
#   - pydantic v2 generated validators

# ruff: noqa: E501

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules


HERE = Path(SPECPATH)
SRC = HERE / "src"

datas = [
    (str(HERE / "kb"), "kb"),
    (str(HERE / "samples"), "samples"),
    (str(SRC / "atms" / "templates"), "atms/templates"),
    (str(SRC / "atms" / "static"), "atms/static"),
]
# uvicorn ships its own data files (logging config etc.)
datas += collect_data_files("uvicorn")
datas += collect_data_files("vsdx")

hiddenimports: list[str] = []
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("fastapi")
hiddenimports += collect_submodules("starlette")
hiddenimports += collect_submodules("anyio")
hiddenimports += collect_submodules("pydantic")
hiddenimports += [
    "atms.web",
    "atms.workflow",
    "atms.kb",
    "atms.cli",
    # v0.14.5: declare every engine / ingest / reporting / evidence / feeds
    # module explicitly so the frozen .exe never ImportErrors at runtime
    # — even if a future Python release tightens static-analysis behaviour
    # in PyInstaller. The static-detection happens to find these today,
    # but the cost of a comprehensive declaration is one line of code.
    "atms.ingest.vsdx",
    "atms.ingest.otm",
    "atms.ingest.terraform",
    "atms.ingest.docker_compose",
    "atms.engines.stride_ai",
    "atms.engines.attack_paths",
    "atms.engines.boundaries",
    "atms.engines.maestro",
    "atms.engines.mapping",
    "atms.engines.mitigations",
    "atms.engines.risk",
    "atms.engines.cloud",            # v0.9
    "atms.engines.kill_chain",       # v0.11
    "atms.engines.linddun",          # v0.10
    "atms.engines.nist_ai_100_2",    # v0.11
    "atms.engines.owasp_ml",         # v0.13
    "atms.engines.compliance",       # v0.13
    "atms.engines.controls",         # v0.13
    "atms.engines.quantitative",     # v0.13 FAIR-lite
    "atms.engines.evidence",         # v0.12
    "atms.engines.d3fend",           # v0.14
    "atms.evidence",                 # v0.12 (package)
    "atms.evidence.nessus",
    "atms.evidence.sarif",
    "atms.evidence.stix",
    "atms.evidence.csv_parser",
    "atms.evidence.matcher",
    "atms.evidence.redteam",         # v0.14
    "atms.feeds",                    # v0.13 (opt-in network)
    "atms.feeds.cve_lookup",
    "atms.feeds.refresh",
    "atms.reporting.markdown",
    "atms.reporting.html",
    "atms.reporting.stix",
    "atms.reporting.navigator",
    "atms.reporting.csv_export",
    "atms.reporting.mermaid",        # v0.6
    "atms.reporting.otm_export",     # v0.13
    "atms.reporting.sarif_export",   # v0.13 CI mode
    "yaml",
    "click",
    "rich",
    "jinja2",
    "vsdx",
    "vsdx.shapes",
    "networkx",
    "defusedxml",
    "bleach",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "h11",
    "anyio._backends._asyncio",
    "fastapi.staticfiles",
    "starlette.staticfiles",
    "aiofiles",
]


a = Analysis(
    [str(SRC / "atms" / "__main__.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Heavyweight test/dev deps not needed at runtime
        "pytest",
        "_pytest",
        "PIL",
        "matplotlib",
        "tkinter",
        # AI / LLM SDKs — the shipped product is deterministic Python; no AI
        # dependency by design. The optional vision module (vision/analyzer.py)
        # is the only file that imports `anthropic`, and we exclude both the
        # SDK and the module from the installer so the product is fully
        # airgap-capable with zero LLM/network requirements.
        "anthropic",
        "openai",
        "cohere",
        "voyageai",                  # added v0.14.5 for parity (catalog mentions it as opt-in)
        "google.generativeai",
        "huggingface_hub",
        "transformers",
        "atms.vision",
        "atms.vision.analyzer",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="atms",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,             # UPX would shrink the binary but adds a security smell + AV false-positives
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
