"""ATMS web UI — FastAPI + Jinja2.

Single-process, file-system-only. No DB. Each analysis run is held in memory until
the user navigates away or the server restarts. Reports can be downloaded.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

import yaml
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from . import __version__
from .kb import get_kb
from .models import System
from .paths import samples_dir, static_dir, templates_dir
from .reporting import (
    render_html,
    render_markdown,
    render_mermaid,
    render_navigator,
    render_stix,
    write_csv,
)
from .workflow import analyze as run_analysis
from .yaml_autocorrect import (
    autocorrect_system_yaml as _autocorrect_system_yaml,
)
from .yaml_autocorrect import (
    format_validation_error as _format_validation_error,
)
from .yaml_autocorrect import (
    safe_load_system_yaml as _safe_load_system_yaml,
)

_TEMPLATE_DIR = templates_dir()
_SAMPLES_DIR = samples_dir()
_STATIC_DIR = static_dir()

# v0.11: PNG / image ingestion uses the opt-in vision module if available.
ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp"}
ALLOWED_DIAGRAM_EXTS_ALL = {".vsdx", ".drawio", ".xml", ".mmd", ".mermaid", ".md",
                            ".png", ".jpg", ".jpeg", ".webp"}  # v0.18.1: drawio + mermaid

app = FastAPI(
    title="ATMS",
    version=__version__,
    # v0.18.69 Hibernation Phase 2 — disable FastAPI's auto Swagger UI
    # (/docs) and ReDoc (/redoc); the REST API is hibernated, and we
    # need /docs ourselves for the collapsed Docs nav index.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# v0.18.69 Hibernation Phase 2 — expose the feature-flag snapshot to
# every Jinja template so base.html nav can render only KEEP surfaces.
# Centralised here so a future template can do `{% if features.editor %}`
# without each route having to thread the dict through its context.
from . import features as _features  # noqa: E402

templates.env.globals["features"] = _features.enabled_features()
templates.env.globals["FEATURES"] = _features  # full module for `FEATURES.is_enabled(...)`


# v0.18.70 Hibernation Phase 3 — middleware-based route gating.
#
# Why middleware (not @requires_feature decorator)?
# FastAPI runs request-body validation (Form/File/JSON) BEFORE the
# wrapped function body. A decorator can return 404 for GET but a POST
# with the wrong body returns 422 (validation error) first — the
# decorator never gets a chance. Middleware intercepts before that.
#
# Path-prefix matching means /evidence/ingest auto-inherits the
# evidence flag without needing a separate map entry.
# Route → FUNCTIONALITY flag. v1.0.1: these gate whether the route works
# at all (all default-ON now). They are deliberately NOT the NAV_* flags
# — those only control top-bar placement, so a focused nav never breaks
# a working tool. A route 404s only if its functional flag is set to 0.
_HIBERNATED_ROUTE_PREFIXES: dict[str, str] = {
    "/evidence":            "evidence",
    "/redteam":             "redteam",
    "/iac":                 "iac",
    "/compliance":          "compliance",
    "/api/compliance":      "compliance",
    "/devices":             "devices",
    "/api/devices":         "devices",
    "/diff":                "diff",
    "/api/v1/analyze":      "rest_api",
    "/api/v1/scan":         "rest_api",
    "/api/v1/metrics":      "rest_api",
}


@app.middleware("http")
async def hibernation_gate(request, call_next):
    """Short-circuit hibernated route prefixes with HTTP 404.

    Runs BEFORE FastAPI's body validation, so POST /evidence/ingest
    with an invalid body still returns the canonical hibernation 404,
    not a 422 validation error.
    """
    path = request.url.path
    for prefix, feature in _HIBERNATED_ROUTE_PREFIXES.items():
        # Match exact path OR a sub-path (e.g. /evidence/ingest under
        # the /evidence prefix). Guard against accidental over-matching:
        # /evidence-x must NOT match /evidence, so require either
        # exact-equality or a `/` boundary.
        if path == prefix or path.startswith(prefix + "/"):
            if not _features.is_enabled(feature):
                from starlette.responses import JSONResponse
                return JSONResponse(
                    status_code=404,
                    content={
                        "detail": (
                            f"ATMS route '{path}' is hibernated. "
                            f"Set ATMS_FEATURE_{feature.upper()}=1 to enable."
                        )
                    },
                )
            break
    return await call_next(request)

# Serve bundled static assets (mermaid.min.js, atms-mermaid.js). Lets the
# inline web report render diagrams without any internet connection.
if _STATIC_DIR.exists():
    from fastapi.staticfiles import StaticFiles  # noqa: PLC0415  (optional path)

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# v0.13: cap the in-memory run store. The web UI is single-user, but a
# tester running for hours used to OOM the process — `_RUNS` grew without
# bound. We keep the most-recent N runs and evict in insertion order.
from collections import OrderedDict  # noqa: E402

_RUNS_MAX = 32
_RUNS: OrderedDict[str, dict] = OrderedDict()


def _store_run(run_id: str, payload: dict) -> None:
    """Insert a run, evicting the oldest if we exceed the cap.

    v0.18.11: if `payload` contains a `model` but no `files`, render
    the default file set automatically (md, html, stix, navigator,
    csv, exec). Callers that need custom files can still pass them
    explicitly.
    """
    if "model" in payload and "files" not in payload:
        model = payload["model"]
        from .reporting.compliance_matrix import (  # noqa: PLC0415
            render_compliance_matrix_csv,
            render_compliance_matrix_html,
        )
        from .reporting.csa_risk_register import (  # noqa: PLC0415
            render_csa_risk_register_csv,
            render_csa_risk_register_html,
        )
        from .reporting.csa_table import (  # noqa: PLC0415
            render_csa_table_csv,
            render_csa_table_html,
        )
        from .reporting.exec_summary import render_exec_summary  # noqa: PLC0415
        from .reporting.jira_export import render_jira_csv, render_jira_json  # noqa: PLC0415
        from .reporting.roadmap_export import render_roadmap_json, render_roadmap_md  # noqa: PLC0415
        from .reporting.sbom_export import render_sbom_cdx  # noqa: PLC0415
        payload = dict(payload)
        payload["files"] = {
            "md": render_markdown(model),
            "html": render_html(model),
            "stix": render_stix(model),
            "navigator": render_navigator(model),
            "csv": write_csv(model, "risk_register"),
            "exec": render_exec_summary(model),
            "compliance": render_compliance_matrix_html(model),
            "compliance_csv": render_compliance_matrix_csv(model),
            "jira_csv": render_jira_csv(model),
            "jira_json": render_jira_json(model),
            "roadmap_md": render_roadmap_md(model),
            "roadmap_json": render_roadmap_json(model),
            "sbom": render_sbom_cdx(model),
            "csa_table": render_csa_table_html(model),
            "csa_table_csv": render_csa_table_csv(model),
            "csa_risk": render_csa_risk_register_html(model),
            "csa_risk_csv": render_csa_risk_register_csv(model),
        }
    elif "model" in payload and "files" in payload:
        # Older call sites pass an explicit files dict but didn't know
        # about exec / compliance / jira. Splice them in.
        if "exec" not in payload["files"]:
            from .reporting.exec_summary import render_exec_summary  # noqa: PLC0415
            payload["files"]["exec"] = render_exec_summary(payload["model"])
        if "compliance" not in payload["files"]:
            from .reporting.compliance_matrix import (  # noqa: PLC0415
                render_compliance_matrix_csv,
                render_compliance_matrix_html,
            )
            payload["files"]["compliance"] = render_compliance_matrix_html(payload["model"])
            payload["files"]["compliance_csv"] = render_compliance_matrix_csv(payload["model"])
        if "jira_csv" not in payload["files"]:
            from .reporting.jira_export import render_jira_csv, render_jira_json  # noqa: PLC0415
            payload["files"]["jira_csv"] = render_jira_csv(payload["model"])
            payload["files"]["jira_json"] = render_jira_json(payload["model"])
        if "roadmap_md" not in payload["files"]:
            from .reporting.roadmap_export import render_roadmap_json, render_roadmap_md  # noqa: PLC0415
            payload["files"]["roadmap_md"] = render_roadmap_md(payload["model"])
            payload["files"]["roadmap_json"] = render_roadmap_json(payload["model"])
        if "sbom" not in payload["files"]:
            from .reporting.sbom_export import render_sbom_cdx  # noqa: PLC0415
            payload["files"]["sbom"] = render_sbom_cdx(payload["model"])
        if "csa_table" not in payload["files"]:
            from .reporting.csa_table import (  # noqa: PLC0415
                render_csa_table_csv,
                render_csa_table_html,
            )
            payload["files"]["csa_table"] = render_csa_table_html(payload["model"])
            payload["files"]["csa_table_csv"] = render_csa_table_csv(payload["model"])
        if "csa_risk" not in payload["files"]:
            from .reporting.csa_risk_register import (  # noqa: PLC0415
                render_csa_risk_register_csv,
                render_csa_risk_register_html,
            )
            payload["files"]["csa_risk"] = render_csa_risk_register_html(payload["model"])
            payload["files"]["csa_risk_csv"] = render_csa_risk_register_csv(payload["model"])
    _RUNS[run_id] = payload
    while len(_RUNS) > _RUNS_MAX:
        _RUNS.popitem(last=False)


def _ctx(request: Request, **extra) -> dict:
    return {"request": request, "version": __version__, "active": "", **extra}


def _render(template_name: str, context: dict, status_code: int = 200):
    request = context.pop("request")
    return templates.TemplateResponse(request=request, name=template_name, context=context, status_code=status_code)


def _system_to_yaml(system: System) -> str:
    """Dump a System back to YAML, dropping empty/default fields so the
    output is friendly to hand-edit. Pydantic's `exclude_defaults` does
    most of the work; we also drop a few fields that default to empty
    lists/dicts (which `exclude_defaults` keeps when re-loaded into the
    model with the explicit empty value)."""
    data = system.model_dump(exclude_defaults=True, exclude_none=True)
    # `exclude_defaults` doesn't strip fields whose value happens to
    # equal the declared default after construction — clean those up.
    def _prune(d):
        if isinstance(d, dict):
            return {k: _prune(v) for k, v in d.items()
                    if v not in (None, "", [], {})}
        if isinstance(d, list):
            return [_prune(x) for x in d]
        return d
    data = _prune(data)
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=100)


@app.get("/", response_class=HTMLResponse)
def home(request: Request, sample: str | None = None) -> HTMLResponse:
    yaml_text = ""
    error = None
    if sample:
        # Defence in depth: only allow plain filenames inside the samples dir.
        safe_name = Path(sample).name
        candidate = _SAMPLES_DIR / safe_name
        if (
            safe_name == sample  # rejects "../../foo" since Path.name == "foo"
            and candidate.exists()
            and candidate.is_file()
            and candidate.resolve().parent == _SAMPLES_DIR.resolve()
        ):
            yaml_text = candidate.read_text(encoding="utf-8")
        else:
            error = "Sample not found."
    return _render("web/index.html", _ctx(request, active="home", yaml_text=yaml_text, error=error))


# Hard cap on diagram upload size (defence in depth — also enforced by reverse proxy)
MAX_DIAGRAM_SIZE = 10 * 1024 * 1024  # 10 MB
# v0.16.9 (Bug-007): cap the /analyze YAML body. A 50MB blob was previously
# accepted and tied up the worker for ~28s; legit System YAMLs are < 100 KB.
MAX_ANALYZE_YAML_SIZE = 2 * 1024 * 1024  # 2 MB
ALLOWED_DIAGRAM_EXTS = {".vsdx", ".drawio", ".xml", ".mmd", ".mermaid", ".md"}  # v0.18.1: mermaid added


@app.post("/ingest", response_class=HTMLResponse)
async def ingest_diagram(
    request: Request,
    diagram: UploadFile = File(...),
    auto_analyze: bool = Form(False),
) -> HTMLResponse:
    """Accept a diagram upload, parse to System YAML.

    Default behaviour (v0.6+): renders the analyze page with the
    parsed YAML pre-populated so the user can review/edit before
    clicking Analyze.

    v0.18.2 Cycle Q: when `auto_analyze=true` is in the form payload,
    skip the review step entirely — run analyze() on the parsed
    System and render the full report directly. Matches the
    IriusRisk-style "upload → comprehensive threat model" UX the
    user asked for. Pure-IT systems auto-detect and run in
    --allow-pure-it mode."""
    from .ingest.vsdx import vsdx_to_system

    filename = (diagram.filename or "").strip()
    suffix = Path(filename).suffix.lower()
    if suffix == ".vsd":
        return _render(
            "web/index.html",
            _ctx(request, active="home", yaml_text="",
                 error="Legacy .vsd is not supported. Open in Visio (or LibreOffice Draw) and "
                       "'Save As' .vsdx, then retry."),
            status_code=400,
        )
    if suffix not in ALLOWED_DIAGRAM_EXTS_ALL:
        return _render(
            "web/index.html",
            _ctx(request, active="home", yaml_text="",
                 error=f"Unsupported diagram format: {suffix or '(none)'}. "
                       "Expected .vsdx, .png, .jpg, .jpeg or .webp."),
            status_code=400,
        )

    # Stream into a temp file with size cap (preserve uploaded extension so the
    # downstream parser can sniff format).
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        total = 0
        while chunk := await diagram.read(64 * 1024):
            total += len(chunk)
            if total > MAX_DIAGRAM_SIZE:
                tmp.close()
                tmp_path.unlink(missing_ok=True)
                return _render(
                    "web/index.html",
                    _ctx(request, active="home", yaml_text="",
                         error=f"File too large (>{MAX_DIAGRAM_SIZE // (1024*1024)} MB)."),
                    status_code=413,
                )
            tmp.write(chunk)

    others: list = []
    vague: list = []
    try:
        pretty_name = Path(filename).stem.replace("_", " ").replace("-", " ").title() or "Imported System"
        if suffix in ALLOWED_IMAGE_EXTS:
            # PNG / JPEG / WebP — use the opt-in vision module (requires
            # ANTHROPIC_API_KEY + `anthropic` package). Returns YAML text;
            # we validate it before showing the editor.
            try:
                from .vision.analyzer import diagram_to_system_yaml  # noqa: PLC0415
                yaml_text = diagram_to_system_yaml(tmp_path)
                # Validate the YAML to catch malformed model output early.
                raw = yaml.safe_load(yaml_text)
                if not isinstance(raw, dict) or "components" not in raw:
                    raise ValueError("vision output did not include a `components` list")
                system = System.model_validate(raw)
            except RuntimeError as e:
                tmp_path.unlink(missing_ok=True)
                return _render(
                    "web/index.html",
                    _ctx(request, active="home", yaml_text="",
                         error=(f"Image ingestion is opt-in. {e} "
                                "Either install ATMS with the [vision] extra and set "
                                "ANTHROPIC_API_KEY, or describe the system in YAML manually.")),
                    status_code=400,
                )
            notice = (
                f"Parsed image {filename}: {len(system.components)} components, "
                f"{len(system.dataflows)} dataflows. Review and edit before analysing."
            )
        elif suffix in (".drawio", ".xml"):
            # v0.17.4 Cycle N: draw.io / diagrams.net XML upload.
            from .ingest.drawio import (  # noqa: PLC0415
                classification_summary,
                drawio_to_system,
            )
            from .ingest.vsdx import vague_dataflows  # noqa: PLC0415
            system = drawio_to_system(tmp_path, system_name=pretty_name)
            vague = vague_dataflows(system)
            cls_sum = classification_summary(system)
            notice = (
                f"Parsed {filename}: {len(system.components)} components, "
                f"{len(system.dataflows)} dataflows, "
                f"{len(system.trust_boundaries)} trust boundaries. "
                f"Classification: {cls_sum['style']} via stencil style, "
                f"{cls_sum['label']} via label, "
                f"{cls_sum['fallback']} fallback. Review before analysing."
            )
        elif suffix in (".mmd", ".mermaid", ".md"):
            # v0.18.1 Cycle P: Mermaid flowchart upload. .md is also
            # accepted — first ```mermaid block in the file is extracted.
            from .ingest.mermaid import mermaid_to_system  # noqa: PLC0415
            from .ingest.vsdx import vague_dataflows  # noqa: PLC0415
            system = mermaid_to_system(tmp_path, system_name=pretty_name)
            vague = vague_dataflows(system)
            if not system.components:
                tmp_path.unlink(missing_ok=True)
                return _render(
                    "web/index.html",
                    _ctx(request, active="home", yaml_text="",
                         error=(f"No mermaid flowchart found in {filename}. "
                                "Expected a `flowchart` or `graph` block.")),
                    status_code=400,
                )
            notice = (
                f"Parsed {filename}: {len(system.components)} components, "
                f"{len(system.dataflows)} dataflows, "
                f"{len(system.trust_boundaries)} trust boundaries "
                f"inferred from subgraphs. Review before analysing."
            )
        else:
            system = vsdx_to_system(tmp_path, system_name=pretty_name)
            from .ingest.vsdx import vague_dataflows  # noqa: PLC0415
            vague = vague_dataflows(system)
            notice = (
                f"Parsed {filename}: {len(system.components)} components, "
                f"{len(system.dataflows)} dataflows."
            )
    except Exception as e:  # noqa: BLE001
        tmp_path.unlink(missing_ok=True)
        return _render(
            "web/index.html",
            _ctx(request, active="home", yaml_text="",
                 error=f"Could not parse diagram: {e}"),
            status_code=400,
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    yaml_text = _system_to_yaml(system)
    others = [c for c in system.components if c.type == "other"]

    # v0.18.2 Cycle Q: optional auto-analyze. Skip the review step
    # and render the full threat report directly. Closes the user's
    # "upload → comprehensive threat model" UX request.
    if auto_analyze:
        from .engines.ai_scope import find_ai_components  # noqa: PLC0415
        has_ai = bool(find_ai_components(system))
        try:
            model = run_analysis(system, require_ai_components=has_ai)
        except ValueError as e:
            # Pure-IT detection should normally avoid this; surface
            # any other validation issue gracefully.
            return _render(
                "web/index.html",
                _ctx(request, active="home", yaml_text=yaml_text,
                     notice=notice, error=str(e),
                     needs_review=others, vague_flows=vague),
                status_code=400,
            )
        run_id = uuid.uuid4().hex[:12]
        _store_run(run_id, {
            "model": model,
            "files": {
                "md": render_markdown(model),
                "html": render_html(model),
                "stix": render_stix(model),
                "navigator": render_navigator(model),
                "csv": write_csv(model, "risk_register"),
            },
        })
        scope_note = (
            " (general-purpose mode — no AI components detected)"
            if not has_ai else ""
        )
        return _render(
            "web/report.html",
            _ctx(
                request, active="home",
                run_id=run_id,
                system=model.system,
                threats=model.threats,
                attack_paths=model.attack_paths,
                mitigations=model.mitigations,
                summary=model.summary,
                mermaid_dfd=render_mermaid(model.system),
                notice=f"{notice}{scope_note}" if notice else f"Auto-analysed{scope_note}.",
            ),
        )

    return _render(
        "web/index.html",
        _ctx(
            request,
            active="home",
            yaml_text=yaml_text,
            notice=notice,
            error=None,
            needs_review=others,
            vague_flows=vague,
        ),
    )


@app.post("/analyze", response_class=HTMLResponse)
def analyze(
    request: Request,
    yaml: str = Form(...),
    methodology: str = Form("stride-ai"),
) -> HTMLResponse:
    # v0.16.9 (Bug-007): bound the YAML body before parsing. Legit System
    # YAMLs are < 100 KB; >2 MB is almost certainly a DoS / mistake.
    if len(yaml) > MAX_ANALYZE_YAML_SIZE:
        raise HTTPException(
            413,
            f"YAML body too large ({len(yaml) // 1024} KB); "
            f"max {MAX_ANALYZE_YAML_SIZE // 1024} KB.",
        )

    notice = None
    try:
        # alias-free loader: bans YAML anchors/aliases so an alias-expansion
        # 'billion laughs' payload can't OOM the server (audit F051).
        raw = _safe_load_system_yaml(yaml)
        # v0.14.9: best-effort autocorrect common authoring mistakes
        # (mostly free-text component types like "IoT Device") so we
        # don't bounce the user out of the analyse flow for typos. We
        # surface what we changed via a notice banner so the user can
        # decide whether to accept or fix the YAML.
        raw, corrections = _autocorrect_system_yaml(raw)
        system = System.model_validate(raw)
        if corrections:
            notice = (
                "Auto-corrected " + str(len(corrections)) + " value(s) before analysis: "
                + "; ".join(corrections[:5])
                + (" ..." if len(corrections) > 5 else "")
            )
    except Exception as e:  # noqa: BLE001
        return _render(
            "web/index.html",
            _ctx(request, active="home", yaml_text=yaml,
                 error=_format_validation_error(e, raw if 'raw' in dir() else None)),
            status_code=400,
        )

    try:
        model = run_analysis(system, methodology=methodology)
    except ValueError as e:
        return _render(
            "web/index.html",
            _ctx(request, active="home", yaml_text=yaml, error=str(e)),
            status_code=400,
        )
    run_id = uuid.uuid4().hex[:12]
    _store_run(run_id, {
        "model": model,
        "files": {
            "md": render_markdown(model),
            "html": render_html(model),
            "stix": render_stix(model),
            "navigator": render_navigator(model),
            "csv": write_csv(model, "risk_register"),
        },
    })

    return _render(
        "web/report.html",
        _ctx(
            request,
            active="home",
            run_id=run_id,
            system=model.system,
            threats=model.threats,
            attack_paths=model.attack_paths,
            mitigations=model.mitigations,
            summary=model.summary,
            mermaid_dfd=render_mermaid(model.system),
            notice=notice,
        ),
    )


# ─── GUI editor (v0.10) ────────────────────────────────────────────────
@app.get("/editor", response_class=HTMLResponse)
def editor(request: Request) -> HTMLResponse:
    """Drag-and-drop system editor — assemble a System on a canvas."""
    return _render("web/editor.html", _ctx(request, active="editor"))


@app.post("/editor/save")
async def editor_save(request: Request) -> Response:
    """Convert the editor's JSON payload into a YAML file the user can download.

    Validates against `System` so we never hand back malformed YAML.
    """
    # v0.16.9 (Bug-002): wrap json() in try/except. Empty / malformed
    # bodies previously surfaced as 500 Internal Server Error; now 400.
    try:
        payload = await request.json()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"Request body is not valid JSON: {e}") from e
    if not isinstance(payload, dict):
        raise HTTPException(400, "Request body must be a JSON object describing a System.")
    try:
        system = System.model_validate(payload)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"Invalid system: {e}") from e
    yaml_text = _system_to_yaml(system)
    safe = (system.name or "system").lower().replace(" ", "_")[:40]
    # v1.0.2 Bug-fix: ASCII-safe Content-Disposition (see download()).
    safe = safe.encode("ascii", "ignore").decode("ascii").strip("_") or "system"
    return Response(
        content=yaml_text,
        media_type="text/yaml; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{safe}.yaml"'},
    )


@app.post("/editor/analyze", response_class=HTMLResponse)
def editor_analyze(
    request: Request,
    system_json: str = Form(...),
    methodology: str = Form("stride-ai"),
) -> HTMLResponse:
    """Receive the editor's JSON payload, validate, analyse, render the report."""
    import json

    try:
        payload = json.loads(system_json)
        # v0.14.9: same autocorrect path as /analyze, in case the editor
        # somehow lets a free-text type sneak through.
        payload, _corrections = _autocorrect_system_yaml(payload)
        system = System.model_validate(payload)
    except Exception as e:  # noqa: BLE001
        return _render(
            "web/editor.html",
            _ctx(request, active="editor",
                 error=_format_validation_error(e, payload if 'payload' in dir() else None)),
            status_code=400,
        )
    try:
        model = run_analysis(system, methodology=methodology)
    except ValueError as e:
        return _render(
            "web/editor.html",
            _ctx(request, active="editor", error=str(e)),
            status_code=400,
        )
    run_id = uuid.uuid4().hex[:12]
    _store_run(run_id, {
        "model": model,
        "files": {
            "md": render_markdown(model),
            "html": render_html(model),
            "stix": render_stix(model),
            "navigator": render_navigator(model),
            "csv": write_csv(model, "risk_register"),
        },
    })
    return _render(
        "web/report.html",
        _ctx(
            request,
            active="editor",
            run_id=run_id,
            system=model.system,
            threats=model.threats,
            attack_paths=model.attack_paths,
            mitigations=model.mitigations,
            summary=model.summary,
            mermaid_dfd=render_mermaid(model.system),
        ),
    )


_FMT_FEATURE_MAP: dict[str, str] = {
    # v0.18.70 Hibernation Phase 3: each fmt = the FEATURE_EXPORT_* flag
    # that gates it. md/html/exec are KEEP (default report). Everything
    # else hibernates by default.
    "md": "report_md",
    "html": "report_html",
    "exec": "report_html",                  # exec summary is rendered HTML
    "stix": "export_stix",
    "navigator": "export_navigator",
    "csv": "export_csv",
    "compliance": "export_compliance_matrix",
    "compliance_csv": "export_compliance_matrix",
    "jira_csv": "export_jira",
    "jira_json": "export_jira",
    "roadmap_md": "export_roadmap",
    "roadmap_json": "export_roadmap",
    "sbom": "export_sbom",
    "csa_table": "export_csa_table",
    "csa_table_csv": "export_csa_table",
    "csa_risk": "export_csa_risk",
    "csa_risk_csv": "export_csa_risk",
}


@app.get("/download/{run_id}/{fmt}")
def download(run_id: str, fmt: str) -> Response:
    # v0.18.70 Hibernation Phase 3: gate fmt by FEATURE_EXPORT_* flag.
    # Hibernated formats return 404 with the canonical re-enable hint.
    required = _FMT_FEATURE_MAP.get(fmt)
    if required and not _features.is_enabled(required):
        raise HTTPException(
            status_code=404,
            detail=(
                f"Export format '{fmt}' is hibernated. "
                f"Set ATMS_FEATURE_{required.upper()}=1 to enable."
            ),
        )
    run = _RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    files = run["files"]
    if fmt not in files:
        raise HTTPException(404, "format not found")
    content = files[fmt]
    media_types = {
        "md": "text/markdown; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "stix": "application/json; charset=utf-8",
        "navigator": "application/json; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
        "exec": "text/html; charset=utf-8",                # v0.18.11
        "compliance": "text/html; charset=utf-8",          # v0.18.16
        "compliance_csv": "text/csv; charset=utf-8",       # v0.18.16
        "jira_csv": "text/csv; charset=utf-8",             # v0.18.17
        "jira_json": "application/json; charset=utf-8",    # v0.18.17
        "roadmap_md": "text/markdown; charset=utf-8",      # v0.18.23
        "roadmap_json": "application/json; charset=utf-8", # v0.18.23
        "sbom": "application/json; charset=utf-8",         # v0.18.29
        "csa_table": "text/html; charset=utf-8",           # v1.0.3 CSA Table of Attack
        "csa_table_csv": "text/csv; charset=utf-8",        # v1.0.3
        "csa_risk": "text/html; charset=utf-8",            # v1.0.6 CSA Risk Register
        "csa_risk_csv": "text/csv; charset=utf-8",         # v1.0.6
    }
    ext = {"md": "md", "html": "html", "stix": "stix.json",
           "navigator": "navigator.json", "csv": "csv",
           "exec": "exec.html",
           "compliance": "compliance.html",
           "compliance_csv": "compliance.csv",
           "jira_csv": "jira.csv",
           "jira_json": "jira.json",
           "roadmap_md": "roadmap.md",
           "roadmap_json": "roadmap.json",
           "sbom": "sbom.cdx.json",
           "csa_table": "csa-table-of-attack.html",
           "csa_table_csv": "csa-table-of-attack.csv",
           "csa_risk": "csa-risk-register.html",
           "csa_risk_csv": "csa-risk-register.csv"}[fmt]
    sysname = run["model"].system.name.lower().replace(" ", "_")[:40]
    # v1.0.2 Bug-fix: Content-Disposition values must be latin-1 encodable
    # (Starlette enforces RFC 7230). A system name with an em-dash / smart-
    # quote / accent (e.g. "RAG — Assistant") otherwise made EVERY export
    # 500 with UnicodeEncodeError. Collapse to an ASCII-safe slug; the
    # downloaded file's *content* is unchanged.
    sysname = sysname.encode("ascii", "ignore").decode("ascii").strip("_") or "report"
    return Response(
        content=content,
        media_type=media_types[fmt],
        headers={"Content-Disposition": f'attachment; filename="{sysname}.{ext}"'},
    )


@app.get("/samples", response_class=HTMLResponse)
def samples(request: Request) -> HTMLResponse:
    samples_list = []
    for path in sorted(_SAMPLES_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            samples_list.append(
                {
                    "name": data.get("name", path.stem),
                    "file": path.name,
                    "component_count": len(data.get("components", [])),
                    "description": data.get("description", "").strip(),
                }
            )
        except Exception:  # noqa: BLE001
            samples_list.append(
                {"name": path.stem, "file": path.name, "component_count": 0, "description": "(parse error)"}
            )
    return _render("web/samples.html", _ctx(request, active="samples", samples=samples_list))


@app.get("/kb", response_class=HTMLResponse)
def kb(request: Request, q: str = "", framework: str = "all") -> HTMLResponse:
    kb_obj = get_kb()
    fw = None if framework == "all" else framework
    results = kb_obj.search(q, framework=fw, limit=25) if q else []
    counts = {
        "owasp": len(kb_obj.owasp_llm),
        "owasp_agentic": len(kb_obj.owasp_agentic),
        "owasp_api": len(kb_obj.owasp_api),
        "atlas_tactics": len(kb_obj.atlas_tactics),
        "atlas_techniques": len(kb_obj.atlas_techniques),
        "atlas_mitigations": len(kb_obj.atlas_mitigations),
        "attack_cloud": len(kb_obj.attack_cloud),
        "attack_enterprise": len(kb_obj.attack_enterprise),
        "linddun": len(kb_obj.linddun),
        "nist_ai_100_2": len(kb_obj.nist_ai_100_2),
        "owasp_ml": len(kb_obj.owasp_ml),
        "compliance_controls": len(kb_obj.compliance_controls),
        "devices": len(kb_obj.devices),
        "kev": len(kb_obj.kev_cves),
        "kev_meta": kb_obj.kev_meta or {},
        "epss": len(kb_obj.epss_scores),
        "epss_meta": kb_obj.epss_meta or {},
        "maestro_layers": len(kb_obj.maestro_layers),
        "maestro_threats": len(kb_obj.maestro_threats),
        "nist": len(kb_obj.nist_ai_rmf),
        "playbooks": len(kb_obj.playbooks),
    }
    return _render(
        "web/kb.html",
        _ctx(request, active="kb", q=q, framework=framework, results=results, counts=counts),
    )


@app.get("/playbooks", response_class=HTMLResponse)
def playbooks(request: Request) -> HTMLResponse:
    kb_obj = get_kb()
    return _render(
        "web/playbooks.html",
        _ctx(request, active="playbooks", playbooks=sorted(kb_obj.playbooks.items())),
    )


@app.get("/maestro", response_class=HTMLResponse)
def maestro(request: Request) -> HTMLResponse:
    kb_obj = get_kb()
    layers = sorted(kb_obj.maestro_layers.items())
    layer_titles = {lid: layer["name"] for lid, layer in kb_obj.maestro_layers.items()}
    layer_titles["cross"] = "Cross-layer threats"
    threats_by_layer: dict[str, list] = {}
    for t in kb_obj.maestro_threats.values():
        threats_by_layer.setdefault(t["layer"], []).append(t)
    # ordered: M.L1..M.L7 then cross
    order = list(kb_obj.maestro_layers.keys()) + ["cross"]
    threats_ordered = [(lid, threats_by_layer[lid]) for lid in order if lid in threats_by_layer]
    return _render(
        "web/maestro.html",
        _ctx(
            request,
            active="maestro",
            layers=layers,
            layer_titles=layer_titles,
            threats_by_layer=threats_ordered,
        ),
    )


@app.get("/agentic", response_class=HTMLResponse)
def agentic(request: Request) -> HTMLResponse:
    kb_obj = get_kb()
    threats = list(kb_obj.owasp_agentic.values())
    return _render("web/agentic.html", _ctx(request, active="agentic", threats=threats))


@app.get("/evidence", response_class=HTMLResponse)
def evidence_page(request: Request) -> HTMLResponse:
    """v0.12: drag-and-drop a Nessus / SARIF / STIX / CSV evidence file
    plus a System YAML and get a report enriched with the findings."""
    return _render("web/evidence.html", _ctx(request, active="evidence"))


# Cap for evidence uploads — same limit as diagram uploads.
MAX_EVIDENCE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EVIDENCE_EXTS = {".nessus", ".sarif", ".json", ".csv"}


@app.post("/evidence/ingest", response_class=HTMLResponse)
async def evidence_ingest(
    request: Request,
    evidence_file: UploadFile = File(...),
    yaml_text: str = Form(...),
    methodology: str = Form("stride-ai"),
) -> HTMLResponse:
    """Parse evidence file, validate system YAML, run pipeline with evidence applied."""
    import yaml as yaml_mod

    filename = (evidence_file.filename or "").strip()
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EVIDENCE_EXTS:
        return _render(
            "web/evidence.html",
            _ctx(request, active="evidence",
                 error=f"Unsupported evidence format: {suffix or '(none)'}. "
                       "Expected .nessus, .sarif, .json (STIX), or .csv."),
            status_code=400,
        )

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        total = 0
        while chunk := await evidence_file.read(64 * 1024):
            total += len(chunk)
            if total > MAX_EVIDENCE_SIZE:
                tmp.close()
                tmp_path.unlink(missing_ok=True)
                return _render(
                    "web/evidence.html",
                    _ctx(request, active="evidence",
                         error=f"File too large (>{MAX_EVIDENCE_SIZE // (1024*1024)} MB)."),
                    status_code=413,
                )
            tmp.write(chunk)

    try:
        from .evidence import parse_any  # noqa: PLC0415
        evidence_rows = parse_any(tmp_path)
    except Exception as e:  # noqa: BLE001
        tmp_path.unlink(missing_ok=True)
        return _render(
            "web/evidence.html",
            _ctx(request, active="evidence",
                 error=f"Could not parse evidence file: {e}"),
            status_code=400,
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    try:
        raw = yaml_mod.safe_load(yaml_text)
        system = System.model_validate(raw)
    except Exception as e:  # noqa: BLE001
        return _render(
            "web/evidence.html",
            _ctx(request, active="evidence",
                 error=f"Could not parse system YAML: {e}"),
            status_code=400,
        )

    try:
        model = run_analysis(system, methodology=methodology, evidence=evidence_rows)
    except ValueError as e:
        return _render(
            "web/evidence.html",
            _ctx(request, active="evidence", error=str(e)),
            status_code=400,
        )
    run_id = uuid.uuid4().hex[:12]
    _store_run(run_id, {
        "model": model,
        "files": {
            "md": render_markdown(model),
            "html": render_html(model),
            "stix": render_stix(model),
            "navigator": render_navigator(model),
            "csv": write_csv(model, "risk_register"),
        },
    })
    return _render(
        "web/report.html",
        _ctx(request, active="evidence",
             run_id=run_id,
             system=model.system,
             threats=model.threats,
             attack_paths=model.attack_paths,
             mitigations=model.mitigations,
             summary=model.summary,
             mermaid_dfd=render_mermaid(model.system)),
    )


ALLOWED_REDTEAM_EXTS = {".json", ".jsonl", ".csv"}
ALLOWED_IAC_EXTS = {".tf", ".yml", ".yaml"}


@app.get("/redteam", response_class=HTMLResponse)
def redteam_page(request: Request) -> HTMLResponse:
    """v0.14: drag-and-drop a Caldera / Atomic Red Team / BAS CSV artefact
    plus a System YAML; matched TTPs flip to status=exploited."""
    return _render("web/redteam.html", _ctx(request, active="redteam"))


_METHODOLOGY_ALLOWLIST = {"stride-ai", "linddun", "pasta"}


@app.post("/redteam/ingest", response_class=HTMLResponse)
async def redteam_ingest(
    request: Request,
    # v0.14.4: file optional at the FastAPI layer so a missing upload
    # returns the same friendly HTML page (with a clear error banner)
    # as a bad methodology — instead of FastAPI's default 422 JSON
    # which is jarring when a user is in a browser form.
    artefact_file: UploadFile | None = File(None),
    yaml_text: str = Form(...),
    methodology: str = Form("stride-ai"),
) -> HTMLResponse:
    if artefact_file is None or not (artefact_file.filename or "").strip():
        return _render(
            "web/redteam.html",
            _ctx(request, active="redteam",
                 error="Please attach a red-team artefact file (.json / .jsonl / .csv)."),
            status_code=400,
        )
    import yaml as yaml_mod
    if methodology not in _METHODOLOGY_ALLOWLIST:
        return _render(
            "web/redteam.html",
            _ctx(request, active="redteam",
                 error=f"Unsupported methodology: {methodology!r}. "
                       f"Choose one of {sorted(_METHODOLOGY_ALLOWLIST)}."),
            status_code=400,
        )
    filename = (artefact_file.filename or "").strip()
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_REDTEAM_EXTS:
        return _render(
            "web/redteam.html",
            _ctx(request, active="redteam",
                 error=f"Unsupported red-team artefact: {suffix or '(none)'}. "
                       "Expected .json, .jsonl or .csv."),
            status_code=400,
        )
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        total = 0
        while chunk := await artefact_file.read(64 * 1024):
            total += len(chunk)
            if total > MAX_EVIDENCE_SIZE:
                tmp.close()
                tmp_path.unlink(missing_ok=True)
                return _render("web/redteam.html",
                               _ctx(request, active="redteam",
                                    error=f"File too large (>{MAX_EVIDENCE_SIZE // (1024*1024)} MB)."),
                               status_code=413)
            tmp.write(chunk)
    try:
        from .evidence.redteam import parse_redteam  # noqa: PLC0415
        rows = parse_redteam(tmp_path)
    except Exception as e:  # noqa: BLE001
        tmp_path.unlink(missing_ok=True)
        return _render("web/redteam.html",
                       _ctx(request, active="redteam",
                            error=f"Could not parse red-team artefact: {e}"),
                       status_code=400)
    finally:
        tmp_path.unlink(missing_ok=True)
    try:
        raw = yaml_mod.safe_load(yaml_text)
        system = System.model_validate(raw)
    except Exception as e:  # noqa: BLE001
        return _render("web/redteam.html",
                       _ctx(request, active="redteam",
                            error=f"Could not parse system YAML: {e}"),
                       status_code=400)
    try:
        model = run_analysis(system, methodology=methodology, evidence=rows)
    except ValueError as e:
        return _render("web/redteam.html",
                       _ctx(request, active="redteam", error=str(e)),
                       status_code=400)
    run_id = uuid.uuid4().hex[:12]
    _store_run(run_id, {
        "model": model,
        "files": {
            "md": render_markdown(model), "html": render_html(model),
            "stix": render_stix(model), "navigator": render_navigator(model),
            "csv": write_csv(model, "risk_register"),
        },
    })
    return _render("web/report.html",
                   _ctx(request, active="redteam",
                        run_id=run_id, system=model.system,
                        threats=model.threats, attack_paths=model.attack_paths,
                        mitigations=model.mitigations, summary=model.summary,
                        mermaid_dfd=render_mermaid(model.system)))


@app.get("/iac", response_class=HTMLResponse)
def iac_page(request: Request) -> HTMLResponse:
    """v0.14: upload a docker-compose YAML or Terraform .tf to draft a System."""
    return _render("web/iac.html", _ctx(request, active="iac"))


@app.post("/iac/ingest", response_class=HTMLResponse)
async def iac_ingest(
    request: Request,
    iac_file: UploadFile = File(...),
) -> HTMLResponse:
    filename = (iac_file.filename or "").strip()
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_IAC_EXTS:
        return _render("web/iac.html",
                       _ctx(request, active="iac",
                            error=f"Unsupported IaC format: {suffix or '(none)'}. "
                                  "Expected .tf, .yml, or .yaml."),
                       status_code=400)
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        total = 0
        while chunk := await iac_file.read(64 * 1024):
            total += len(chunk)
            if total > MAX_EVIDENCE_SIZE:
                tmp.close(); tmp_path.unlink(missing_ok=True)
                return _render("web/iac.html",
                               _ctx(request, active="iac",
                                    error=f"File too large (>{MAX_EVIDENCE_SIZE // (1024*1024)} MB)."),
                               status_code=413)
            tmp.write(chunk)
    try:
        from .ingest.docker_compose import parse_docker_compose  # noqa: PLC0415
        from .ingest.terraform import parse_terraform  # noqa: PLC0415
        if suffix == ".tf":
            system = parse_terraform(tmp_path)
        else:
            system = parse_docker_compose(tmp_path)
    except Exception as e:  # noqa: BLE001
        tmp_path.unlink(missing_ok=True)
        return _render("web/iac.html",
                       _ctx(request, active="iac",
                            error=f"Could not parse IaC: {e}"),
                       status_code=400)
    finally:
        tmp_path.unlink(missing_ok=True)
    yaml_out = _system_to_yaml(system)
    notice = (f"Parsed {filename}: {len(system.components)} components, "
              f"{len(system.dataflows)} dataflows. Review and edit before analysing.")
    return _render(
        "web/index.html",
        _ctx(request, active="home", yaml_text=yaml_out, notice=notice, error=None,
             needs_review=[c for c in system.components if c.type == "other"]),
    )


@app.get("/compliance", response_class=HTMLResponse)
def compliance(request: Request, q: str = "", framework: str = "all") -> HTMLResponse:
    """Browse the bundled compliance-control library (v0.13)."""
    kb_obj = get_kb()
    rows = list(kb_obj.compliance_controls.values())
    if framework != "all":
        rows = [r for r in rows if r.get("framework", "").lower() == framework.lower()]
    if q:
        ql = q.lower()
        rows = [r for r in rows
                if ql in str(r.get("title", "")).lower()
                or ql in str(r.get("description", "")).lower()
                or ql in str(r.get("id", "")).lower()]
    frameworks = sorted({r.get("framework", "") for r in kb_obj.compliance_controls.values()
                         if r.get("framework")})
    return _render(
        "web/compliance.html",
        _ctx(request, active="compliance",
             rows=rows, q=q, framework=framework,
             frameworks=frameworks, total=len(kb_obj.compliance_controls)),
    )


@app.post("/api/v1/analyze")
def api_analyze(payload: dict) -> dict:
    """Programmatic analyse endpoint for CI/CD pipelines (v0.18.21 Cycle KK).

    POST JSON body:
        {
          "yaml": "<System YAML text>",
          "methodology": "stride-ai" | "linddun" | "pasta",  # optional, default stride-ai
          "allow_pure_it": true,                              # optional, default true
          "include_compliance_matrix": false,                 # optional, default false
          "include_jira_payload": false                       # optional, default false
        }

    Returns:
        {
          "ok": true,
          "version": "0.18.21",
          "model": { …ThreatModel.model_dump()… },
          "summary": { components, threats, attack_paths, mitigations,
                       severity_breakdown, owasp_coverage, … },
          "compliance_matrix": [...]   # if include_compliance_matrix
          "jira": [...]                # if include_jira_payload
        }

    Errors:
        400 — missing `yaml`, invalid YAML, or invalid System schema
        500 — internal error (rare; covered by suite)
    """
    yaml_text = payload.get("yaml")
    if not isinstance(yaml_text, str) or not yaml_text.strip():
        raise HTTPException(400, "missing or empty `yaml` in body")
    methodology = payload.get("methodology", "stride-ai")
    if methodology not in _METHODOLOGY_ALLOWLIST:
        raise HTTPException(
            400, f"unsupported methodology {methodology!r}; "
                 f"allowed: {sorted(_METHODOLOGY_ALLOWLIST)}"
        )
    allow_pure_it = bool(payload.get("allow_pure_it", True))
    include_matrix = bool(payload.get("include_compliance_matrix", False))
    include_jira = bool(payload.get("include_jira_payload", False))

    # Parse the System YAML.
    try:
        data = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as exc:
        raise HTTPException(400, f"YAML parse error: {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(400, "YAML root must be a mapping")
    try:
        system = System.model_validate(data)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"System schema validation: {exc}") from exc

    try:
        model = run_analysis(
            system, methodology=methodology,
            require_ai_components=not allow_pure_it,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"analysis failed: {exc}") from exc

    result: dict = {
        "ok": True,
        "version": __version__,
        "summary": dict(model.summary),
        "model": json.loads(model.model_dump_json()),
    }
    if include_matrix:
        from .reporting.compliance_matrix import compute_coverage  # noqa: PLC0415
        result["compliance_matrix"] = compute_coverage(model)
    if include_jira:
        from .reporting.jira_export import render_jira_json  # noqa: PLC0415
        # render_jira_json returns a JSON string; parse it once for JSON-native nesting.
        result["jira"] = json.loads(render_jira_json(model))
    return result


@app.get("/capabilities", response_class=HTMLResponse)
def capabilities(request: Request) -> HTMLResponse:
    """Single-page surface inventory (v0.18.31 Cycle UU).

    What can ATMS read? What can it emit? Which frameworks does it
    cover? People ask these questions on first contact; spelunking
    through the changelog isn't a great UX. This page enumerates
    everything live (from the running KB + arch-rule registry +
    web routes), so it never goes stale."""
    kb_obj = get_kb()
    from .engines.architectural_rules import ARCHITECTURAL_RULES  # noqa: PLC0415
    frameworks = sorted({
        c.get("framework", "")
        for c in (kb_obj.compliance_controls or {}).values()
        if c.get("framework")
    })
    return _render(
        "web/capabilities.html",
        _ctx(request, active="capabilities",
             frameworks=frameworks,
             playbooks_count=len(kb_obj.playbooks or {}),
             compliance_count=len(kb_obj.compliance_controls or {}),
             atlas_count=len(kb_obj.atlas_techniques or {}),
             owasp_llm_count=len(kb_obj.owasp_llm or {}),
             owasp_agentic_count=len(kb_obj.owasp_agentic or {}),
             owasp_api_count=len(kb_obj.owasp_api or {}),
             device_count=len(kb_obj.devices or []),
             arch_rules=ARCHITECTURAL_RULES),
    )


@app.get("/healthz")
def healthz() -> dict:
    """Liveness probe for load balancers / k8s deployments (v0.18.30 Cycle TT).

    Always returns 200 with a tiny payload. Confirms the FastAPI
    app is up, the version string loaded, and the KB is reachable.
    Suitable as a k8s `livenessProbe`/`readinessProbe` target.
    """
    return {"ok": True, "version": __version__}


@app.get("/api/v1/metrics")
def api_metrics() -> dict:
    """Operational metrics for monitoring (v0.18.30 Cycle TT).

    Reports the size of the in-memory run cache, the KB inventory
    counts (playbooks, compliance controls, vendor threats), the
    arch-rule registry size, and the supported-frameworks list.
    Useful for dashboards confirming the bundled KB hasn't drifted.
    """
    kb_obj = get_kb()
    from .engines.architectural_rules import ARCHITECTURAL_RULES  # noqa: PLC0415
    frameworks = sorted({
        c.get("framework", "")
        for c in (kb_obj.compliance_controls or {}).values()
        if c.get("framework")
    })
    return {
        "ok": True,
        "version": __version__,
        "runs_cached": len(_RUNS),
        "runs_capacity": _RUNS_MAX,
        "kb": {
            "playbooks": len(kb_obj.playbooks or {}),
            "compliance_controls": len(kb_obj.compliance_controls or {}),
            "compliance_frameworks": len(frameworks),
            "frameworks": frameworks,
            "atlas_techniques": len(kb_obj.atlas_techniques or {}),
            "owasp_llm": len(kb_obj.owasp_llm or {}),
            "owasp_agentic": len(kb_obj.owasp_agentic or {}),
            "owasp_api": len(kb_obj.owasp_api or {}),
            "device_catalog": len(kb_obj.devices or []),
        },
        "arch_rules": len(ARCHITECTURAL_RULES),
    }


@app.get("/attack-paths/{run_id}", response_class=HTMLResponse)
def attack_paths_view(request: Request, run_id: str) -> HTMLResponse:
    """Dedicated attack-path viewer (v0.18.27 Cycle QQ).

    The main /report page lists attack paths near the bottom as
    text. Reviewers asked for a focused, scrollable view where
    every path's full narrative is expanded and the kill-chain
    tactics are visualised as a flow. This route surfaces that.
    """
    run = _RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    model = run["model"]
    return _render(
        "web/attack_paths.html",
        _ctx(request, active="",
             system=model.system,
             run_id=run_id,
             attack_paths=sorted(
                 model.attack_paths,
                 key=lambda p: (p.business_impact, -p.estimated_difficulty),
                 reverse=True,
             ),
             threats={t.id: t for t in model.threats}),
    )


@app.post("/api/v1/scan")
async def api_scan(
    file: UploadFile = File(...),
    format: str = Form("auto"),
    methodology: str = Form("stride-ai"),
    allow_pure_it: str = Form("true"),
) -> dict:
    """Programmatic scan endpoint — ingest any of the 11 supported
    formats and return analysis JSON (v0.18.26 Cycle PP).

    Pairs with `/api/v1/analyze` (Cycle KK). Use this one when the
    caller has a non-YAML artefact (Bicep / Pulumi / draw.io /
    Mermaid / CFN / K8s manifest / docker-compose / Terraform /
    ARM JSON / OTM) instead of an ATMS System YAML.

    Form fields (multipart):
        file:        the uploaded diagram / IaC / manifest file
        format:      "auto" (default) | one of:
                       drawio, mermaid, vsdx, terraform, bicep,
                       arm, pulumi, cloudformation, kubernetes,
                       docker-compose, otm, system-yaml
        methodology: stride-ai | linddun | pasta (default stride-ai)
        allow_pure_it: "true"|"false" (default "true")

    Returns the same shape as `/api/v1/analyze` plus a
    `detected_format` field showing which ingester ran.
    """
    if methodology not in _METHODOLOGY_ALLOWLIST:
        raise HTTPException(400, f"unsupported methodology {methodology!r}")
    allow_pure_it_bool = allow_pure_it.lower() not in ("false", "0", "no")

    # Persist the upload to a temp file so the existing ingesters
    # (which take Paths) can read it. delete=False + manual cleanup
    # in the `finally` block below — ruff SIM115 silenced because
    # the file handle MUST outlive this scope to be re-opened by a
    # downstream parser.
    tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
        delete=False, suffix=Path(file.filename or "upload").suffix
    )
    try:
        content = await file.read()
        tmp.write(content)
        tmp.close()
        tmp_path = Path(tmp.name)
    except Exception as exc:
        raise HTTPException(400, f"file read failed: {exc}") from exc

    try:
        fmt = (format or "auto").lower()
        text = ""
        if tmp_path.suffix.lower() not in (".vsdx", ".png", ".jpg"):
            try:
                text = tmp_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = ""

        # Auto-detect when caller didn't specify.
        suffix = tmp_path.suffix.lower()
        if fmt == "auto":
            if suffix in (".drawio", ".xml"):
                fmt = "drawio"
            elif suffix in (".mmd", ".mermaid") or suffix == ".md":
                fmt = "mermaid"
            elif suffix == ".vsdx":
                fmt = "vsdx"
            elif suffix == ".tf":
                fmt = "terraform"
            elif suffix == ".bicep":
                fmt = "bicep"
            elif suffix == ".otm":
                fmt = "otm"
            elif suffix in (".yaml", ".yml", ".json"):
                sniff = text[:4000]
                if "AWSTemplateFormatVersion" in sniff or (
                    "AWS::" in sniff and "Resources:" in sniff
                ):
                    fmt = "cloudformation"
                elif "apiVersion:" in sniff and "kind:" in sniff:
                    fmt = "kubernetes"
                elif "otmVersion" in sniff:
                    fmt = "otm"
                elif "deploymentTemplate.json" in sniff or (
                    "$schema" in sniff and "Microsoft." in sniff
                ):
                    fmt = "arm"
                elif "runtime: yaml" in sniff or (
                    "resources:" in sniff
                    and any(t in sniff for t in ("aws:", "azure-native:",
                                                  "gcp:", "kubernetes:"))
                ):
                    fmt = "pulumi"
                elif (("services:" in sniff or '"services"' in sniff)
                      and "version:" in sniff and "name:" not in sniff[:200]):
                    fmt = "docker-compose"
                else:
                    fmt = "system-yaml"
            else:
                raise HTTPException(400, f"cannot auto-detect format for suffix {suffix!r}")

        # Dispatch.
        try:
            if fmt == "drawio":
                from .ingest.drawio import drawio_to_system
                system = drawio_to_system(tmp_path)
            elif fmt == "mermaid":
                from .ingest.mermaid import mermaid_to_system
                system = mermaid_to_system(tmp_path)
            elif fmt == "vsdx":
                from .ingest.vsdx import vsdx_to_system
                system = vsdx_to_system(tmp_path)
            elif fmt == "terraform":
                from .ingest.terraform import parse_terraform
                system = parse_terraform(tmp_path)
            elif fmt == "bicep" or fmt == "arm":
                from .ingest.azure_arm import azure_to_system_from_path
                system = azure_to_system_from_path(tmp_path)
            elif fmt == "pulumi":
                from .ingest.pulumi_yaml import pulumi_to_system
                system = pulumi_to_system(path=tmp_path)
            elif fmt == "cloudformation":
                from .ingest.cloudformation import cloudformation_to_system
                system = cloudformation_to_system(tmp_path)
            elif fmt == "kubernetes":
                from .ingest.kubernetes import kubernetes_to_system
                system = kubernetes_to_system(tmp_path)
            elif fmt == "docker-compose":
                from .ingest.docker_compose import parse_docker_compose
                system = parse_docker_compose(tmp_path)
            elif fmt == "otm":
                from .ingest.otm import parse_otm
                system = parse_otm(tmp_path)
            elif fmt == "system-yaml":
                data = yaml.safe_load(text or tmp_path.read_text(encoding="utf-8")) or {}
                system = System.model_validate(data)
            else:
                raise HTTPException(400, f"unsupported format {fmt!r}")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(400, f"ingest failed ({fmt}): {exc}") from exc

        try:
            model = run_analysis(
                system, methodology=methodology,
                require_ai_components=not allow_pure_it_bool,
            )
        except Exception as exc:
            raise HTTPException(500, f"analysis failed: {exc}") from exc

        return {
            "ok": True,
            "version": __version__,
            "detected_format": fmt,
            "summary": dict(model.summary),
            "model": json.loads(model.model_dump_json()),
        }
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


@app.get("/api/compliance")
def api_compliance(framework: str | None = None, q: str | None = None) -> dict:
    """JSON view used for CI / scripted access."""
    kb_obj = get_kb()
    rows = list(kb_obj.compliance_controls.values())
    if framework:
        rows = [r for r in rows if r.get("framework", "").lower() == framework.lower()]
    if q:
        ql = q.lower()
        rows = [r for r in rows
                if ql in str(r.get("title", "")).lower()
                or ql in str(r.get("description", "")).lower()]
    return {"count": len(rows), "controls": rows}


@app.get("/devices", response_class=HTMLResponse)
def devices(request: Request, q: str = "", category: str = "all") -> HTMLResponse:
    """Browse the bundled device & product catalog (v0.11)."""
    kb_obj = get_kb()
    devs = kb_obj.devices_for(category if category != "all" else None)
    if q:
        ql = q.lower()
        devs = [
            d for d in devs
            if ql in str(d.get("vendor", "")).lower()
            or ql in str(d.get("product", "")).lower()
            or ql in str(d.get("description", "")).lower()
            or any(ql in str(v).lower() for v in d.get("versions", []))
        ]
    categories = sorted({d.get("category", "other") for d in kb_obj.devices})
    return _render(
        "web/devices.html",
        _ctx(request, active="devices",
             devices=devs, q=q, category=category, categories=categories,
             total=len(kb_obj.devices)),
    )


@app.get("/api/devices")
def api_devices(category: str | None = None, q: str | None = None) -> dict:
    """JSON API used by the GUI editor's vendor/product/version picker."""
    kb_obj = get_kb()
    devs = kb_obj.devices_for(category)
    if q:
        ql = q.lower()
        devs = [
            d for d in devs
            if ql in str(d.get("vendor", "")).lower()
            or ql in str(d.get("product", "")).lower()
        ]
    return {"count": len(devs), "devices": devs}


@app.get("/docs", response_class=HTMLResponse)
def docs_index(request: Request) -> HTMLResponse:
    """v0.18.69 Hibernation Phase 2 — collapsed nav index.

    Replaces the eight reference nav items (Knowledge base, Playbooks,
    MAESTRO, OWASP Agentic, Methodology, Architecture, Capabilities,
    About) with a single Docs landing page. Cards link to the existing
    routes — same content, fewer top-level surfaces. The HIBERNATE
    nav surfaces (Evidence/Red-team/IaC/Compliance/Devices/Diff) are
    NOT linked from here; they need their feature flag flipped to
    surface at all.
    """
    return _render("web/docs.html", _ctx(request, active="docs"))


@app.get("/about", response_class=HTMLResponse)
def about(request: Request) -> HTMLResponse:
    # v0.16.10: surface the methodology-provenance table so reviewers can
    # see where each STRIDE-for-AI category comes from.
    kb = get_kb()
    # Order: classic STRIDE-LM first (in canonical sequence), then the
    # AI-native extensions. v1.0.4: any provenance category NOT named here
    # is appended (sorted) rather than silently dropped — so adding a
    # STRIDE category to the KB can never leave it un-rendered on /about
    # (the bug that hid Lateral_Movement when STRIDE-LM landed).
    order = [
        "Spoofing", "Tampering", "Repudiation",
        "Information_Disclosure", "Denial_of_Service", "Elevation_of_Privilege",
        "Lateral_Movement",
        "Defense_Evasion", "Bias_Fairness", "Emergent_Behavior",
    ]
    ordered = [c for c in order if c in kb.methodology_provenance]
    leftover = sorted(c for c in kb.methodology_provenance if c not in order)
    prov = [(cat, kb.methodology_provenance[cat]) for cat in ordered + leftover]
    return _render(
        "web/about.html",
        _ctx(request, active="about", methodology_provenance=prov),
    )


def _compute_diff(old_data: dict, new_data: dict) -> dict:
    """v0.17.3 Cycle G: helper shared by the /diff web route.

    Mirrors the CLI `atms diff` semantics: compares two saved
    ThreatModel JSON dicts by threat.id and returns the structured
    delta (added / removed / severity-changed / disposition-changed
    threats). Used by templates/web/diff.html to render the page.
    """
    def _index(doc: dict) -> dict[str, dict]:
        return {t["id"]: t for t in (doc.get("threats") or []) if isinstance(t, dict) and "id" in t}

    old_idx = _index(old_data)
    new_idx = _index(new_data)
    added_ids = sorted(set(new_idx) - set(old_idx))
    removed_ids = sorted(set(old_idx) - set(new_idx))
    common_ids = sorted(set(old_idx) & set(new_idx))
    severity_changed = [
        (tid, old_idx[tid].get("severity", "?"), new_idx[tid].get("severity", "?"))
        for tid in common_ids
        if old_idx[tid].get("severity") != new_idx[tid].get("severity")
    ]
    disposition_changed = [
        (tid, old_idx[tid].get("disposition", "open"), new_idx[tid].get("disposition", "open"))
        for tid in common_ids
        if old_idx[tid].get("disposition", "open") != new_idx[tid].get("disposition", "open")
    ]
    return {
        "added": [new_idx[t] for t in added_ids],
        "removed": [old_idx[t] for t in removed_ids],
        "severity_changed": [
            {"id": t, "old": o, "new": n, "title": new_idx[t].get("title", "")}
            for t, o, n in severity_changed
        ],
        "disposition_changed": [
            {"id": t, "old": o, "new": n, "title": new_idx[t].get("title", "")}
            for t, o, n in disposition_changed
        ],
        "summary_old": old_data.get("summary", {}),
        "summary_new": new_data.get("summary", {}),
    }


def _resolve_saved_json(p: str) -> Path | None:
    """Resolve a user-supplied saved-analysis path, CONFINED to the output/
    and cwd directories.

    Only the file *basename* is honoured, so absolute paths (``/etc/passwd``,
    ``C:\\Windows\\...``) and ``../`` traversal are rejected: the web UI cannot
    be turned into an arbitrary-file reader (audit F048/F049/F050). JSON only.
    """
    if not p:
        return None
    name = Path(p).name  # strips drive / directory / .. components
    if not name or Path(name).suffix.lower() != ".json":
        return None
    for base in (Path.cwd() / "output", Path.cwd()):
        try:
            base_resolved = base.resolve()
            cand = base_resolved / name
            if cand.is_file() and cand.parent == base_resolved:
                return cand
        except OSError:
            continue
    return None


# Back-compat alias (the diff route used this name).
_resolve_diff_path = _resolve_saved_json


@app.get("/diff", response_class=HTMLResponse)
def diff_route(request: Request, a: str = "", b: str = "") -> HTMLResponse:
    """v0.17.3 Cycle G: web-facing diff between two saved analyses.

    Mirrors `atms diff <a.json> <b.json>` in HTML. Pass two saved
    ThreatModel JSON paths via ?a=... &b=... query params; the page
    renders added / removed / severity-changed / disposition-changed
    threats. Failure-tolerant: missing or malformed paths surface as
    a friendly status banner, never a 500.
    """
    ctx_extras: dict = {
        "a_path": a, "b_path": b,
        "diff": None, "error": None,
    }
    if not (a and b):
        return _render(
            "web/diff.html",
            _ctx(request, active="diff", **ctx_extras),
        )
    resolved_a = _resolve_diff_path(a)
    resolved_b = _resolve_diff_path(b)
    if resolved_a is None:
        ctx_extras["error"] = f"Path A not found: {a}"
    elif resolved_b is None:
        ctx_extras["error"] = f"Path B not found: {b}"
    else:
        try:
            old_data = json.loads(resolved_a.read_text(encoding="utf-8"))
            new_data = json.loads(resolved_b.read_text(encoding="utf-8"))
            ctx_extras["diff"] = _compute_diff(old_data, new_data)
            ctx_extras["a_path"] = str(resolved_a.name)
            ctx_extras["b_path"] = str(resolved_b.name)
        except (json.JSONDecodeError, OSError) as exc:
            ctx_extras["error"] = f"Could not load JSON: {exc}"
    return _render(
        "web/diff.html",
        _ctx(request, active="diff", **ctx_extras),
    )


@app.get("/architecture", response_class=HTMLResponse)
def architecture(request: Request) -> HTMLResponse:
    """v0.17.1: interactive architecture diagram.

    Renders a self-contained SVG map of the ATMS pipeline — 42 nodes
    across inputs, workflow, engines, KB, reporting, and outputs.
    Click any node to see what it does + the source files that
    implement it. Fully offline; no external libs.
    """
    return _render(
        "web/architecture.html",
        _ctx(request, active="architecture"),
    )


@app.get("/methodology", response_class=HTMLResponse)
def methodology(request: Request, path: str = "") -> HTMLResponse:
    """v0.16.10: per-threat methodology / framework-provenance drill-down.

    Renders a saved ThreatModel JSON (path passed as ?path=output/x.json,
    resolved relative to cwd / well-known output dirs). Shows every
    threat with its STRIDE category anchor + all other framework
    citations side-by-side, so an auditor can trace any threat to a
    published source.
    """
    kb = get_kb()
    order = [
        "Spoofing", "Tampering", "Repudiation",
        "Information_Disclosure", "Denial_of_Service", "Elevation_of_Privilege",
        "Defense_Evasion", "Bias_Fairness", "Emergent_Behavior",
    ]
    provenance_ordered = [
        (cat, kb.methodology_provenance[cat])
        for cat in order
        if cat in kb.methodology_provenance
    ]

    threats: list[dict] = []
    stride_counts: list[tuple[str, int]] = []
    pct_with_framework = 0
    source = ""

    if path:
        # Resolve via the sandboxed resolver: basename-only, confined to
        # output/ and cwd, .json only (audit F049/F050 -- was an arbitrary
        # file read of any JSON on disk).
        cand = _resolve_saved_json(path)
        if cand is not None:
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
            except Exception:
                data = None
            # ThreatModel JSON has a `threats` list at the top level.
            raw_threats = data.get("threats") if isinstance(data, dict) else None
            if isinstance(raw_threats, list):
                threats = raw_threats
                source = str(cand.name)

    if threats:
        # Count threats with at least one framework citation.
        framework_fields = (
            "owasp_llm", "owasp_agentic", "owasp_api", "atlas_techniques",
            "attack_cloud", "attack_enterprise", "maestro_threats",
            "nist_ai_100_2", "linddun", "csa_singapore",
        )
        with_fw = sum(
            1 for t in threats
            if any(t.get(f) for f in framework_fields)
        )
        pct_with_framework = round(100 * with_fw / max(1, len(threats)))

        # STRIDE distribution.
        from collections import Counter
        counter: Counter = Counter()
        for t in threats:
            for s in t.get("stride_ai") or []:
                counter[s] += 1
        stride_counts = counter.most_common()

    return _render(
        "web/methodology.html",
        _ctx(
            request, active="methodology",
            threats=threats,
            source=source,
            stride_counts=stride_counts,
            pct_with_framework=pct_with_framework,
            provenance=kb.methodology_provenance,
            provenance_ordered=provenance_ordered,
        ),
    )


# Note: `/healthz` is now defined earlier (v0.18.30 Cycle TT) and
# returns JSON {"ok": true, "version": ...} for load-balancer probes
# that prefer a typed payload. The old plaintext-"ok" handler was
# retired with TT; both deployment models (LB + k8s) accept the new
# shape.
