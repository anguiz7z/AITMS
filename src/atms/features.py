"""ATMS feature-flag registry — v0.18.68 (Hibernation phase).

Every non-core capability checks its flag here. Defaults reflect the
"focused product" state per the core promise:

  "Give ATMS an AI system architecture (System YAML / drawio / sample)
   and get back the AI-specific threats mapped to OWASP LLM,
   OWASP Agentic, MITRE ATLAS, MAESTRO, and CSA Singapore as a
   clean HTML+Markdown report on the web UI."

Anything NOT required by that promise defaults to OFF.

Re-enabling a hibernated feature
================================

1. Flip the constant below in source, OR
2. Set an environment variable: ATMS_FEATURE_<NAME>=1
   (overrides the compiled default for one process), OR
3. See README "Re-enabling hibernated features" for the canonical
   workflow + verification steps.

Removing a flag is a deliberate decision. Hibernated code stays in
the repo so reversal is one constant flip. Hibernated tests still
pass when explicitly invoked (`pytest -m hibernated`) so nothing rots.

Conventions
===========

* Names are lower-snake-case.
* Env override pattern: ``ATMS_FEATURE_<UPPER_NAME>=1|true|yes|on``
  (anything else is False).
* Read in module-level code (constants) so import time = decision time;
  no per-request overhead.
* Importing a hibernated module is fine — only the public entry point
  guards via ``if not FEATURE_X: raise FeatureDisabledError(...)``.
"""

from __future__ import annotations

import os
from typing import Final


class FeatureDisabledError(RuntimeError):
    """Raised by a hibernated public entry point when its flag is off.

    Carries the canonical re-enable hint so the error message itself
    teaches the caller how to flip it.
    """

    def __init__(self, feature: str) -> None:
        super().__init__(
            f"ATMS feature '{feature}' is hibernated. "
            f"Re-enable via the ATMS_FEATURE_{feature.upper()}=1 env "
            f"var or by flipping FEATURE_{feature.upper()} in "
            f"src/atms/features.py. See README "
            f"'Re-enabling hibernated features'."
        )
        self.feature = feature


def _flag(name: str, default: bool) -> bool:
    env = os.environ.get(f"ATMS_FEATURE_{name.upper()}")
    if env is not None:
        return env.strip().lower() in ("1", "true", "yes", "on")
    return default


# ─── KEEP (core promise; defaults True) ────────────────────────────
FEATURE_ANALYZE: Final = _flag("analyze", True)
FEATURE_EDITOR: Final = _flag("editor", True)
FEATURE_SAMPLES: Final = _flag("samples", True)
FEATURE_DOCS: Final = _flag("docs", True)                  # collapsed nav target
FEATURE_INGEST_YAML: Final = _flag("ingest_yaml", True)
FEATURE_INGEST_DRAWIO: Final = _flag("ingest_drawio", True)
FEATURE_WEB_UI: Final = _flag("web_ui", True)
FEATURE_REPORT_HTML: Final = _flag("report_html", True)
FEATURE_REPORT_MD: Final = _flag("report_md", True)

# ─────────────────────────────────────────────────────────────────
# v1.0.1 — UN-HIBERNATION (owner request 2026-05-31).
#
# The aggressive hibernation in v0.18.68 broke the actual product: the
# upload form advertised .vsdx / .mermaid / IaC formats but the parsers
# behind them errored ("feature hibernated"). Per the owner, every
# capability that is FREE and works OFFLINE is now enabled by default.
#
# Only `vision` (image → YAML) stays default-OFF, because the original
# path needed a paid Anthropic API key. It is re-implemented on top of
# LOCAL Ollama (see src/atms/vision/) and is opt-in via ATMS_FEATURE_
# VISION=1 once an Ollama vision model is pulled — still zero API cost.
#
# Nav de-clutter is handled separately in base.html (extra reference
# pages collapse under the Docs index); enabling a feature here makes it
# WORK, not necessarily occupy a top-nav tab.
# ─────────────────────────────────────────────────────────────────

# ─── Input parsers (free, offline, deterministic) ──────────────────
FEATURE_INGEST_MERMAID: Final = _flag("ingest_mermaid", True)
FEATURE_INGEST_VSDX: Final = _flag("ingest_vsdx", True)
FEATURE_INGEST_TM7: Final = _flag("ingest_tm7", True)
FEATURE_INGEST_OTM: Final = _flag("ingest_otm", True)
FEATURE_INGEST_TERRAFORM: Final = _flag("ingest_terraform", True)
FEATURE_INGEST_PULUMI: Final = _flag("ingest_pulumi", True)
FEATURE_INGEST_CFN: Final = _flag("ingest_cfn", True)
FEATURE_INGEST_AZURE: Final = _flag("ingest_azure", True)
FEATURE_INGEST_K8S: Final = _flag("ingest_k8s", True)
FEATURE_INGEST_COMPOSE: Final = _flag("ingest_compose", True)
# Vision: opt-in. Local Ollama backend (no API cost), default OFF until
# the user has pulled a vision model. See src/atms/vision/.
FEATURE_VISION: Final = _flag("vision", False)

# ─── Evidence + red-team paths (free, offline) ─────────────────────
FEATURE_EVIDENCE: Final = _flag("evidence", True)
FEATURE_REDTEAM: Final = _flag("redteam", True)
FEATURE_CVE_LOOKUP: Final = _flag("cve_lookup", True)
FEATURE_FEEDS_REFRESH: Final = _flag("feeds_refresh", True)

# ─── Analysis-tool surfaces (free, offline) ────────────────────────
# FUNCTIONALITY flags for the IaC / Compliance / Devices / Diff tools.
# These gate whether the ROUTE works at all (distinct from the NAV_*
# placement flags further below, which only control a top-bar tab).
FEATURE_IAC: Final = _flag("iac", True)
FEATURE_COMPLIANCE: Final = _flag("compliance", True)
FEATURE_DEVICES: Final = _flag("devices", True)
FEATURE_DIFF: Final = _flag("diff", True)

# ─── Top-bar PLACEMENT flags (NOT functionality) ───────────────────
# The tools themselves (evidence/redteam/iac/compliance/devices/diff)
# are ENABLED above and reachable from the /docs hub. These NAV_* flags
# only control whether each ALSO gets a dedicated top-bar tab. Default
# OFF to keep the global nav focused on the core loop; flip one to 1 to
# pin that tool back onto the bar.
FEATURE_NAV_IAC: Final = _flag("nav_iac", False)
FEATURE_NAV_COMPLIANCE: Final = _flag("nav_compliance", False)
FEATURE_NAV_DEVICES: Final = _flag("nav_devices", False)
FEATURE_NAV_DIFF: Final = _flag("nav_diff", False)

# ─── Report exporters (free, offline) ──────────────────────────────
FEATURE_EXPORT_SBOM: Final = _flag("export_sbom", True)
FEATURE_EXPORT_STIX: Final = _flag("export_stix", True)
FEATURE_EXPORT_SARIF: Final = _flag("export_sarif", True)
FEATURE_EXPORT_NAVIGATOR: Final = _flag("export_navigator", True)
FEATURE_EXPORT_JIRA: Final = _flag("export_jira", True)
FEATURE_EXPORT_ROADMAP: Final = _flag("export_roadmap", True)
FEATURE_EXPORT_OTM: Final = _flag("export_otm", True)
FEATURE_EXPORT_CSV: Final = _flag("export_csv", True)
FEATURE_EXPORT_COMPLIANCE_MATRIX: Final = _flag("export_compliance_matrix", True)
# v1.0.3 - CSA Singapore "Table of Attack" threat-library export (HTML + CSV).
FEATURE_EXPORT_CSA_TABLE: Final = _flag("export_csa_table", True)
# v1.0.6 - CSA Singapore "Risk Register" export (D-E-R / C-I-A / 5x5 / 8-element).
FEATURE_EXPORT_CSA_RISK: Final = _flag("export_csa_risk", True)

# ─── Extra delivery surfaces (free, offline) ───────────────────────
FEATURE_REST_API: Final = _flag("rest_api", True)
FEATURE_MCP_SERVER: Final = _flag("mcp_server", True)
FEATURE_BUILD_EXE: Final = _flag("build_exe", True)
FEATURE_BUILD_INSTALLER: Final = _flag("build_installer", True)

# ─── Framework engines (free, offline) ─────────────────────────────
FEATURE_FRAMEWORK_LINDDUN: Final = _flag("framework_linddun", True)
FEATURE_FRAMEWORK_NIST_AI_100_2: Final = _flag("framework_nist_ai_100_2", True)
FEATURE_FRAMEWORK_NIST_AI_RMF: Final = _flag("framework_nist_ai_rmf", True)
FEATURE_FRAMEWORK_OWASP_ML: Final = _flag("framework_owasp_ml", True)

# ─── Extra CLI subcommands (free, offline) ─────────────────────────
FEATURE_CLI_WATCH: Final = _flag("cli_watch", True)
FEATURE_CLI_REVIEW: Final = _flag("cli_review", True)
FEATURE_CLI_DIFF: Final = _flag("cli_diff", True)
FEATURE_CLI_KB_BROWSERS: Final = _flag("cli_kb_browsers", True)


def graceful_hibernation(fn):
    """Wrap a KEEP CLI command whose *auto-detect* dispatch may reach a
    hibernated parser. Converts ``FeatureDisabledError`` into a clean
    ``click.UsageError`` (exit 2, the re-enable hint, no traceback).

    Unlike ``cli_gated`` (which gates a whole command by one flag), this
    is for commands that are themselves KEEP (``scan``, ``ingest``) but
    may select a hibernated parser based on the input file's format.
    """
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except FeatureDisabledError as exc:
            import click
            raise click.UsageError(str(exc)) from exc
    return wrapper


def is_enabled(name: str) -> bool:
    """Generic runtime lookup. `name` is the flag's lowercased suffix
    (e.g. ``is_enabled("evidence")`` → returns the EVIDENCE flag).

    Resolves env vars at CALL time (not just at import) so tests can
    toggle ``ATMS_FEATURE_X`` between calls without ``importlib.reload``.

    Falls back to the module-level constant set at import time when
    no env override is present.
    """
    key = name.upper()
    env_val = os.environ.get(f"ATMS_FEATURE_{key}")
    if env_val is not None:
        return env_val.strip().lower() in ("1", "true", "yes", "on")
    return bool(globals().get(f"FEATURE_{key}", False))


def require(feature: str) -> None:
    """Raise ``FeatureDisabledError`` if the named feature is off.

    For use at the top of a hibernated public function so the
    error message itself documents the re-enable path.

    Example::

        def parse_terraform(path):
            from atms.features import require
            require("ingest_terraform")
            # ... rest of the parser ...
    """
    if not is_enabled(feature):
        raise FeatureDisabledError(feature)


def cli_gated(feature: str):
    """Click-friendly variant of `gated`. Aborts with `click.UsageError`
    (clean exit-1 message, no traceback) when the feature is off.

    Usage::

        @cli.command()
        @cli_gated("ingest_terraform")
        def ingest_iac(...):
            ...
    """
    from functools import wraps

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not is_enabled(feature):
                import click
                raise click.UsageError(
                    f"ATMS subcommand for feature '{feature}' is hibernated. "
                    f"Re-enable: set ATMS_FEATURE_{feature.upper()}=1 or flip "
                    f"FEATURE_{feature.upper()} in src/atms/features.py. "
                    f"See README 'Re-enabling hibernated features'."
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def gated(feature: str):
    """Decorator: ``require(feature)`` runs before the wrapped function body.

    For hibernated parser / engine / exporter entry points::

        from atms.features import gated

        @gated("ingest_terraform")
        def parse_terraform(path):
            ...

    ``functools.wraps`` preserves the wrapped function's ``__doc__`` /
    ``__name__`` / signature so introspection (and Click help) keeps
    working unchanged.
    """
    from functools import wraps

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            require(feature)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def requires_feature(feature: str):
    """FastAPI route guard. When the named feature is off, the route
    returns HTTP 404 (so the URL behaves as if it doesn't exist —
    a cleaner UX than 403 or a custom code).

    Usage::

        @app.get("/evidence")
        @requires_feature("evidence")
        def evidence_page(...):
            ...

    The wrapper preserves the wrapped function's name + docstring so
    FastAPI's introspection still works. The 404 response uses
    HTMLResponse so the user gets the same shape as a missing page,
    not a JSON error body.
    """
    from functools import wraps

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not is_enabled(feature):
                # Lazy import — avoids circular imports during module load.
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=404,
                    detail=(
                        f"ATMS feature '{feature}' is hibernated. "
                        f"Set ATMS_FEATURE_{feature.upper()}=1 to enable."
                    ),
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def enabled_features() -> dict[str, bool]:
    """Snapshot of every flag's CURRENT effective value (env var if
    set, else compiled default), keyed by the lower-snake name.

    Used by `atms info` and the /docs hibernation-state table. Reads
    env vars each call, matching ``is_enabled`` semantics.
    """
    out: dict[str, bool] = {}
    for k, v in globals().items():
        if k.startswith("FEATURE_") and isinstance(v, bool):
            name = k.removeprefix("FEATURE_").lower()
            out[name] = is_enabled(name)
    return out


__all__ = [
    "FeatureDisabledError",
    "is_enabled",
    "enabled_features",
    "require",
    "requires_feature",
    "gated",
    "cli_gated",
    "graceful_hibernation",
    # Flags re-exported so `from atms.features import FEATURE_X` works.
    "FEATURE_ANALYZE",
    "FEATURE_EDITOR",
    "FEATURE_SAMPLES",
    "FEATURE_DOCS",
    "FEATURE_INGEST_YAML",
    "FEATURE_INGEST_DRAWIO",
    "FEATURE_WEB_UI",
    "FEATURE_REPORT_HTML",
    "FEATURE_REPORT_MD",
    "FEATURE_INGEST_MERMAID",
    "FEATURE_INGEST_VSDX",
    "FEATURE_INGEST_TM7",
    "FEATURE_INGEST_OTM",
    "FEATURE_INGEST_TERRAFORM",
    "FEATURE_INGEST_PULUMI",
    "FEATURE_INGEST_CFN",
    "FEATURE_INGEST_AZURE",
    "FEATURE_INGEST_K8S",
    "FEATURE_INGEST_COMPOSE",
    "FEATURE_VISION",
    "FEATURE_EVIDENCE",
    "FEATURE_REDTEAM",
    "FEATURE_CVE_LOOKUP",
    "FEATURE_FEEDS_REFRESH",
    "FEATURE_IAC",
    "FEATURE_COMPLIANCE",
    "FEATURE_DEVICES",
    "FEATURE_DIFF",
    "FEATURE_NAV_IAC",
    "FEATURE_NAV_COMPLIANCE",
    "FEATURE_NAV_DEVICES",
    "FEATURE_NAV_DIFF",
    "FEATURE_EXPORT_SBOM",
    "FEATURE_EXPORT_STIX",
    "FEATURE_EXPORT_SARIF",
    "FEATURE_EXPORT_NAVIGATOR",
    "FEATURE_EXPORT_JIRA",
    "FEATURE_EXPORT_ROADMAP",
    "FEATURE_EXPORT_OTM",
    "FEATURE_EXPORT_CSV",
    "FEATURE_EXPORT_COMPLIANCE_MATRIX",
    "FEATURE_EXPORT_CSA_TABLE",
    "FEATURE_EXPORT_CSA_RISK",
    "FEATURE_REST_API",
    "FEATURE_MCP_SERVER",
    "FEATURE_BUILD_EXE",
    "FEATURE_BUILD_INSTALLER",
    "FEATURE_FRAMEWORK_LINDDUN",
    "FEATURE_FRAMEWORK_NIST_AI_100_2",
    "FEATURE_FRAMEWORK_NIST_AI_RMF",
    "FEATURE_FRAMEWORK_OWASP_ML",
    "FEATURE_CLI_WATCH",
    "FEATURE_CLI_REVIEW",
    "FEATURE_CLI_DIFF",
    "FEATURE_CLI_KB_BROWSERS",
]
