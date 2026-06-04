"""Pytest configuration + shared fixtures (v0.17.3 Cycle D).

Adds session-scoped fixtures that cache full `analyze()` results for
the three hot canonical samples. Multiple test files re-analysed
these (aws_bedrock_agent, azure_openai_rag, rag_system) at ~0.5–0.8 s
per call; caching cuts ~5 s off the wall-clock.

**Important**: these fixtures hand out a SHARED ThreatModel instance.
Tests using them MUST NOT mutate the result. If you need to modify
fields, build your own `analyze()` call (function-scoped → fresh).
The naming convention `*_readonly` makes the contract explicit.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ─── v0.18.70 Hibernation Phase 3 — enable all hibernated features ──
# when the user runs `pytest -m hibernated`. The hibernated tests
# assume the underlying routes/parsers serve; without this fixture
# they'd 404 because the flags are off by default.
#
# We detect the request mode by looking at config.option.markexpr at
# collection time. If "hibernated" appears in the marker filter, set
# every ATMS_FEATURE_*=1 and reload the features + web modules.


def _enable_all_hibernated_features() -> None:
    """Set every hibernated flag's env var. ``is_enabled()`` reads env
    at call time (v0.18.72 Phase 7 refactor), so no module reload is
    needed. Idempotent."""
    import atms.features as features_mod
    # Snapshot compiled defaults BEFORE setting env vars, so we only
    # enable the things that ARE hibernated by default.
    saved_env = {}
    for k in list(os.environ):
        if k.startswith("ATMS_FEATURE_"):
            saved_env[k] = os.environ.pop(k)
    try:
        compiled = {
            k.removeprefix("FEATURE_").lower(): v
            for k, v in vars(features_mod).items()
            if k.startswith("FEATURE_") and isinstance(v, bool)
        }
        hibernated = [name for name, v in compiled.items() if v is False]
    finally:
        for k, v in saved_env.items():
            os.environ[k] = v
    for name in hibernated:
        os.environ[f"ATMS_FEATURE_{name.upper()}"] = "1"


def pytest_configure(config):
    """Detect when hibernated tests will run and pre-enable the
    feature flags BEFORE any test module is imported (so atms.web's
    module-level decorators see the right values).

    Triggers when:
      - `-m hibernated` (only hibernated tests)
      - `-m ''` (no marker filter, runs literally everything)
    Does NOT trigger when:
      - default `-m 'not slow and not hibernated'` (set in
        pyproject.toml addopts)
      - `-m slow` (perf tests only)
      - `-m 'not hibernated'`
    """
    markexpr = config.getoption("-m", default="") or ""
    will_run_hibernated = (
        ("hibernated" in markexpr and "not hibernated" not in markexpr)
        or markexpr.strip() == ""
    )
    if will_run_hibernated:
        _enable_all_hibernated_features()


# ─── Session-scoped paths ───────────────────────────────────────────
@pytest.fixture(scope="session")
def samples_dir() -> Path:
    return ROOT / "samples"


# ─── Web TestClient (already existed pre-v0.17.3) ───────────────────
@pytest.fixture(scope="module")
def client_module_scope():
    from fastapi.testclient import TestClient

    from atms.web import app

    return TestClient(app)


# ─── Cached sample analyses (v0.17.3) ───────────────────────────────
#
# Each fixture analyses a canonical sample ONCE per session and shares
# the result across every consuming test. Callers MUST treat the
# returned ThreatModel as immutable.

def _analyze_sample(samples_dir: Path, name: str):
    """Helper: load + analyse a sample. Lazy import so this file
    stays cheap to load for tests that don't need it."""
    from atms.models import System
    from atms.workflow import analyze

    raw = yaml.safe_load((samples_dir / name).read_text(encoding="utf-8"))
    return analyze(System.model_validate(raw))


@pytest.fixture(scope="session")
def aws_bedrock_tm_readonly(samples_dir):
    """v0.17.3: cached analysis of samples/aws_bedrock_agent.yaml.

    Saves ~3 s on the suite (this sample was re-analysed by 5+ tests).
    DO NOT mutate the returned ThreatModel.
    """
    return _analyze_sample(samples_dir, "aws_bedrock_agent.yaml")


@pytest.fixture(scope="session")
def azure_openai_rag_tm_readonly(samples_dir):
    """v0.17.3: cached analysis of samples/azure_openai_rag.yaml."""
    return _analyze_sample(samples_dir, "azure_openai_rag.yaml")


@pytest.fixture(scope="session")
def rag_system_tm_readonly(samples_dir):
    """v0.17.3: cached analysis of samples/rag_system.yaml."""
    return _analyze_sample(samples_dir, "rag_system.yaml")
