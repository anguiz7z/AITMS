"""Roadmap V5 Phase 6 — sample fleet & onboarding contract.

First-run experience decides adoption. On inspection the onboarding
surface is already in good shape:
  * `atms init` scaffolds a starter System YAML (4 templates: basic /
    rag / agentic / chatbot) that each validate + analyse cleanly.
  * The bundled fleet is diverse (16 samples spanning many distinct
    component types) and every sample analyses.
  * `docs/GETTING-STARTED.md` walks the core loop.

Phase 6 LOCKS that as a regression net — no production change.

KEEP suite (flags off).
"""

from __future__ import annotations

import glob
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from atms.cli import cli
from atms.engines.ai_scope import find_ai_components
from atms.models import System
from atms.workflow import analyze

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = sorted(glob.glob(str(ROOT / "samples" / "*.yaml")))


# ─── `atms init` scaffolds (all templates) are valid + analysable ───


@pytest.mark.parametrize("template", ["basic", "rag", "agentic", "chatbot"])
def test_init_template_writes_valid_analysable_system(tmp_path, template):
    out = tmp_path / f"{template}.yaml"
    r = CliRunner().invoke(cli, ["init", "--out", str(out), "--template", template])
    assert r.exit_code == 0, r.output
    assert out.exists()

    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert data.get("name")
    assert isinstance(data.get("components"), list) and data["components"]

    # Validates.
    rv = CliRunner().invoke(cli, ["validate", str(out)])
    assert rv.exit_code == 0, rv.output

    # Analyses end-to-end (no traceback).
    ra = CliRunner().invoke(cli, ["analyze", str(out), "--out", str(tmp_path / f"o_{template}")])
    assert ra.exit_code == 0, ra.output
    assert "Traceback (most recent call last)" not in ra.output


def test_init_refuses_overwrite_without_force(tmp_path):
    out = tmp_path / "s.yaml"
    CliRunner().invoke(cli, ["init", "--out", str(out)])
    r = CliRunner().invoke(cli, ["init", "--out", str(out)])
    assert r.exit_code != 0, "init should refuse to clobber an existing file"
    r2 = CliRunner().invoke(cli, ["init", "--out", str(out), "--force"])
    assert r2.exit_code == 0, "init --force should overwrite"


# ─── Sample fleet is diverse and every sample analyses ──────────────


def test_fleet_is_large_and_diverse():
    types = set()
    for f in SAMPLES:
        d = yaml.safe_load(Path(f).read_text(encoding="utf-8"))
        for c in d.get("components", []):
            types.add(c.get("type"))
    assert len(SAMPLES) >= 12, f"expected >=12 samples, got {len(SAMPLES)}"
    assert len(types) >= 25, f"expected >=25 distinct component types, got {len(types)}"


def test_every_sample_analyses():
    for f in SAMPLES:
        s = System.model_validate(yaml.safe_load(Path(f).read_text(encoding="utf-8")))
        has_ai = bool(find_ai_components(s))
        tm = analyze(s, require_ai_components=has_ai)
        assert tm.threats is not None, f"{Path(f).name} produced no threat model"


def test_ai_samples_produce_threats_and_mitigations():
    for f in SAMPLES:
        s = System.model_validate(yaml.safe_load(Path(f).read_text(encoding="utf-8")))
        if not find_ai_components(s):
            continue
        tm = analyze(s)
        name = Path(f).name
        assert len(tm.threats) >= 1, f"{name}: no threats"
        assert len(tm.mitigations) >= 1, f"{name}: no mitigations"


# ─── Getting-started doc covers the core loop ───────────────────────


def test_getting_started_doc_covers_core_loop():
    doc = ROOT / "docs" / "GETTING-STARTED.md"
    assert doc.exists(), "docs/GETTING-STARTED.md missing"
    text = doc.read_text(encoding="utf-8").lower()
    assert "analyze" in text
    assert "atms" in text
    assert "web" in text  # the demo surface
