"""Reporting tests — Markdown, HTML, STIX, Navigator, CSV exports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from atms.models import System
from atms.reporting import render_html, render_markdown, render_navigator, render_stix, write_csv
from atms.workflow import analyze

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture(scope="module")
def model():
    raw = yaml.safe_load((SAMPLES_DIR / "rag_system.yaml").read_text(encoding="utf-8"))
    return analyze(System.model_validate(raw))


def test_markdown(model):
    md = render_markdown(model)
    assert "# Threat Model" in md
    assert "Customer Support RAG Assistant" in md
    assert "OWASP" in md
    assert "ATLAS" in md
    assert "## All mitigations" in md
    assert "## Recommended roadmap" in md
    assert "```mermaid" in md  # DFD embedded


def test_html(model):
    html = render_html(model)
    assert "<!doctype html>" in html.lower() or "<html" in html.lower()
    assert "Customer Support RAG Assistant" in html
    assert 'class="severity sev-critical"' in html or 'class="severity sev-high"' in html
    # Mermaid DFD embedded + CDN script tag
    assert '<pre class="mermaid">' in html
    assert "mermaid.min.js" in html
    # Heatmap legend
    assert "matrix-legend" in html
    # Roadmap section
    assert "Recommended roadmap" in html


def test_stix(model):
    stix_str = render_stix(model)
    bundle = json.loads(stix_str)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    types = {obj["type"] for obj in bundle["objects"]}
    assert "attack-pattern" in types
    assert "course-of-action" in types
    assert "relationship" in types


def test_navigator(model):
    nav_str = render_navigator(model)
    layer = json.loads(nav_str)
    assert layer["domain"] == "atlas"
    assert "techniques" in layer
    assert all("techniqueID" in t and "score" in t for t in layer["techniques"])
    assert all(t["techniqueID"].startswith("AML.") for t in layer["techniques"])


def test_csv_risk_register(model):
    csv = write_csv(model, "risk_register")
    lines = csv.strip().splitlines()
    assert lines[0].startswith("threat_id")
    assert len(lines) == len(model.threats) + 1


def test_csv_mitigations(model):
    csv = write_csv(model, "mitigations")
    lines = csv.strip().splitlines()
    assert lines[0].startswith("mitigation_id")
    assert len(lines) == len(model.mitigations) + 1
