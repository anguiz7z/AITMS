"""Structural-validity lock-in for ATMS export formats (audit).

These tests assert that the exported artefacts are STRUCTURALLY VALID,
not merely present on disk. They guard against a regression where an
exporter still writes a file but emits a malformed bundle / report
(e.g. a STIX bundle missing `spec_version`, an empty SARIF run, a
navigator layer that no longer parses, or a CSV with a header but no
data rows).

Two complementary paths exercise the same guarantee:

1. `test_cli_*` — drive the real CLI end-to-end via subprocess
   (`python -m atms analyze samples/rag_system.yaml --out <tmp>`),
   then load each emitted file and assert its internal structure.
   This is the true user-facing contract: the writer wiring in
   `cli.py` plus every renderer.

2. `test_direct_*` — call the `reporting/` renderers directly on an
   in-memory `analyze()` result, so a structural break is attributed
   to the renderer rather than the CLI plumbing.

The sample (`samples/rag_system.yaml`) contains AI primaries (an
`agent` + `llm_inference` + `rag_vector_store`), so `analyze()` does
NOT raise `NoAIComponentsError` and the AI-native framework maps
(OWASP LLM, ATLAS) are populated — which is what makes the STIX
external-references and the navigator ATLAS layer non-empty.
"""

from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SAMPLE = ROOT / "samples" / "rag_system.yaml"
STEM = SAMPLE.stem  # "rag_system"


# ─── Shared CLI run (one subprocess, reused by every CLI assertion) ──
@pytest.fixture(scope="module")
def cli_out_dir(tmp_path_factory) -> Path:
    """Run the real `atms analyze` CLI once into a tmp dir and return it.

    Mirrors the documented invocation exactly:
        PYTHONPATH=src ATMS_KB_NO_CACHE=1 python -m atms analyze \
            samples/rag_system.yaml --out <tmp>
    Default `--format` is `all`, so every exporter fires.
    """
    out_dir = tmp_path_factory.mktemp("atms_cli_out")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["ATMS_KB_NO_CACHE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "atms", "analyze", str(SAMPLE), "--out", str(out_dir)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        f"CLI analyze exited {proc.returncode}\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    return out_dir


# ─── In-memory model (one analyze(), reused by the direct-renderer tests) ──
@pytest.fixture(scope="module")
def model():
    """A real ThreatModel from analyze() on the RAG sample.

    `require_ai_components=True` is the default; the sample has AI
    primaries so this exercises the normal (non-pure-IT) path.
    """
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    from atms.models import System
    from atms.workflow import analyze

    raw = yaml.safe_load(SAMPLE.read_text(encoding="utf-8"))
    tm = analyze(System.model_validate(raw))
    # Sanity: the whole point of the structural checks is that there's
    # real content to validate. A zero-threat model would make every
    # "non-empty" assertion below vacuous.
    assert tm.threats, "analyze() produced no threats; structural checks would be vacuous"
    return tm


def _load_json(path: Path):
    assert path.exists(), f"expected export missing: {path.name}"
    text = path.read_text(encoding="utf-8")
    assert text.strip(), f"export is empty: {path.name}"
    return json.loads(text)  # raises on malformed JSON → real failure


# ════════════════════════════════════════════════════════════════════
# CLI-path structural assertions (end-to-end through cli.py + renderers)
# ════════════════════════════════════════════════════════════════════

def test_cli_stix_is_valid_bundle(cli_out_dir: Path):
    """STIX export is a real STIX 2.1 bundle: type=='bundle',
    has spec_version, and a non-empty objects list of well-formed SDOs."""
    bundle = _load_json(cli_out_dir / f"{STEM}.stix.json")
    assert isinstance(bundle, dict)
    assert bundle.get("type") == "bundle"
    assert bundle.get("spec_version") == "2.1"
    assert "id" in bundle and isinstance(bundle["id"], str) and bundle["id"]
    objects = bundle.get("objects")
    assert isinstance(objects, list)
    assert len(objects) > 0, "STIX bundle has an empty objects list"
    # Every object must carry the STIX SDO essentials.
    for obj in objects:
        assert isinstance(obj, dict)
        assert obj.get("type"), "STIX object missing 'type'"
        assert obj.get("id"), "STIX object missing 'id'"
        # SDO id form is "<type>--<uuid>".
        assert "--" in obj["id"]
    # The threat-model maps every Threat → attack-pattern, so at least
    # one must exist (otherwise the whole bundle is structurally empty
    # of findings).
    types = {o["type"] for o in objects}
    assert "attack-pattern" in types, f"no attack-pattern SDOs; got {sorted(types)}"


def test_cli_sarif_has_version_and_tool(cli_out_dir: Path):
    """SARIF export has version '2.1.0' and runs[0].tool.driver populated,
    with the result/rule wiring intact."""
    sarif = _load_json(cli_out_dir / f"{STEM}.sarif")
    assert sarif.get("version") == "2.1.0"
    runs = sarif.get("runs")
    assert isinstance(runs, list) and len(runs) >= 1, "SARIF has no runs"
    run = runs[0]
    tool = run.get("tool")
    assert isinstance(tool, dict), "runs[0].tool missing"
    driver = tool.get("driver")
    assert isinstance(driver, dict), "tool.driver missing"
    assert driver.get("name") == "ATMS"
    rules = driver.get("rules")
    assert isinstance(rules, list) and len(rules) > 0, "no SARIF rules"
    results = run.get("results")
    assert isinstance(results, list) and len(results) > 0, "no SARIF results"
    # Each result must reference a rule and carry a level/message — the
    # contract GitHub code-scanning enforces.
    rule_ids = {r["id"] for r in rules}
    for res in results:
        assert res.get("ruleId") in rule_ids, "result references undefined rule"
        assert res.get("level") in {"note", "warning", "error"}
        assert res.get("message", {}).get("text"), "result missing message text"


def test_cli_json_model_loads_with_threats(cli_out_dir: Path):
    """The primary JSON model deliverable loads and round-trips into a
    ThreatModel with a non-empty threats list and a real summary."""
    data = _load_json(cli_out_dir / f"{STEM}.json")
    assert isinstance(data, dict)
    assert "threats" in data, "model JSON has no 'threats' key"
    assert isinstance(data["threats"], list) and len(data["threats"]) > 0
    # Each threat carries the core schema fields the reports rely on.
    sample_threat = data["threats"][0]
    for key in ("id", "component_id", "title", "severity"):
        assert key in sample_threat, f"threat missing '{key}'"
    assert "system" in data and data["system"].get("name")
    assert isinstance(data.get("summary"), dict) and data["summary"], "empty summary"
    # And it must re-validate against the real pydantic model — the
    # strongest structural check available.
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    from atms.models import ThreatModel

    reparsed = ThreatModel.model_validate(data)
    assert len(reparsed.threats) == len(data["threats"])


def test_cli_navigator_parses_as_atlas_layer(cli_out_dir: Path):
    """ATLAS navigator export parses and is a valid Navigator layer (or
    multi-layer document). Each layer has techniques + versions + domain."""
    nav = _load_json(cli_out_dir / f"{STEM}.navigator.json")
    # render_navigator returns a single dict for one layer or a list for
    # a hybrid AI+cloud system (the RAG sample is hybrid → list). Both
    # are valid Navigator imports; normalise to a list of layers.
    layers = nav if isinstance(nav, list) else [nav]
    assert len(layers) >= 1, "navigator produced no layers"
    domains = set()
    for layer in layers:
        assert isinstance(layer, dict)
        assert layer.get("name"), "layer missing name"
        versions = layer.get("versions")
        assert isinstance(versions, dict) and "attack" in versions
        assert "navigator" in versions and "layer" in versions
        assert layer.get("domain"), "layer missing domain"
        domains.add(layer["domain"])
        techniques = layer.get("techniques")
        assert isinstance(techniques, list), "layer.techniques is not a list"
        # Every technique entry must have an id and a numeric score.
        for tech in techniques:
            assert tech.get("techniqueID"), "technique missing techniqueID"
            assert isinstance(tech.get("score"), (int, float))
    # The sample maps ATLAS techniques, so an 'atlas' layer must exist
    # and carry at least one technique.
    atlas_layers = [
        layer for layer in layers
        if layer.get("domain") == "atlas"
    ]
    assert atlas_layers, f"no atlas-domain layer; domains={sorted(domains)}"
    assert any(layer["techniques"] for layer in atlas_layers), (
        "atlas navigator layer has zero techniques despite ATLAS mappings"
    )


def test_cli_risk_register_csv_has_header_and_rows(cli_out_dir: Path):
    """The risk-register CSV has the expected header columns AND at least
    one data row, one row per threat."""
    path = cli_out_dir / f"{STEM}.risk_register.csv"
    assert path.exists(), "risk_register CSV missing"
    text = path.read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    assert len(rows) >= 2, "CSV has a header but no data rows"
    header = rows[0]
    for col in ("threat_id", "component_id", "title", "severity", "risk_score"):
        assert col in header, f"risk_register CSV missing column '{col}'"
    data_rows = rows[1:]
    assert len(data_rows) > 0
    # Each data row must have the same column count as the header (no
    # ragged rows that would break a spreadsheet import).
    for r in data_rows:
        assert len(r) == len(header), "ragged CSV row width != header width"
    # threat_id column is non-empty for every row.
    tid_idx = header.index("threat_id")
    assert all(r[tid_idx].strip() for r in data_rows), "blank threat_id in a row"


def test_cli_mitigations_csv_has_header_and_rows(cli_out_dir: Path):
    """The mitigations CSV is structurally valid: header + >=1 data row."""
    path = cli_out_dir / f"{STEM}.mitigations.csv"
    assert path.exists(), "mitigations CSV missing"
    rows = list(csv.reader(io.StringIO(path.read_text(encoding="utf-8"))))
    assert len(rows) >= 2, "mitigations CSV has a header but no data rows"
    header = rows[0]
    for col in ("mitigation_id", "title", "effort"):
        assert col in header, f"mitigations CSV missing column '{col}'"
    for r in rows[1:]:
        assert len(r) == len(header), "ragged mitigations CSV row"


# ════════════════════════════════════════════════════════════════════
# Direct-renderer structural assertions (renderer-attributed failures)
# ════════════════════════════════════════════════════════════════════

def test_direct_stix_bundle_structure(model):
    """render_stix() on the live model yields a valid 2.1 bundle whose
    attack-pattern count equals the threat count."""
    from atms.reporting.stix import render_stix

    bundle = json.loads(render_stix(model))
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert isinstance(bundle["objects"], list) and bundle["objects"]
    aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert len(aps) == len(model.threats), (
        f"attack-pattern count {len(aps)} != threat count {len(model.threats)}"
    )
    # external_references, when present, must be a NON-empty list (STIX
    # 2.1 minItems:1 — the exporter omits the key when empty rather than
    # writing []). This is an explicit audit-F018 invariant.
    for o in bundle["objects"]:
        if "external_references" in o:
            assert isinstance(o["external_references"], list)
            assert len(o["external_references"]) >= 1, (
                "empty external_references list violates STIX 2.1 minItems:1"
            )
            for ref in o["external_references"]:
                assert "source_name" in ref


def test_direct_sarif_structure(model):
    """render_sarif() yields one result per threat and one rule per
    distinct threat-id pattern, all wired to defined rules."""
    from atms.reporting.sarif_export import render_sarif

    sarif = json.loads(render_sarif(model))
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ATMS"
    # One result per concrete threat (the renderer appends one per threat).
    assert len(run["results"]) == len(model.threats)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids, "no rules defined"
    for res in run["results"]:
        assert res["ruleId"] in rule_ids


def test_direct_navigator_structure(model):
    """render_navigator() parses and every layer is a valid Navigator
    layer; the gradient/min-max metadata is intact."""
    from atms.reporting.navigator import render_navigator

    nav = json.loads(render_navigator(model))
    layers = nav if isinstance(nav, list) else [nav]
    assert layers
    for layer in layers:
        assert layer["versions"]["layer"]  # schema version string
        assert isinstance(layer["techniques"], list)
        grad = layer.get("gradient", {})
        assert "colors" in grad and isinstance(grad["colors"], list)


def test_direct_csv_risk_register_structure(model):
    """write_csv(risk_register) returns a header + one row per threat,
    and parses cleanly as CSV with no ragged rows."""
    from atms.reporting.csv_export import write_csv

    out = write_csv(model, "risk_register")
    rows = list(csv.reader(io.StringIO(out)))
    assert len(rows) == len(model.threats) + 1, "row count != threats + header"
    header = rows[0]
    assert header[0] == "threat_id"
    for r in rows[1:]:
        assert len(r) == len(header)
