"""CSA Singapore "Table of Attack" threat-library export (v1.0.3).

Organizations following the CSA Singapore *Guide to Cyber Threat
Modelling* (Feb 2021) use its Attack-Modelling step, which produces a **Table of
Attack** with these columns:

    S/N | Point of Entry | Threat Actor(s) | Sequence of Attack |
    Threat Description | Examples

plus the CSA crown-jewel (★) and stepping-stone concepts.

This file pins:
  * the row builder projects every attack path into the CSA shape;
  * crown-jewel detection flags data/secret/model/identity/OT targets;
  * threat actors are derived deterministically from the entry type;
  * CSV + standalone-HTML renderers are well-formed;
  * the section appears in BOTH downloadable reports (md + html);
  * the web download routes serve csa_table (HTML) + csa_table_csv (CSV)
    with ASCII-safe Content-Disposition (the v1.0.2 lesson);
  * output is deterministic (no LLM, no network).
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from atms.models import Component, System
from atms.reporting import render_html, render_markdown
from atms.reporting.csa_table import (
    _classify_actors,
    _is_crown_jewel,
    build_table_of_attack,
    render_csa_table_csv,
    render_csa_table_html,
)
from atms.web import _RUNS, app
from atms.workflow import analyze

_SAMPLES = Path(__file__).resolve().parents[1] / "samples"
# A unicode-named, multi-component sample so we exercise attack paths AND
# the latin-1 header path together.
_SAMPLE = _SAMPLES / "azure_openai_rag.yaml"


@pytest.fixture(scope="module")
def model():
    data = yaml.safe_load(_SAMPLE.read_text(encoding="utf-8"))
    return analyze(System.model_validate(data), methodology="stride-ai")


# ─── Row builder ────────────────────────────────────────────────────


def test_build_table_returns_one_row_per_path(model):
    rows = build_table_of_attack(model)
    assert rows, "no CSA rows built"
    # One row per attack path (capped), or per-threat fallback if no paths.
    if model.attack_paths:
        assert len(rows) == min(len(model.attack_paths), 50)


def test_every_row_has_all_csa_columns(model):
    required = {
        "sn", "point_of_entry", "threat_actors", "sequence_str",
        "threat_description", "examples", "crown_jewel", "is_crown_jewel",
        "stepping_stones", "difficulty", "business_impact",
    }
    for r in build_table_of_attack(model):
        missing = required - set(r.keys())
        assert not missing, f"row missing CSA columns: {missing}"
        assert r["threat_actors"], "threat_actors must never be empty"
        assert isinstance(r["sn"], int)


def test_sn_is_sequential_from_one(model):
    rows = build_table_of_attack(model)
    assert [r["sn"] for r in rows] == list(range(1, len(rows) + 1))


def test_rows_ranked_by_business_impact(model):
    rows = build_table_of_attack(model)
    if len(rows) >= 2 and model.attack_paths:
        impacts = [r["business_impact"] for r in rows]
        assert impacts == sorted(impacts, reverse=True), (
            "CSA rows should be ranked by business impact (desc)"
        )


# ─── Crown-jewel detection ──────────────────────────────────────────


@pytest.mark.parametrize("ctype", [
    "rag_vector_store", "object_storage", "database", "secrets_vault",
    "model_registry", "kms_key", "identity_provider", "scada",
])
def test_crown_jewel_types_flagged(ctype):
    assert _is_crown_jewel(Component(id="c", name="C", type=ctype)) is True


@pytest.mark.parametrize("ctype", ["user", "external_api", "load_balancer", "waf"])
def test_non_crown_jewel_types_not_flagged(ctype):
    assert _is_crown_jewel(Component(id="c", name="C", type=ctype)) is False


def test_crown_jewel_none_is_false():
    assert _is_crown_jewel(None) is False


# ─── Threat-actor derivation ────────────────────────────────────────


def test_actor_external_for_internet_surface():
    actors = _classify_actors(Component(id="c", name="API", type="external_api"))
    assert any("External" in a for a in actors)


def test_actor_supply_chain_for_pipeline():
    actors = _classify_actors(Component(id="c", name="Train", type="training_pipeline"))
    assert any("Supply-chain" in a for a in actors)


def test_actor_insider_for_iam_principal():
    actors = _classify_actors(Component(id="c", name="SA", type="iam_principal"))
    assert any("insider" in a.lower() or "compromised" in a.lower() for a in actors)


def test_actor_user_variant():
    actors = _classify_actors(Component(id="c", name="U", type="user"))
    assert actors and any("user" in a.lower() for a in actors)


def test_actor_never_empty_for_unknown_type():
    actors = _classify_actors(Component(id="c", name="X", type="other"))
    assert actors  # at least one default actor


# ─── CSV renderer ───────────────────────────────────────────────────


def test_csv_header_is_csa_columns(model):
    text = render_csa_table_csv(model)
    header = text.splitlines()[0]
    for col in ("S/N", "Point of Entry", "Threat Actor(s)",
                "Sequence of Attack", "Threat Description", "Examples"):
        assert col in header, f"CSV header missing {col!r}"


def test_csv_is_parseable_and_row_count_matches(model):
    text = render_csa_table_csv(model)
    rows = list(csv.reader(io.StringIO(text)))
    data_rows = rows[1:]
    assert len(data_rows) == len(build_table_of_attack(model))
    # every data row has the same column count as the header
    assert all(len(r) == len(rows[0]) for r in data_rows)


# ─── Standalone HTML renderer ───────────────────────────────────────


def test_standalone_html_is_well_formed(model):
    html = render_csa_table_html(model)
    assert html.startswith("<!doctype html>")
    assert "CSA Table of Attack" in html
    assert "</html>" in html.strip()[-10:]
    assert "Point of Entry" in html


def test_standalone_html_marks_crown_jewels(model):
    rows = build_table_of_attack(model)
    if any(r["is_crown_jewel"] for r in rows):
        assert "★" in render_csa_table_html(model)  # ★


# ─── Embedded in both downloadable reports ──────────────────────────


def test_markdown_report_includes_csa_section(model):
    md = render_markdown(model)
    assert "## CSA Table of Attack" in md
    assert "| S/N | Point of Entry |" in md


def test_markdown_csa_rows_do_not_break_table(model):
    """Each CSA markdown row must have exactly 6 cells (7 pipes) — a stray
    pipe in a threat description would otherwise shatter the table."""
    md = render_markdown(model)
    block = md[md.find("## CSA Table of Attack"):]
    nxt = block.find("\n## ", 5)
    if nxt != -1:
        block = block[:nxt]
    data_rows = [
        ln for ln in block.splitlines()
        if ln.startswith("| ") and not ln.startswith("| S/N") and not ln.startswith("|---")
    ]
    assert data_rows, "no CSA data rows in markdown"
    for ln in data_rows:
        assert ln.count("|") == 7, f"row has wrong cell count: {ln!r}"


def test_html_report_includes_csa_section(model):
    html = render_html(model)
    assert "CSA Table of Attack" in html
    assert "<th>S/N</th>" in html


# ─── Determinism ────────────────────────────────────────────────────


def test_csv_is_deterministic(model):
    assert render_csa_table_csv(model) == render_csa_table_csv(model)


def test_html_is_deterministic(model):
    assert render_csa_table_html(model) == render_csa_table_html(model)


# ─── Web download routes ────────────────────────────────────────────


@pytest.fixture(scope="module")
def web_run():
    client = TestClient(app, raise_server_exceptions=False)
    yaml_text = _SAMPLE.read_text(encoding="utf-8")
    resp = client.post("/analyze", data={"yaml": yaml_text, "methodology": "stride-ai"})
    assert resp.status_code == 200
    return client, list(_RUNS.keys())[-1]


def test_download_csa_table_html_serves(web_run):
    client, run_id = web_run
    r = client.get(f"/download/{run_id}/csa_table")
    assert r.status_code == 200
    assert len(r.content) > 0
    assert "CSA Table of Attack" in r.text
    # ASCII-safe header (v1.0.2 lesson) even with a unicode system name.
    cd = r.headers["content-disposition"]
    cd.encode("latin-1")
    assert cd.isascii()
    assert "csa-table-of-attack.html" in cd


def test_download_csa_table_csv_serves(web_run):
    client, run_id = web_run
    r = client.get(f"/download/{run_id}/csa_table_csv")
    assert r.status_code == 200
    assert r.text.splitlines()[0].startswith("S/N")
    cd = r.headers["content-disposition"]
    cd.encode("latin-1")
    assert "csa-table-of-attack.csv" in cd


def test_download_csa_table_not_hibernation_gated():
    """A bogus run id 404s on run lookup, not on a hibernation gate."""
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/download/bogus_run/csa_table")
    assert r.status_code == 404
    assert "hibernated" not in r.text.lower()
