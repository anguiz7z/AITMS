"""Edge-case tests for the analysis pipeline (v0.14.1+).

These cover input shapes that the unit tests on individual engines don't
exercise — e.g. a system with zero dataflows, with a self-loop, with
unicode names, with very long descriptions. Catches engine-level bugs
that show up only at the workflow seam.
"""

from __future__ import annotations

import json

import pytest
import yaml

from atms.models import Component, Dataflow, System
from atms.workflow import analyze


# ───────────────────────────────────────────────────────────── Empty / minimal
def test_workflow_handles_zero_dataflow_system():
    """A system with components but no dataflows should still analyse."""
    sys_obj = System(
        name="zero-flow",
        components=[
            Component(id="u", name="User", type="user", trust_zone="internet"),
            Component(id="l", name="LLM", type="llm_inference", trust_zone="prod"),
        ],
    )
    tm = analyze(sys_obj)
    assert tm.threats, "expected at least one threat from playbooks"
    # No dataflows → attack paths still possible from playbook ATLAS chains
    # alone, but the test must not crash.
    assert isinstance(tm.attack_paths, list)


def test_workflow_handles_single_component():
    """A pathological one-component system — typical when a user is just
    poking the tool. Must not crash, must produce some threats."""
    sys_obj = System(
        name="solo",
        components=[Component(id="agent", name="Agent", type="agent",
                              trust_zone="prod")],
    )
    tm = analyze(sys_obj)
    assert tm.threats
    assert tm.summary["components"] == 1


def test_workflow_handles_self_loop_dataflow():
    """A self-loop dataflow (component depends on itself) is unusual but
    not illegal — e.g. an agent recursively calling its own tool."""
    sys_obj = System(
        name="self-loop",
        components=[Component(id="a", name="Agent", type="agent",
                              trust_zone="prod")],
        dataflows=[Dataflow(source="a", target="a", label="recursive call")],
    )
    tm = analyze(sys_obj)
    assert tm.threats


def test_workflow_handles_unicode_component_names():
    """Non-ASCII component names must round-trip cleanly through the
    pipeline + Mermaid rendering + YAML serialisation."""
    sys_obj = System(
        name="ユニコード",
        components=[
            Component(id="a", name="エージェント", type="agent",
                      trust_zone="prod"),
            Component(id="u", name="user-α", type="user", trust_zone="internet"),
        ],
    )
    tm = analyze(sys_obj)
    assert tm.threats
    # Serialise + deserialise the resulting model — Pydantic round-trip
    out = tm.model_dump_json()
    assert "ユニコード" in out


def test_workflow_handles_very_long_description():
    """A description close to the 1000-char cap must pass; one over the
    cap should be rejected by Pydantic with a clear error."""
    sys_obj = System(
        name="long",
        components=[
            Component(id="a", name="Agent", type="agent",
                      description="x" * 999, trust_zone="prod"),
        ],
    )
    # 999 chars — within cap
    tm = analyze(sys_obj)
    assert tm.threats
    # 1001 chars — should fail validation
    with pytest.raises(Exception):
        Component(id="a", name="Agent", type="agent",
                  description="x" * 1001, trust_zone="prod")


# ───────────────────────────────────────────────────────────── OTM round-trip
@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4
def test_otm_round_trip_preserves_components_and_threats():
    """parse_otm(render_otm(model)) → System equivalent to the original.
    Catches OTM-export drift when new Threat fields are added."""
    from pathlib import Path

    from atms.ingest.otm import parse_otm
    from atms.reporting.otm_export import render_otm

    raw = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "samples" / "rag_system.yaml")
        .read_text(encoding="utf-8")
    )
    sys_obj = System.model_validate(raw)
    model = analyze(sys_obj)

    otm_text = render_otm(model)
    # Must be valid JSON
    parsed = json.loads(otm_text)
    assert parsed["otmVersion"] == "0.2.0"
    assert parsed["threats"], "OTM export must include threats"

    # Round-trip the OTM through parse_otm
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(otm_text)
        p = Path(f.name)
    try:
        roundtrip = parse_otm(p)
    finally:
        p.unlink(missing_ok=True)

    # Component IDs preserved
    original_ids = {c.id for c in sys_obj.components}
    roundtrip_ids = {c.id for c in roundtrip.components}
    assert original_ids == roundtrip_ids


# ───────────────────────────────────────────────────────────── SARIF schema
def test_sarif_export_well_formed_with_minimum_fields():
    """SARIF output must have version, runs, tool.driver.name, results,
    locations[*].physicalLocation, properties — the minimum set that
    GitHub code-scanning will ingest."""
    from pathlib import Path

    from atms.reporting.sarif_export import render_sarif

    raw = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "samples" / "rag_system.yaml")
        .read_text(encoding="utf-8")
    )
    tm = analyze(System.model_validate(raw))
    sarif = json.loads(render_sarif(tm))

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"]
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ATMS"
    assert run["tool"]["driver"]["rules"]
    assert run["results"]
    for result in run["results"][:5]:
        assert "ruleId" in result
        assert "level" in result
        assert result["level"] in {"note", "warning", "error"}
        assert "message" in result
        assert "locations" in result
        # Each location should have a physicalLocation with an artifactLocation.uri
        loc = result["locations"][0]
        assert "physicalLocation" in loc
        assert "artifactLocation" in loc["physicalLocation"]
        assert loc["physicalLocation"]["artifactLocation"]["uri"]


def test_navigator_export_has_required_fields():
    """ATLAS Navigator JSON must have the structure the Navigator UI
    expects: version, name, techniques."""
    from pathlib import Path

    from atms.reporting.navigator import render_navigator

    raw = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "samples" / "rag_system.yaml")
        .read_text(encoding="utf-8")
    )
    tm = analyze(System.model_validate(raw))
    nav = json.loads(render_navigator(tm))
    # audit F016: a hybrid AI+cloud system emits a multi-layer ARRAY; every
    # layer (or the single object) must carry the Navigator structure.
    layers = nav if isinstance(nav, list) else [nav]
    assert layers
    for layer in layers:
        assert "name" in layer
        assert "techniques" in layer or "matrix" in layer.get("name", "").lower()


def test_stix_export_has_objects_array():
    """STIX 2.1 bundle must have type and objects."""
    from pathlib import Path

    from atms.reporting.stix import render_stix

    raw = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "samples" / "rag_system.yaml")
        .read_text(encoding="utf-8")
    )
    tm = analyze(System.model_validate(raw))
    stix = json.loads(render_stix(tm))
    assert stix["type"] == "bundle"
    assert stix["objects"]
    types = {o.get("type") for o in stix["objects"]}
    assert "attack-pattern" in types or "vulnerability" in types or "indicator" in types


# ───────────────────────────────────────────────────────────── Mermaid
def test_mermaid_renders_with_special_characters_in_names():
    """Component names with `[`, `]`, `&`, `<`, `>`, `|` must not break
    Mermaid output."""
    from atms.reporting.mermaid import render_mermaid
    sys_obj = System(
        name="weird-names",
        components=[
            Component(id="a", name="Agent <script>alert(1)</script>", type="agent"),
            Component(id="b", name="API & Tool [v2]", type="external_api"),
            Component(id="c", name="DB|primary", type="database"),
        ],
        dataflows=[
            Dataflow(source="a", target="b", label="call & retry"),
            Dataflow(source="b", target="c", label="<sql>"),
        ],
    )
    out = render_mermaid(sys_obj)
    assert "flowchart" in out
    # No raw `<script>` should reach the Mermaid output (would break parser)
    assert "<script>" not in out


def test_mermaid_handles_empty_system():
    """Zero-component system should still produce a parseable (if empty)
    Mermaid declaration, not crash."""
    from atms.reporting.mermaid import render_mermaid
    sys_obj = System(
        name="empty",
        components=[Component(id="x", name="x", type="other")],
    )
    out = render_mermaid(sys_obj)
    assert out  # must produce something
    assert "flowchart" in out


# ───────────────────────────────────────────────────────────── Risk + scoring
# ───────────────────────────────────────────────────────────── v0.14.2 fixes
def test_owasp_api_title_bonus_alone_no_longer_admits():
    """v0.14.2 fix: in v0.14.0 a threat title containing `apiN`
    contributed a +3 score that admitted the entry even when keyword
    overlap was 0 — the `score >= 3` clause bypassed the overlap
    threshold. v0.14.2 requires `overlap >= 2` regardless of title.

    We test the bypass directly by patching `_tokenize` to return an
    empty intersection, then confirming no admission."""
    from unittest import mock

    from atms.engines import cloud as cloud_mod
    from atms.models import Component, Threat
    components = [Component(id="agw", name="x", type="api_gateway")]
    threats = [Threat(
        id="t", component_id="agw",
        title="API10 stalking title with no real OWASP keywords here",
        description="zzzz",
        likelihood=1, impact=1,
    )]
    # Force every catalog overlap to 0 so the only signal would be the
    # title-id bonus. Pre-fix that would have admitted the entry; post-
    # fix it shouldn't.
    real_tokenize = cloud_mod._tokenize
    def empty_tokenize(t):
        if t == threats[0].title + " " + threats[0].description:
            return set()
        return real_tokenize(t)
    with mock.patch.object(cloud_mod, "_tokenize", side_effect=empty_tokenize):
        cloud_mod.enrich_with_cloud(threats, components)
    assert "API10:2023" not in threats[0].owasp_api


def test_sarif_rule_collapse_keeps_most_severe():
    """v0.14.2 fix: when two threats share a local rule_id but have
    different severities, the SARIF rule definition must take the
    more-severe variant — not first-occurrence-wins."""
    import json

    from atms.models import (
        Component,
        System,
        Threat,
        ThreatModel,
    )
    from atms.reporting.sarif_export import render_sarif
    sys_obj = System(
        name="x",
        components=[
            Component(id="a", name="A", type="agent"),
            Component(id="b", name="B", type="agent"),
        ],
    )
    threats = [
        Threat(id="a.same", component_id="a", title="low variant",
               description="low variant",
               severity="low", likelihood=2, impact=2),
        Threat(id="b.same", component_id="b", title="critical variant",
               description="critical variant",
               severity="critical", likelihood=5, impact=5),
    ]
    tm = ThreatModel(system=sys_obj, threats=threats, attack_paths=[],
                     mitigations=[], summary={})
    sarif = json.loads(render_sarif(tm))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    same_rule = next(r for r in rules if r["id"] == "same")
    assert same_rule["properties"]["severity"] == "critical"
    assert same_rule["defaultConfiguration"]["level"] == "error"


def test_quantitative_preserves_asymmetric_overrides():
    """v0.14.2 fix: setting `freq_low=10, freq_high=0` (one side
    explicit, the other unset) must keep the explicit side."""
    from atms.engines.quantitative import score_quantitative
    from atms.models import Threat
    t = Threat(id="t", component_id="c", title="x", description="x",
               likelihood=3, impact=4,
               freq_low=10.0, freq_high=0.0)
    score_quantitative([t])
    assert t.freq_low == 10.0  # author override preserved


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_otm_round_trips_prompt_template_store_type():
    """v0.14.2 fix: OTM type mapping was missing prompt_template_store
    and network_segment, so they round-tripped to `other`."""
    from atms.ingest.otm import parse_otm
    from atms.models import Component, System, ThreatModel
    from atms.reporting.otm_export import render_otm

    sys_obj = System(
        name="round-trip",
        components=[
            Component(id="ps", name="Prompt store",
                      type="prompt_template_store"),
            Component(id="ns", name="VPC private subnet",
                      type="network_segment"),
        ],
    )
    tm = ThreatModel(system=sys_obj, threats=[], attack_paths=[],
                     mitigations=[], summary={})
    otm_json = render_otm(tm)
    import tempfile
    from pathlib import Path
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write(otm_json)
        p = Path(f.name)
    try:
        rt = parse_otm(p)
    finally:
        p.unlink(missing_ok=True)
    by_id = {c.id: c.type for c in rt.components}
    assert by_id["ps"] == "prompt_template_store"
    assert by_id["ns"] == "network_segment"


def test_stix_export_includes_v0_10_to_v0_14_fields():
    """v0.14.3 fix: every framework field added since v0.9 (owasp_api,
    owasp_ml, attack_cloud, attack_enterprise, linddun, nist_ai_100_2,
    compliance_controls, kill_chain_phase, evidence_status, ALE,
    disposition, D3FEND on mitigations) now appears in STIX export."""
    import json
    from pathlib import Path

    from atms.reporting.stix import render_stix
    raw = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "samples" / "aws_bedrock_agent.yaml")
        .read_text(encoding="utf-8")
    )
    tm = analyze(System.model_validate(raw))
    stix = json.loads(render_stix(tm))
    # Find an attack-pattern that has at least one of each field set.
    aps = [o for o in stix["objects"] if o.get("type") == "attack-pattern"]
    assert aps
    # At least one AP should have v0.10+ tags (the Bedrock sample is rich)
    has_kill_chain = any(o.get("x_atms_kill_chain_phase") for o in aps)
    has_evidence_status = any(
        o.get("x_atms_evidence_status") for o in aps
    )
    has_compliance = any(o.get("x_atms_compliance_controls") for o in aps)
    has_ale = any(o.get("x_atms_ale_high", 0) > 0 for o in aps)
    assert has_kill_chain, "STIX must surface kill_chain_phase"
    assert has_evidence_status
    assert has_compliance
    assert has_ale, "STIX must surface ALE high"
    # Course-of-action gets D3FEND
    coas = [o for o in stix["objects"] if o.get("type") == "course-of-action"]
    assert coas
    has_d3fend = any(o.get("x_atms_d3fend") for o in coas)
    assert has_d3fend, "STIX must surface D3FEND on course-of-action"


def test_stix_external_references_include_attack_enterprise():
    """v0.14.3 fix: STIX external_references now include attack_cloud
    and attack_enterprise URLs, not just ATLAS / OWASP / MAESTRO."""
    import json
    from pathlib import Path

    from atms.reporting.stix import render_stix
    raw = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "samples" / "it_ot_factory.yaml")
        .read_text(encoding="utf-8")
    )
    tm = analyze(System.model_validate(raw))
    stix = json.loads(render_stix(tm))
    aps = [o for o in stix["objects"] if o.get("type") == "attack-pattern"]
    sources = set()
    for ap in aps:
        for ref in ap.get("external_references", []) or []:
            sources.add(ref.get("source_name", ""))
    assert "mitre-attack" in sources
    assert "atms-compliance" in sources or "csa-maestro-2026" in sources


def test_mermaid_safe_id_distinguishes_unicode_names():
    """v0.14.2 fix: two distinct non-ASCII names must produce
    distinct Mermaid ids."""
    from atms.reporting.mermaid import _safe_id
    a = _safe_id("ユーザー")
    b = _safe_id("ユーザ")
    assert a != b


def test_tool_version_in_threat_model_matches_package_version():
    """v0.14.4 fix: ThreatModel.tool_version was hard-coded to "0.2.0";
    every report leaked that. Now resolves to the live __version__."""
    from atms import __version__
    from atms.models import System, ThreatModel
    sys_obj = System(name="x", components=[])
    tm = ThreatModel(system=sys_obj, threats=[], attack_paths=[],
                     mitigations=[], summary={})
    assert tm.tool_version == __version__


def test_cli_friendly_error_on_non_utf8_yaml(tmp_path):
    """v0.14.4 fix: a non-UTF-8 file passed to `atms analyze` must
    produce a friendly one-line error, not a stack trace."""
    from click.testing import CliRunner

    from atms.cli import cli
    p = tmp_path / "bad.yaml"
    # Write Latin-1 bytes that aren't valid UTF-8.
    p.write_bytes(b"\xca\xff\xfe garbage")
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", str(p)])
    assert res.exit_code == 2
    assert "not UTF-8" in res.output or "could not read" in res.output.lower()
    assert "Traceback" not in res.output


def test_cli_friendly_error_on_malformed_yaml(tmp_path):
    """v0.14.4 fix: malformed-but-text YAML produces a friendly error."""
    from click.testing import CliRunner

    from atms.cli import cli
    p = tmp_path / "broken.yaml"
    p.write_text("name: tiny\ncomponents:\n  -- broken: : :\n", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", str(p)])
    assert res.exit_code == 2
    assert "Malformed YAML" in res.output or "Invalid System" in res.output
    assert "Traceback" not in res.output


def test_cli_friendly_error_on_empty_yaml(tmp_path):
    """v0.14.4 fix: empty YAML must produce a friendly error."""
    from click.testing import CliRunner

    from atms.cli import cli
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", str(p)])
    assert res.exit_code == 2
    assert "Empty YAML" in res.output


@pytest.mark.hibernated  # v0.18.70 Hibernation Phase 3


def test_redteam_ingest_friendly_error_on_missing_file(client_module_scope):
    """v0.14.4 fix: missing artefact_file returns a friendly HTML page,
    not FastAPI's default 422 JSON."""
    yaml_text = yaml.safe_dump({"name": "x", "components": [
        {"id": "u", "name": "U", "type": "user"}]})
    # Submit without an artefact_file field at all.
    r = client_module_scope.post(
        "/redteam/ingest",
        data={"yaml_text": yaml_text, "methodology": "stride-ai"},
    )
    assert r.status_code == 400
    body = r.text.lower()
    assert "html" in (r.headers.get("content-type") or "").lower()
    assert "attach" in body or "red-team artefact" in body


def test_risk_scoring_clamps_likelihood_and_impact():
    """Likelihood / impact are bounded 1..5 by Pydantic — out-of-range
    values must raise."""
    from atms.models import Threat
    with pytest.raises(Exception):
        Threat(id="t", component_id="c", title="x", description="x",
               likelihood=6, impact=3)
    with pytest.raises(Exception):
        Threat(id="t", component_id="c", title="x", description="x",
               likelihood=0, impact=3)


def test_workflow_drops_duplicate_threat_ids(caplog):
    """v0.14.7: if two threats end up with the same ID (e.g. a playbook
    author copy-pasted), workflow drops later occurrences and logs a
    warning. STIX export collapses duplicate UUIDs silently — the
    deduplication makes that intent explicit."""
    import logging

    from atms.engines.stride_ai import enumerate_threats
    # We can't easily inject a duplicate via the public stride_ai engine
    # (it always derives `{comp.id}.{threat.id}`), so directly exercise
    # the dedup branch in `analyze` by stubbing enumerate_threats.
    sys_obj = System(name="dup", components=[
        Component(id="u", name="U", type="user", trust_zone="internet"),
        Component(id="l", name="L", type="llm_inference", trust_zone="prod"),
    ])
    real = enumerate_threats
    def stubbed(components, kb=None, **kwargs):
        ts = real(components, kb=kb, **kwargs)
        # Force a duplicate ID by appending a clone of the first threat
        if ts:
            clone = ts[0].model_copy()
            ts.append(clone)
        return ts
    import atms.workflow as wf
    original = wf.enumerate_threats
    wf.enumerate_threats = stubbed
    try:
        with caplog.at_level(logging.WARNING):
            tm = wf.analyze(sys_obj)
    finally:
        wf.enumerate_threats = original
    ids = [t.id for t in tm.threats]
    assert len(ids) == len(set(ids)), "duplicates must be dropped"
    assert any("duplicate ID" in rec.message for rec in caplog.records)


def test_navigator_falls_back_to_enterprise_for_cloud_only_systems():
    """v0.14.7: a cloud-leaning AI system (LLM + DB + IAM) has plenty of
    ATT&CK Cloud / Enterprise IDs but few ATLAS. Render Navigator should
    switch domain to enterprise-attack instead of emitting an empty
    ATLAS layer.

    v0.15.0: now requires at least one AI primary in the system — the
    AI-scope gate rejects pure-IT systems. Adding an `llm_inference`
    keeps the test in scope while still exercising the cloud-bias path.
    """
    import json as _json

    from atms.reporting.navigator import render_navigator
    sys_obj = System(name="cloud-only", components=[
        Component(id="llm", name="LLM", type="llm_inference", trust_zone="prod"),
        Component(id="db", name="DB", type="database", trust_zone="prod"),
        Component(id="iam", name="IAM", type="iam_principal", trust_zone="prod"),
    ])
    tm = analyze(sys_obj)
    # Strip ATLAS techniques to simulate a pure-cloud system.
    for t in tm.threats:
        t.atlas_techniques = []
    layer = _json.loads(render_navigator(tm))
    assert layer["domain"] == "enterprise-attack"
    # And it must contain at least one technique row, otherwise the
    # fallback was useless.
    assert len(layer["techniques"]) > 0


def test_match_evidence_cidr_routes_to_component_with_ip():
    """v0.14.8: a Nessus CIDR `affected_asset=10.0.0.0/24` must route to a
    component whose `metadata.ip=10.0.0.5`. Previously the exact-string
    compare missed all CIDR-shaped rows."""
    from atms.evidence.matcher import match_evidence
    from atms.models import Component, Evidence
    components = [
        Component(id="c1", name="Web", type="web_application",
                  metadata={"ip": "10.0.0.5"}),
        Component(id="c2", name="DB", type="database",
                  metadata={"ip": "192.168.1.10"}),
    ]
    ev = Evidence(source="vapt", source_type="nessus", source_id="x",
                  title="CVE", description="x", affected_asset="10.0.0.0/24")
    pairs = match_evidence([ev], components)
    assert len(pairs) == 1
    matched = pairs[0][1]
    assert any(c.id == "c1" for c in matched), "10.0.0.5 must match the CIDR"
    assert not any(c.id == "c2" for c in matched), "192.168.1.10 outside CIDR"


def test_match_evidence_cidr_overlap_with_component_cidr():
    """v0.14.8: when a component declares its OWN CIDR (network_segment), an
    evidence CIDR that overlaps it must match."""
    from atms.evidence.matcher import match_evidence
    from atms.models import Component, Evidence
    components = [
        Component(id="seg", name="Prod subnet", type="network_segment",
                  metadata={"cidr": "10.0.0.0/16"}),
    ]
    ev = Evidence(source="vapt", source_type="nessus", source_id="x",
                  title="CVE", description="x", affected_asset="10.0.5.0/24")
    pairs = match_evidence([ev], components)
    assert len(pairs) == 1
    assert pairs[0][1] and pairs[0][1][0].id == "seg"


def test_sarif_short_description_capped_at_256():
    """v0.14.8: GitHub code-scanning rejects SARIF whose
    `shortDescription.text` exceeds spec limits. Cap at 256 chars."""
    import json as _json

    from atms.models import Component, System, Threat, ThreatModel
    from atms.reporting.sarif_export import render_sarif
    long_title = "X" * 500
    sys_obj = System(name="t", components=[
        Component(id="u", name="U", type="user")])
    tm = ThreatModel(
        system=sys_obj,
        threats=[Threat(id="u.T1", component_id="u",
                        title=long_title, description="d",
                        likelihood=3, impact=3)],
        attack_paths=[], mitigations=[], summary={},
    )
    out = _json.loads(render_sarif(tm))
    rules = out["runs"][0]["tool"]["driver"]["rules"]
    assert rules
    assert len(rules[0]["shortDescription"]["text"]) <= 256
