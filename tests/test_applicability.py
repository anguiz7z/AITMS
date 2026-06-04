"""Tests for v0.16.0 applicability-predicate engine.

The applicability gate closes false positives where a per-component
playbook fires threats indiscriminately on every instance of a
component type, even when the threat is structurally inapplicable:

* Amazon Cognito inheriting Active-Directory Kerberoast threats.
* AWS WAF / CloudFront / Cloud Armor picking up F5 BIG-IP and Palo
  Alto firmware-CVE threats.
* A single-orchestrator system inheriting "rogue agent in multi-agent
  system" without any peer agents being modelled.

The gate evaluates ``requires``, ``not_applicable_to``, and
``applicable_to_topology`` on each playbook threat. Threats without
any of these blocks emit unchanged (back-compat).
"""

from __future__ import annotations

from atms.engines.applicability import (
    has_multi_agent,
    has_outbound_internet,
    threat_applies,
)
from atms.engines.stride_ai import enumerate_threats
from atms.models import Component, Dataflow, System


# ─── Direct predicate tests ────────────────────────────────────────────────
def test_requires_match_emits():
    """A `requires` block whose fields all match the component → emit."""
    threat = {
        "id": "X",
        "requires": {
            "component_type": "directory_service",
            "metadata.idp_kind": ["active_directory", "ldap"],
        },
    }
    comp = Component(
        id="ad", name="AD", type="directory_service",
        metadata={"idp_kind": "active_directory"},
    )
    sys_obj = System(name="t", components=[comp])
    should_emit, reason = threat_applies(threat, comp, sys_obj)
    assert should_emit is True
    assert reason == ""


def test_requires_mismatch_suppresses():
    """A `requires` block with at least one mismatched field → suppress."""
    threat = {
        "id": "X",
        "requires": {"metadata.idp_kind": ["active_directory"]},
    }
    comp = Component(
        id="idp", name="IdP", type="directory_service",
        metadata={"idp_kind": "cognito"},
    )
    sys_obj = System(name="t", components=[comp])
    should_emit, reason = threat_applies(threat, comp, sys_obj)
    assert should_emit is False
    assert "requires" in reason
    assert "idp_kind" in reason


def test_not_applicable_to_match_suppresses_with_reason():
    """`not_applicable_to` match → suppress, reason mentions the field."""
    threat = {
        "id": "X",
        "not_applicable_to": {
            "metadata.vendor": ["AWS", "Microsoft", "Google"],
        },
    }
    comp = Component(
        id="fw", name="AWS WAF", type="firewall",
        metadata={"vendor": "AWS", "deployment_mode": "managed_service"},
    )
    sys_obj = System(name="t", components=[comp])
    should_emit, reason = threat_applies(threat, comp, sys_obj)
    assert should_emit is False
    assert "vendor" in reason
    assert "AWS" in reason


def test_not_applicable_to_mismatch_and_no_requires_emits():
    """`not_applicable_to` with no match, and no `requires` → emit."""
    threat = {
        "id": "X",
        "not_applicable_to": {"metadata.vendor": ["AWS"]},
    }
    comp = Component(
        id="fw", name="On-prem FW", type="firewall",
        metadata={"vendor": "Palo Alto Networks"},
    )
    sys_obj = System(name="t", components=[comp])
    should_emit, reason = threat_applies(threat, comp, sys_obj)
    assert should_emit is True
    assert reason == ""


# ─── End-to-end: playbook integration ──────────────────────────────────────
def test_cognito_directory_service_suppresses_kerberoast():
    """Amazon Cognito (a managed cloud IdP) must NOT inherit
    Active-Directory credential-theft / Golden-Ticket / GPO-modification
    threats. This is the canonical v0.16 regression."""
    sys_obj = System(name="cognito-app", components=[
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(
            id="idp", name="Cognito", type="directory_service",
            metadata={"idp_kind": "cognito", "vendor": "AWS"},
        ),
    ], dataflows=[
        Dataflow(source="llm", target="idp", label="auth"),
    ])
    threats = enumerate_threats(sys_obj.components, system=sys_obj)
    idp_threat_ids = {
        t.id.rsplit(".", 1)[-1]
        for t in threats if t.component_id == "idp"
    }
    assert "T_DIR_001" not in idp_threat_ids, (
        "Kerberoast must not fire on Cognito"
    )
    assert "T_DIR_002" not in idp_threat_ids, (
        "Golden Ticket must not fire on Cognito"
    )
    assert "T_DIR_004" not in idp_threat_ids, (
        "GPO modification must not fire on Cognito"
    )
    # The generic / cloud-IdP-applicable ones (T_DIR_003 stale accounts)
    # should still emit — orphaned accounts apply to any IdP.
    assert "T_DIR_003" in idp_threat_ids


def test_aws_waf_firewall_suppresses_firmware_threat():
    """AWS WAF / Network Firewall is a managed service — the customer
    can't patch firmware. T_FW_002 must be suppressed."""
    sys_obj = System(name="waf-app", components=[
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(
            id="fw", name="AWS WAF", type="firewall",
            metadata={"vendor": "AWS", "deployment_mode": "managed_service"},
        ),
    ], dataflows=[
        Dataflow(source="llm", target="fw", label="egress"),
    ])
    threats = enumerate_threats(sys_obj.components, system=sys_obj)
    fw_threat_ids = {
        t.id.rsplit(".", 1)[-1]
        for t in threats if t.component_id == "fw"
    }
    assert "T_FW_002" not in fw_threat_ids, (
        "Firmware-CVE threat must not fire on AWS WAF"
    )
    # But over-permissive rules + missing logs still apply.
    assert "T_FW_001" in fw_threat_ids
    assert "T_FW_003" in fw_threat_ids


def test_cloudfront_load_balancer_suppresses_f5_firmware_threat():
    """CloudFront / Cloud Armor / managed CDNs must not pick up
    F5 BIG-IP firmware-RCE threats — they don't ship firmware."""
    sys_obj = System(name="cdn-app", components=[
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(
            id="cdn", name="CloudFront", type="load_balancer",
            metadata={"vendor": "AWS", "deployment_mode": "cdn"},
        ),
    ], dataflows=[
        Dataflow(source="cdn", target="llm", label="proxy"),
    ])
    threats = enumerate_threats(sys_obj.components, system=sys_obj)
    cdn_threat_ids = {
        t.id.rsplit(".", 1)[-1]
        for t in threats if t.component_id == "cdn"
    }
    assert "T_LB_001" not in cdn_threat_ids, (
        "F5 firmware threat must not fire on CloudFront"
    )
    # TLS misconfiguration + smuggling are still relevant.
    assert "T_LB_002" in cdn_threat_ids


def test_single_orchestrator_suppresses_rogue_agent_threat():
    """A single-agent system has no peer agents → 'rogue agent in
    multi-agent system' (T_AGENT_008) is structurally inapplicable."""
    sys_obj = System(name="solo", components=[
        Component(id="user", name="User", type="user"),
        Component(id="orch", name="Orchestrator", type="agent"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ], dataflows=[
        Dataflow(source="user", target="orch", label="task"),
        Dataflow(source="orch", target="llm", label="call"),
    ])
    threats = enumerate_threats(sys_obj.components, system=sys_obj)
    agent_threat_ids = {
        t.id.rsplit(".", 1)[-1]
        for t in threats if t.component_id == "orch"
    }
    assert "T_AGENT_008" not in agent_threat_ids, (
        "Single-orchestrator system must not get rogue-agent threat"
    )
    # The other agent threats still fire.
    assert "T_AGENT_001" in agent_threat_ids
    assert "T_AGENT_002" in agent_threat_ids


def test_multi_agent_mesh_emits_rogue_agent_threat():
    """A system with >1 agent triggers the topology predicate, so
    T_AGENT_008 emits on each agent component."""
    sys_obj = System(name="mesh", components=[
        Component(id="user", name="User", type="user"),
        Component(id="planner", name="Planner", type="agent"),
        Component(id="executor", name="Executor", type="agent"),
        Component(id="critic", name="Critic", type="agent"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ], dataflows=[
        Dataflow(source="user", target="planner", label="task"),
        Dataflow(source="planner", target="executor", label="plan"),
        Dataflow(source="executor", target="critic", label="output"),
        Dataflow(source="planner", target="llm", label="call"),
    ])
    threats = enumerate_threats(sys_obj.components, system=sys_obj)
    planner_threat_ids = {
        t.id.rsplit(".", 1)[-1]
        for t in threats if t.component_id == "planner"
    }
    assert "T_AGENT_008" in planner_threat_ids, (
        "Multi-agent mesh must emit rogue-agent threat"
    )


# ─── Topology predicates direct ────────────────────────────────────────────
def test_has_multi_agent_predicate():
    """The multi-agent predicate counts agent-typed components."""
    one_agent = System(name="solo", components=[
        Component(id="a", name="A", type="agent"),
        Component(id="l", name="L", type="llm_inference"),
    ])
    two_agents = System(name="mesh", components=[
        Component(id="a", name="A", type="agent"),
        Component(id="b", name="B", type="agent"),
    ])
    assert has_multi_agent(one_agent) is False
    assert has_multi_agent(two_agents) is True


def test_has_outbound_internet_predicate_default_true_for_agent():
    """An agent-bearing system has outbound internet by default
    (conservative — we don't suppress threats unless explicitly told)."""
    sys_obj = System(name="x", components=[
        Component(id="a", name="A", type="agent"),
    ])
    assert has_outbound_internet(sys_obj) is True


def test_back_compat_threat_without_predicates_emits():
    """Playbook threats that don't declare any predicates emit
    unchanged — full backwards compatibility with v0.15 KB."""
    threat = {"id": "X"}  # No requires, no not_applicable_to.
    comp = Component(id="c", name="C", type="database")
    sys_obj = System(name="t", components=[comp])
    should_emit, reason = threat_applies(threat, comp, sys_obj)
    assert should_emit is True
    assert reason == ""


def test_case_insensitive_string_match():
    """String value comparison is case-insensitive on both sides."""
    threat = {
        "id": "X",
        "requires": {"metadata.idp_kind": "active_directory"},
    }
    comp = Component(
        id="ad", name="AD", type="directory_service",
        metadata={"idp_kind": "Active_Directory"},
    )
    sys_obj = System(name="t", components=[comp])
    should_emit, _ = threat_applies(threat, comp, sys_obj)
    assert should_emit is True
