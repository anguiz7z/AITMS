"""End-to-end false-positive gating regression tests (via `analyze`).

The v0.16 applicability-predicate engine closes a recurring false-positive
class where per-component playbooks fire threats indiscriminately for every
instance of a component type, even when the threat is structurally
inapplicable. `tests/test_applicability.py` already exercises the engine
(`enumerate_threats`) and the bare predicate helpers directly; THIS module
locks the same fixes in at the *public* boundary — the `analyze()` workflow
that the CLI and web UI both call — so a regression anywhere in the
enumerate → enrich → score pipeline that re-introduced a suppressed threat
would be caught.

Every system below includes an AI primary (an `llm_inference` or `agent`)
plus a dataflow that places the gated infrastructure component inside the
AI blast radius, so:
  * the AI-scope gate passes (no NoAIComponentsError), and
  * the non-AI component is classified `adjacent` (not `out_of_scope`)
    and therefore actually emits its playbook threats — which is what
    makes the negative ("must NOT fire") assertions meaningful rather
    than vacuously true.

Threat IDs/titles asserted here were read from the live playbooks:
  * kb/playbooks/directory_service.yaml — T_DIR_001 (Kerberoast/DCSync/
    Pass-the-Hash), T_DIR_002 (Golden Ticket), T_DIR_004 (GPO abuse),
    T_DIR_003 (stale accounts — applies to any IdP).
  * kb/playbooks/firewall.yaml — T_FW_002 (outdated firmware / mgmt-plane CVE),
    gated to appliance/virtual_appliance; T_FW_001/T_FW_003 always apply.
  * kb/playbooks/load_balancer.yaml — T_LB_001 (outdated firmware / F5 BIG-IP),
    gated to appliance/virtual_appliance; T_LB_002 (TLS) always applies.
  * kb/playbooks/agent.yaml — T_AGENT_008 (rogue agent in multi-agent system),
    gated to `applicable_to_topology: [multi_agent_mesh]`.
"""

from __future__ import annotations

from atms.models import Component, Dataflow, System
from atms.workflow import analyze


# ─── Helpers ───────────────────────────────────────────────────────────────
def _short_ids_for(tm, component_id: str) -> set[str]:
    """Return the bare playbook IDs (the part after `{component_id}.`) of
    every threat `analyze` emitted for the given component."""
    return {
        t.id.rsplit(".", 1)[-1]
        for t in tm.threats
        if t.component_id == component_id
    }


def _titles_for(tm, component_id: str) -> set[str]:
    return {t.title for t in tm.threats if t.component_id == component_id}


# ───────────────────────────────────────────────────────────────────────────
# (a) directory_service: AD-family threats only fire on AD-shaped IdPs
# ───────────────────────────────────────────────────────────────────────────
# The three AD-only threats. T_DIR_001 fires on active_directory OR ldap;
# T_DIR_002/T_DIR_004 require active_directory specifically.
_AD_THREAT_IDS = {"T_DIR_001", "T_DIR_002", "T_DIR_004"}


def _directory_system(idp_kind: str) -> System:
    """Minimal AI system whose IdP sits in the LLM's blast radius."""
    return System(
        name=f"dir-{idp_kind}",
        components=[
            Component(id="llm", name="Chat LLM", type="llm_inference"),
            Component(
                id="idp",
                name=f"IdP ({idp_kind})",
                type="directory_service",
                metadata={"idp_kind": idp_kind},
            ),
        ],
        dataflows=[Dataflow(source="idp", target="llm", label="authn")],
    )


def test_cognito_directory_service_no_ad_threats():
    """A directory_service tagged idp_kind=cognito must NOT inherit the
    Active-Directory credential-theft / Golden-Ticket / GPO threats."""
    tm = analyze(_directory_system("cognito"))
    idp_ids = _short_ids_for(tm, "idp")
    assert idp_ids, "Cognito IdP should still be in scope and emit *some* threats"
    assert _AD_THREAT_IDS.isdisjoint(idp_ids), (
        f"AD-only threats leaked onto a Cognito IdP: "
        f"{sorted(_AD_THREAT_IDS & idp_ids)}"
    )
    # Kerberoast title must not appear either (belt-and-braces on title).
    assert "Credential theft + replay (Kerberoast / DCSync / Pass-the-Hash)" \
        not in _titles_for(tm, "idp")
    # The IdP-agnostic stale-account threat SHOULD still fire — proving the
    # component is genuinely analysed, not wholesale dropped.
    assert "T_DIR_003" in idp_ids


def test_entra_id_directory_service_no_ad_threats():
    """Entra ID is also a managed cloud IdP — same suppression as Cognito.
    Covers the second metadata value called out in the audit."""
    tm = analyze(_directory_system("entra_id"))
    idp_ids = _short_ids_for(tm, "idp")
    assert idp_ids
    assert _AD_THREAT_IDS.isdisjoint(idp_ids), (
        f"AD-only threats leaked onto an Entra ID IdP: "
        f"{sorted(_AD_THREAT_IDS & idp_ids)}"
    )
    assert "T_DIR_003" in idp_ids


def test_active_directory_directory_service_emits_ad_threats():
    """The on-prem Active-Directory case is the positive control: every
    AD-only threat MUST fire here, or the gate is over-suppressing."""
    tm = analyze(_directory_system("active_directory"))
    idp_ids = _short_ids_for(tm, "idp")
    assert _AD_THREAT_IDS.issubset(idp_ids), (
        f"Active Directory is missing AD threats it should emit: "
        f"{sorted(_AD_THREAT_IDS - idp_ids)}"
    )
    # And the canonical Kerberoast title is present.
    assert "Credential theft + replay (Kerberoast / DCSync / Pass-the-Hash)" \
        in _titles_for(tm, "idp")


# ───────────────────────────────────────────────────────────────────────────
# (b) firewall / load_balancer: 'outdated firmware' / F5 BIG-IP threat only
#     fires on self-managed (appliance/virtual_appliance) deployments, not on
#     managed-service / cloud / CDN deployments.
# ───────────────────────────────────────────────────────────────────────────
def _firewall_system(metadata: dict) -> System:
    return System(
        name="fw-sys",
        components=[
            Component(id="llm", name="Chat LLM", type="llm_inference"),
            Component(id="fw", name="Edge Firewall", type="firewall",
                      metadata=metadata),
        ],
        dataflows=[Dataflow(source="fw", target="llm", label="ingress")],
    )


def _load_balancer_system(metadata: dict) -> System:
    return System(
        name="lb-sys",
        components=[
            Component(id="llm", name="Chat LLM", type="llm_inference"),
            Component(id="lb", name="Front LB", type="load_balancer",
                      metadata=metadata),
        ],
        dataflows=[Dataflow(source="lb", target="llm", label="proxy")],
    )


def test_managed_firewall_no_firmware_threat():
    """AWS-managed firewall (managed_service): the vendor patches firmware,
    so the 'outdated firmware / mgmt-plane CVE' threat (T_FW_002) must be
    suppressed — while the deployment-agnostic threats still fire."""
    tm = analyze(_firewall_system(
        {"vendor": "AWS", "deployment_mode": "managed_service"}
    ))
    fw_ids = _short_ids_for(tm, "fw")
    assert "T_FW_002" not in fw_ids, (
        "Firmware-CVE threat must not fire on a managed cloud firewall"
    )
    assert "Outdated firmware / known CVE on management plane" \
        not in _titles_for(tm, "fw")
    # Over-permissive rule + missing-logging threats are deployment-agnostic.
    assert {"T_FW_001", "T_FW_003"}.issubset(fw_ids), (
        f"managed firewall lost its always-applicable threats: {sorted(fw_ids)}"
    )


def test_onprem_firewall_emits_firmware_threat():
    """A self-managed appliance firewall (e.g. Palo Alto NGFW) ships firmware
    the customer must patch — T_FW_002 MUST fire (positive control)."""
    tm = analyze(_firewall_system(
        {"vendor": "Palo Alto Networks", "deployment_mode": "appliance"}
    ))
    fw_ids = _short_ids_for(tm, "fw")
    assert "T_FW_002" in fw_ids, (
        "On-prem appliance firewall must emit the firmware-CVE threat"
    )
    assert "Outdated firmware / known CVE on management plane" \
        in _titles_for(tm, "fw")


def test_managed_load_balancer_no_f5_firmware_threat():
    """A managed cloud LB / CDN (CloudFront, deployment_mode=cdn) does not
    ship customer-patchable firmware, so the F5 BIG-IP firmware-RCE threat
    (T_LB_001) must be suppressed."""
    tm = analyze(_load_balancer_system(
        {"vendor": "AWS", "deployment_mode": "cdn"}
    ))
    lb_ids = _short_ids_for(tm, "lb")
    assert "T_LB_001" not in lb_ids, (
        "F5 BIG-IP firmware threat must not fire on a managed cloud LB / CDN"
    )
    assert "Outdated load-balancer firmware (vendor CVEs)" \
        not in _titles_for(tm, "lb")
    # TLS-misconfig threat is deployment-agnostic and should still fire.
    assert "T_LB_002" in lb_ids, (
        f"managed LB lost its always-applicable TLS threat: {sorted(lb_ids)}"
    )


def test_onprem_load_balancer_emits_f5_firmware_threat():
    """A self-managed F5 BIG-IP appliance MUST emit the firmware-RCE threat
    (T_LB_001) — positive control for the gate."""
    tm = analyze(_load_balancer_system(
        {"vendor": "F5", "deployment_mode": "appliance"}
    ))
    lb_ids = _short_ids_for(tm, "lb")
    assert "T_LB_001" in lb_ids, (
        "On-prem F5 BIG-IP appliance must emit the firmware-RCE threat"
    )
    assert "Outdated load-balancer firmware (vendor CVEs)" \
        in _titles_for(tm, "lb")


# ───────────────────────────────────────────────────────────────────────────
# (c) agent: T_AGENT_008 'rogue agent in multi-agent system' only fires when
#     the system topology is a multi-agent mesh (>1 agent component).
# ───────────────────────────────────────────────────────────────────────────
def test_single_agent_no_rogue_agent_threat():
    """A single-agent (orchestrator-only) system has no peer agents, so
    'rogue agent in multi-agent system' (T_AGENT_008) is structurally
    inapplicable and must NOT fire."""
    sys_obj = System(
        name="solo-agent",
        components=[
            Component(id="user", name="User", type="user"),
            Component(id="orch", name="Orchestrator", type="agent"),
            Component(id="llm", name="Backing LLM", type="llm_inference"),
        ],
        dataflows=[
            Dataflow(source="user", target="orch", label="task"),
            Dataflow(source="orch", target="llm", label="invoke"),
        ],
    )
    tm = analyze(sys_obj)
    orch_ids = _short_ids_for(tm, "orch")
    assert orch_ids, "the single agent should still emit its own threats"
    assert "T_AGENT_008" not in orch_ids, (
        "single-agent system must not emit the multi-agent rogue-agent threat"
    )
    assert "Rogue agent in multi-agent system / infectious backdoor" \
        not in _titles_for(tm, "orch")


def test_multi_agent_mesh_emits_rogue_agent_threat():
    """A system with >1 agent satisfies the multi_agent_mesh topology
    predicate, so T_AGENT_008 fires on the agent components (positive
    control)."""
    sys_obj = System(
        name="agent-mesh",
        components=[
            Component(id="user", name="User", type="user"),
            Component(id="planner", name="Planner", type="agent"),
            Component(id="executor", name="Executor", type="agent"),
            Component(id="llm", name="Backing LLM", type="llm_inference"),
        ],
        dataflows=[
            Dataflow(source="user", target="planner", label="task"),
            Dataflow(source="planner", target="executor", label="plan"),
            Dataflow(source="planner", target="llm", label="invoke"),
        ],
    )
    tm = analyze(sys_obj)
    planner_ids = _short_ids_for(tm, "planner")
    assert "T_AGENT_008" in planner_ids, (
        "multi-agent mesh must emit the rogue-agent threat on the planner"
    )
    assert "Rogue agent in multi-agent system / infectious backdoor" \
        in _titles_for(tm, "planner")
    # It fires per agent component, not just one.
    assert "T_AGENT_008" in _short_ids_for(tm, "executor")
