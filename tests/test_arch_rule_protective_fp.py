"""Defensibility regressions: protective / access-mediation appliances and
downstream SaaS providers must not be treated as untrusted Internet actors
(audit F025/F026/F027/F028).

v1.0.5 made _is_external_facing zone-aware for users; it still classified a
WAF / load-balancer / VPN-gateway placed in a DMZ ('external'-labelled) zone
as the untrusted source, flagging the tier behind it -- the textbook
"recommend the control that's already present" false positive. These pin the
fix while keeping the genuine positives (a user reaching a DB directly).
"""

from __future__ import annotations

from atms.engines.architectural_rules import (
    _fire_direct_datastore_access,
    _fire_missing_network_segmentation,
    _fire_unguarded_internet,
    _is_external_facing,
)
from atms.models import Component, Dataflow, System


def _sys(components, dataflows=()):
    return System(name="t", components=list(components), dataflows=list(dataflows))


def test_protective_appliance_in_dmz_is_not_external_facing():
    for typ in ("waf", "load_balancer", "reverse_proxy", "vpn_gateway",
                "bastion_host", "private_link", "network_access_control"):
        c = Component(id="g", name="G", type=typ, trust_zone="dmz_external")
        assert _is_external_facing(c) is False, f"{typ} in dmz_external must not be untrusted"


def test_web_app_behind_waf_not_flagged_internet_reachable():
    """F025: a WAF in a dmz_external zone must not make the web app behind it
    'directly reachable from the Internet'."""
    s = _sys(
        [Component(id="u", name="User", type="user", trust_zone="internet"),
         Component(id="waf", name="WAF", type="waf", trust_zone="dmz_external"),
         Component(id="web", name="web", type="web_application", trust_zone="app"),
         Component(id="db", name="db", type="database", trust_zone="data")],
        [Dataflow(source="u", target="waf", label="https"),
         Dataflow(source="waf", target="web", label="https"),
         Dataflow(source="web", target="db", label="query")],
    )
    assert [c.id for c, _ in _fire_unguarded_internet(s)] == []


def test_vpn_gateway_not_flagged_as_internet_reachable_subject():
    """F026: a VPN gateway / bastion is the access-mediation control, not an
    'unguarded Internet-reachable sensitive component'."""
    s = _sys(
        [Component(id="u", name="Vendor", type="user", trust_zone="internet"),
         Component(id="vpn", name="VPN", type="vpn_gateway", trust_zone="dmz_external"),
         Component(id="hist", name="Historian", type="database", trust_zone="ot")],
        [Dataflow(source="u", target="vpn", label="TLS (MFA enforced)"),
         Dataflow(source="vpn", target="hist", label="read")],
    )
    fired = {c.id for c, _ in _fire_unguarded_internet(s)}
    assert "vpn" not in fired


def test_downstream_llm_provider_response_is_not_an_internet_path():
    """F027: a managed model provider (external_provider zone) RESPONDING to
    the orchestrator is an egress dependency, not an inbound Internet attack."""
    s = _sys(
        [Component(id="orch", name="Orchestrator", type="agent", trust_zone="corp_dmz"),
         Component(id="llm", name="Anthropic API", type="llm_inference",
                   trust_zone="external_provider")],
        [Dataflow(source="orch", target="llm", label="prompt"),
         Dataflow(source="llm", target="orch", label="completion")],
    )
    assert [c.id for c, _ in _fire_unguarded_internet(s)] == []


def test_datastore_behind_load_balancer_not_directly_exposed():
    """F028: a DB whose only inbound is a load-balancer/proxy in a DMZ is
    fronted, not 'reachable directly from an untrusted source'."""
    s = _sys(
        [Component(id="lb", name="LB", type="load_balancer", trust_zone="external_dmz"),
         Component(id="db", name="Session DB", type="database", trust_zone="data")],
        [Dataflow(source="lb", target="db", label="session")],
    )
    assert [c.id for c, _ in _fire_direct_datastore_access(s)] == []
    # ...and a cache co-located with the proxy is not "co-located with an
    # external-facing component" when the only such component is the proxy.
    s2 = _sys(
        [Component(id="rp", name="RP", type="reverse_proxy", trust_zone="dmz_external"),
         Component(id="cache", name="Redis", type="database", trust_zone="dmz_external")],
        [Dataflow(source="rp", target="cache", label="cache")],
    )
    assert [c.id for c, _ in _fire_missing_network_segmentation(s2)] == []


def test_true_positive_user_directly_on_db_still_fires():
    """Genuine exposure must still fire: a user reaching a database directly."""
    s = _sys(
        [Component(id="u", name="User", type="user", trust_zone="internet"),
         Component(id="db", name="DB", type="database", trust_zone="data")],
        [Dataflow(source="u", target="db", label="direct query")],
    )
    assert [(c.id, sv) for c, sv in _fire_direct_datastore_access(s)] == [("db", "high")]
