"""Defensibility regression: the missing_waf rule must not cry wolf.

The "output must be justifiable to a client/auditor" review (v1.0.5) found
the missing_waf architectural rule producing indefensible false positives
on the azure_openai_rag sample:

  * front_door — literally "Azure Front Door + WAF" — was flagged for
    *lacking* a WAF, because the rule only recognised a WAF when a hop's
    component *type* was waf/cdn/ddos_mitigation, ignoring a WAF declared
    in the name / description / controls.
  * azure_openai — a private-endpoint llm_inference 4 hops behind the API
    gateway — was flagged "internet-facing web tier" because the rule
    treated any 4-hop-transitive reachability to a user as internet-facing.
  * apim — behind the WAF-bearing front door — flagged for the same reason.

The fix: (1) recognise a WAF declared inline (name/description/controls),
consistent with the operational-control rules 16-25; (2) scope the rule to
a *direct* inbound Internet edge, not transitive reachability.

These tests pin both the suppression (no false positives) and that a
genuine naked internet web app is still caught (no over-suppression)."""

from __future__ import annotations

from pathlib import Path

from atms.cli import _load_system_yaml
from atms.engines.architectural_rules import _declares_waf, _fire_missing_waf
from atms.models import Component, Dataflow, System

_SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ─── False positives that must be gone ──────────────────────────────


def test_azure_sample_does_not_flag_waf_protected_frontdoor():
    """The azure_openai_rag sample fronts everything with 'Azure Front Door
    + WAF'. missing_waf must fire on NOTHING there."""
    system = _load_system_yaml(_SAMPLES / "azure_openai_rag.yaml")
    fired = [c.id for c, _ in _fire_missing_waf(system)]
    assert fired == [], (
        f"missing_waf false-positived on {fired}; the sample has a WAF "
        f"(Azure Front Door + WAF) fronting the web tier."
    )


def test_private_inference_endpoint_not_called_internet_facing():
    """A private-endpoint llm_inference several hops behind the gateway is
    not an 'internet-facing web tier'."""
    system = _load_system_yaml(_SAMPLES / "azure_openai_rag.yaml")
    fired = {c.id for c, _ in _fire_missing_waf(system)}
    assert "azure_openai" not in fired


# ─── WAF detection via the three declaration styles ─────────────────


def test_declares_waf_recognises_component_type():
    assert _declares_waf(Component(id="w", name="W", type="waf")) is True
    assert _declares_waf(Component(id="c", name="CDN", type="cdn")) is True


def test_declares_waf_recognises_name_and_description():
    assert _declares_waf(
        Component(id="fd", name="Azure Front Door + WAF", type="api_gateway")
    ) is True
    assert _declares_waf(
        Component(id="g", name="Gateway", type="api_gateway",
                  description="fronted by Cloudflare WAF with OWASP CRS")
    ) is True


def test_declares_waf_recognises_controls():
    assert _declares_waf(
        Component(id="web", name="web", type="web_application", controls=["waf", "tls"])
    ) is True


def test_declares_waf_false_for_plain_component():
    assert _declares_waf(
        Component(id="web", name="web", type="web_application")
    ) is False
    assert _declares_waf(None) is False


# ─── True positive must still fire (no over-suppression) ────────────


def test_naked_internet_web_app_still_flagged():
    """A customer-facing web_application directly behind a user with no WAF
    anywhere must still be caught — that's the rule's whole job."""
    system = System(
        name="naked",
        components=[
            Component(id="u", name="User", type="user", trust_zone="internet"),
            Component(id="web", name="Public portal", type="web_application", trust_zone="dmz"),
        ],
        dataflows=[Dataflow(source="u", target="web", label="http")],
    )
    fired = [c.id for c, _ in _fire_missing_waf(system)]
    assert fired == ["web"]


def test_bank_sample_still_flags_unprotected_portal():
    """bank_with_llm_fraud's internet banking portal has no WAF — a
    legitimate, defensible finding that must survive the fix."""
    system = _load_system_yaml(_SAMPLES / "bank_with_llm_fraud.yaml")
    fired = {c.id for c, _ in _fire_missing_waf(system)}
    assert "web_banking" in fired


def test_waf_component_in_path_suppresses():
    """user -> WAF component -> web app must NOT fire."""
    system = System(
        name="haswaf",
        components=[
            Component(id="u", name="User", type="user", trust_zone="internet"),
            Component(id="waf", name="WAF", type="waf"),
            Component(id="web", name="web", type="web_application"),
        ],
        dataflows=[
            Dataflow(source="u", target="waf", label="http"),
            Dataflow(source="waf", target="web", label="http"),
        ],
    )
    assert _fire_missing_waf(system) == []
