"""Defensibility regression: 'external-facing' must mean externally-facing.

The output-justification review (v1.0.5) found that architectural rules
treated EVERY `user` component as Internet-facing, via
`_INTERNET_FACING_TYPES = {"user"}`, ignoring the user's trust_zone. That
produced indefensible findings such as "Datastore shares trust zone with
external-facing components" on an Azure Key Vault whose only zone co-tenant
was an SSO-authenticated *internal employee* (trust_zone corp_internal).

The fix adds `_is_external_facing(component)`: a `user` is external-facing
only when its trust_zone is NOT a clearly-internal one (corp_internal,
clinical, corporate, ...); any component in an explicitly external/internet/
public/untrusted zone is external-facing regardless of type.

These tests pin the classifier and the corrected network-segmentation rule,
including that a GENUINE flat network (store co-located with an Internet
user) still fires."""

from __future__ import annotations

from pathlib import Path

import pytest

from atms.cli import _load_system_yaml
from atms.engines.architectural_rules import (
    _fire_direct_datastore_access,
    _fire_missing_network_segmentation,
    _fire_unguarded_internet,
    _is_external_facing,
)
from atms.models import Component, Dataflow, System

_SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ─── _is_external_facing classifier ─────────────────────────────────


@pytest.mark.parametrize("zone,expected", [
    ("corp_internal", False),
    ("corp_net", False),
    ("clinical", False),
    ("corporate", False),
    ("internal", False),
    ("internet", True),
    ("external", True),
    ("external_customer", True),
    ("external-untrusted", True),
    ("public_dmz", True),
    ("", True),  # an unspecified-zone user is treated as untrusted (safe default)
])
def test_user_external_facing_depends_on_zone(zone, expected):
    u = Component(id="u", name="U", type="user", trust_zone=zone)
    assert _is_external_facing(u) is expected


def test_internal_store_is_not_external_facing():
    s = Component(id="kv", name="KV", type="secrets_vault", trust_zone="corp_internal")
    assert _is_external_facing(s) is False


def test_any_component_in_external_zone_is_external_facing():
    """Even a non-user type counts when it sits in an external zone."""
    c = Component(id="x", name="X", type="container_runtime", trust_zone="internet_edge")
    assert _is_external_facing(c) is True


# ─── The corrected network-segmentation rule ────────────────────────


def test_azure_keyvault_not_flagged_for_internal_employee_colocation():
    """The azure_openai_rag Key Vault / CMK / corpus must NOT be flagged
    'shares trust zone with external-facing components' — their only zone
    co-tenant that's a user is an internal SSO employee."""
    system = _load_system_yaml(_SAMPLES / "azure_openai_rag.yaml")
    fired = {c.id for c, _ in _fire_missing_network_segmentation(system)}
    for cid in ("key_vault", "cmk", "corpus_blob", "ai_search"):
        assert cid not in fired, (
            f"{cid} false-positived: its zone co-tenant is an internal "
            f"employee, not an external-facing component."
        )


def test_flat_network_with_internet_user_still_flagged():
    """Genuine flat network — a datastore sharing a zone with an Internet
    user — must still fire. No over-suppression."""
    system = System(
        name="flat",
        components=[
            Component(id="u", name="Customer", type="user", trust_zone="public_dmz"),
            Component(id="db", name="Customer DB", type="database", trust_zone="public_dmz"),
            Component(id="agent", name="Agent", type="agent", trust_zone="public_dmz"),
        ],
        dataflows=[
            Dataflow(source="u", target="agent", label="req"),
            Dataflow(source="agent", target="db", label="query"),
        ],
    )
    fired = [c.id for c, _ in _fire_missing_network_segmentation(system)]
    assert fired == ["db"]


def test_internal_colocation_not_flagged():
    """A datastore co-located only with an internal employee is fine."""
    system = System(
        name="ok",
        components=[
            Component(id="u", name="Employee", type="user", trust_zone="corp_internal"),
            Component(id="db", name="DB", type="database", trust_zone="corp_internal"),
            Component(id="agent", name="Agent", type="agent", trust_zone="corp_internal"),
        ],
        dataflows=[
            Dataflow(source="u", target="agent", label="req"),
            Dataflow(source="agent", target="db", label="query"),
        ],
    )
    assert _fire_missing_network_segmentation(system) == []


# ─── unguarded_internet (rule 1) must also be zone-aware ─────────────


def test_unguarded_internet_ignores_internal_user():
    """aws_bedrock_agent's refund_queue is reachable from an INTERNAL
    support agent (corp_internal). It must not be flagged as an Internet
    exposure."""
    system = _load_system_yaml(_SAMPLES / "aws_bedrock_agent.yaml")
    fired = {c.id for c, _ in _fire_unguarded_internet(system)}
    assert "refund_queue" not in fired


def test_unguarded_internet_still_flags_external_customer():
    """bank_with_llm_fraud's customer is external — its directly-reachable
    components must still be flagged."""
    system = _load_system_yaml(_SAMPLES / "bank_with_llm_fraud.yaml")
    fired = {c.id for c, _ in _fire_unguarded_internet(system)}
    assert "web_banking" in fired


def test_direct_datastore_access_flags_internet_user():
    """A datastore with a direct edge from an Internet user is still a
    real finding."""
    system = System(
        name="exposed",
        components=[
            Component(id="u", name="Cust", type="user", trust_zone="internet"),
            Component(id="db", name="DB", type="database", trust_zone="dmz"),
            Component(id="ai", name="LLM", type="llm_inference", trust_zone="dmz"),
        ],
        dataflows=[
            Dataflow(source="u", target="db", label="direct query"),
            Dataflow(source="u", target="ai", label="prompt"),
        ],
    )
    fired = {c.id for c, _ in _fire_direct_datastore_access(system)}
    assert "db" in fired
