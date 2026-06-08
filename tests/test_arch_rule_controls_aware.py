"""Defensibility regressions: auth / encryption / PII / MFA rules must honour
declared Component.controls and recognise mTLS (audit F024/F029/F030/F031/F033).

v1.0.5 made missing_waf and rules 16-25 controls-aware; missing_authentication,
unencrypted_communication, missing_pii_redaction and mfa_not_enforced were left
checking only dataflow labels / component types, so a system that correctly
modelled mTLS / OIDC / tokenization as deployed controls still got HIGH
"unauthenticated / unencrypted / no-redaction" findings. These pin the fix.
"""

from __future__ import annotations

import atms.engines.architectural_rules as a
from atms.models import Component, Dataflow, System


def _sys(components, dataflows=()):
    return System(name="t", components=list(components), dataflows=list(dataflows))


def test_missing_auth_suppressed_by_declared_auth_control():
    """F031: a receiver declaring mfa_required / oidc must not be flagged
    'no authentication'."""
    s = _sys(
        [Component(id="svc", name="Svc", type="llm_inference", trust_zone="internal"),
         Component(id="db", name="DB", type="database", trust_zone="internal",
                   controls=["mfa_required", "rbac"])],
        [Dataflow(source="svc", target="db", label="read")],
    )
    assert [c.id for c, _ in a._fire_missing_authentication(s)] == []


def test_missing_auth_recognises_mtls_edge_label():
    """F030: an mTLS edge label authenticates the hop."""
    s = _sys(
        [Component(id="gw", name="G", type="api_gateway", trust_zone="dmz"),
         Component(id="svc", name="B", type="web_application", trust_zone="app")],
        [Dataflow(source="gw", target="svc", label="mTLS")],
    )
    assert "svc" not in {c.id for c, _ in a._fire_missing_authentication(s)}


def test_unencrypted_suppressed_by_mtls_control():
    """F029: an endpoint declaring mtls / tls_1_3 is not plaintext."""
    s = _sys(
        [Component(id="gw", name="G", type="api_gateway", trust_zone="dmz"),
         Component(id="svc", name="B", type="web_application", trust_zone="app",
                   controls=["mtls", "tls_1_3"])],
        [Dataflow(source="gw", target="svc", label="gRPC", crosses_boundary=True)],
    )
    assert [c.id for c, _ in a._fire_unencrypted_communication(s)] == []


def test_pii_redaction_suppressed_by_declared_control():
    """F024: a tokenization / pii_redaction / DLP control satisfies the
    redaction boundary."""
    s = _sys(
        [Component(id="db", name="DB", type="database", trust_zone="app",
                   controls=["field_level_tokenization", "pii_redaction_at_source"]),
         Component(id="llm", name="LLM", type="llm_inference", trust_zone="app",
                   controls=["pii_redaction", "presidio_dlp"])],
        [Dataflow(source="db", target="llm", label="retrieve")],
    )
    assert [c.id for c, _ in a._fire_missing_pii_redaction(s)] == []


def test_mfa_not_enforced_skips_internal_only_login():
    """F033: an internal employee -> internal directory bind has no perimeter,
    so 'no perimeter MFA' must not fire."""
    s = _sys(
        [Component(id="emp", name="Emp", type="user", trust_zone="corp_internal"),
         Component(id="ad", name="AD", type="directory_service", trust_zone="corp_internal")],
        [Dataflow(source="emp", target="ad", label="LDAP bind")],
    )
    assert [c.id for c, _ in a._fire_mfa_not_enforced(s)] == []


def test_backup_modelled_as_inbound_edge_suppresses_missing_backup():
    """F032: a backup relationship modelled as an INBOUND edge
    (backup_service -> datastore, i.e. a restore / replication-pull) must
    suppress the 'missing backup for critical data' finding."""
    s = _sys(
        [Component(id="db", name="DB", type="database"),
         Component(id="bk", name="Backup", type="backup_service")],
        [Dataflow(source="bk", target="db", label="restore")],
    )
    s.deployment_stage = "production"
    assert [c.id for c, _ in a._fire_missing_backup_for_critical_data(s)] == []
    # ...but a production datastore with NO backup_service at all still fires.
    s2 = _sys([Component(id="db", name="DB", type="database")])
    s2.deployment_stage = "production"
    assert "db" in {c.id for c, _ in a._fire_missing_backup_for_critical_data(s2)}


def test_true_positives_preserved():
    """Genuinely-missing controls must still fire."""
    # plaintext, no auth control, no auth label -> missing_authentication fires
    s = _sys(
        [Component(id="u", name="U", type="user", trust_zone="internet"),
         Component(id="api", name="API", type="api_gateway", trust_zone="dmz")],
        [Dataflow(source="u", target="api", label="plain http")],
    )
    assert "api" in {c.id for c, _ in a._fire_missing_authentication(s)}
    # external user -> auth backend with no MFA anywhere -> mfa_not_enforced fires
    s2 = _sys(
        [Component(id="u", name="U", type="user", trust_zone="internet"),
         Component(id="idp", name="IdP", type="identity_provider", trust_zone="dmz")],
        [Dataflow(source="u", target="idp", label="login")],
    )
    assert "idp" in {c.id for c, _ in a._fire_mfa_not_enforced(s2)}
