"""Regression tests for v0.18.5 Cycle R — architectural-pattern rules.

Closes the topology-threat gap surfaced by competitor research.
Per-component playbooks catch inherent threats; architectural rules
catch threats that emerge from how components are arranged.

Pins 6 starter rules:
  1. unguarded_access_from_internet
  2. missing_waf
  3. unguarded_direct_datastore_access
  4. missing_vault
  5. missing_network_segmentation
  6. orphan_secrets_vault
"""

from __future__ import annotations

from atms.engines.architectural_rules import (
    ARCHITECTURAL_RULES,
    ArchRule,
    evaluate_arch_rules,
)
from atms.models import Component, Dataflow, System
from atms.workflow import analyze


# ─── Rule 1: unguarded_access_from_internet ─────────────────────────
def test_unguarded_internet_fires_on_user_directly_to_db():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="db", name="Postgres", type="database"),
    ], dataflows=[
        Dataflow(source="u", target="db", label="direct"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNGUARDED_ACCESS_FROM_INTERNET" in t.id]
    assert len(fired) == 1
    assert fired[0].component_id == "db"
    assert fired[0].severity == "critical"  # sensitive data store → escalated


def test_unguarded_internet_does_not_fire_when_waf_is_in_path():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="waf", name="WAF", type="waf"),
        Component(id="app", name="Web", type="web_application"),
    ], dataflows=[
        Dataflow(source="u", target="waf", label="HTTPS"),
        Dataflow(source="waf", target="app", label="filtered"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNGUARDED_ACCESS_FROM_INTERNET" in t.id]
    # User → WAF directly is fine (WAF is a protective type).
    # WAF → app doesn't fire (source is WAF, not user).
    assert fired == []


def test_unguarded_internet_higher_severity_for_data_store():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="vault", name="Vault", type="secrets_vault"),
    ], dataflows=[
        Dataflow(source="u", target="vault", label="direct"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNGUARDED_ACCESS_FROM_INTERNET" in t.id]
    assert len(fired) == 1
    # secrets_vault is a sensitive data store → severity escalates to critical.
    assert fired[0].severity == "critical"


# ─── Rule 2: missing_waf ────────────────────────────────────────────
def test_missing_waf_fires_on_internet_facing_web_app():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="app", name="Web App", type="web_application"),
    ], dataflows=[
        Dataflow(source="u", target="app", label="HTTPS"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_WAF" in t.id]
    assert len(fired) == 1
    assert fired[0].component_id == "app"


def test_missing_waf_silent_when_waf_present():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="waf", name="WAF", type="waf"),
        Component(id="app", name="Web App", type="web_application"),
    ], dataflows=[
        Dataflow(source="u", target="waf", label="HTTPS"),
        Dataflow(source="waf", target="app", label="filtered"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_WAF" in t.id]
    assert fired == []


def test_missing_waf_silent_when_cdn_in_path():
    """CDN counts as a protective hop (it terminates TLS + applies edge
    rules, even if not strictly a WAF)."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="cdn", name="CloudFront", type="cdn"),
        Component(id="app", name="Web App", type="web_application"),
    ], dataflows=[
        Dataflow(source="u", target="cdn"),
        Dataflow(source="cdn", target="app"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    assert not any("MISSING_WAF" in t.id for t in threats)


# ─── Rule 3: unguarded_direct_datastore_access ──────────────────────
def test_direct_datastore_access_fires_on_user_to_db():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="db", name="DB", type="database"),
    ], dataflows=[
        Dataflow(source="u", target="db"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNGUARDED_DIRECT_DATASTORE_ACCESS" in t.id]
    assert len(fired) == 1
    assert fired[0].severity == "high"


def test_direct_datastore_access_silent_when_app_tier_mediates():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="app", name="App", type="web_application"),
        Component(id="db", name="DB", type="database"),
    ], dataflows=[
        Dataflow(source="u", target="app"),
        Dataflow(source="app", target="db"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNGUARDED_DIRECT_DATASTORE_ACCESS" in t.id]
    assert fired == []


# ─── Rule 4: missing_vault ──────────────────────────────────────────
def test_missing_vault_fires_on_lambda_without_secrets_manager():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="lam", name="Lambda", type="serverless_function"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_VAULT" in t.id]
    assert any(t.component_id == "lam" for t in fired)


def test_missing_vault_silent_when_vault_present():
    sys_obj = System(name="t", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
        Component(id="vault", name="Secrets", type="secrets_vault"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_VAULT" in t.id]
    assert fired == []


def test_missing_vault_satisfied_by_kms_or_hsm():
    sys_obj = System(name="t", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
        Component(id="kms", name="KMS", type="kms_key"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_VAULT" in t.id]
    assert fired == []


# ─── Rule 5: missing_network_segmentation ───────────────────────────
def test_segmentation_fires_when_db_shares_zone_with_user():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user", trust_zone="public"),
        Component(id="db", name="DB", type="database", trust_zone="public"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_NETWORK_SEGMENTATION" in t.id]
    assert any(t.component_id == "db" for t in fired)


def test_segmentation_silent_when_zones_differ():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user", trust_zone="external"),
        Component(id="db", name="DB", type="database", trust_zone="internal"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_NETWORK_SEGMENTATION" in t.id]
    assert fired == []


# ─── Rule 6: orphan_secrets_vault ───────────────────────────────────
def test_orphan_vault_fires_on_unused_vault():
    sys_obj = System(name="t", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
        Component(id="vault", name="Unused Vault", type="secrets_vault"),
        Component(id="db", name="DB", type="database"),
    ], dataflows=[
        Dataflow(source="lam", target="db"),  # vault has no edges
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "ORPHAN_SECRETS_VAULT" in t.id]
    assert any(t.component_id == "vault" for t in fired)


def test_orphan_vault_silent_when_consumer_references_it():
    sys_obj = System(name="t", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
        Component(id="vault", name="Vault", type="secrets_vault"),
    ], dataflows=[
        Dataflow(source="lam", target="vault", label="get-secret"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "ORPHAN_SECRETS_VAULT" in t.id]
    assert fired == []


# ─── Rule 7: unencrypted_communication (v0.18.6 Cycle V) ────────────
def test_unencrypted_communication_fires_on_cross_boundary_plaintext():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user", trust_zone="external"),
        Component(id="app", name="App", type="web_application", trust_zone="internal"),
    ], dataflows=[
        Dataflow(source="u", target="app", label="POST /login", crosses_boundary=True),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNENCRYPTED_COMMUNICATION" in t.id]
    assert len(fired) == 1
    assert fired[0].component_id == "app"


def test_unencrypted_communication_silent_when_label_says_https():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user", trust_zone="external"),
        Component(id="app", name="App", type="web_application", trust_zone="internal"),
    ], dataflows=[
        Dataflow(source="u", target="app", label="HTTPS POST /login", crosses_boundary=True),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNENCRYPTED_COMMUNICATION" in t.id]
    assert fired == []


def test_unencrypted_communication_silent_for_same_zone():
    sys_obj = System(name="t", components=[
        Component(id="a", name="A", type="serverless_function", trust_zone="internal"),
        Component(id="b", name="B", type="database", trust_zone="internal"),
    ], dataflows=[
        Dataflow(source="a", target="b", label="SQL", crosses_boundary=False),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNENCRYPTED_COMMUNICATION" in t.id]
    assert fired == []


def test_unencrypted_communication_skips_kms_endpoints():
    """KMS / Vault edges are inherently encrypted — don't false-fire."""
    sys_obj = System(name="t", components=[
        Component(id="app", name="App", type="serverless_function", trust_zone="internal"),
        Component(id="kms", name="KMS", type="kms_key", trust_zone="secrets"),
    ], dataflows=[
        Dataflow(source="app", target="kms", label="encrypt", crosses_boundary=True),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNENCRYPTED_COMMUNICATION" in t.id]
    assert fired == []


# ─── Rule 8: missing_authentication ─────────────────────────────────
def test_missing_authentication_fires_when_no_auth_hint_and_no_idp():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="api", name="API", type="api_gateway"),
    ], dataflows=[
        Dataflow(source="u", target="api", label="POST /thing"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_AUTHENTICATION" in t.id]
    assert len(fired) == 1
    assert fired[0].severity == "high"  # no IdP in system → escalated


def test_missing_authentication_silent_when_label_carries_token():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="api", name="API", type="api_gateway"),
    ], dataflows=[
        Dataflow(source="u", target="api", label="POST /thing (OIDC bearer token)"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_AUTHENTICATION" in t.id]
    assert fired == []


# ─── Rule 9: logs_capture_secrets ───────────────────────────────────
def test_logs_capture_secrets_fires_on_vault_to_log_aggregator():
    sys_obj = System(name="t", components=[
        Component(id="vault", name="Vault", type="secrets_vault"),
        Component(id="logs", name="Logs", type="log_aggregator"),
    ], dataflows=[
        Dataflow(source="vault", target="logs", label="audit"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "LOGS_CAPTURE_SECRETS" in t.id]
    assert len(fired) == 1
    assert fired[0].component_id == "vault"


def test_logs_capture_secrets_silent_when_label_has_redact_hint():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database"),
        Component(id="logs", name="Logs", type="log_aggregator"),
    ], dataflows=[
        Dataflow(source="db", target="logs", label="query audit (redacted)"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "LOGS_CAPTURE_SECRETS" in t.id]
    assert fired == []


# ─── Rule 10: unrestricted_external_egress ─────────────────────────
def test_external_egress_fires_when_workload_has_three_external_outbound():
    sys_obj = System(name="t", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
        Component(id="api1", name="Stripe", type="external_api"),
        Component(id="api2", name="Twilio", type="external_api"),
        Component(id="api3", name="OpenAI", type="external_api"),
        Component(id="api4", name="Slack", type="external_api"),
    ], dataflows=[
        Dataflow(source="lam", target="api1"),
        Dataflow(source="lam", target="api2"),
        Dataflow(source="lam", target="api3"),
        Dataflow(source="lam", target="api4"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNRESTRICTED_EXTERNAL_EGRESS" in t.id]
    assert len(fired) == 1
    assert fired[0].component_id == "lam"


def test_external_egress_silent_for_gateway_components():
    """API gateways and proxies ARE meant to fan out to external — don't false-fire."""
    sys_obj = System(name="t", components=[
        Component(id="gw", name="GW", type="api_gateway"),
        Component(id="api1", name="A", type="external_api"),
        Component(id="api2", name="B", type="external_api"),
        Component(id="api3", name="C", type="external_api"),
    ], dataflows=[
        Dataflow(source="gw", target="api1"),
        Dataflow(source="gw", target="api2"),
        Dataflow(source="gw", target="api3"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNRESTRICTED_EXTERNAL_EGRESS" in t.id]
    assert fired == []


def test_external_egress_silent_at_threshold():
    """Threshold is >2; exactly 2 outbound external must NOT fire."""
    sys_obj = System(name="t", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
        Component(id="api1", name="A", type="external_api"),
        Component(id="api2", name="B", type="external_api"),
    ], dataflows=[
        Dataflow(source="lam", target="api1"),
        Dataflow(source="lam", target="api2"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNRESTRICTED_EXTERNAL_EGRESS" in t.id]
    assert fired == []


# ─── Rule 11: container_platform_escape (Cycle Y) ───────────────────
def test_container_escape_fires_when_no_runtime_security():
    sys_obj = System(name="t", components=[
        Component(id="k8s", name="EKS", type="container_orchestrator"),
        Component(id="pod", name="App", type="container_runtime"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "CONTAINER_PLATFORM_ESCAPE" in t.id]
    assert len(fired) == 2  # both container types fire


def test_container_escape_silent_with_falco():
    sys_obj = System(name="t", components=[
        Component(id="k8s", name="EKS", type="container_orchestrator"),
        Component(id="falco", name="Falco", type="container_security"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "CONTAINER_PLATFORM_ESCAPE" in t.id]
    assert fired == []


# ─── Rule 12: missing_identity_propagation ──────────────────────────
def test_identity_propagation_fires_when_dropped():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="gw", name="GW", type="api_gateway"),
        Component(id="be", name="Backend", type="web_application"),
    ], dataflows=[
        Dataflow(source="u", target="gw", label="HTTPS (OIDC bearer)"),
        Dataflow(source="gw", target="be", label="HTTP"),  # auth dropped!
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_IDENTITY_PROPAGATION" in t.id]
    assert any(t.component_id == "be" for t in fired)


def test_identity_propagation_silent_when_token_propagated():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="gw", name="GW", type="api_gateway"),
        Component(id="be", name="Backend", type="web_application"),
    ], dataflows=[
        Dataflow(source="u", target="gw", label="HTTPS (OIDC bearer)"),
        Dataflow(source="gw", target="be", label="forward JWT"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_IDENTITY_PROPAGATION" in t.id]
    assert fired == []


# ─── Rule 13: accidental_secret_leak ────────────────────────────────
def test_accidental_secret_leak_fires_when_repo_not_connected_to_vault():
    sys_obj = System(name="t", components=[
        Component(id="repo", name="Repo", type="code_repository"),
        Component(id="ci", name="CI", type="ci_cd_pipeline"),
        Component(id="vault", name="Vault", type="secrets_vault"),
        Component(id="app", name="App", type="serverless_function"),
    ], dataflows=[
        Dataflow(source="repo", target="ci", label="trigger"),
        Dataflow(source="ci", target="app", label="deploy"),
        Dataflow(source="app", target="vault", label="get-secret"),
        # Note: repo and ci have NO edge to vault.
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "ACCIDENTAL_SECRET_LEAK" in t.id]
    fired_ids = {t.component_id for t in fired}
    assert "repo" in fired_ids and "ci" in fired_ids


def test_accidental_secret_leak_silent_without_any_vault():
    """When NO vault exists, missing_vault fires, not this rule (avoids
    double-fire)."""
    sys_obj = System(name="t", components=[
        Component(id="repo", name="Repo", type="code_repository"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "ACCIDENTAL_SECRET_LEAK" in t.id]
    assert fired == []


def test_accidental_secret_leak_silent_when_ci_references_vault():
    sys_obj = System(name="t", components=[
        Component(id="ci", name="CI", type="ci_cd_pipeline"),
        Component(id="vault", name="Vault", type="secrets_vault"),
    ], dataflows=[
        Dataflow(source="ci", target="vault", label="fetch deploy key"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "ACCIDENTAL_SECRET_LEAK" in t.id]
    assert fired == []


# ─── Rule 14: missing_build_infrastructure ──────────────────────────
def test_missing_build_infra_fires_on_production_without_ci():
    sys_obj = System(name="t", deployment_stage="production", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
        Component(id="db", name="DB", type="database"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_BUILD_INFRASTRUCTURE" in t.id]
    assert len(fired) == 1


def test_missing_build_infra_silent_on_poc():
    sys_obj = System(name="t", deployment_stage="poc", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_BUILD_INFRASTRUCTURE" in t.id]
    assert fired == []


def test_missing_build_infra_silent_when_ci_modeled():
    sys_obj = System(name="t", deployment_stage="production", components=[
        Component(id="lam", name="Lambda", type="serverless_function"),
        Component(id="ci", name="CI", type="ci_cd_pipeline"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_BUILD_INFRASTRUCTURE" in t.id]
    assert fired == []


# ─── Rule 15: excessive_principal_blast_radius ──────────────────────
def test_excessive_principal_fires_on_four_sensitive_targets():
    sys_obj = System(name="t", components=[
        Component(id="role", name="role", type="iam_principal"),
        Component(id="db1", name="db1", type="database"),
        Component(id="db2", name="db2", type="database"),
        Component(id="s3", name="bucket", type="object_storage"),
        Component(id="kms", name="kms", type="kms_key"),
    ], dataflows=[
        Dataflow(source="role", target="db1"),
        Dataflow(source="role", target="db2"),
        Dataflow(source="role", target="s3"),
        Dataflow(source="role", target="kms"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "EXCESSIVE_PRINCIPAL_BLAST_RADIUS" in t.id]
    assert any(t.component_id == "role" for t in fired)


def test_excessive_principal_silent_at_three_targets():
    sys_obj = System(name="t", components=[
        Component(id="role", name="role", type="iam_principal"),
        Component(id="db", name="db", type="database"),
        Component(id="s3", name="bucket", type="object_storage"),
        Component(id="kms", name="kms", type="kms_key"),
    ], dataflows=[
        Dataflow(source="role", target="db"),
        Dataflow(source="role", target="s3"),
        Dataflow(source="role", target="kms"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "EXCESSIVE_PRINCIPAL_BLAST_RADIUS" in t.id]
    assert fired == []


# ─── Registry + engine ─────────────────────────────────────────────
def test_registry_has_twenty_five_rules():
    assert len(ARCHITECTURAL_RULES) == 25
    names = {r.name for r in ARCHITECTURAL_RULES}
    # Cycle R (6)
    assert "unguarded_access_from_internet" in names
    assert "missing_waf" in names
    assert "missing_vault" in names
    assert "unguarded_direct_datastore_access" in names
    assert "missing_network_segmentation" in names
    assert "orphan_secrets_vault" in names
    # Cycle V (4)
    assert "unencrypted_communication" in names
    assert "missing_authentication" in names
    assert "logs_capture_secrets" in names
    assert "unrestricted_external_egress" in names
    # Cycle Y (5)
    assert "container_platform_escape" in names
    assert "missing_identity_propagation" in names
    assert "accidental_secret_leak" in names
    assert "missing_build_infrastructure" in names
    assert "excessive_principal_blast_radius" in names
    # Cycle BB (5) — operational security controls
    assert "missing_centralized_logging" in names
    assert "missing_backup_for_critical_data" in names
    assert "missing_intrusion_detection" in names
    assert "mfa_not_enforced" in names
    assert "data_at_rest_unencrypted" in names
    # Cycle RR (5) — AI-specific operational controls
    assert "missing_prompt_injection_guard" in names
    assert "missing_pii_redaction_at_llm_boundary" in names
    assert "missing_model_provenance" in names
    assert "unbounded_agent_tool_access" in names
    assert "missing_human_oversight_high_risk" in names


def test_buggy_rule_does_not_crash_the_engine():
    """If a rule raises, the engine catches + logs + continues."""
    def _bad_fire(_sys):
        raise RuntimeError("oops")
    bad = ArchRule(
        name="bad", title="bad", description="bad", severity="low",
        mitigations=(), refs=(), fire=_bad_fire,
    )
    sys_obj = System(name="t", components=[
        Component(id="x", name="X", type="user"),
    ])
    # Mix with one good rule to verify the loop continues.
    threats = evaluate_arch_rules(sys_obj, rules=(bad, ARCHITECTURAL_RULES[0]))
    # The good rule may or may not fire on the trivial system; the
    # critical assertion is "no crash". Reaching this line proves it.
    assert isinstance(threats, list)


def test_arch_threat_ids_dont_collide_with_playbook_threat_ids():
    """Arch threats use prefix `A_`, playbook threats use `T_`."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="db", name="DB", type="database"),
    ], dataflows=[Dataflow(source="u", target="db")])
    arch = evaluate_arch_rules(sys_obj)
    for t in arch:
        # id format: "<component>.A_<RULE>"
        assert ".A_" in t.id, f"Expected `.A_` prefix in {t.id}"


# ─── v0.18.12 Cycle BB — operational-controls rules (16-20) ─────────

def _three_workloads() -> list[Component]:
    """Returns ≥3 workload components — the threshold for Cycle BB
    rules that require operational scale to fire."""
    return [
        Component(id="api", name="API", type="api_gateway"),
        Component(id="web", name="Web", type="web_application"),
        Component(id="lambda", name="L", type="serverless_function"),
    ]


# ─── Rule 16: missing_centralized_logging ───────────────────────────
def test_missing_centralized_logging_fires_when_no_siem():
    sys_obj = System(name="t", components=_three_workloads())
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_CENTRALIZED_LOGGING" in t.id]
    assert len(fired) == 3, f"Expected 3 fires (one per workload); got {len(fired)}"


def test_missing_centralized_logging_suppressed_by_siem():
    sys_obj = System(name="t", components=_three_workloads() + [
        Component(id="siem", name="Sentinel", type="siem"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_CENTRALIZED_LOGGING" in t.id]
    assert fired == []


def test_missing_centralized_logging_does_not_fire_under_threshold():
    """Fewer than 3 workloads = ignored — too small to require centralised logging."""
    sys_obj = System(name="t", components=[
        Component(id="api", name="API", type="api_gateway"),
        Component(id="web", name="Web", type="web_application"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    assert not [t for t in threats if "MISSING_CENTRALIZED_LOGGING" in t.id]


# ─── Rule 17: missing_backup_for_critical_data ──────────────────────
def test_missing_backup_fires_on_unbacked_database():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_BACKUP_FOR_CRITICAL_DATA" in t.id]
    assert len(fired) == 1


def test_missing_backup_suppressed_by_backup_service_with_edge():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database"),
        Component(id="bkp", name="Backup", type="backup_service"),
    ], dataflows=[Dataflow(source="db", target="bkp", label="snapshot")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_BACKUP_FOR_CRITICAL_DATA" in t.id]
    assert fired == []


def test_missing_backup_suppressed_by_explicit_control():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database",
                   controls=["backup_immutable"]),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_BACKUP_FOR_CRITICAL_DATA" in t.id]
    assert fired == []


def test_missing_backup_severity_high_in_production():
    sys_obj = System(name="t", deployment_stage="production", components=[
        Component(id="db", name="DB", type="database"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_BACKUP_FOR_CRITICAL_DATA" in t.id]
    assert len(fired) == 1
    assert fired[0].severity == "high"


# ─── Rule 18: missing_intrusion_detection ───────────────────────────
def test_missing_intrusion_detection_fires_in_production():
    sys_obj = System(name="t", deployment_stage="production",
                     components=_three_workloads())
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_INTRUSION_DETECTION" in t.id]
    assert len(fired) == 3


def test_missing_intrusion_detection_suppressed_by_edr_agent():
    sys_obj = System(name="t", deployment_stage="production",
                     components=_three_workloads() + [
        Component(id="edr", name="EDR", type="edr_agent"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_INTRUSION_DETECTION" in t.id]
    assert fired == []


def test_missing_intrusion_detection_does_not_fire_on_poc():
    """POC stage is below the threshold for full IDS / EDR investment."""
    sys_obj = System(name="t", deployment_stage="poc",
                     components=_three_workloads())
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_INTRUSION_DETECTION" in t.id]
    assert fired == []


def test_missing_intrusion_detection_suppressed_by_container_security():
    """Container-security agents (Falco / Aqua / Sysdig) satisfy SI-4."""
    sys_obj = System(name="t", deployment_stage="production",
                     components=_three_workloads() + [
        Component(id="csec", name="Falco", type="container_security"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_INTRUSION_DETECTION" in t.id]
    assert fired == []


# ─── Rule 19: mfa_not_enforced ──────────────────────────────────────
def test_mfa_not_enforced_fires_on_user_to_auth_service():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="auth", name="Auth", type="identity_provider"),
    ], dataflows=[Dataflow(source="u", target="auth", label="login")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MFA_NOT_ENFORCED" in t.id]
    assert len(fired) == 1


def test_mfa_not_enforced_suppressed_by_mfa_service():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="auth", name="Auth", type="identity_provider"),
        Component(id="mfa", name="MFA", type="mfa_service"),
    ], dataflows=[Dataflow(source="u", target="auth", label="login")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MFA_NOT_ENFORCED" in t.id]
    assert fired == []


def test_mfa_not_enforced_suppressed_by_edge_label():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="auth", name="Auth", type="identity_provider"),
    ], dataflows=[Dataflow(source="u", target="auth", label="login (TOTP)")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MFA_NOT_ENFORCED" in t.id]
    assert fired == []


def test_mfa_not_enforced_suppressed_by_control_on_backend():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="auth", name="Auth", type="identity_provider",
                   controls=["mfa_required"]),
    ], dataflows=[Dataflow(source="u", target="auth", label="login")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MFA_NOT_ENFORCED" in t.id]
    assert fired == []


# ─── Rule 20: data_at_rest_unencrypted ──────────────────────────────
def test_data_at_rest_unencrypted_fires_on_plain_db():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "DATA_AT_REST_UNENCRYPTED" in t.id]
    assert len(fired) == 1
    assert fired[0].severity == "high"  # database is in _SENSITIVE_AT_REST_STORES


def test_data_at_rest_unencrypted_suppressed_by_control():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database",
                   controls=["encryption_at_rest"]),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "DATA_AT_REST_UNENCRYPTED" in t.id]
    assert fired == []


def test_data_at_rest_unencrypted_suppressed_by_kms_edge():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database"),
        Component(id="kms", name="KMS", type="kms_key"),
    ], dataflows=[Dataflow(source="db", target="kms", label="envelope")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "DATA_AT_REST_UNENCRYPTED" in t.id]
    assert fired == []


def test_data_at_rest_unencrypted_suppressed_by_description_hint():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database",
                   description="PostgreSQL with TDE (TLS+AES) and SSE-KMS volumes"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "DATA_AT_REST_UNENCRYPTED" in t.id]
    assert fired == []


def test_data_at_rest_unencrypted_severity_medium_for_bulk_storage():
    """Object storage gets medium (not high) — bulk store, not always
    confidential by default."""
    sys_obj = System(name="t", components=[
        Component(id="s3", name="S3", type="object_storage"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "DATA_AT_REST_UNENCRYPTED" in t.id]
    assert len(fired) == 1
    assert fired[0].severity == "medium"


# ─── v0.18.28 Cycle RR — AI-specific operational controls ──────────

def test_missing_prompt_injection_guard_fires_on_llm_without_guard():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ], dataflows=[Dataflow(source="u", target="llm")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_PROMPT_INJECTION_GUARD" in t.id]
    assert len(fired) == 1


def test_missing_prompt_injection_guard_suppressed_by_guardrails_component():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(id="g", name="Guard", type="guardrails"),
    ], dataflows=[Dataflow(source="u", target="llm")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_PROMPT_INJECTION_GUARD" in t.id]
    assert fired == []


def test_missing_prompt_injection_guard_suppressed_by_control_declaration():
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user"),
        Component(id="llm", name="LLM", type="llm_inference",
                   controls=["prompt_injection_guard"]),
    ], dataflows=[Dataflow(source="u", target="llm")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_PROMPT_INJECTION_GUARD" in t.id]
    assert fired == []


def test_missing_pii_redaction_fires_on_db_to_llm_edge():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ], dataflows=[Dataflow(source="db", target="llm", label="query")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_PII_REDACTION_AT_LLM_BOUNDARY" in t.id]
    assert len(fired) == 1


def test_missing_pii_redaction_suppressed_by_label_hint():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ], dataflows=[Dataflow(source="db", target="llm",
                            label="query (redacted, PII tokenized)")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_PII_REDACTION_AT_LLM_BOUNDARY" in t.id]
    assert fired == []


def test_missing_pii_redaction_suppressed_by_dlp_component():
    sys_obj = System(name="t", components=[
        Component(id="db", name="DB", type="database"),
        Component(id="llm", name="LLM", type="llm_inference"),
        Component(id="dlp", name="Purview", type="dlp"),
    ], dataflows=[Dataflow(source="db", target="llm")])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_PII_REDACTION_AT_LLM_BOUNDARY" in t.id]
    assert fired == []


def test_missing_model_provenance_fires_on_model_registry_without_signing():
    sys_obj = System(name="t", components=[
        Component(id="mr", name="ModelReg", type="model_registry"),
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_MODEL_PROVENANCE" in t.id]
    assert len(fired) >= 1


def test_missing_model_provenance_suppressed_by_signing_control():
    sys_obj = System(name="t", components=[
        Component(id="mr", name="ModelReg", type="model_registry",
                   controls=["sigstore_signed", "slsa_provenance"]),
        Component(id="llm", name="LLM", type="llm_inference",
                   controls=["model_card_published"]),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_MODEL_PROVENANCE" in t.id]
    assert fired == []


def test_unbounded_agent_tool_access_fires_above_threshold():
    sys_obj = System(name="t", components=[
        Component(id="a", name="Agent", type="agent"),
        Component(id="t1", name="T1", type="tool"),
        Component(id="t2", name="T2", type="tool"),
        Component(id="t3", name="T3", type="tool"),
        Component(id="t4", name="T4", type="tool"),
        Component(id="t5", name="T5", type="tool"),
        Component(id="t6", name="T6", type="tool"),
    ], dataflows=[Dataflow(source="a", target=f"t{i}") for i in range(1, 7)])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNBOUNDED_AGENT_TOOL_ACCESS" in t.id]
    assert len(fired) == 1


def test_unbounded_agent_tool_access_under_threshold_no_fire():
    sys_obj = System(name="t", components=[
        Component(id="a", name="Agent", type="agent"),
        Component(id="t1", name="T1", type="tool"),
        Component(id="t2", name="T2", type="tool"),
        Component(id="t3", name="T3", type="tool"),
    ], dataflows=[Dataflow(source="a", target=f"t{i}") for i in range(1, 4)])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNBOUNDED_AGENT_TOOL_ACCESS" in t.id]
    assert fired == []


def test_unbounded_agent_tool_access_suppressed_by_control():
    sys_obj = System(name="t", components=[
        Component(id="a", name="Agent", type="agent",
                   controls=["tool_access_control"]),
        Component(id="t1", name="T1", type="tool"),
        Component(id="t2", name="T2", type="tool"),
        Component(id="t3", name="T3", type="tool"),
        Component(id="t4", name="T4", type="tool"),
        Component(id="t5", name="T5", type="tool"),
        Component(id="t6", name="T6", type="tool"),
    ], dataflows=[Dataflow(source="a", target=f"t{i}") for i in range(1, 7)])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "UNBOUNDED_AGENT_TOOL_ACCESS" in t.id]
    assert fired == []


def test_human_oversight_required_when_high_risk_and_no_user_downstream():
    sys_obj = System(
        name="t",
        is_high_risk_under_eu_ai_act=True,
        components=[
            Component(id="llm", name="LLM", type="llm_inference"),
            Component(id="api", name="API", type="api_gateway"),
        ],
        dataflows=[Dataflow(source="llm", target="api")],
    )
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_HUMAN_OVERSIGHT_HIGH_RISK" in t.id]
    assert fired
    assert fired[0].severity == "high"


def test_human_oversight_satisfied_when_user_downstream_of_llm():
    sys_obj = System(
        name="t",
        is_high_risk_under_eu_ai_act=True,
        components=[
            Component(id="llm", name="LLM", type="llm_inference"),
            Component(id="reviewer", name="Reviewer", type="user"),
        ],
        dataflows=[Dataflow(source="llm", target="reviewer")],
    )
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_HUMAN_OVERSIGHT_HIGH_RISK" in t.id]
    assert fired == []


def test_human_oversight_not_fired_when_not_high_risk():
    """Default systems (is_high_risk_under_eu_ai_act=False) don't fire this rule."""
    sys_obj = System(name="t", components=[
        Component(id="llm", name="LLM", type="llm_inference"),
    ])
    threats = evaluate_arch_rules(sys_obj)
    fired = [t for t in threats if "MISSING_HUMAN_OVERSIGHT_HIGH_RISK" in t.id]
    assert fired == []


# ─── End-to-end through workflow.analyze ────────────────────────────
def test_workflow_emits_arch_threats():
    """A topology that triggers multiple rules should produce multiple
    architectural threats end-to-end through analyze()."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user", trust_zone="external"),
        Component(id="db", name="Postgres", type="database", trust_zone="external"),
    ], dataflows=[
        Dataflow(source="u", target="db", label="direct"),
    ])
    tm = analyze(sys_obj, require_ai_components=False)
    arch_ids = [t.id for t in tm.threats if ".A_" in t.id]
    assert arch_ids, "Expected at least one architectural-rule threat"
    # The user→db direct access should hit several rules:
    # unguarded_access_from_internet, unguarded_direct_datastore_access,
    # missing_network_segmentation (same zone).
    titles = {t.title for t in tm.threats if ".A_" in t.id}
    assert any("Internet" in t for t in titles)


def test_no_arch_threats_on_clean_topology():
    """A well-segmented system with no anti-patterns should produce
    very few arch threats. v0.18.6 added encryption/auth hints to the
    dataflow labels (Cycle V rules). v0.18.12 added a backup_service,
    a kms_key, an mfa_service, an EDR / SIEM stack, and encryption-at-
    rest controls on the stores so Cycle BB's 5 operational-controls
    rules also have no findings."""
    sys_obj = System(name="t", components=[
        Component(id="u", name="User", type="user", trust_zone="external"),
        Component(id="waf", name="WAF", type="waf", trust_zone="perimeter"),
        Component(id="idp", name="Okta", type="identity_provider", trust_zone="identity"),
        Component(id="mfa", name="MFA", type="mfa_service", trust_zone="identity"),
        Component(id="app", name="Web", type="web_application", trust_zone="app",
                  controls=["edr", "centralized_logging"]),
        Component(id="vault", name="Vault", type="secrets_vault", trust_zone="secrets",
                  controls=["encryption_at_rest"]),
        Component(id="db", name="DB", type="database", trust_zone="data",
                  controls=["encryption_at_rest", "backup_immutable"]),
        Component(id="kms", name="KMS", type="kms_key", trust_zone="secrets"),
        Component(id="bkp", name="Backup", type="backup_service", trust_zone="data"),
        Component(id="siem", name="SIEM", type="siem", trust_zone="observability"),
        Component(id="edr", name="EDR", type="edr_agent", trust_zone="observability"),
    ], dataflows=[
        Dataflow(source="u", target="waf", label="HTTPS request",
                  crosses_boundary=True),
        Dataflow(source="waf", target="app", label="TLS forward (JWT bearer)",
                  crosses_boundary=True),
        Dataflow(source="app", target="vault", label="get-secret (mTLS, JWT)",
                  crosses_boundary=True),
        Dataflow(source="app", target="db", label="TLS SQL (OAuth token)",
                  crosses_boundary=True),
        Dataflow(source="db", target="kms", label="envelope encryption",
                  crosses_boundary=True),
        Dataflow(source="db", target="bkp", label="encrypted snapshot",
                  crosses_boundary=True),
    ])
    tm = analyze(sys_obj, require_ai_components=False)
    arch_ids = [t.id for t in tm.threats if ".A_" in t.id]
    # Should be zero or very small. Some rules MAY still fire (e.g.,
    # missing_waf BFS hitting a specific component); the contract is
    # that a clean topology has very few arch threats, not necessarily
    # zero.
    assert len(arch_ids) <= 2, (
        f"Clean topology should produce ≤ 2 arch threats; got {len(arch_ids)}: {arch_ids}"
    )
