"""Component-controls engine (v0.13).

Implements the Adam-Shostack-school check: "what's already in place?"
A component author can list controls they consider deployed (TLS,
mTLS, WAF, OAuth2 / OIDC, MFA-required, EDR, segmentation, etc.) on
``Component.controls``. This engine lowers likelihood for threats
those controls plausibly mitigate, so reports stop nagging about
phishing on a passwordless-MFA-only system.

Mapping is conservative: each control reduces likelihood by 1 only
when the threat's keywords intersect the control's mitigation surface,
and never below 1.

The recognised control vocabulary lives in ``CONTROL_EFFECTS``.
Authors can add their own — unrecognised tokens are noted in the
threat's references for traceability without changing scoring.
"""

from __future__ import annotations

import re

from ..models import Component, Threat

CONTROL_EFFECTS: dict[str, dict] = {
    # value: {"keywords": [...], "stride": [...], "delta": -1}
    "tls_terminated":         {"keywords": ["mitm", "sniff", "intercept", "cleartext"], "delta": -1},
    "mtls":                   {"keywords": ["mitm", "spoof", "client", "auth"], "delta": -1},
    "tls_pinning":            {"keywords": ["mitm", "downgrade", "ca compromise"], "delta": -1},
    "waf":                    {"keywords": ["xss", "csrf", "ssrf", "sql injection", "owasp"], "delta": -1},
    "rate_limit":             {"keywords": ["dos", "brute force", "stuffing", "exhaust", "fatigue"], "delta": -1},
    "input_validation":       {"keywords": ["injection", "xss", "deserialization", "path traversal"], "delta": -1},
    "output_encoding":        {"keywords": ["xss", "html", "injection"], "delta": -1},
    "csrf_token":             {"keywords": ["csrf", "cross-site request forgery"], "delta": -1},
    "oauth2_client_creds":    {"keywords": ["credential", "token", "auth"], "delta": -1},
    "oidc":                   {"keywords": ["sso", "auth"], "delta": -1},
    "mfa_required":           {"keywords": ["credential", "stolen", "phish", "stuffing"], "delta": -1},
    "phishing_resistant_mfa": {"keywords": ["mfa", "fatigue", "sim swap", "otp", "phish"], "delta": -2},
    "least_privilege":        {"keywords": ["privilege", "escalation", "role", "manipulation"], "delta": -1},
    "rbac":                   {"keywords": ["privilege", "role", "manipulation"], "delta": -1},
    "abac":                   {"keywords": ["privilege", "role"], "delta": -1},
    "edr":                    {"keywords": ["malware", "ransomware", "implant", "lolbin"], "delta": -1},
    "av":                     {"keywords": ["malware"], "delta": -1},
    "segmentation":           {"keywords": ["lateral", "movement", "vlan hop", "flat network"], "delta": -1},
    "data_diode":             {"keywords": ["exfil", "ot", "ics"], "delta": -2},
    "private_subnet":         {"keywords": ["public", "exposed", "internet-facing"], "delta": -1},
    "no_internet_egress":     {"keywords": ["c2", "callback", "exfil"], "delta": -1},
    "egress_filter":          {"keywords": ["exfil", "c2", "tunnel"], "delta": -1},
    "encryption_at_rest":     {"keywords": ["disclosure", "exfil", "leak", "stolen"], "delta": -1},
    "envelope_encryption":    {"keywords": ["disclosure", "exfil", "key"], "delta": -1},
    "kms_managed_key":        {"keywords": ["key compromise", "encryption"], "delta": -1},
    "secrets_in_vault":       {"keywords": ["credential", "hardcoded", "leak"], "delta": -1},
    "no_long_lived_keys":     {"keywords": ["credential", "leak", "rotation"], "delta": -1},
    "siem_centralised":       {"keywords": ["detect", "alert", "log tampering"], "delta": -1},
    "log_tamper_evident":     {"keywords": ["log tampering", "deletion", "log manipulation"], "delta": -1},
    "backup_immutable":       {"keywords": ["ransomware", "destruction", "wipe"], "delta": -1},
    "patch_within_14_days":   {"keywords": ["cve", "patch", "vulnerability", "exploit"], "delta": -1},
    "sbom_signed":            {"keywords": ["supply chain", "dependency", "tampering"], "delta": -1},
    "model_signing":          {"keywords": ["supply chain", "model", "registry", "tampering"], "delta": -1},
    "guardrails_enabled":     {"keywords": ["prompt injection", "jailbreak", "harmful"], "delta": -1},
    "input_output_guardrails": {"keywords": ["prompt injection", "jailbreak", "harmful", "leak"], "delta": -2},
    "human_in_the_loop":      {"keywords": ["agent", "autonomy", "agency", "tool"], "delta": -1},
    "tool_allowlist":         {"keywords": ["agent", "tool", "rce", "command"], "delta": -1},
    "prompt_injection_classifier": {"keywords": ["prompt injection"], "delta": -2},
    "pii_redaction":          {"keywords": ["pii", "redaction", "leak", "personal"], "delta": -1},
    "dp_sgd":                 {"keywords": ["privacy", "membership", "inversion"], "delta": -2},
    "dlp":                    {"keywords": ["exfil", "leak", "loss prevention"], "delta": -1},
    "physical_security":      {"keywords": ["physical", "tamper", "site"], "delta": -1},
}


def _tokenize(text: object) -> set[str]:
    if text is None:
        return set()
    return set(re.findall(r"[a-zA-Z]+", str(text).lower()))


def apply_component_controls(
    threats: list[Threat],
    components: list[Component],
) -> list[Threat]:
    """Lower likelihood (and refresh severity) when component controls
    plausibly mitigate the threat. Mutates threats in place; never
    raises likelihood and never goes below 1.
    """
    comp_by_id = {c.id: c for c in components}
    for t in threats:
        comp = comp_by_id.get(t.component_id)
        if comp is None or not comp.controls:
            continue
        text_haystack = (t.title + " " + t.description).lower()
        deltas = 0
        applied: list[str] = []
        for ctrl_name in comp.controls:
            ctrl_def = CONTROL_EFFECTS.get(ctrl_name.strip().lower())
            if not ctrl_def:
                # Unknown control — track for traceability but don't score.
                applied.append(f"{ctrl_name}(unrecognised)")
                continue
            if any(kw in text_haystack for kw in ctrl_def["keywords"]):
                deltas += int(ctrl_def["delta"])
                applied.append(ctrl_name)
        if deltas != 0:
            t.likelihood = max(1, min(5, t.likelihood + deltas))
            # Note in references for traceability
            for name in applied:
                tag = f"control:{name}"
                if tag not in t.references:
                    t.references.append(tag)
    return threats


__all__ = ["apply_component_controls", "CONTROL_EFFECTS"]
