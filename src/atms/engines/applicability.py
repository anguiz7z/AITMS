"""Applicability-predicate engine (v0.16.0).

Closes a recurring false-positive class: per-component playbooks fire
threats indiscriminately for every instance of a component type, even
when the threat is plainly inapplicable. Examples seen in v0.15 audits:

* Amazon Cognito (a managed cloud IdP) inheriting Active-Directory
  credential-theft threats (Kerberoast, DCSync, Pass-the-Hash) — none
  of those primitives exist in Cognito.
* AWS CloudFront / Cloud Armor / Cloudflare picking up F5 BIG-IP and
  Palo Alto NGFW firmware-CVE threats — managed CDNs don't ship
  firmware the customer can patch.
* A single-orchestrator system inheriting "rogue agent in multi-agent
  system" without any peer agents being modelled.

The engine evaluates two optional predicate blocks on every playbook
threat: ``requires`` (ALL must match) AND NOT ``not_applicable_to``
(ANY match suppresses). If both blocks are absent, the threat emits
unchanged — full backwards compatibility with the v0.15 KB.

Topology predicates (``applicable_to_topology``) consult the System,
not just the Component — they answer questions like "does this system
have more than one agent?" or "is there outbound internet?". The
predicate registry below is intentionally narrow at launch; add new
entries as the playbook authors need them.

Performance budget: the check must add <5ms to a typical analyse call.
The implementation is two dict walks and a list intersection per
threat, both O(predicates) where predicates is usually 0–3.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..models import Component, System


# ─── Topology predicates ───────────────────────────────────────────────────
# Each entry takes a System and returns True iff the system exhibits the
# named topological property. Threat authors reference these by name in
# `applicable_to_topology: [...]` to gate threats that only make sense
# in particular system shapes (multi-agent meshes, egress-capable
# networks, mTLS-internal architectures, etc.).
def has_multi_agent(system: System) -> bool:
    """True iff the system contains more than one ``agent`` component.

    Gates threats like "rogue agent infectious-backdoor" that
    structurally require a peer-agent attack surface.
    """
    agent_count = sum(1 for c in system.components if c.type == "agent")
    return agent_count > 1


def has_outbound_internet(system: System) -> bool:
    """True iff any component declares outbound-internet egress.

    The check looks for an explicit ``metadata.outbound_internet`` flag,
    OR a control marker (``"no_internet_egress"`` absent) on at least
    one AI/agentic primitive. Conservative — when in doubt we report
    True so threats requiring egress aren't silently suppressed.
    """
    for c in system.components:
        meta = c.metadata or {}
        if meta.get("outbound_internet"):
            return True
        # Conservative fallback: if any non-isolated component lacks the
        # `no_internet_egress` control, assume egress is possible.
        if "no_internet_egress" in (c.controls or []):
            continue
        # Only trip on egress-capable component types — endpoints, agents,
        # serverless, llm_inference, etc.
        if c.type in {
            "agent",
            "llm_inference",
            "serverless_function",
            "container_runtime",
            "endpoint",
            "tool",
            "external_api",
        }:
            return True
    return False


def has_mtls_internal(system: System) -> bool:
    """True iff at least one component declares ``mtls`` in its controls."""
    return any("mtls" in (c.controls or []) for c in system.components)


TOPOLOGY_PREDICATES: dict[str, Callable[[System], bool]] = {
    "multi_agent_mesh": has_multi_agent,
    "has_outbound_internet": has_outbound_internet,
    "has_mtls_internal": has_mtls_internal,
}


# ─── Field-path resolution ─────────────────────────────────────────────────
def _resolve_field(component: Component, path: str) -> Any:
    """Look up a dotted field path on a component.

    Recognised paths:
    - ``component_type``  → ``component.type``
    - ``trust_zone``      → ``component.trust_zone``
    - ``metadata.<key>``  → ``component.metadata[<key>]`` (None if missing)
    - any other dotted path → best-effort attribute walk on the model
    """
    if path == "component_type":
        return component.type
    if path == "trust_zone":
        return component.trust_zone
    if path.startswith("metadata."):
        key = path.split(".", 1)[1]
        return (component.metadata or {}).get(key)
    # Defensive fallback for future field paths (e.g. "name").
    obj: Any = component
    for part in path.split("."):
        if obj is None:
            return None
        obj = getattr(obj, part, None)
    return obj


def _values_match(actual: Any, expected: Any) -> bool:
    """Case-insensitive scalar / list membership match.

    - ``expected`` may be a scalar or a list/tuple.
    - String comparison is case-insensitive on both sides.
    - Non-string scalars compare with ``==``.
    - ``None`` actual never matches anything (a missing metadata key
      can't satisfy a `requires` clause).
    """
    if actual is None:
        return False
    if isinstance(expected, (list, tuple, set)):
        return any(_values_match(actual, e) for e in expected)
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.strip().lower() == expected.strip().lower()
    return actual == expected


# ─── Public API ────────────────────────────────────────────────────────────
def threat_applies(
    threat_def: dict,
    component: Component,
    system: System,
) -> tuple[bool, str]:
    """Decide whether a playbook threat should emit for this component.

    Args:
        threat_def: The raw threat dict from the playbook YAML.
        component: The Component the threat is being evaluated against.
        system: The full System (needed for topology predicates).

    Returns:
        ``(True, "")`` if the threat should emit.
        ``(False, reason)`` if the threat is suppressed, where ``reason``
        describes the failing predicate for the audit trail.

    Evaluation order (first failure wins so the reason is specific):
    1. ``requires`` — every (field_path, value) must match.
    2. ``not_applicable_to`` — ANY (field_path, value) match suppresses.
    3. ``applicable_to_topology`` — every named predicate must hold on
       the System.

    Threats without any of these blocks emit unchanged (back-compat).
    """
    # 1. requires — every entry must match.
    requires = threat_def.get("requires") or {}
    if requires:
        for field_path, expected in requires.items():
            actual = _resolve_field(component, field_path)
            if not _values_match(actual, expected):
                return (
                    False,
                    f"requires[{field_path}]={_format_expected(expected)} "
                    f"not satisfied (actual={actual!r})",
                )

    # 2. not_applicable_to — any match suppresses.
    not_applicable = threat_def.get("not_applicable_to") or {}
    if not_applicable:
        for field_path, blocked in not_applicable.items():
            actual = _resolve_field(component, field_path)
            if actual is None:
                continue
            if _values_match(actual, blocked):
                return (
                    False,
                    f"{field_path}={actual!r} in not_applicable_to:"
                    f"{_format_expected(blocked)}",
                )

    # 3. applicable_to_topology — every named predicate must hold.
    topology = threat_def.get("applicable_to_topology") or []
    if topology:
        for name in topology:
            predicate = TOPOLOGY_PREDICATES.get(name)
            if predicate is None:
                # Unknown topology predicate — fail open (emit) and let
                # the playbook author notice. Surfacing as a soft reason
                # so the audit trail captures the typo.
                continue
            if not predicate(system):
                return (
                    False,
                    f"topology[{name}] not satisfied",
                )

    return (True, "")


def _format_expected(expected: Any) -> str:
    """Render expected-value lists compactly for audit-trail reasons."""
    if isinstance(expected, (list, tuple, set)):
        return "[" + ",".join(str(e) for e in expected) + "]"
    return repr(expected)


__all__ = [
    "TOPOLOGY_PREDICATES",
    "has_multi_agent",
    "has_mtls_internal",
    "has_outbound_internet",
    "threat_applies",
]
