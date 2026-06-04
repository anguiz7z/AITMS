---
role: applicability-engineer
summary: Owns the threat-applicability-predicate engine and the per-threat predicates that gate emission, preventing vendor/topology false positives.
---

# Applicability engineer

This guide covers the threat-applicability-predicate engine and the
per-threat predicates that decide whether a threat is emitted for a given
component. The goal is to prevent false positives — for example, a managed
cloud identity service receiving on-prem Active Directory threats.

## Area of ownership

- `src/atms/engines/applicability.py`
- `tests/test_applicability.py`
- The `requires:`, `not_applicable_to:`, and `applicable_to_topology:`
  fields on every threat in:
  - `kb/playbooks/*.yaml`
  - `kb/vendor_threats/*.yaml`

This does NOT include other engines (`stride_ai.py`, `mapping.py`,
`cloud.py`, etc.) — coordinate before touching them.

## Predicate schema (load-bearing)

```yaml
- id: T_DIR_001
  requires:                              # ALL must match for threat to emit
    component_type: directory_service
    metadata.idp_kind: [active_directory, ldap]
    metadata.deployment_mode: [appliance, virtual_appliance, on_prem]
  not_applicable_to:                     # ANY match suppresses
    metadata.idp_kind: [cognito, entra_id, auth0, okta]
    metadata.vendor: [AWS, Microsoft, Google]
  applicable_to_topology:                # optional system-level predicates
    - multi_agent_mesh
    - has_outbound_internet
```

Semantics:

- `requires` is `AND` across keys; for list values, ANY match satisfies the
  key.
- `not_applicable_to` is `OR`; ANY satisfied key suppresses.
- `applicable_to_topology` is `AND` across the named system-level
  predicates.
- Missing all three means emit unconditionally (back-compat).

## Hard rules

1. **Closure of the system-level predicates.** Every
   `applicable_to_topology` value MUST correspond to a function in
   `applicability.py`. New ones need a corresponding helper plus a test.

2. **Predicate authoring.** When a review flags a false-positive vendor
   mismatch, add the predicate promptly and record the rationale in its test and commit message.

3. **Audit trail.** Keep emitting suppressed-threat reasons even when
   downstream code doesn't surface them yet. The reason lets a future
   reporter explain "we suppressed N threats because vendor=AWS in
   not_applicable_to."

## Workflow

1. Review the latest content-audit findings for false-positive flags.
2. For each one, add an applicability predicate to the offending threat.
3. Add a regression test in `tests/test_applicability.py`.
4. Run `python -m pytest tests/test_applicability.py -v` first, then
   `python -m pytest tests/ -q` for the full suite.
5. Summarise: files touched, predicates added, test-count delta.
