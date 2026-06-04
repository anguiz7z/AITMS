"""Regression tests for v0.18.37 Cycle AAA — Bicep `for` + `module`.

Closes the two limitations documented in Cycle DD:
  - `[for x in y: { … }]` resource fan-out is now detected (tagged
    with metadata.bicep_loop = "true")
  - `module foo 'bar.bicep' = {}` references emit a placeholder
    component with metadata.bicep_module = "<path>"
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_cycle_aaa_bicep_loops.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


from atms.ingest.azure_arm import bicep_to_system

_SRC_FOR_LOOPS = """
var regions = ['eastus', 'westeurope']
resource kv 'Microsoft.KeyVault/vaults@2022-07-01' = [for r in regions: {
  name: 'kv-${r}'
  location: r
}]
resource sql 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: 'mysql'
}
"""

_SRC_MODULE = """
resource sql 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: 'mysql'
}

module app 'app-stack.bicep' = {
  name: 'app-deploy'
  params: {
    sqlServerId: sql.id
  }
}
"""

_SRC_MODULE_LOOP = """
var regions = ['eastus', 'westeurope']
module apps 'app-stack.bicep' = [for r in regions: {
  name: 'apps-${r}'
  params: { region: r }
}]
"""


# ─── `for` loops on resources ──────────────────────────────────────
def test_for_loop_resource_emitted_with_loop_metadata():
    s = bicep_to_system(_SRC_FOR_LOOPS)
    by_id = {c.id: c for c in s.components}
    assert "kv" in by_id
    assert by_id["kv"].metadata.get("bicep_loop") == "true"
    assert "for" in by_id["kv"].description.lower() or \
           "loop" in by_id["kv"].description.lower()


def test_non_loop_resource_has_no_loop_flag():
    s = bicep_to_system(_SRC_FOR_LOOPS)
    by_id = {c.id: c for c in s.components}
    assert "sql" in by_id
    assert "bicep_loop" not in by_id["sql"].metadata


# ─── `module` references ───────────────────────────────────────────
def test_module_emitted_as_placeholder_component():
    s = bicep_to_system(_SRC_MODULE)
    by_id = {c.id: c for c in s.components}
    assert "app" in by_id
    assert by_id["app"].metadata.get("bicep_module") == "app-stack.bicep"
    assert by_id["app"].type == "other"  # opaque — we don't know the contents


def test_module_inbound_references_become_dataflows():
    """The module body had `sqlServerId: sql.id` — that should
    appear as a `module-uses` edge from the module to `sql`."""
    s = bicep_to_system(_SRC_MODULE)
    edges = {(df.source, df.target, df.label) for df in s.dataflows}
    assert ("app", "sql", "module-uses") in edges


def test_module_inside_for_loop_carries_both_flags():
    s = bicep_to_system(_SRC_MODULE_LOOP)
    by_id = {c.id: c for c in s.components}
    assert "apps" in by_id
    md = by_id["apps"].metadata
    assert md.get("bicep_module") == "app-stack.bicep"
    assert md.get("bicep_loop") == "true"


def test_module_with_resource_collision_skipped_silently():
    """If a `module foo` collides with `resource foo`, the resource
    declaration wins (we add the module second only when no clash)."""
    src = """
    resource shared 'Microsoft.KeyVault/vaults@2022-07-01' = {
      name: 'shared-kv'
    }
    module shared 'kv-module.bicep' = {
      name: 'shared-mod'
    }
    """
    s = bicep_to_system(src)
    by_id = {c.id: c for c in s.components}
    # The resource (not the module) is recorded under id `shared`.
    assert by_id["shared"].type == "secrets_vault"
    assert "bicep_module" not in by_id["shared"].metadata
