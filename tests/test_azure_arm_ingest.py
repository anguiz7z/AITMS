"""Regression tests for v0.18.14 Cycle DD — Azure Bicep + ARM template ingest."""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_azure_arm_ingest.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import json

import pytest

from atms.ingest.azure_arm import (
    arm_template_to_system,
    azure_to_system,
    bicep_to_system,
)

_SAMPLE_BICEP = """
// header comment
/* block
   comment */
resource plan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: 'myplan'
  location: 'eastus'
}

resource fn 'Microsoft.Web/sites@2022-03-01' = {
  name: 'myfunc'
  kind: 'functionapp'
  properties: {
    serverFarmId: plan.id
  }
}

resource site 'Microsoft.Web/sites@2022-03-01' = {
  name: 'mysite'
  kind: 'app'
  properties: {
    serverFarmId: plan.id
  }
}

resource kv 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: 'mykv'
}

resource sql 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: 'mysql'
}

resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2022-08-15' = {
  name: 'mycosmos'
}

resource vnet 'Microsoft.Network/virtualNetworks@2022-09-01' = {
  name: 'myvnet'
}

resource appins 'Microsoft.Insights/components@2020-02-02' = {
  name: 'myins'
  properties: {
    WorkspaceResourceId: la.id
  }
}

resource la 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'myla'
}
"""


# ─── Bicep DSL ─────────────────────────────────────────────────────
def test_bicep_parses_basic_resources():
    s = bicep_to_system(_SAMPLE_BICEP)
    types = {c.id: c.type for c in s.components}
    assert types["plan"] == "cloud_compute"
    assert types["fn"] == "serverless_function"  # kind=functionapp
    assert types["site"] == "web_application"    # kind=app
    assert types["kv"] == "secrets_vault"
    assert types["sql"] == "database"
    assert types["cosmos"] == "nosql_database"
    assert types["vnet"] == "network_segment"
    assert types["appins"] == "observability_stack"
    assert types["la"] == "siem"


def test_bicep_emits_edges_via_symbolic_reference():
    s = bicep_to_system(_SAMPLE_BICEP)
    edges = {(df.source, df.target) for df in s.dataflows}
    # `site -> plan` and `fn -> plan` both reference `plan.id`.
    assert ("site", "plan") in edges
    assert ("fn", "plan") in edges
    # `appins -> la` (WorkspaceResourceId: la.id)
    assert ("appins", "la") in edges


def test_bicep_creates_trust_boundary_for_vnet():
    s = bicep_to_system(_SAMPLE_BICEP)
    assert len(s.trust_boundaries) == 1
    assert s.trust_boundaries[0].id == "vnet:vnet"
    assert s.trust_boundaries[0].type == "network"


def test_bicep_strips_comments_before_parsing():
    """Resource declarations inside comments should NOT be picked up."""
    bicep_with_commented_out = """
    // resource fake 'Microsoft.Compute/virtualMachines@2022-01-01' = { name: 'fake' }
    /* resource also_fake 'Microsoft.Storage/storageAccounts@2022-09-01' = { name: 'fake' } */
    resource real 'Microsoft.KeyVault/vaults@2022-07-01' = {
      name: 'real'
    }
    """
    s = bicep_to_system(bicep_with_commented_out)
    ids = {c.id for c in s.components}
    assert ids == {"real"}


def test_bicep_friendly_name_from_name_property():
    s = bicep_to_system(_SAMPLE_BICEP)
    by_id = {c.id: c for c in s.components}
    assert by_id["kv"].name == "mykv"
    assert by_id["site"].name == "mysite"


def test_bicep_handles_existing_keyword():
    """`resource X 'T@V' existing = { ... }` should be parsed identically."""
    src = """
    resource k 'Microsoft.KeyVault/vaults@2022-07-01' existing = {
      name: 'sharedkv'
    }
    """
    s = bicep_to_system(src)
    assert len(s.components) == 1
    assert s.components[0].type == "secrets_vault"


def test_bicep_handles_conditional_resource():
    """`if (cond)` clauses before the body should not break parsing."""
    src = """
    param createKv bool = true
    resource k 'Microsoft.KeyVault/vaults@2022-07-01' = if (createKv) {
      name: 'maybekv'
    }
    """
    s = bicep_to_system(src)
    assert len(s.components) == 1
    assert s.components[0].type == "secrets_vault"


def test_bicep_unknown_type_falls_back_to_other():
    src = """
    resource exotic 'Microsoft.Made.Up/foo@2099-01-01' = {
      name: 'huh'
    }
    """
    s = bicep_to_system(src)
    assert s.components[0].type == "other"


def test_bicep_empty_file_raises():
    with pytest.raises(ValueError, match="no `resource`"):
        bicep_to_system("// empty file\n")


def test_bicep_dataflows_deduplicated():
    """Multiple `.id` references between the same pair collapse to one edge."""
    src = """
    resource a 'Microsoft.KeyVault/vaults@2022-07-01' = {
      name: 'a'
    }
    resource b 'Microsoft.Sql/servers@2022-05-01-preview' = {
      name: 'b'
      properties: {
        keyVaultUri: a.id
        secretIdentifier: a.properties.uri
        backupVault: a.id
      }
    }
    """
    s = bicep_to_system(src)
    edges = [(df.source, df.target) for df in s.dataflows]
    assert edges.count(("b", "a")) == 1


# ─── ARM JSON ──────────────────────────────────────────────────────
def test_arm_template_parses_basic_resources():
    tpl = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.Storage/storageAccounts",
                "name": "mystg",
                "apiVersion": "2022-09-01",
            },
            {
                "type": "Microsoft.KeyVault/vaults",
                "name": "mykv",
                "apiVersion": "2022-07-01",
                "dependsOn": ["[resourceId('Microsoft.Storage/storageAccounts', 'mystg')]"],
            },
        ],
    }
    s = arm_template_to_system(json.dumps(tpl))
    types = {c.id: c.type for c in s.components}
    assert types["mystg"] == "object_storage"
    assert types["mykv"] == "secrets_vault"
    # dependsOn yields an edge from mykv -> mystg.
    edges = {(df.source, df.target) for df in s.dataflows}
    assert ("mykv", "mystg") in edges


def test_arm_template_rejects_non_arm_json():
    not_arm = {"foo": "bar"}
    with pytest.raises(ValueError, match="ARM"):
        arm_template_to_system(json.dumps(not_arm))


def test_arm_template_empty_resources_raises():
    tpl = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "resources": [],
    }
    with pytest.raises(ValueError, match="empty"):
        arm_template_to_system(json.dumps(tpl))


def test_arm_template_nested_resources_parsed():
    tpl = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "resources": [
            {
                "type": "Microsoft.Web/sites",
                "name": "mysite",
                "kind": "functionapp",
                "apiVersion": "2022-03-01",
                "resources": [
                    {
                        "type": "config",
                        "name": "appsettings",
                        "apiVersion": "2022-03-01",
                    },
                ],
            },
        ],
    }
    s = arm_template_to_system(json.dumps(tpl))
    ids = {c.id for c in s.components}
    assert "mysite" in ids
    by_id = {c.id: c for c in s.components}
    assert by_id["mysite"].type == "serverless_function"  # kind=functionapp


# ─── Auto-dispatch ─────────────────────────────────────────────────
def test_azure_to_system_dispatches_to_bicep_for_dsl():
    s = azure_to_system(_SAMPLE_BICEP, name="dsl-test")
    assert s.name == "dsl-test"
    assert len(s.components) >= 5


def test_azure_to_system_dispatches_to_arm_for_json():
    tpl = json.dumps({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "resources": [{
            "type": "Microsoft.KeyVault/vaults", "name": "kv", "apiVersion": "2022-07-01",
        }],
    })
    s = azure_to_system(tpl, name="json-test")
    assert s.name == "json-test"
    by_id = {c.id: c.type for c in s.components}
    assert by_id["kv"] == "secrets_vault"
