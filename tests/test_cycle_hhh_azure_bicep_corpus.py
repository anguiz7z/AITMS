"""Phase D corpus #4 — Microsoft-official Azure quickstart Bicep.

Source:
  https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/quickstarts/microsoft.keyvault/key-vault-create/main.bicep
Fetched 2026-05-16. License: MIT.

KeyVault + child secret with the `parent:` modifier — exercises the
Bicep ingester's parent-child handling on a real upstream template,
not contrived fixtures.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_cycle_hhh_azure_bicep_corpus.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


from pathlib import Path

SAMPLE = (Path(__file__).resolve().parents[1] /
          "samples" / "corpus" / "azure_keyvault.bicep")


def _system():
    from atms.ingest.azure_arm import azure_to_system_from_path
    return azure_to_system_from_path(SAMPLE)


def _model():
    from atms.workflow import analyze
    s = _system()
    return s, analyze(s, require_ai_components=False)


def test_bicep_corpus_file_exists_and_is_upstream():
    """Provenance check — file must contain the exact upstream
    snippets, so a future 'cleanup' that hand-edits the file
    can't pass this test silently."""
    text = SAMPLE.read_text(encoding="utf-8")
    assert "Microsoft.KeyVault/vaults@2023-07-01" in text
    assert "Microsoft.KeyVault/vaults/secrets@2023-07-01" in text
    assert "parent: kv" in text
    assert "@secure()" in text
    assert "enableRbacAuthorization: true" in text


def test_bicep_ingester_finds_two_resources():
    """KeyVault + secret. The secret's ComponentType is 'other'
    (no mapping for `Microsoft.KeyVault/vaults/secrets`) — that's
    fine; what matters is the parent edge is preserved."""
    s = _system()
    assert len(s.components) == 2
    by_id = {c.id: c for c in s.components}
    assert "kv" in by_id
    assert by_id["kv"].type == "secrets_vault"
    assert "secret" in by_id


def test_bicep_parent_modifier_becomes_dataflow():
    """`parent: kv` on the secret resource must produce a
    kv -> secret edge with label 'parent-of'. Phase D regression
    against a hypothetical refactor that drops parent-tracking."""
    s = _system()
    edges = {(df.source, df.target, df.label) for df in s.dataflows}
    assert ("kv", "secret", "parent-of") in edges


def test_bicep_analysis_emits_meaningful_threats():
    """A real-world KeyVault setup should produce ≥5 threats from
    the secrets_vault playbook + arch rules."""
    _, m = _model()
    assert len(m.threats) >= 5


def test_bicep_arch_rules_fire_on_keyvault_without_kms():
    """The 25-rule engine should flag the KeyVault topology — no
    inbound flows from any consumer, no upstream MFA, etc."""
    _, m = _model()
    arch = [t for t in m.threats if ".A_" in t.id]
    # We don't pin specific rule IDs (they may change as the
    # registry grows). Just confirm AT LEAST ONE arch finding
    # fires — proves the engine wasn't accidentally bypassed.
    assert len(arch) >= 1


def test_bicep_corpus_kv_is_classified_as_cryptographic_asset_in_sbom():
    """Cross-check Phase 1's SBOM type-map invariant on real data:
    secrets_vault must map to cryptographic-asset in the SBOM."""
    from atms.reporting.sbom_export import _TYPE_MAP, render_sbom_cdx
    _, m = _model()
    import json
    sbom = json.loads(render_sbom_cdx(m))
    kv = next((c for c in sbom["components"] if c["bom-ref"] == "kv"), None)
    assert kv is not None
    assert kv["type"] == "cryptographic-asset"
    # Sanity: the mapping table has the entry.
    assert _TYPE_MAP["secrets_vault"] == "cryptographic-asset"
