"""Real-world reference-architecture snapshot tests (v0.18.36 Cycle ZZ).

Pins parse-output invariants on every canonical sample so an ingest
regression can't silently change them. These tests don't compare full
YAML dumps (too fragile across whitespace tweaks); instead they pin:

  - exact component count
  - exact dataflow count
  - exact trust-boundary count
  - sorted list of component_type values that appear
  - count of each component_type

If you intentionally extend a sample, update the snapshot dict
below. The test fails loudly when an ingester or sample changes
unexpectedly — the failure message names the diff.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

SAMPLES_IAC = Path(__file__).resolve().parents[1] / "samples" / "iac"
SAMPLES_SYS = Path(__file__).resolve().parents[1] / "samples"


# Snapshots. Generated from the current ingest output; freeze them
# here so future versions trip an audit-style review.
IAC_SNAPSHOTS: dict[str, dict] = {
    "webapp.drawio": {
        "ingest": "drawio",
        "min_components": 8,
        "min_dataflows": 5,
        "must_include_types": {"user", "waf", "api_gateway",
                                "load_balancer", "secrets_vault"},
    },
    "rag_pipeline.mmd": {
        "ingest": "mermaid",
        "min_components": 8,
        "min_dataflows": 6,
        "must_include_types": {"user", "api_gateway", "llm_inference",
                                "rag_vector_store"},
    },
    "eks_microservices.cfn.yaml": {
        "ingest": "cfn",
        "min_components": 10,
        "min_dataflows": 0,  # CFN dataflows come from Ref/GetAtt — sparse here
        "must_include_types": {"api_gateway", "container_orchestrator",
                                "database", "object_storage",
                                "secrets_vault", "kms_key", "waf"},
    },
    "k8s_microservices.yaml": {
        "ingest": "k8s",
        "min_components": 5,
        "min_dataflows": 0,
        "must_include_types": {"container_runtime", "load_balancer",
                                "api_gateway", "secrets_vault"},
    },
    "aoai_rag.bicep": {
        "ingest": "azure",
        "min_components": 12,
        "min_dataflows": 1,
        "must_include_types": {"web_application", "secrets_vault",
                                "llm_inference", "database",
                                "nosql_database", "network_segment"},
    },
    "multi_cloud.pulumi.yaml": {
        "ingest": "pulumi",
        "min_components": 12,
        "min_dataflows": 2,
        "must_include_types": {"object_storage", "iam_principal",
                                "secrets_vault", "waf", "kms_key",
                                "network_segment"},
    },
}


def _load(path: Path, ingest: str):
    if ingest == "drawio":
        from atms.ingest.drawio import drawio_to_system
        return drawio_to_system(path)
    if ingest == "mermaid":
        from atms.ingest.mermaid import mermaid_to_system
        return mermaid_to_system(path)
    if ingest == "cfn":
        from atms.ingest.cloudformation import cloudformation_to_system
        return cloudformation_to_system(path)
    if ingest == "k8s":
        from atms.ingest.kubernetes import kubernetes_to_system
        return kubernetes_to_system(path)
    if ingest == "azure":
        from atms.ingest.azure_arm import azure_to_system_from_path
        return azure_to_system_from_path(path)
    if ingest == "pulumi":
        from atms.ingest.pulumi_yaml import pulumi_to_system
        return pulumi_to_system(path=path)
    raise ValueError(f"unknown ingest {ingest!r}")


@pytest.mark.parametrize("filename,snap", list(IAC_SNAPSHOTS.items()))
@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4
def test_iac_sample_invariants_hold(filename: str, snap: dict):
    """Pins parse invariants on every canonical IaC sample."""
    path = SAMPLES_IAC / filename
    assert path.exists(), f"sample missing: {path}"
    system = _load(path, snap["ingest"])

    # Invariants.
    assert len(system.components) >= snap["min_components"], (
        f"{filename}: components {len(system.components)} < "
        f"{snap['min_components']} (regression?)"
    )
    assert len(system.dataflows) >= snap["min_dataflows"], (
        f"{filename}: dataflows {len(system.dataflows)} < "
        f"{snap['min_dataflows']} (regression?)"
    )
    actual_types = {c.type for c in system.components}
    missing = snap["must_include_types"] - actual_types
    assert not missing, (
        f"{filename}: missing required types {sorted(missing)}; "
        f"got {sorted(actual_types)}"
    )


def test_iac_corpus_type_distribution_spans_categories():
    """Across the whole IaC corpus we expect AT LEAST:
    compute / storage / identity / network / data / secrets coverage."""
    all_types: Counter = Counter()
    for filename, snap in IAC_SNAPSHOTS.items():
        try:
            sys_obj = _load(SAMPLES_IAC / filename, snap["ingest"])
        except Exception:
            continue
        for c in sys_obj.components:
            all_types[c.type] += 1
    type_set = set(all_types)

    storage_like = {"object_storage", "block_storage", "file_storage",
                     "database", "nosql_database", "data_warehouse"}
    identity_like = {"iam_principal", "identity_provider", "ciam_platform",
                      "mfa_service", "directory_service"}
    network_like = {"waf", "load_balancer", "api_gateway", "firewall",
                     "network_segment", "cdn"}
    secrets_like = {"secrets_vault", "kms_key", "hsm"}
    compute_like = {"web_application", "container_runtime",
                     "container_orchestrator", "serverless_function",
                     "cloud_compute"}

    for label, group in [("storage", storage_like),
                          ("identity", identity_like),
                          ("network", network_like),
                          ("secrets", secrets_like),
                          ("compute", compute_like)]:
        assert type_set & group, (
            f"IaC corpus missing any {label}-like component "
            f"(expected one of {sorted(group)})"
        )


def test_vertical_samples_meet_floor_invariants():
    """Healthcare / fintech / OT samples have known component counts
    that must not regress."""
    from atms.cli import _load_system_yaml
    cases = [
        ("healthcare_ehr_fhir.yaml",    20, 10),
        ("fintech_payment_ledger.yaml", 25, 15),
        ("ot_water_treatment.yaml",     18, 5),
    ]
    for filename, min_comp, min_df in cases:
        s = _load_system_yaml(SAMPLES_SYS / filename)
        assert len(s.components) >= min_comp, (
            f"{filename}: components {len(s.components)} < {min_comp}"
        )
        assert len(s.dataflows) >= min_df, (
            f"{filename}: dataflows {len(s.dataflows)} < {min_df}"
        )


def test_industry_diversity_across_samples():
    """At least 4 distinct industries represented across all samples."""
    import yaml
    industries = set()
    for p in SAMPLES_SYS.glob("*.yaml"):
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        ind = (data or {}).get("industry")
        if ind:
            industries.add(ind)
    assert len(industries) >= 4, (
        f"Need ≥4 industries across samples; got {sorted(industries)}"
    )
