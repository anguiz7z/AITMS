"""Phase M corpus #5 — HashiCorp official two-tier AWS Terraform example.

Source:
  https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/main/examples/two-tier/main.tf
Fetched 2026-05-23. License: MPL-2.0 (HashiCorp / IBM Corp.).

This closes the IaC corpus to a full quartet of the four major IaC
tools used in production:

  Phase D corpus #4  Azure Bicep        (azure_keyvault.bicep)
  Phase 4 corpus #2  Kubernetes YAML    (k8s_guestbook.yaml)
  Phase 4 corpus #3  AWS CloudFormation (aws_cfn_lambda_sample.yaml)
  Phase M corpus #5  HashiCorp Terraform (hashicorp_aws_two_tier.tf)
  Plus Phase 4 #1    OWASP Threat Dragon (cross-tool import)

Terraform is the most-used IaC tool in industry and was conspicuously
absent from the corpus. The bundled `samples/iac/main.tf` is a
hand-authored AI-focused stack (which is fine for the v0.14 ingest
smoke test) — this corpus entry is a *verbatim* upstream file from
HashiCorp's official terraform-provider-aws repo, providing a real
regression floor against parser refactors.

The 9-resource topology exercised:
  - aws_vpc (network_segment)
  - aws_internet_gateway (other; not in _RESOURCE_MAP — defensible,
    it's network plumbing not a workload)
  - aws_route (other)
  - aws_subnet (network_segment)
  - aws_security_group × 2 (firewall) — note BOTH names map to
    `firewall` and id-collision is handled by terraform_resource
    name embedding in the cid
  - aws_elb (load_balancer) — newly mapped in v0.18.61 after this
    corpus surfaced the legacy-ELB gap
  - aws_key_pair (other)
  - aws_instance (endpoint)

Side effect of this corpus addition (v0.18.61):
  `aws_elb` was added to `_RESOURCE_MAP` (it was legitimately missing).
  See terraform.py:53-60 for the comment justifying it.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_cycle_jjj_terraform_corpus.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


from pathlib import Path

SAMPLE = (Path(__file__).resolve().parents[1]
          / "samples" / "corpus" / "hashicorp_aws_two_tier.tf")


def _system():
    from atms.ingest.terraform import parse_terraform
    return parse_terraform(SAMPLE)


def _model():
    from atms.workflow import analyze
    s = _system()
    return s, analyze(s, require_ai_components=False)


def test_terraform_corpus_file_exists_and_is_upstream():
    """Provenance check — the file must contain HashiCorp's exact
    upstream snippets, so a future hand-edit can't pass this test
    silently. Includes MPL-2.0 license assertion."""
    text = SAMPLE.read_text(encoding="utf-8")
    # License + provenance
    assert "SPDX-License-Identifier: MPL-2.0" in text
    assert "Copyright IBM Corp." in text
    # Canonical upstream snippets
    assert 'resource "aws_vpc" "default"' in text
    assert 'resource "aws_elb" "web"' in text
    assert 'resource "aws_instance" "web"' in text
    assert "metadata_options" in text
    assert 'http_tokens = "required"' in text  # IMDSv2 — security-relevant


def test_terraform_corpus_ingester_finds_nine_resources():
    """9 resource blocks in the upstream file → 9 ATMS Components."""
    s = _system()
    assert len(s.components) == 9


def test_terraform_corpus_component_types():
    """Spot-check the type mapping on real-world inputs.

    `aws_elb` mapping was added in v0.18.61 Phase M specifically because
    this corpus surfaced that the legacy-ELB resource was being silently
    classified as "other" (load_balancer is the correct mapping)."""
    s = _system()
    by_name = {c.metadata["terraform_name"]: c for c in s.components
               if c.metadata.get("terraform_resource") == "aws_elb"}
    assert "web" in by_name, "missing aws_elb.web in parsed components"
    assert by_name["web"].type == "load_balancer", (
        "aws_elb should map to load_balancer — if this fails, check "
        "_RESOURCE_MAP in terraform.py; the v0.18.61 mapping may have "
        "been reverted")

    # aws_vpc + aws_subnet → network_segment
    types_by_rt = {(c.metadata["terraform_resource"], c.metadata["terraform_name"]): c.type
                   for c in s.components}
    assert types_by_rt[("aws_vpc", "default")] == "network_segment"
    assert types_by_rt[("aws_subnet", "default")] == "network_segment"
    # Both security groups → firewall (despite same Terraform name)
    assert types_by_rt[("aws_security_group", "elb")] == "firewall"
    assert types_by_rt[("aws_security_group", "default")] == "firewall"
    # aws_instance → endpoint
    assert types_by_rt[("aws_instance", "web")] == "endpoint"


def test_terraform_corpus_dataflows_from_interpolations():
    """Cross-resource interpolations (`aws_vpc.default.id`,
    `aws_subnet.default.id`, etc.) produce ATMS Dataflow edges with
    label='reference'. The exact count depends on the parser's
    detection of refs in masked strings; pin a floor that says
    "the graph isn't empty"."""
    s = _system()
    assert len(s.dataflows) >= 10, \
        f"expected ≥10 reference edges, got {len(s.dataflows)}"
    # All dataflows from this corpus are reference edges (no depends_on).
    labels = {df.label for df in s.dataflows}
    assert labels == {"reference"}, \
        f"expected only 'reference' edges, got {labels}"


def test_terraform_corpus_elb_references_subnet_and_instance():
    """aws_elb.web has `subnets = [aws_subnet.default.id]` and
    `instances = [aws_instance.web.id]` — both must show up as edges
    from elb → subnet and elb → instance."""
    s = _system()
    ids = {(c.metadata["terraform_resource"], c.metadata["terraform_name"]): c.id
           for c in s.components}
    edges = {(df.source, df.target) for df in s.dataflows}
    assert (ids[("aws_elb", "web")], ids[("aws_subnet", "default")]) in edges
    assert (ids[("aws_elb", "web")], ids[("aws_instance", "web")]) in edges


def test_terraform_corpus_instance_references_security_group():
    """aws_instance.web references aws_security_group.default via
    `vpc_security_group_ids = [aws_security_group.default.id]`."""
    s = _system()
    ids = {(c.metadata["terraform_resource"], c.metadata["terraform_name"]): c.id
           for c in s.components}
    edges = {(df.source, df.target) for df in s.dataflows}
    src = ids[("aws_instance", "web")]
    tgt = ids[("aws_security_group", "default")]
    assert (src, tgt) in edges


def test_terraform_corpus_analysis_emits_threats():
    """A 2-tier AWS deployment with a public-facing ELB + open SGs
    should produce ≥5 threats from the playbooks + arch rules."""
    _, m = _model()
    assert len(m.threats) >= 5


def test_terraform_corpus_security_relevant_threats_surface():
    """The 25-rule + playbook engine should flag security-relevant
    issues on this topology. Concrete check: the open `0.0.0.0/0`
    ingress in `aws_security_group.elb` should surface the
    over-permissive-ingress playbook threat (T_NET_001).

    HashiCorp's own example uses `0.0.0.0/0` for HTTP (port 80) on the
    ELB SG, which is intentional for a public webserver but worth
    flagging in a threat model. The signal here is that ATMS catches
    it without manual review."""
    _, m = _model()
    # T_NET_001 = Over-permissive ingress on inference/training endpoints
    open_ingress = [t for t in m.threats if "T_NET_001" in t.id]
    assert len(open_ingress) >= 1, (
        f"expected ≥1 T_NET_001 (over-permissive ingress) finding "
        f"given the 0.0.0.0/0 SG in this topology; got 0. Total "
        f"threats: {len(m.threats)}"
    )


def test_terraform_corpus_vendor_metadata_present():
    """Every parsed AWS resource gets `vendor=AWS` in metadata
    (terraform.py:392-398)."""
    s = _system()
    vendors = {c.metadata.get("vendor") for c in s.components}
    assert vendors == {"AWS"}, f"expected vendor=AWS on all, got {vendors}"


def test_terraform_corpus_trust_boundary_emitted():
    """parse_terraform creates a single `terraform_default` trust
    boundary containing every parsed component (terraform.py:444-450)."""
    s = _system()
    assert len(s.trust_boundaries) == 1
    tb = s.trust_boundaries[0]
    assert tb.id == "terraform_default"
    assert tb.type == "deployment_zone"
    assert len(tb.components_inside) == len(s.components)


def test_terraform_corpus_load_balancer_classified_in_sbom():
    """Cross-check Phase 1's SBOM type-map invariant on the new
    resource: aws_elb mapped to load_balancer must serialize to
    `application` (the CycloneDX type for load balancers)."""
    from atms.reporting.sbom_export import _TYPE_MAP, render_sbom_cdx
    _, m = _model()
    import json
    sbom = json.loads(render_sbom_cdx(m))
    # aws_elb__web is the cid the parser generates.
    elb = next((c for c in sbom["components"]
                if c["bom-ref"] == "aws_elb__web"), None)
    assert elb is not None, \
        "aws_elb__web should be in the SBOM components list"
    # load_balancer maps to 'application' in the CycloneDX 1.5 type map.
    assert elb["type"] == _TYPE_MAP["load_balancer"]
