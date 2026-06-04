"""Regression tests for v0.18.34 Cycle XX — Pulumi state.json + CDK detect."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from atms.cli import cli

# ─── Pulumi state.json ─────────────────────────────────────────────
_STATE = {
    "deployment": {
        "resources": [
            {"type": "pulumi:pulumi:Stack",
             "urn": "urn:pulumi:dev::demo::pulumi:pulumi:Stack::demo"},
            {"type": "aws:s3:Bucket",
             "urn": "urn:pulumi:dev::demo::aws:s3:Bucket::bucket"},
            {"type": "aws:lambda:Function",
             "urn": "urn:pulumi:dev::demo::aws:lambda:Function::func",
             "dependencies": [
                 "urn:pulumi:dev::demo::aws:s3:Bucket::bucket",
                 "urn:pulumi:dev::demo::aws:iam:Role::lambdaRole",
             ]},
            {"type": "aws:iam:Role",
             "urn": "urn:pulumi:dev::demo::aws:iam:Role::lambdaRole"},
            {"type": "aws:ec2:Vpc",
             "urn": "urn:pulumi:dev::demo::aws:ec2:Vpc::main"},
        ]
    }
}


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_pulumi_state_parses_basic_resources():
    from atms.ingest.pulumi_yaml import pulumi_state_to_system
    s = pulumi_state_to_system(text=json.dumps(_STATE))
    types = {c.id: c.type for c in s.components}
    assert types["bucket"] == "object_storage"
    assert types["func"] == "serverless_function"
    assert types["lambdaRole"] == "iam_principal"
    assert types["main"] == "network_segment"


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_pulumi_state_emits_edges_via_dependencies():
    from atms.ingest.pulumi_yaml import pulumi_state_to_system
    s = pulumi_state_to_system(text=json.dumps(_STATE))
    edges = {(df.source, df.target) for df in s.dataflows}
    assert ("func", "bucket") in edges
    assert ("func", "lambdaRole") in edges


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_pulumi_state_skips_meta_resources():
    """The pulumi:pulumi:Stack pseudo-resource is meta — not a component."""
    from atms.ingest.pulumi_yaml import pulumi_state_to_system
    s = pulumi_state_to_system(text=json.dumps(_STATE))
    ids = {c.id for c in s.components}
    assert "demo" not in ids  # the Stack pseudo-resource


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_pulumi_state_creates_trust_boundary_for_vpc():
    from atms.ingest.pulumi_yaml import pulumi_state_to_system
    s = pulumi_state_to_system(text=json.dumps(_STATE))
    assert any(b.id == "pulumi-state:main" for b in s.trust_boundaries)


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_pulumi_state_rejects_non_state_json():
    from atms.ingest.pulumi_yaml import pulumi_state_to_system
    with pytest.raises(ValueError, match="Not a Pulumi state"):
        pulumi_state_to_system(text=json.dumps({"foo": "bar"}))


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_pulumi_state_rejects_empty_resources():
    from atms.ingest.pulumi_yaml import pulumi_state_to_system
    with pytest.raises(ValueError, match="no recognisable"):
        pulumi_state_to_system(text=json.dumps({
            "deployment": {"resources": [
                {"type": "pulumi:pulumi:Stack",
                 "urn": "urn:pulumi:dev::demo::pulumi:pulumi:Stack::demo"},
            ]}
        }))


# ─── scan auto-detect ───────────────────────────────────────────────
def _run_scan(input_path: str):
    runner = CliRunner()
    return runner.invoke(cli, ["scan", input_path, "--format", "md"]), runner


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_pulumi_state(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(json.dumps(_STATE), encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "pulumi-state" in res.output


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_detects_cdk_synth(tmp_path):
    """A CFN-looking JSON with `aws:cdk:*` markers should report as CDK."""
    p = tmp_path / "stack.template.json"
    p.write_text(json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "CDK auto-synthesised stack",
        "Resources": {
            "Func": {
                "Type": "AWS::Lambda::Function",
                "Properties": {},
                "Metadata": {"aws:cdk:path": "MyStack/Func/Resource"},
            },
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {},
                "Metadata": {"aws:cdk:path": "MyStack/Bucket/Resource"},
            },
        },
    }), encoding="utf-8")
    res, _ = _run_scan(str(p))
    assert res.exit_code == 0, res.output
    assert "cdk" in res.output.lower()
