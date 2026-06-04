"""Regression tests for v0.18.4 Cycle T — CloudFormation YAML/JSON ingest.

Pins the contract that AWS CloudFormation templates become structured
ATMS Systems via deterministic resource-type mapping. Pairs with the
existing Terraform ingest.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_cloudformation_ingest.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import json
import tempfile
from pathlib import Path

import pytest

from atms.ingest.cloudformation import _RESOURCE_MAP, cloudformation_to_system

_SIMPLE_CFN_YAML = """
AWSTemplateFormatVersion: "2010-09-09"
Description: Simple Lambda + S3 + DynamoDB stack
Resources:
  OrdersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: orders
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH
  IngestBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: ingest-2026
  OrderProcessor:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: order-processor
      Runtime: python3.13
      Handler: index.handler
      Code:
        S3Bucket: { Ref: IngestBucket }
      Environment:
        Variables:
          TABLE_NAME: { Ref: OrdersTable }
    DependsOn:
      - OrdersTable
"""


def _write_yaml(text: str) -> Path:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8",
    )
    f.write(text)
    f.close()
    return Path(f.name)


def test_basic_yaml_parses_three_resources():
    p = _write_yaml(_SIMPLE_CFN_YAML)
    try:
        system = cloudformation_to_system(p)
        assert len(system.components) == 3
        by_name = {c.name: c.type for c in system.components}
        assert by_name["OrdersTable"] == "nosql_database"
        assert by_name["IngestBucket"] == "object_storage"
        assert by_name["OrderProcessor"] == "serverless_function"
    finally:
        p.unlink(missing_ok=True)


def test_resource_ids_are_lower_snake_case():
    p = _write_yaml(_SIMPLE_CFN_YAML)
    try:
        system = cloudformation_to_system(p)
        ids = {c.id for c in system.components}
        assert "orders_table" in ids
        assert "ingest_bucket" in ids
        assert "order_processor" in ids
    finally:
        p.unlink(missing_ok=True)


def test_refs_become_dataflows():
    """Lambda.Code.S3Bucket = Ref:IngestBucket → dataflow lambda→bucket.
    Lambda.Environment.TABLE_NAME = Ref:OrdersTable → dataflow lambda→table.
    DependsOn: OrdersTable → already covered by Ref above (deduped).
    """
    p = _write_yaml(_SIMPLE_CFN_YAML)
    try:
        system = cloudformation_to_system(p)
        edges = {(d.source, d.target) for d in system.dataflows}
        assert ("order_processor", "ingest_bucket") in edges
        assert ("order_processor", "orders_table") in edges
    finally:
        p.unlink(missing_ok=True)


def test_json_template_also_parses():
    """CloudFormation can be JSON or YAML. JSON is a YAML subset; the
    same parser must handle both."""
    payload = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "Topic"}},
            },
        },
    }
    p = _write_yaml(json.dumps(payload))
    try:
        system = cloudformation_to_system(p)
        assert len(system.components) == 2
        assert all(c.type == "message_queue" for c in system.components)
    finally:
        p.unlink(missing_ok=True)


def test_unknown_resource_type_falls_back_to_other():
    """A resource type ATMS doesn't recognise must NOT crash — it
    classifies as `other` so the user can refine."""
    template = """
Resources:
  Mystery:
    Type: AWS::SomethingThatDoesntExist::Yet
    Properties: {}
"""
    p = _write_yaml(template)
    try:
        system = cloudformation_to_system(p)
        assert len(system.components) == 1
        assert system.components[0].type == "other"
    finally:
        p.unlink(missing_ok=True)


def test_short_form_intrinsic_tags_give_friendly_error():
    """Short-form !Ref / !GetAtt aren't supported by safe_load; we
    should surface a clear "convert to long-form" message, not a
    raw PyYAML traceback."""
    template = """
Resources:
  Lam:
    Type: AWS::Lambda::Function
    Properties:
      Code: !Ref Bucket
"""
    p = _write_yaml(template)
    try:
        with pytest.raises(ValueError) as exc:
            cloudformation_to_system(p)
        assert "short-form intrinsic" in str(exc.value).lower() or "long-form" in str(exc.value).lower()
    finally:
        p.unlink(missing_ok=True)


def test_missing_resources_section_is_a_clear_error():
    """A template with no Resources is invalid."""
    p = _write_yaml("AWSTemplateFormatVersion: 2010-09-09\nDescription: empty\n")
    try:
        with pytest.raises(ValueError) as exc:
            cloudformation_to_system(p)
        assert "Resources" in str(exc.value)
    finally:
        p.unlink(missing_ok=True)


def test_vpc_subnet_become_trust_boundaries():
    """A resource referencing VpcId/SubnetId should join the
    corresponding trust boundary."""
    template = """
Resources:
  MainVpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  AppSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: { Ref: MainVpc }
      CidrBlock: 10.0.1.0/24
  AppDb:
    Type: AWS::RDS::DBInstance
    Properties:
      VpcId: { Ref: MainVpc }
      SubnetId: { Ref: AppSubnet }
"""
    p = _write_yaml(template)
    try:
        system = cloudformation_to_system(p)
        # MainVpc + AppSubnet → 2 trust boundaries (with AppDb member)
        assert len(system.trust_boundaries) >= 1
        # AppDb should be inside at least one boundary
        boundary_members = [m for b in system.trust_boundaries for m in b.components_inside]
        assert "app_db" in boundary_members
    finally:
        p.unlink(missing_ok=True)


def test_metadata_carries_cfn_type():
    p = _write_yaml(_SIMPLE_CFN_YAML)
    try:
        system = cloudformation_to_system(p)
        by_name = {c.name: c for c in system.components}
        assert by_name["OrderProcessor"].metadata["cfn_type"] == "AWS::Lambda::Function"
        assert by_name["OrderProcessor"].metadata["vendor"] == "aws"
    finally:
        p.unlink(missing_ok=True)


def test_system_analyses_end_to_end():
    from atms.workflow import analyze
    p = _write_yaml(_SIMPLE_CFN_YAML)
    try:
        system = cloudformation_to_system(p)
        # No AI components → general-purpose mode.
        tm = analyze(system, require_ai_components=False)
        assert tm.threats
    finally:
        p.unlink(missing_ok=True)


def test_resource_map_covers_60_plus_types():
    """Sanity check on map breadth — the value of this ingest scales
    with how many AWS resource types we recognise."""
    assert len(_RESOURCE_MAP) >= 60
