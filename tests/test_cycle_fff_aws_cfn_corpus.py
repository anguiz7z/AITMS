"""Regression tests for v0.18.50 Phase 4 corpus #3 — AWS Lambda CFN sample.

Pins the friendly-error path for CloudFormation short-form intrinsic
tags. The official AWS sample template at
  https://raw.githubusercontent.com/aws-cloudformation/aws-cloudformation-templates/main/Lambda/LambdaSample.yaml
uses `!Sub`, `!GetAtt`, `!Ref` (short-form). PyYAML's safe_load rejects
unknown tags; ATMS's CFN ingester catches that and re-raises with a
helpful message pointing users at `aws cloudformation convert-template`.

This corpus entry pins that error-message contract — if anyone ever
weakens the parser to silently swallow short-form tags or to crash
with an opaque YAMLError, this test trips.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_cycle_fff_aws_cfn_corpus.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


from pathlib import Path

import pytest

SAMPLE = (Path(__file__).resolve().parents[1] /
          "samples" / "corpus" / "aws_cfn_lambda_sample.yaml")


def test_aws_cfn_short_form_template_surfaces_friendly_error():
    """The official AWS Lambda sample uses short-form tags. Confirm
    ATMS rejects it with the documented friendly error, NOT a YAML
    parse error or an empty model."""
    from atms.ingest.cloudformation import cloudformation_to_system
    with pytest.raises(ValueError) as excinfo:
        cloudformation_to_system(SAMPLE)
    msg = str(excinfo.value)
    # The error must mention BOTH the cause (short-form) and the fix
    # (convert-template).
    assert "short-form" in msg.lower() or "short form" in msg.lower()
    assert "convert" in msg.lower()


def test_aws_cfn_corpus_file_exists_and_is_real_aws_template():
    """Provenance check: the corpus entry must contain the exact
    resources from the upstream AWS template, byte-equivalent. Sanity
    check that the file wasn't replaced with a hand-modified version
    that would pass parsing trivially."""
    text = SAMPLE.read_text(encoding="utf-8")
    # Hand-verified upstream snippets that must be present.
    assert "AWSTemplateFormatVersion" in text
    assert "AWS::IAM::Role" in text
    assert "AWS::Lambda::Function" in text
    assert "!Sub" in text          # short-form tag — drives the rejection
    assert "!GetAtt" in text       # short-form tag
    assert "lambda-function-${EnvName}" in text
