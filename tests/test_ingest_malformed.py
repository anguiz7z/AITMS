"""Ingest crash-hardening regressions (audit F053/F054/F055/F056/F057).

Malformed IaC / diagram input must not abort with an unhandled AttributeError;
the parser must skip the bad bits and return a (possibly partial) System.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.hibernated  # ingest surfaces are hibernated


def _tmp(text: str, suffix: str) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8")
    f.write(text)
    f.close()
    return f.name


def test_azure_arm_tolerates_non_dict_resource_and_non_string_type():
    """F053: a resources[] entry that is a string, or a non-string type, must
    be skipped, not crash."""
    from atms.ingest.azure_arm import arm_template_to_system
    arm = ('{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/'
           'deploymentTemplate.json#","resources":["junk",{"type":123,"name":"x"},'
           '{"type":"Microsoft.Web/sites","name":"app"}]}')
    sys = arm_template_to_system(arm)
    assert any(c.type for c in sys.components)


def test_cloudformation_tolerates_properties_as_list():
    """F054: a resource whose Properties is a YAML list (malformed) must not
    crash the .items() walk."""
    from atms.ingest.cloudformation import cloudformation_to_system
    p = _tmp("Resources:\n  R:\n    Type: AWS::EC2::Instance\n    Properties: [oops]\n", ".yaml")
    sys = cloudformation_to_system(p)
    assert len(sys.components) >= 1


def test_kubernetes_tolerates_scalar_metadata():
    """F055: scalar/null `metadata` (top-level or spec.template.metadata) must
    not crash; well-formed docs still parse."""
    from atms.ingest.kubernetes import kubernetes_to_system
    k8s = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: scalarmeta\n"
        "spec: {template: {metadata: scalartmpl}}\n---\n"
        "apiVersion: v1\nkind: Service\nmetadata: scalarsvc\n---\n"
        "apiVersion: v1\nkind: Pod\nmetadata: {name: realpod}\n"
    )
    sys = kubernetes_to_system(k8s)
    assert any(c.name == "realpod" or "realpod" in c.id for c in sys.components)


def test_otm_tolerates_scalar_parent():
    """F057: an OTM component whose `parent` is a scalar (id string) instead of
    an object must not crash the trustZone lookup."""
    from atms.ingest.otm import parse_otm
    p = _tmp(json.dumps({
        "otmVersion": "0.2.0",
        "components": [{"id": "c1", "name": "C", "type": "web-application", "parent": "scalarparent"}],
    }), ".otm")
    sys = parse_otm(Path(p))
    assert len(sys.components) == 1


def test_mermaid_parses_left_and_bidirectional_arrows():
    """F056: leftward (A <-- B => B->A) and bidirectional (A <--> B => both)
    edges must be captured, not silently dropped."""
    from atms.ingest.mermaid import mermaid_to_system
    sys = mermaid_to_system("flowchart LR\n  A[User] <--> B[API]\n  C[DB] <-- D[Worker]\n")
    edges = {(d.source, d.target) for d in sys.dataflows}
    assert ("A", "B") in edges and ("B", "A") in edges  # bidirectional
    assert ("D", "C") in edges                            # leftward reversed
