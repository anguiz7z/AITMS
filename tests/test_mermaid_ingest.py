"""Regression tests for v0.18.1 Cycle P — Mermaid flowchart ingest.

Pins the contract that Mermaid `flowchart` source becomes a structured
ATMS System (components + dataflows + trust boundaries inferred from
subgraphs).
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_mermaid_ingest.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


from atms.ingest.mermaid import mermaid_to_system


def test_simple_flowchart_extracts_2_nodes_1_edge():
    src = """
    flowchart LR
        A[User] --> B[API Gateway]
    """
    system = mermaid_to_system(src)
    assert len(system.components) == 2
    assert len(system.dataflows) == 1
    names = {c.name for c in system.components}
    assert "User" in names
    assert "API Gateway" in names


def test_label_regex_classifies_lambda():
    src = """
    flowchart LR
        u[Customer] --> lam[AWS Lambda]
    """
    system = mermaid_to_system(src)
    by_name = {c.name: c.type for c in system.components}
    assert by_name["Customer"] == "user"
    assert by_name["AWS Lambda"] == "serverless_function"


def test_cylinder_shape_classifies_as_database():
    """Shape-based hint: A[(Postgres)] → database."""
    src = """
    flowchart TD
        api[App] --> db[(Customer DB)]
    """
    system = mermaid_to_system(src)
    by_name = {c.name: c.type for c in system.components}
    assert by_name["Customer DB"] == "database"


def test_circle_shape_classifies_as_user():
    """Shape-based hint: A((Label)) → user (actor)."""
    src = """
    flowchart LR
        u((End user)) --> app[Web App]
    """
    system = mermaid_to_system(src)
    by_name = {c.name: c.type for c in system.components}
    assert by_name["End user"] == "user"


def test_hexagon_shape_classifies_as_agent():
    src = """
    flowchart LR
        u[User] --> ag{{Coordinator agent}}
    """
    system = mermaid_to_system(src)
    by_name = {c.name: c.type for c in system.components}
    assert by_name["Coordinator agent"] == "agent"


def test_edge_label_carries_into_dataflow():
    src = """
    flowchart LR
        A[user] -->|HTTPS| B[api]
    """
    system = mermaid_to_system(src)
    assert system.dataflows[0].label == "HTTPS"


def test_inline_edge_label_alt_syntax():
    """A -- label --> B is the inline-label syntax."""
    src = """
    flowchart LR
        A[user] -- POST /login --> B[api]
    """
    system = mermaid_to_system(src)
    assert system.dataflows[0].label == "POST /login"


def test_subgraph_with_vpc_label_becomes_trust_boundary():
    src = """
    flowchart LR
        user[User]
        subgraph "VPC: production"
            apigw[API Gateway]
            lambda[Lambda]
        end
        user --> apigw
        apigw --> lambda
    """
    system = mermaid_to_system(src)
    assert len(system.trust_boundaries) == 1
    assert system.trust_boundaries[0].description == "VPC: production"
    assert system.trust_boundaries[0].type == "network"


def test_subgraph_with_non_boundary_label_is_not_a_boundary():
    """A subgraph labelled `Services` is NOT a trust boundary — only
    container-y nouns (VPC / subnet / DMZ / cluster / tenant) count."""
    src = """
    flowchart LR
        subgraph "Services"
            a[A]
            b[B]
        end
        a --> b
    """
    system = mermaid_to_system(src)
    assert system.trust_boundaries == []


def test_dataflow_crosses_boundary_when_subgraph_differs():
    src = """
    flowchart LR
        user[User]
        subgraph "DMZ subnet"
            apigw[API Gateway]
        end
        subgraph "Internal subnet"
            db[(DB)]
        end
        user --> apigw
        apigw --> db
    """
    system = mermaid_to_system(src)
    name_to_id = {c.name: c.id for c in system.components}
    flows = {(d.source, d.target): d for d in system.dataflows}
    # user (default) → apigw (DMZ): crosses
    assert flows[(name_to_id["User"], name_to_id["API Gateway"])].crosses_boundary
    # apigw (DMZ) → db (Internal): crosses
    assert flows[(name_to_id["API Gateway"], name_to_id["DB"])].crosses_boundary


def test_extracts_from_markdown_codefence(tmp_path):
    """A markdown file with a ```mermaid block extracts the embedded
    diagram."""
    p = tmp_path / "README.md"
    p.write_text("""# Architecture

```mermaid
flowchart LR
    user[User] --> api[API]
```

Some prose.
""", encoding="utf-8")
    system = mermaid_to_system(p)
    assert len(system.components) == 2


def test_ignores_class_style_directives():
    src = """
    flowchart LR
        classDef api fill:#fcc
        A[User] --> B[API]
        class B api
        style A fill:#ccf
    """
    system = mermaid_to_system(src)
    assert len(system.components) == 2
    assert len(system.dataflows) == 1


def test_ignores_mermaid_comments():
    src = """
    flowchart LR
    %% This is a comment, should be ignored.
    A[User] --> B[API]
    %% Another comment with -->|fake edge|
    """
    system = mermaid_to_system(src)
    assert len(system.components) == 2
    assert len(system.dataflows) == 1


def test_thick_arrow_and_dotted_arrow_both_work():
    """Mermaid supports `==>` (thick) and `-.->` (dotted)."""
    src = """
    flowchart LR
        A[user] ==> B[api]
        B -.-> C[(db)]
    """
    system = mermaid_to_system(src)
    assert len(system.dataflows) == 2


def test_system_is_analyzable_end_to_end():
    """The parsed System runs through analyze() cleanly."""
    from atms.workflow import analyze
    src = """
    flowchart LR
        user[User] --> llm[Bedrock LLM]
        llm --> rag[(Kendra)]
    """
    system = mermaid_to_system(src)
    tm = analyze(system)
    assert tm.threats


def test_pure_it_mermaid_works_with_allow_pure_it():
    """Mermaid for a non-AI system flows through pure-IT mode."""
    from atms.workflow import analyze
    src = """
    flowchart LR
        user[User] --> fw[Firewall]
        fw --> web[Web App]
        web --> db[(Postgres)]
    """
    system = mermaid_to_system(src)
    tm = analyze(system, require_ai_components=False)
    assert tm.threats


def test_metadata_carries_source_tag():
    src = "flowchart LR\n  A[Lambda] --> B[(DB)]\n"
    system = mermaid_to_system(src)
    by_name = {c.name: c for c in system.components}
    assert by_name["Lambda"].metadata["source"].startswith("mermaid:")
    assert by_name["DB"].metadata["source"].startswith("mermaid:")
    assert by_name["DB"].metadata["shape"] == "cylinder"
