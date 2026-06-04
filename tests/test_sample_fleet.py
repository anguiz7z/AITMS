"""Canonical-sample round-trip tests (v0.18.19 Cycle II).

Every input format ATMS supports should ship with a working
demo file in `samples/iac/` (or `samples/` for system YAML).
This test scans each canonical sample with the format-detecting
`atms scan` pipeline and asserts:

  1. Parsing produces at least N components.
  2. Analysis runs to completion (no exceptions).
  3. At least 1 threat is generated (otherwise the sample is
     vacuous — and the playbooks would have caught nothing,
     meaning the sample doesn't exercise the engine).

Skips `.vsdx` since it's a binary fixture (already round-tripped
elsewhere) and `.tf` because the existing `parse_terraform`
needs richer setup than the scan-CLI provides.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "samples" / "iac"


# (filename, ingest entrypoint, min-components, min-threats)
CANONICAL_SAMPLES = [
    ("webapp.drawio",            "drawio",      8, 1),
    ("rag_pipeline.mmd",         "mermaid",     8, 1),
    ("eks_microservices.cfn.yaml", "cfn",       8, 1),
    ("k8s_microservices.yaml",   "k8s",         5, 1),
    ("aoai_rag.bicep",           "azure",      10, 1),
    ("multi_cloud.pulumi.yaml",  "pulumi",     10, 1),
]


@pytest.mark.parametrize("filename,ingest,min_comp,min_threats", CANONICAL_SAMPLES)
@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4
def test_canonical_sample_parses_and_analyzes(
    filename: str, ingest: str, min_comp: int, min_threats: int,
) -> None:
    path = SAMPLES_DIR / filename
    assert path.exists(), f"Missing canonical sample: {path}"

    if ingest == "drawio":
        from atms.ingest.drawio import drawio_to_system
        system = drawio_to_system(path)
    elif ingest == "mermaid":
        from atms.ingest.mermaid import mermaid_to_system
        system = mermaid_to_system(path)
    elif ingest == "cfn":
        from atms.ingest.cloudformation import cloudformation_to_system
        system = cloudformation_to_system(path)
    elif ingest == "k8s":
        from atms.ingest.kubernetes import kubernetes_to_system
        system = kubernetes_to_system(path)
    elif ingest == "azure":
        from atms.ingest.azure_arm import azure_to_system_from_path
        system = azure_to_system_from_path(path)
    elif ingest == "pulumi":
        from atms.ingest.pulumi_yaml import pulumi_to_system
        system = pulumi_to_system(path=path)
    else:
        pytest.fail(f"unknown ingest type {ingest}")

    assert len(system.components) >= min_comp, (
        f"{filename}: expected ≥{min_comp} components, "
        f"got {len(system.components)}"
    )

    # auto-detect AI; some samples are pure-IT.
    from atms.engines.ai_scope import find_ai_components
    from atms.workflow import analyze
    has_ai = bool(find_ai_components(system))
    model = analyze(system, require_ai_components=has_ai)
    assert len(model.threats) >= min_threats, (
        f"{filename}: expected ≥{min_threats} threats, "
        f"got {len(model.threats)}"
    )


def test_every_sample_file_is_in_the_parametrize_list():
    """Guards against authoring a new sample without wiring it
    into the round-trip test. Whenever a new sample lands in
    samples/iac/, this test fails until CANONICAL_SAMPLES is
    updated."""
    existing = {p.name for p in SAMPLES_DIR.glob("*")
                if p.is_file() and p.suffix.lower() not in {".md", ".tf", ".yml"}
                and p.name not in {"docker-compose.yml"}}
    listed = {filename for filename, *_ in CANONICAL_SAMPLES}
    missing = existing - listed
    assert not missing, (
        f"Canonical samples without round-trip coverage: {sorted(missing)}. "
        f"Add them to CANONICAL_SAMPLES in tests/test_sample_fleet.py."
    )
