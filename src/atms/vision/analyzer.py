"""Vision-based diagram → System-YAML draft.

If the user has `anthropic` installed and `ANTHROPIC_API_KEY` set, this module
asks Claude to extract components, dataflows, and trust boundaries from an
architecture-diagram image. Output is a draft `System` YAML that the user is
expected to review and edit.

Strict opt-in: never invoked from the deterministic core. ATMS works with no
key — manual YAML authoring is the supported workflow.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

VISION_PROMPT = """You are a security architect helping to threat-model an AI/ML/LLM/agentic system.
You are looking at an architecture diagram of an AI system. Your job is to extract a structured
description that an automated threat-modeling tool can analyze.

Return ONLY a YAML document conforming to this schema (no surrounding text, no fences):

name: <short name>
description: <1-3 sentences describing the system>
business_context: <1-2 sentences of business context if visible>
components:
  - id: <short id, lowercase, no spaces>
    name: <human name>
    type: <one of: llm_inference, rag_vector_store, agent, tool, mcp_server,
           training_pipeline, fine_tuning_pipeline, embedding_service,
           prompt_template_store, model_registry, guardrails, output_filter,
           data_source, external_api, user,
           iam_principal, secrets_vault, object_storage, network_segment,
           serverless_function, api_gateway, container_runtime, kms_key,
           message_queue, observability_stack,
           database, firewall, directory_service, web_application, endpoint,
           legacy_mainframe, plc, scada, iot_device, load_balancer,
           vpn_gateway, network_switch, email_server, mfa_service,
           industrial_protocol,
           other>
    metadata:
      vendor: <vendor name if visible, else omit>
      product: <product name if visible, else omit>
      version: <version if visible, else omit>
    trust_zone: <free-form: internet, corp_dmz, corp_internal, external_provider, training_vpc, etc.>
    description: <1 sentence>
dataflows:
  - source: <component id>
    target: <component id>
    label: <short verb-phrase>
    crosses_boundary: <true|false>
    data_classification: <public|internal|confidential|restricted>
trust_boundaries:
  - id: <short id>
    type: <network|identity|data_classification|tenancy|deployment_zone>
    components_inside: [<id>, ...]
    components_outside: [<id>, ...]
    description: <1 sentence>

Rules:
- Use the listed `type` values exactly. If unsure, use "other" and add a note in description.
- Every component referenced in dataflows or boundaries must be declared in `components`.
- Output YAML only. No surrounding markdown. No comments. UTF-8 only.
"""


def diagram_to_system_yaml(image_path: Path, model: str = "claude-opus-4-7") -> str:
    """Run an image through Claude vision; return a YAML draft string.

    Raises RuntimeError if the optional `anthropic` package or API key is missing.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set. Vision is opt-in; describe the system in YAML manually instead."
        )
    try:
        import anthropic  # noqa: PLC0415  (optional import)
    except ImportError as e:
        raise RuntimeError(
            "anthropic package not installed. `pip install anthropic` to enable vision-based analysis."
        ) from e

    image_bytes = image_path.read_bytes()
    media_type = _guess_media_type(image_path)
    encoded = base64.b64encode(image_bytes).decode("ascii")

    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model,
        max_tokens=4096,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {"type": "base64", "media_type": media_type, "data": encoded},
                    },
                    {"type": "text", "text": VISION_PROMPT},
                ],
            }
        ],
    )
    text = ""
    for block in msg.content:
        if getattr(block, "type", None) == "text":
            text += block.text
    return text.strip()


def _guess_media_type(path: Path) -> str:
    suffix = path.suffix.lower()
    return {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
    }.get(suffix, "image/png")


__all__: list[str] = ["diagram_to_system_yaml"]


# ---- placate linters when we don't return Any
_ = Any
