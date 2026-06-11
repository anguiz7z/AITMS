---
name: tm-from-image
description: Threat-model an architecture from a DIAGRAM IMAGE (PNG/JPG/screenshot) or a draw.io/Visio export, when AITMS's deterministic ingest can't read the raw picture. Use when the user uploads/links an architecture diagram and asks to threat-model it, or says "tm this diagram", "/tm-from-image". Vision reads the image into a model; AITMS does the deterministic analysis.
license: Apache-2.0
---

# tm-from-image — diagram image → AITMS threat model

Bridges the one gap in AITMS's offline pipeline: it ingests *structured* inputs (YAML / draw.io / IaC), not flat images. Turning a *picture* into a model is fundamentally a vision-AI task — so this skill uses the model's own vision for that ONE step, then hands off to AITMS's deterministic, no-LLM engine. **Honest split: AI-assisted ingest, AI-free analysis.**

**Success criteria:** a faithful AITMS system YAML derived from the image, a clean `atms analyze` run, and the report surfaced (DFD, framework-mapped threats, attack paths). The YAML reflects *only* what's in the diagram — no invented components.

## How
1. **Read the image with vision.** Enumerate every component, its type, the trust zones/subnets it sits in, and the dataflows (arrows). Note vendor/product labels (AWS/Azure/GCP services, Bedrock/Kendra/etc.).
2. **Transcribe to AITMS YAML** (`atms`'s native schema):
   - Map each box to a valid `ComponentType` (run `ls kb/playbooks/` for the full set: `agent`, `llm_inference`, `rag_vector_store`, `tool`, `serverless_function`, `batch_compute`, `cloud_compute`, `nosql_database`, `object_storage`, `load_balancer`, `api_gateway`, `message_queue`, `container_runtime`, `container_registry`, `user`, …).
   - Set `metadata: {vendor, product}` so vendor overlays fire (e.g. `vendor: aws, product: bedrock`).
   - For managed cloud services set `metadata.deployment_mode: managed` (and `idp_kind` for IdPs) so the applicability engine suppresses on-prem FPs (AD/Kerberos, firmware CVEs).
   - Capture `dataflows` with `data_classification` (public/internal/confidential/restricted) — drives impact scoring.
   - Use `trust_zone` per subnet (internet / public_subnet / private_subnet / aws_managed / …).
3. **Analyze:** `PYTHONPATH=src python -m atms analyze <model>.yaml --out <out>` (or `atms analyze` if installed).
4. **Surface the report** (`.md`/`.html`): the data-flow diagram, per-component framework-mapped threats, the attack paths, and the mitigation roadmap.

## Guardrails
- **Faithful only** — transcribe what the diagram shows; flag anything ambiguous rather than inventing it. Re-read the image if unsure of a component or arrow.
- State plainly that vision did the *ingest* (it can misread a busy diagram) and that the *analysis* is deterministic; a human should sanity-check the transcribed model.
- For best fidelity with no AI at all, prefer the source artifact when available: export the diagram as **draw.io / .vsdx / Mermaid**, or point AITMS at the **IaC** (Terraform/CloudFormation/k8s) — those go straight through the deterministic ingest.
