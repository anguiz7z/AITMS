# `kb/reference_patterns/` — reference-architecture cross-walk

This folder holds **cross-walk catalogues** that let an ATMS mitigation
say "this is AWS SRA pattern `AWS_SRA.NETWORK.2`" or
"this is Azure WAF AI `Azure_WAF_AI.SEC-3`" instead of "another generic
security tip."

A reviewer reading an ATMS report can then click through to the
canonical Microsoft Learn / AWS docs / Well-Architected page that
defines the pattern.

## Files

| File                  | Framework                                       | Entries |
|-----------------------|-------------------------------------------------|---------|
| `aws_sra.yaml`        | AWS Security Reference Architecture             | 25      |
| `aws_genai_lens.yaml` | AWS Well-Architected Generative AI Lens         | 18      |
| `azure_lza.yaml`      | Azure Landing Zone (Cloud Adoption Framework)   | 20      |
| `azure_waf_ai.yaml`   | Azure Well-Architected — AI workloads (Security) | 15      |

Minimum 78 entries total; current pack is 78.

## Per-entry schema

Every entry across the four files conforms to:

```yaml
- id: AWS_SRA.NETWORK.2
  display_name: VPC endpoints (Interface + Gateway) keep traffic on the AWS backbone
  framework: AWS_SRA                  # one of: AWS_SRA, AWS_GenAI_Lens, Azure_LZA, Azure_WAF_AI
  category: network                   # identity | network | data | observability | governance | resilience
  applies_to_component_types:         # ATMS ComponentType slugs the pattern relates to (>= 1)
    - private_link
    - object_storage
    - llm_inference
  keywords:                           # substrings matched against mitigation title + description
    - vpc endpoint
    - privatelink
    - interface endpoint
  ai_specific: false                  # true if pattern is AI-Lens-specific; false for general security
  url: https://docs.aws.amazon.com/vpc/latest/privatelink/what-is-privatelink.html
  short_summary: |
    Provision VPC interface endpoints for service APIs (Bedrock, S3,
    KMS, Secrets Manager, SSM, ECR, CloudWatch). Eliminates NAT egress
    and stops data exfil via public service endpoints.
```

### Field reference

| Field                      | Type     | Required | Notes                                                                                       |
|----------------------------|----------|----------|---------------------------------------------------------------------------------------------|
| `id`                       | string   | yes      | Dot-separated. `<FRAMEWORK>.<DOMAIN_OR_PILLAR>.<NUMBER>`. Must be globally unique.            |
| `display_name`             | string   | yes      | One-line human-readable title.                                                              |
| `framework`                | enum     | yes      | `AWS_SRA` / `AWS_GenAI_Lens` / `Azure_LZA` / `Azure_WAF_AI`.                                  |
| `category`                 | enum     | yes      | `identity` / `network` / `data` / `observability` / `governance` / `resilience`.             |
| `applies_to_component_types` | list   | yes      | At least one valid `ComponentType` slug from `kb/system.schema.json`.                       |
| `keywords`                 | list     | yes      | Lowercase substrings matched against mitigation text by the enricher.                       |
| `ai_specific`              | bool     | yes      | `true` if AI-/ML-specific; `false` for general cloud security.                              |
| `url`                      | URL      | yes      | Real Microsoft Learn / AWS docs / Well-Architected page. No invented paths.                  |
| `short_summary`            | string   | yes      | 2-4 sentences. Plain English, no marketing.                                                  |

### `applies_to_component_types` valid values

Pull the canonical list from `kb/system.schema.json` (the
`ComponentType` enum) — at the time of writing this includes:

`llm_inference, rag_vector_store, agent, tool, mcp_server,
training_pipeline, fine_tuning_pipeline, embedding_service,
prompt_template_store, model_registry, guardrails, output_filter,
ml_feature_store, ml_pipeline_orchestrator, ml_data_labeling,
ml_experiment_tracker, ml_inference_endpoint, vision_pipeline,
speech_pipeline, content_safety_classifier, data_source, external_api,
user, cloud_compute, serverless_function, container_runtime,
container_orchestrator, container_registry, edge_compute, batch_compute,
high_performance_compute, object_storage, block_storage, file_storage,
data_lake, data_warehouse, cache_store, backup_service, database,
nosql_database, graph_database, time_series_database, message_queue,
stream_processor, etl_orchestrator, load_balancer, cdn, api_gateway,
service_mesh, private_link, network_segment, transit_gateway,
dns_service, firewall, waf, ids_ips, ddos_mitigation, web_proxy,
reverse_proxy, vpn_gateway, router, network_switch, switch_l3,
sdwan_edge, network_access_control, bastion_host, pam_vault,
iam_principal, directory_service, identity_provider, mfa_service,
sso_service, ciam_platform, secrets_vault, kms_key, certificate_manager,
hsm, siem, soar, edr_agent, vulnerability_scanner, casb, dlp, cspm,
container_security, security_data_lake, observability_stack,
log_aggregator, metrics_platform, tracing_platform, alerting_platform,
endpoint, server_windows, server_linux, server_unix, mainframe,
virtual_desktop, mobile_device, mdm_emm, web_application, email_server,
file_transfer_service, code_repository, ci_cd_pipeline, artifact_registry,
build_runner, feature_flag_service, iac_template_registry, other`.

## How the engine uses these files

The enricher (added by a separate session — do **not** modify Python here):

1. Loads all four YAML files into a single `reference_patterns` table.
2. For each mitigation produced by ATMS, computes a match score using:
   * `keywords` overlap against mitigation title + description.
   * `applies_to_component_types` ∩ component.type.
   * Bonus weight if `ai_specific=true` and the mitigation targets an
     AI / ML component, or if `ai_specific=false` and the component is
     general infrastructure.
3. Annotates the mitigation with the top-N matched `id`s plus their
   canonical `url`.

## Curator guidance

1. **Use real IDs only.** Don't invent a Well-Architected ID — use the
   numbering already published by AWS / Microsoft. If you can't find an
   exact ID, use a closest parent (e.g. `AWS_GenAI_Lens.SEC-1` covers
   "controlled access to FMs" in the Lens).
2. **Real URLs only.** Every URL must resolve to a public Microsoft
   Learn, AWS docs, or Well-Architected page. If the deepest URL 404s,
   point at the parent docs root for that section — never invent a
   path.
3. **One pattern per ID.** Don't conflate two ideas (e.g. KMS + HSM
   should be separate entries).
4. **AI-specific vs general.** Set `ai_specific: true` only when the
   pattern is genuinely AI / ML-specific (Bedrock Guardrails, Prompt
   Shields, PTU). Cross-cutting things (CloudTrail, Azure Policy) are
   `false`.
5. **Validate component-types** against `kb/system.schema.json` before
   committing — the enricher silently drops unknown slugs.
6. **Keep `short_summary` ≤ 4 sentences.** Reviewer-friendly, no
   marketing voice.

## Roadmap

Future packs (not in this drop):

- `gcp_csa_ccm.yaml`      — GCP Cloud Foundation + CSA CCM mapping.
- `oci_landing_zone.yaml` — Oracle CIS Landing Zone.
- `nist_csf_ai.yaml`      — NIST AI RMF / CSF 2.0 control overlay
                            (currently held in `kb/nist_ai_rmf/`).
