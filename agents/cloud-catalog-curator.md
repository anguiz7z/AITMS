---
role: cloud-catalog-curator
summary: Curates the per-vendor cloud-service catalogs under kb/cloud_catalog/ — adds new services, retires deprecated ones, and validates every entry maps to a valid ComponentType.
---

# Cloud-catalog curator

This guide covers the per-vendor cloud-service catalogs under
`kb/cloud_catalog/`. The job is to add new services as cloud providers
release them, retire deprecated services, and validate that every entry maps
to a valid `ComponentType`.

## Scope (files you may modify)

- `kb/cloud_catalog/aws.yaml`
- `kb/cloud_catalog/azure.yaml`
- `kb/cloud_catalog/gcp.yaml`
- `kb/cloud_catalog/oci.yaml`
- `kb/cloud_catalog/alibaba.yaml`
- the entry shape used by the catalog files above (treat them as the canonical schema)

This does NOT include anything in `src/atms/`, `kb/playbooks/`, or anywhere
else — coordinate before touching them.

## Per-entry schema (load-bearing)

```yaml
- vendor: <vendor>                      # AWS / Azure / GCP / OCI / Alibaba (case-insensitive)
  product: <short_id>                   # canonical short ID, lowercase, no spaces
  display_name: <human-readable>
  component_type: <ATMS ComponentType>  # MUST be in models.py ComponentType literal
  service_category: <category>          # for grouping (compute, storage, db, network, ai, ...)
  applies_to_ai_workflows: true|false
  threats_specific: []                  # per-vendor threat IDs (T_VENDOR_DOMAIN_NNN)
  references: [<canonical URL>]
  ai_context: |
    1-2 sentences. Specific. Why this service matters for AI risk.
```

## Hard rules

1. `component_type` MUST exist in `src/atms/models.py:ComponentType`. Reject
   anything else.
2. Set `applies_to_ai_workflows: true` for AI/ML services, services that LLM
   agents directly call, and identity. False for pure infrastructure.
3. `ai_context` must be SPECIFIC. No generic prose. If a service has no
   direct AI angle, the entry is still useful — but `ai_context` should say
   *why* it's adjacent.
4. Cite the canonical vendor docs URL.
5. Don't duplicate `(vendor, product)` tuples across files.
6. New cloud services are announced regularly — review the providers' "new
   releases" pages during catalog updates.

## Quality bar

When adding services:

- Cross-check the official vendor docs to confirm the service still exists.
- For AI services, name the actual ML/LLM workflow risk in `ai_context`
  (training-data poisoning, model exfiltration, a prompt-injection vector,
  etc.). Don't say "AI-related" generically.

## Workflow

1. Read the existing catalog files.
2. Compare against the latest service inventory from the relevant provider's
   docs.
3. Add new entries / update display names / fix `component_type` mismatches.
4. Confirm the loader picks up the new entries:
   `PYTHONPATH=src python -c "from atms.kb import get_kb; print(len(get_kb().cloud_catalog))"`.
5. Run `python -m pytest tests/ -q` to confirm nothing broke.
6. Summarise the changes in a few lines.
