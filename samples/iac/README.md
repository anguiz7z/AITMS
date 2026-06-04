# IaC ingest samples (v0.14)

Two reference inputs for the new `atms ingest-iac` command:

- **`docker-compose.yml`** — a self-hosted RAG stack (nginx + API + Postgres
  + pgvector + Vault + minio + Ollama + Prometheus + Grafana) covering 10
  service types and three trust zones.
- **`main.tf`** — an AWS-only Bedrock+Lambda RAG architecture covering 14
  resource types across IAM, KMS, S3, DynamoDB, Secrets Manager, Lambda,
  API Gateway, ALB, VPC, SQS, CloudWatch and SageMaker.

## Quick try

```bash
# Convert + analyse in one shot
atms ingest-iac samples/iac/docker-compose.yml --out compose-system.yaml --analyze
atms ingest-iac samples/iac/main.tf            --out tf-system.yaml      --analyze

# Or just convert and review in the GUI editor first
atms ingest-iac samples/iac/main.tf --out tf-system.yaml
atms web   # → http://127.0.0.1:8765/editor → load tf-system.yaml
```

## What the parser does (and doesn't)

**docker-compose**: services → components, networks → trust zones, `depends_on`
edges → dataflows, host-mapped ports → user-facing edge with
`crosses_boundary=true`. Image-tag prefixes feed the type classifier
(`postgres` → `database`, `vault` → `secrets_vault`, `ollama` →
`llm_inference`, …).

**Terraform**: regex-based HCL parser; ~70 AWS / Azure / GCP `resource`
types are mapped to ATMS component types. `depends_on` blocks +
cross-resource interpolations become dataflows. `var.x`, `local.y`,
`data.z`, `module.…` are skipped (they're HCL pseudo-namespaces, not
resources). Cache directories (`.terraform/`, `.git/`, `node_modules/`,
`.idea/`, `.vscode/`) are skipped on directory-mode parses.

**Out of scope** (file in the GUI editor after conversion if you need
these): `count`, `for_each` and `dynamic` blocks (the Terraform parser
reads source HCL, not the plan), `secrets:` / `configs:` top-level
sections in compose, build-only services without an `image:`.
