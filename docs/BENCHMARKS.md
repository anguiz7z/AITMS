# ATMS — real-world benchmarks

ATMS is benchmarked against canonical public threat models from
established tools. Every benchmark is reproducible: the source
artefact is preserved under `samples/corpus/` with provenance + a
regression test that pins the comparison numbers so future versions
can't silently shrink coverage.

## Benchmark 1 — OWASP Threat Dragon demo model

The OWASP Threat Dragon project ships a canonical
[demo-threat-model.json](https://github.com/OWASP/threat-dragon/blob/main/ThreatDragonModels/demo-threat-model.json),
hand-authored by the project lead Mike Goodwin. It depicts a
classic 3-tier web application with a queue-decoupled background
worker — 7 elements (Browser, Web App, Background Worker, Worker
Config, Web App Config, Message Queue, Database), 12 data flows,
3 trust boundaries.

Threat Dragon documents **14 threats** hand-curated by the author.
ATMS was run on the exact same topology, translated verbatim into
ATMS YAML. **Result on identical input:**

| Metric                          | OWASP Threat Dragon | ATMS  | Δ        |
|---------------------------------|--------------------:|------:|----------|
| Threats enumerated              |                  14 |    39 | **2.8×** |
| Multi-step attack paths         |                   0 |    10 | new      |
| Mitigations recommended         |                  14 |   131 | **9.4×** |
| Architectural-rule findings     |                   0 |    14 | new      |
| OWASP API Top 10 mappings       |                   0 |     8 | new      |
| MITRE ATLAS techniques          |                   0 |    11 | new      |
| MITRE ATT&CK Cloud techniques   |                   0 |    13 | new      |
| MITRE ATT&CK Enterprise techs   |                   0 |    13 | new      |
| LINDDUN privacy categories      |                   0 |    10 | new      |
| Compliance frameworks scored    |                   0 |     5 (GDPR / HIPAA / ISO 27001 / NIS2 / PCI DSS) |
| Compliance gaps surfaced        |                   0 |    29 (in-scope, uncovered) |
| Annual loss-expectancy estimate |                   — |  $79M – $1.9B |
| Severity breakdown              |                   — | 0 crit / 6 high / 30 med / 3 low |
| Export artefacts                |                   2 (HTML, OTM) | 10 (md, html, exec.html, compliance.html, compliance.csv, jira.csv, jira.json, roadmap.md, roadmap.json, sbom.cdx.json) |

**Reproducibility:**
- Source JSON preserved at
  `samples/corpus/owasp_threat_dragon_demo.json` (Apache-2.0, fetched 2026-05-16).
- ATMS-translated YAML at
  `samples/corpus/owasp_threat_dragon_demo.yaml`.
- Regression test at
  `tests/test_cycle_ddd_threat_dragon_corpus.py` pins the floors —
  any future ATMS version that drops below this coverage fails CI.

To reproduce locally:

```bash
atms scan samples/corpus/owasp_threat_dragon_demo.yaml \
  --out /tmp/td \
  --format all
```

## Why ATMS produces more

Where Threat Dragon expects the human to author every threat
manually, ATMS layers four independent enrichment engines:

1. **Per-component playbooks** (121 of them, one per ComponentType
   — 100% coverage) fire 3-13 templated threats each, each carrying
   STRIDE-for-AI category + framework refs + L×I + mitigations.
2. **Architectural-rule engine** (25 rules across 6 themes —
   external exposure / auth / secrets / supply-chain / operational /
   AI-specific) catches topology-level patterns that no single
   playbook would flag.
3. **Framework cross-walk** auto-maps each threat to OWASP LLM +
   Agentic + API + ATLAS + ATT&CK Cloud + ATT&CK Enterprise + LINDDUN
   + MAESTRO + NIST AI 100-2 + NIST AI RMF using a curated keyword +
   stride alignment matrix.
4. **Compliance enricher** maps to 11 regulatory frameworks (NIS2 /
   DORA / EU AI Act / GDPR / PCI DSS / HIPAA / NIST 800-53 / NIST CSF /
   ISO 27001 / ISO 27017 / ISO 27018 / SEC Cyber / SOC 2 + OWASP MASVS /
   SAMM), with per-framework coverage matrix exports.

Plus a NetworkX-based attack-path finder, FAIR-lite ALE pricing,
D3FEND-mapped mitigations, evidence overlay (KEV / EPSS / VAPT /
red-team), and 12+ export formats.

## Benchmark 2 — Kubernetes "Guestbook" reference (Phase 4)

The Kubernetes project ships the
[Guestbook tutorial](https://kubernetes.io/docs/tutorials/stateless-application/guestbook/)
as their canonical multi-tier reference architecture. 6 manifests:
3 Deployments (redis-leader, redis-follower, frontend) + 3 Services.
The official YAMLs were pulled verbatim from the k8s.io website
content repo, concatenated into a single multi-doc YAML, and run
through `atms scan`.

| Metric                          | Hand-authored docs | ATMS  |
|---------------------------------|-------------------:|------:|
| Threats enumerated              |                ~3 (commentary-style) |    **37** |
| Multi-step attack paths         |                  0 |    **10** |
| Mitigations recommended         |                  0 (informal "best practices") |    **43** |
| Architectural-rule findings     |                  0 |  ≥1 (missing SIEM / IDS / etc.) |
| Inferred Service→Workload edges |                manual reading |    3 (auto) |
| Severity breakdown              |                  — | 0 critical / 3 high / 21 medium / 13 low |

ATMS ingester correctly:
- Parsed all 6 multi-doc manifests
- Mapped Deployments → `container_runtime`, Services → `load_balancer`
- Inferred each Service's `spec.selector` → matching Deployment edge
- Fired the 25-rule architectural pattern engine on the bare topology
  (no SIEM / MFA / encryption hints → operational-controls rules trip)

**Reproducibility:**
- Source under `samples/corpus/k8s_guestbook.yaml`
  (Apache-2.0, fetched 2026-05-16).
- Regression test: `tests/test_cycle_eee_k8s_guestbook_corpus.py`.

```bash
atms scan samples/corpus/k8s_guestbook.yaml \
  --out /tmp/k8s \
  --format all
```

## Benchmark 3 — AWS-official Lambda CFN sample (negative-path test)

`aws-cloudformation/aws-cloudformation-templates/main/Lambda/LambdaSample.yaml`
— the AWS-published reference template (MIT-0). Two resources: an
IAM role + a Lambda function. The template uses **short-form** CFN
intrinsic tags (`!Sub`, `!GetAtt`, `!Ref`).

ATMS's CFN ingester documents that PyYAML's `safe_load` rejects
unknown tags by default and re-raises with a friendly error
pointing users at `aws cloudformation convert-template`. This corpus
entry pins that error-message contract — if the parser ever weakens
to silently swallow short-form tags or crashes with an opaque
`YAMLError`, the regression test trips.

**Outcome on identical input:**

| Metric                           | ATMS behaviour |
|----------------------------------|----------------|
| Parse                            | rejects with `ValueError` mentioning both the cause (short-form) and the fix (convert-template) |
| Friendly error contract          | pinned in `tests/test_cycle_fff_aws_cfn_corpus.py` |

**Reproducibility:**
- Source: `samples/corpus/aws_cfn_lambda_sample.yaml` (MIT-0, fetched 2026-05-16).
- Test:   `tests/test_cycle_fff_aws_cfn_corpus.py`.

## Benchmark 4 — Azure quickstart Bicep (Phase D)

Microsoft publishes the
[azure-quickstart-templates repo](https://github.com/Azure/azure-quickstart-templates)
as the canonical source of starter templates for every Azure
resource. The `key-vault-create/main.bicep` template ships a
KeyVault + a child Secret resource using the Bicep `parent:`
modifier — a common but non-trivial pattern (the secret can't be
modelled standalone; it has a hierarchical name like
`kv/secret-name`).

Pulled verbatim. ATMS Bicep ingester picks up the
parent-child relationship and emits a `kv → secret` dataflow with
label `parent-of`.

| Metric                            | ATMS auto-derived |
|-----------------------------------|------------------:|
| Components                        |                 2 (kv = secrets_vault; secret = other) |
| Dataflows                         |                 1 (`parent-of`) |
| Threats                           |                 9 |
| Attack paths                      |                10 |
| Mitigations                       |                41 |
| Architectural-rule findings       |                ≥1 |
| Severity                          | 2 high / 7 medium |
| SBOM type for kv                  | `cryptographic-asset` (Phase 1 invariant cross-check) |

**Reproducibility:**
- Source: `samples/corpus/azure_keyvault.bicep` (MIT, fetched 2026-05-16).
- Test:   `tests/test_cycle_hhh_azure_bicep_corpus.py` (6 floor asserts).

## Benchmark 5+ — pending

Remaining candidates:

- Public Microsoft Threat Modeling Tool samples (TM7 ingest)
- Pulumi Examples repo entries (TS/Python/Go converted to YAML)
- IriusRisk / ThreatModeler public template comparison (manual,
  vendor permissions permitting)

## Methodology — clean comparison

When benchmarking ATMS against a tool that produces a hand-authored
threat model:

1. Preserve the source artefact under `samples/corpus/` with a
   `_note:` line in metadata recording the URL + fetch date +
   license.
2. Translate the topology verbatim — same components, same edges,
   same trust boundaries — into ATMS YAML. Do not add or remove
   structure.
3. Run `atms scan <yaml> --format all`.
4. Compare the threat / mitigation / path / framework / compliance
   numbers in a per-row table like the OWASP benchmark above.
5. Pin the numbers as floor-asserts in a regression test so they
   can only grow, never silently shrink.
