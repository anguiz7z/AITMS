# ATMS Roadmap

This document is the public-facing plan for what ATMS aims to be — and
what it deliberately is not. Reading order: *Positioning* (where we
fit, who we serve), *Pain points we solve* (grounded in published
literature on existing threat-modeling tools), *Pain points we don't
yet solve* (committed work), *Deferred / out-of-scope* (won't fix).

## Positioning

ATMS is an **AI-induced-risk evaluator**. Three sentences:

1. It analyses the full architecture an AI sits in (firewalls, DBs,
   switches, OT, mainframes — every component) but only emits threats
   that exist *because of* AI integration.
2. Pure-IT systems with zero AI components are rejected at load time —
   for those use OWASP Threat Dragon, Microsoft Threat Modeling Tool,
   or IriusRisk.
3. The deterministic core makes zero outbound HTTP calls; the .exe
   ships with no AI/LLM SDKs bundled.

If your real product question is *"what does the LLM I'm bolting on
change about my existing risk profile?"* — that's the question ATMS
is built to answer.

## Pain points we solve (positioning gap matrix)

These are the recurring complaints in published threat-modeling
literature and OSS issue trackers. Each row names which ATMS feature
addresses it.

| Pain (with citation) | ATMS today |
|---|---|
| **"3-week threat-modelling cycles produce a model dev teams already shipped past."** [^1] | Deterministic engine analyses a 16-component System YAML in <5 s end-to-end. CI integration via `atms ci` blocks PRs at a severity threshold. |
| **"STRIDE wasn't designed to handle AI threats — adversarial ML, data poisoning, prompt injection."** [^2] [^3] | STRIDE-for-AI playbook + OWASP LLM Top 10 + OWASP Agentic AI + MITRE ATLAS + MAESTRO + NIST AI 100-2 (adversarial ML taxonomy) all wired in. Every threat is cross-walked across these frameworks. |
| **"Microsoft Threat Modeling Tool is overwhelming for small teams; not enterprise-friendly."** [^4] | Single-page web UI, single CLI command, bundled samples to learn from. No upfront ontology to build. |
| **"OWASP Threat Dragon's GitHub integration requires repo-level access — breaks least privilege."** [^5] | Local-first. Zero cloud dependency. The .exe runs offline; the wheel runs in your venv. Your YAML never leaves your laptop unless you explicitly upload it somewhere. |
| **"IriusRisk free tier limits to 1 threat model; paid tiers are vendor-locked."** [^6] | Apache-2.0. Free for any use, including commercial. Fork the playbooks. |
| **"You build the perfect threat model and nobody uses it."** [^1] | Output formats = the formats reviewers already use: SARIF (GitHub code-scanning), STIX 2.1 (TI platforms), Markdown / HTML (humans), CSV risk register (spreadsheets), ATT&CK Navigator JSON (red teams). The threat model goes where reviewers are, not the other way around. |
| **"SOCs lack telemetry to evaluate AI-specific adversarial activity."** [^7] | The `atms ingest-evidence` flow accepts Nessus / SARIF / STIX / CSV / Caldera / Atomic / BAS so an existing SOC's outputs map onto the AI threat model directly. Status promotion (`hypothetical → likely → observed → exploited`) closes the AI-evidence telemetry gap. |
| **"Threat Dragon: not obvious how to enter a threat model as a first-time user."** [^8] | Multiple entry paths: paste YAML, upload a Visio diagram, upload a docker-compose file, upload Terraform, drag-and-drop in the visual editor, load a bundled sample. Auto-correct on common type-typos so you don't bounce out of analysis. Friendly per-component errors instead of Pydantic blobs. |
| **"Threat modelling for SMBs feels like a compliance checkbox or consultant cash-cow."** [^9] | Bundled compliance cross-walks (NIS2, DORA, EU AI Act, PCI, HIPAA, SOC2, ISO 27001, FedRAMP, Singapore CSA Guidelines). The compliance hits are derivative of the threats — you don't pay for compliance content separately. |

[^1]: Loomis, J. — *Threat Modeling and the SMB: Why it can be a waste of time.* LinkedIn.
[^2]: Microsoft Learn — *Threat Modeling AI/ML Systems and Dependencies.*
[^3]: Cloud Security Alliance — *Agentic AI Threat Modeling Framework: MAESTRO* (2025).
[^4]: Wuyts et al. — *Evaluating Threat Modeling Tools: Microsoft TMT versus OWASP Threat Dragon* (IEEE 2021).
[^5]: ThreatModeler — *ThreatModeler vs Microsoft TMT.*
[^6]: IriusRisk — *11 Recommended Threat Modeling Tools.*
[^7]: Mandiant — *AI risk and resilience: A Mandiant special report* (Google Cloud, 2025).
[^8]: OWASP/threat-dragon issue #1117 — *Not obvious how to enter a threat model in.*
[^9]: Security Compass — *Common Mistakes in Threat Modeling and How to Avoid Them.*

## Pain points we don't yet solve (committed work)

### v0.15.1 — already shipped

Open-source release prep: TI ingestion guide, public roadmap, repo
sanitisation. See CHANGELOG.

### v0.15.2 — applicability gating + scoring honesty (highest priority)

After three independent expert critiques (risk-assessment, red-team,
security-architect) of the v0.15.1 output, the convergent finding is:

> *Template-vs-instance mismatch is the single highest-leverage flaw.
> Hard-coded priors and constant confidence are the second.*

This release closes both. Four shipped changes:

#### 1. Per-template applicability predicates

Every threat template gets metadata gating its emission:

```yaml
- id: T_DIR_001
  title: Kerberoast / DCSync / Pass-the-Hash
  requires:
    component_type: directory_service
    metadata.idp_kind: [active_directory, ldap]
  not_applicable_to:
    metadata.idp_kind: [cognito, entra_id, auth0, okta]
  ...
```

Closes the Cognito-as-AD, CloudFront-as-F5, AWS-WAF-as-firewall, and
single-orchestrator-multi-agent false positives in one move. Components
that don't satisfy the predicate emit a "this template did not apply"
line in the audit trail rather than a wrong threat. ([Risk-assessment expert recommendation #2; red-team #1; security-architect #1](#))

#### 2. Industry / scale / deployment-stage priors

Replace hard-coded `loss_low / loss_high / freq_low / freq_high`
defaults with a `kb/priors/loss_priors.yaml` keyed on
`(industry × annual_revenue_bucket × deployment_stage)`:

```yaml
- match: { industry: smb, revenue: under_50m, stage: poc }
  loss_low: 1_000
  loss_high: 100_000
  freq_low: 0.1
  freq_high: 1.0
- match: { industry: tier1_bank, revenue: over_10b, stage: production }
  loss_low: 1_000_000
  loss_high: 1_000_000_000
  freq_low: 0.5
  freq_high: 5.0
```

Caps the $10B-on-a-POC defect every reviewer hit. The
`business_context` block on a System YAML gets new fields:
`industry`, `revenue_bucket`, `deployment_stage`. Defaults fall back
to "midmarket / pilot" so existing samples keep analysing.
([Risk-assessment expert #1](#))

#### 3. Computed per-threat confidence

Drop the constant `confidence: 0.95`. Compute from:

- (a) Template applicability score (binary 0 or 1 from predicate above).
- (b) Component-metadata richness (vendor / product / version /
  hostname / cidr / cpe / purl all populated → 1.0; only `name`
  populated → 0.4).
- (c) Compliance-mapping completeness (threats with mapped controls
  rated higher).

Then re-bucket severity using `effective_severity = bucket(risk_score
× confidence)`. Low-confidence highs collapse to mediums; this turns
65-threat firehoses into triage-able registers.
([Risk-assessment expert #3](#))

#### 4. Cloud-IAM lineage threat family

Add a first-class threat family in `kb/playbooks/iam_principal.yaml`
covering the bread-and-butter of cloud red-teaming that ATMS doesn't
yet emit:

- AssumeRole cross-account confused-deputy (ATT&CK `T1078.004`)
- IAM PassRole → resource-creation (`T1098.003`)
- IAM-role chaining → Bedrock invocation impersonation
- Managed-identity scope creep (`T1550.001`)
- DynamoDB / Cosmos DB cross-tenant data exfil via
  weak-partition-key

Plus: agent-specific IAM threats — BOLA on Bedrock Agent action-groups,
agent prompt-extraction via `traceLevel=enabled`, Easy Auth bypass via
`X-MS-CLIENT-PRINCIPAL` header spoofing.
([Red-team expert #2](#))

**Plus carry-over from v0.15.1's plan:**
- Wire the Singapore CSA Guidelines on Securing AI Systems into a
  per-threat enricher (`engines/csa_singapore.py`).
- Fix `business_user` AI-adjacent threats — re-tag onto
  output-filter / app component instead of the user.

### v0.15.3 — close LLM-specific false negatives + path-novelty + structural mitigations

Three groups of fixes informed by the same expert review.

**LLM-specific FNs.** Pain points #2 and the v0.15.0 self-evaluation
surfaced three LLM-system-specific risks ATMS doesn't yet emit:

- **Context-window stuffing / hijacking** — adversary fills the
  context window with adversarial content to displace system-prompt
  guardrails.
- **Provisioned-throughput exhaustion (per-tenant)** — multi-tenant
  Bedrock / OpenAI provisioned-throughput shared across tenants;
  one tenant DoSes another.
- **Guardrail bypass** — explicit threats about bypassing the
  guardrails component, not just "guardrails missing."

These need to land in the LLM-inference and agent playbooks with
proper STRIDE / OWASP LLM / ATLAS mappings.

**Attack-path novelty + diversity.** All 10 paths emitted in the
real-world tests were permutations of one chain. Add a
path-similarity hash + a diversity selector that surfaces only
chains with different terminal nodes or different intermediate
technique classes. Plus: build paths that pivot from an AI primary
**outward to non-AI infra** — the v0.15.0 adjacency-tagging promise
the path engine doesn't yet deliver.
([Red-team expert #3](#))

**Structural-mitigation roadmap.** Today's mitigation-roadmap is a
checklist over the existing DFD. When N critical threats on one
component share an underlying root cause, the engine should propose
a **new component** ("insert `policy_engine` between
`agent_service` and tool calls; addresses T_AGENT_001/002/006/007")
with a sample DFD edit. Stride-by-Component-**Edit**, not
Stride-by-Component.
([Security-architect expert #1](#))

**Disposition lifecycle + delta-aware re-runs.** Today every threat
re-runs as `disposition: open`. Add real states
(`accepted_with_compensating_control → compensating_control_id`,
`transferred → vendor_id`, `mitigated → adr_id + commit_sha`). On
re-run, diff against prior threat model rather than regenerating —
emit `threats_added / threats_removed / dispositions_changed`.
([Security-architect expert #3](#))

**Cross-walk to CSP reference architectures.** Tag every mitigation
with the equivalent AWS SRA / Azure LZA / GCP-WAF reference-pattern
ID where one exists. Suppress mitigations already shipped by the
platform's default reference; surface only the **delta versus
CSP-recommended baseline**. The tag is metadata only; the existing
mitigation list is unchanged for users without the cross-walk.
([Security-architect expert #2](#))

### v0.16.0 — bias / fairness as a security-adjacent threat category

Pain point: *"a biased model isn't being attacked but is failing in a
way STRIDE wasn't designed to describe"* [^2]. Add a new
`bias_fairness` STRIDE-for-AI subcategory. Cross-walk to NIST AI 100-2
abuse / availability classes and EU AI Act Article 10 (data and data
governance).

### v0.16.1 — emergent-behaviour threats

Pain point: *"emergent capabilities are a class of risk with no
traditional parallel"* [^2]. Add a small playbook of
emergent-behaviour threats keyed off agent autonomy levels:

- Tool-chain capability discovery beyond design intent
- Cross-agent collusion in multi-agent systems (already partially
  covered by AGT13 / AGT17 — extend)
- Specification gaming / reward hacking on optimisation agents
- Negative side-effects from over-broad task framing

### v0.17.0 — Shadow-AI inventory + drift detection

Pain point: *"Shadow AI — tools deployed without oversight — and a
lack of AI asset visibility remain critical friction points"* [^7].

- `atms inventory` — read a cloud-account export (AWS Config / Azure
  Resource Graph / Google Cloud Asset Inventory), find all
  AI/LLM-bearing assets (Bedrock endpoints, OpenAI deployments,
  SageMaker endpoints, Vertex AI Workbench instances, Anthropic API
  keys in Secrets Manager / Key Vault), produce an AI-only System YAML
  draft.
- `atms drift` — compare a previously-analysed system to a fresh
  inventory and surface what changed. Wires into `atms diff` for the
  threat-level delta.

### v0.18.0 — visual editor parity

Pain point: *"not obvious how to enter a threat model as a first-time
user"* [^8]. The graphical editor at `/editor` exists but is still
secondary in the UX. Make it the default entry path:

- Default `/` route shows the editor canvas, not a YAML textarea.
- Component palette grouped by AI / cloud / IT / OT.
- Drag-from-palette-to-canvas; auto-snap to grid.
- Auto-classify dragged components based on common patterns.
- One-click "Run analysis" hand-off to the report.

## Deferred / out-of-scope

These are features the project deliberately won't ship.

| Feature | Why not |
|---|---|
| **Multi-user / SaaS hosting** | The local-first contract is what gives ATMS a credible privacy story. Going SaaS would compete with IriusRisk on a different axis (commercial enterprise) and dilute the pitch. |
| **LLM-as-evaluator** | The deterministic-core promise rules out using an LLM to grade or generate threats. Optional vision is the only AI touchpoint and it stays opt-in. |
| **Generic IT threat modeling** | Pure-IT systems are rejected by design. ATMS is not a successor to MTM / Threat Dragon for non-AI use cases. |
| **Real-time monitoring / alerting** | ATMS is design-time. Runtime telemetry belongs in your SIEM. The `evidence/` ingest path is how runtime signals come back into the threat model, not the other way around. |
| **Bundled SaaS-vendor-specific scanners** | We don't include Trivy / Snyk / Wiz / Prisma scan engines. We integrate with their output formats (SARIF, CSV) instead. |
| **Visual diff of architecture changes** | Out of scope — `atms diff` produces a textual / JSON delta of threats, not the architecture. |

## Cadence

Releases are versioned semver. Breaking changes (like the v0.14 → v0.15
rescope) bump the minor version. Patch releases (v0.15.1, v0.15.2)
ship sharpened content + closed false-negative gaps without changing
the analysis contract. The build is reproducible from a tagged commit
with one `python scripts/build_installer.py --clean` invocation.

If you want to influence priorities, file a GitHub issue with a real
architecture and the threats you'd expect ATMS to emit (or NOT emit)
for it. Concrete signal beats abstract feature requests.
