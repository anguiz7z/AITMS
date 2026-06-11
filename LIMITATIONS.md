# Current limitations of ATMS

This document is the honest catalog of where ATMS falls short. Updated
with findings from the v0.15.0 self-evaluation against three real public
AI architecture references (AWS Generative AI App Builder Text/RAG and
Bedrock Agent use cases, Microsoft Azure Foundry Basic Chat) and from
three independent expert critiques (risk-assessment, red-team,
security-architect) of the same outputs.

## Convergent finding from all three expert critiques

The single highest-leverage flaw — independently flagged by every
critic — is **template-vs-instance mismatch**: the catalog applies the
same threat playbook to every component of a given type, regardless of
vendor, deployment mode, or topology. Concrete consequences:

- **AWS Cognito** (managed OAuth IdP) gets `T_DIR_001` Kerberoast /
  DCSync / Pass-the-Hash from the `directory_service` playbook — there
  is no Kerberos in Cognito (FP-1).
- **CloudFront** (managed CDN) gets `T_LB_001` "Outdated load-balancer
  firmware (F5 BIG-IP CVE-2020-5902)" — the *narrative quotes F5 by
  vendor name* (FP-4, new from red-team review).
- **AWS WAF** (managed control plane) gets `T_FW_002` "outdated firmware
  on management plane" with Palo Alto / Cisco ASA CVEs in the
  description (FP-2).
- **Single-orchestrator architectures** get `T_AGENT_008` "Rogue agent
  in multi-agent system / infectious backdoor" — the threat requires
  an A2A mesh that doesn't exist in the architecture (FP-5, new from
  red-team review).

The fix all three experts converge on: **applicability predicates per
threat template** (`requires: kerberos`, `applicable_to_vendor: [...]`,
`requires_topology: multi_agent_mesh`) with a no-match path that
suppresses, not rebrands, the threat. Roadmap `v0.15.2`.

The point of publishing this is not to apologise — it's to set
expectations correctly and tell maintainers + contributors where the
high-leverage work is.

## Categorical limitations

These are statements about what ATMS structurally cannot do or doesn't
do well today, regardless of any individual playbook or threat content.

### L-01 — Image-based diagram ingest is not in the .exe

The `vision/` module that parses architecture-diagram PNGs into draft
System YAML requires `anthropic` SDK + `ANTHROPIC_API_KEY`, and is
explicitly excluded from the PyInstaller `.exe` build. So if you
download `ATMS-Setup-X.Y.Z.exe` and try to upload a JPEG, you get a
clear error explaining how to enable it via `pip install atms[vision]`,
but you can't do it from the .exe. **By design** (preserves the
"AI-free contract" for the shipped binary) but still a real friction
point for non-Python testers. See `BUILDING.md` for the contract.

### L-02 — STRIDE-for-AI and "DREAD-derived risk score" are our extensions, not peer-reviewed standalone methodologies

STRIDE is real (Microsoft, 1999); DREAD is real (Microsoft, deprecated
in 2008). ATMS extends both to AI risks. But there is no published
"STRIDE-AI" / "DREAD-AI" standard with named authors and a formal
spec. v0.15.0 fixed the misleading naming. Any reviewer who's
sceptical of method names should be referred to:

- The actual [STRIDE for AI/ML reference (Microsoft Learn)](https://learn.microsoft.com/en-us/security/engineering/threat-modeling-aiml)
- `kb/stride_ai_matrix.yaml` — our subcategory expansion
- The risk-score function in `engines/risk.py` (~25 lines, fully reviewable)

### L-03 — Single-region / single-tenant architectures only

The threat catalog assumes one deployment region and one tenant. Some
real risks only manifest at multi-region or multi-tenant scale:

- Cross-region data residency violations
- Regional model-availability differences
- Cross-tenant prompt leakage via shared prefix-cache
- Per-tenant rate-limit fairness
- Region-specific compliance regimes (EU AI Act vs. CSA Singapore vs. NIST AI RMF)

The `samples/multi_tenant_llm_platform.yaml` sample exists but the
underlying playbooks don't deeply model these.

### L-04 — Design-time only, no runtime telemetry

ATMS analyses what you describe in YAML, not what's actually deployed.
There is no `atms watch` or `atms inventory` mode that pulls live
architecture state from AWS Config, Azure Resource Graph, or Google
Cloud Asset Inventory. Roadmap `v0.17.0` commits to this.

### L-05 — No drift detection between analyses

`atms diff` compares two analysis JSONs at threat-level, but there is no
detection of "the architecture changed since you last threat-modelled."
A user who re-runs `atms analyze` after editing the YAML can see threat
deltas; a user who deploys a change without re-running ATMS gets no
signal.

### L-06 — Mitigations are recommendations, not workflow tickets

The `mitigations.csv` output is a flat list. It doesn't generate Jira
tickets, doesn't sync with an existing ADR/control register, and
doesn't track mitigation status over time. The threat-level `disposition`
field (open / accepted / mitigated / transferred) exists in the model
but ATMS doesn't enforce a lifecycle — you have to set it in the YAML
yourself.

## False positives we know about

Found during v0.15.0 real-world testing. **Status (audit 2026-06-11): FP-1,
FP-2, FP-4, FP-5 are RESOLVED.** The v0.16.0 applicability engine
(`engines/applicability.py`) gates these threats by `metadata.idp_kind`,
managed-service vendor, and the `multi_agent_mesh` topology predicate.
Verified by a full 18-sample sweep: zero AD/Kerberos/firmware false fires on
managed services, zero multi-agent threats on single-agent systems. (The only
firmware hit is `it_ot_factory`, which models real on-prem F5/Fortigate/Cisco
appliances — a true positive, not an FP.) FP-6 is largely mitigated (per-threat
caps + tier scaling removed the $10B-on-a-POC ranges). FP-3 remains open (a
re-tagging preference, not a defect). The original entries are kept below for
provenance — each is annotated with its current status.

### FP-1 (HIGH) — `directory_service` playbook fires Active Directory threats against AWS Cognito and Microsoft Entra ID

When the AWS Generative AI App Builder reference architecture's
Cognito component goes through the directory_service playbook, it
picks up threats like `T_DIR_001` Kerberoast / DCSync / Pass-the-Hash,
`T_DIR_002` Golden Ticket / krbtgt forging, `T_DIR_004` Group Policy
modification. **None of these apply to Cognito** — there's no
Kerberos, no krbtgt, no GPO. The playbook was written for on-prem AD
only.

**Fix path (v0.15.1):** split into `directory_service_active_directory`
and `directory_service_managed_idp` (Cognito, Entra ID, Auth0, Okta),
or add a `metadata.idp_kind` discriminator and gate threat emission
on it.

### FP-2 (MED) — `firewall` playbook fires "outdated firmware on management plane" against AWS WAF / Azure WAF / Cloudflare

Managed services don't have firmware; the playbook was written
assuming on-prem appliances. Two of three WAF threats produced are
off-target. Same fix pattern as FP-1.

### FP-3 (MED) — `business_user` (the `user` component) picks up adjacent threats

The user is not a controllable engineering surface. Threats like
"user social-engineered via AI output" are AI-relevant but
architecturally awkward — they should be re-tagged onto the
output-filter / app component instead, where there's actually
something an architect can change.

### FP-4 (HIGH) — `load_balancer` playbook fires F5 BIG-IP firmware threat against AWS CloudFront

Same root cause as FP-1 / FP-2: managed cloud services don't have
firmware. The narrative on `cf.T_LB_001` literally names "F5 BIG-IP
CVE-2020-5902" against an AWS CloudFront distribution. The
load_balancer playbook needs the same `vendor` / `deployment_mode`
discriminator the firewall + directory_service playbooks need.

### FP-5 (HIGH) — Multi-agent threats fire on single-agent architectures

`orchestrator.T_AGENT_008` "Rogue agent in multi-agent system /
infectious backdoor" emits at HIGH severity on architectures with
exactly one orchestrator Lambda. The threat requires an A2A
(agent-to-agent) mesh that doesn't exist in the modelled system.
The agent playbook needs topology-aware emission gates
(`requires_topology: multi_agent_mesh`).

### FP-6 (MED) — FAIR-lite ALE ranges include numbers no one believes

`api_gw.T_APIGW_002` Denial-of-Wallet on AWS API Gateway is rated
$20M–$1B/yr. The threat itself is real, but Bedrock has hard service-
quota ceilings and AWS account-level cost-anomaly alerts that cap
real-world DoW losses well below $1B. Same pattern: `kendra.T_RAG_001`
(AWS RAG) and `ai_search.T_RAG_001` (Azure POC) get the **identical**
$200M–$10B ALE range — proving the priors are hard-coded constants,
not architecture-output. See M-01 for the methodology fix.

## False negatives we know about

Risks that ATMS *should* emit but doesn't.

### FN-1 — Context-window stuffing / hijacking

Zero threats reference the context window in the AWS Text RAG report.
A real adversary fills the context window with adversarial content to
displace system-prompt guardrails or RAG-injected content. This is
LLM01:2025-adjacent but distinct enough to deserve its own threat ID.

### FN-2 — Provisioned-throughput exhaustion (per-tenant)

Bedrock provisioned throughput, OpenAI provisioned-throughput tiers,
and Azure OpenAI's Provisioned model deployment are all shared across
the tenant's workloads. One workload DoSing another by exhausting
provisioned tokens is an LLM10:2025 (unbounded consumption) variant
the playbooks don't currently cover.

### FN-3 — Guardrail bypass as a distinct threat

ATMS emits "guardrails missing" but not "guardrails bypassed." Real
adversaries probe for guardrail-class blind spots (Unicode-escape,
language-switch, role-play / DAN attacks). LLM01:2025 covers prompt
injection generically but the *specific* practice of probing the
guardrail layer is under-specified.

### FN-4 — Bias / fairness as a security-adjacent risk category

A biased model isn't being attacked but is failing in a way STRIDE
wasn't designed to describe. EU AI Act Article 10 (data and data
governance) requires bias evaluation as a security control. ATMS
doesn't model this. Roadmap `v0.16.0` commits to a `bias_fairness`
STRIDE-for-AI subcategory.

### FN-5 — Emergent-behaviour / specification-gaming threats

Capabilities that weren't explicitly trained for and are discovered
in production. AGT13 / AGT17 partially cover this; the playbooks
don't yet have a coherent emergent-behaviour threat group. Roadmap
`v0.16.1`.

### FN-6 — AI-specific TTPs missing from current playbooks

From the v0.15.0 real-world test:

- **AWS RAG**: cross-account confused-deputy via assume-role on the
  orchestrator's IAM role, IMDS exfiltration from a compromised
  Lambda, Bedrock model-stealing via repeated targeted prompts, IAM
  role-chain abuse from orchestrator → KMS or DynamoDB.
- **Bedrock Agent**: BOLA on the agent's tool definitions
  (action-group spoofing), agent system-prompt extraction.
- **Azure Foundry**: Easy Auth bypass via the Microsoft.Web RP,
  managed-identity scope creep across Foundry projects, Cosmos DB
  exfiltration from the Microsoft-hosted Agent Service backplane (a
  real risk — those resources don't appear in the customer's
  subscription so the customer can't audit them).

## Methodology / scoring weaknesses

### M-01 — FAIR-lite ALE ranges are very wide

The reports show ranges like "$200M – $10B / year" for a single threat
(e.g. `kendra.T_RAG_001` indirect prompt injection). The wide priors
come from defaulting `loss_low / loss_high` per playbook without any
size-of-business calibration. A 50-person SMB and a Fortune 100 bank
both see the same dollar figures. Useful as relative-ranking but not as
absolute risk dollars. **A `--organisation-size` flag** to scale priors
by industry / revenue tier would be a high-ROI v0.15.2 addition.

### M-02 — Risk-matrix density skews to the high-impact rows

Across all three real-world tests, the 5×5 likelihood-impact matrix
shows almost everything in the impact-3+ rows. That's because the
playbooks default to impact=4-5 for AI-specific threats (which is
defensible for the threat *class*) but doesn't account for whether the
specific component bearing the threat is mission-critical or not. Every
LLM gets impact-5; in reality, an internal-only fraud scoring LLM and a
customer-facing chatbot have very different impact profiles.

### M-03 — The "10/10 OWASP coverage" headline metric is misleading

It just means at least one threat references each of LLM01..LLM10. It
doesn't mean each is *deeply* covered. A reviewer reading "10/10
OWASP" might assume the threat model is complete; it isn't.

### M-04 — Mitigation prioritisation formula is debatable

`reduction × severity / effort` is the current top-N mitigation
ranker. There's no published basis for this weighting; it's a
plausible heuristic. The right formula depends on the reviewer's
goal (compliance coverage vs. attacker priority vs. lowest-effort
quick wins). v0.15.2 should expose alternative rankers.

### M-05 — Confidence is constant at 0.95 on every threat

The `confidence` field on `Threat` is set to a hard-coded 0.95 in
the playbook conversion path. There is no signal differentiating
high-template-applicability findings from speculative ones. The
risk-assessment expert recommends driving confidence from
(a) template applicability score, (b) presence of architecture-
specific evidence (component metadata, dataflow attributes),
(c) compliance-control mapping completeness — then collapsing the
severity bucket using `risk_score × confidence` so low-confidence
highs become mediums. This single change converts an
undifferentiated list of 65 threats into a triage-able list.

### M-06 — Severity buckets cluster pathologically high

Across the three real-world reports the severity distribution is:

| Report | low | info | medium | high | critical |
|---|---|---|---|---|---|
| AWS RAG | 0 | 0 | 12 | 40 | 13 |
| Bedrock Agent | 0 | 0 | 8 | 34 | 10 |
| Azure POC | 0 | 0 | 7 | 27 | 6 |

The 5×5 matrix's likelihood-1 row is empty across all three reports;
impact columns 1 and 2 are empty too. Every AI-specific threat
defaults to impact-4-or-5, regardless of whether the bearing
component is mission-critical. Result: the canonical "everything is
critical so nothing is" anti-pattern. A real risk register expects
60-70% medium-or-below.

### M-07 — EU AI Act mappings are audit-bait

The Azure POC report tags `agent_service.T_AGENT_001` (Excessive
Agency) with `EU_AI_ACT.14`. Article 14 — "Human Oversight" — is
binding **only on high-risk AI systems per Annex III**. A
Microsoft-published learning POC for chat is almost certainly NOT
an Annex III system. Stamping this in a regulator's office would
discredit the entire register. Fix: gate EU AI Act control mapping
on a `business_context.is_high_risk_under_eu_ai_act_annex_iii`
discriminator, not just on the threat type.

## Architecture-decision-support weaknesses (from security-architect critique)

### A-01 — Top-10 mitigation roadmap rows 4-10 collapse into generic guidance

Across all three real-world reports, of the 30 top-10 lines (3 reports
× 10 each), **only 3** carry actual validation tests — and they're the
generic IAM-hygiene rows (`AML.M0019`, `AML.M0012`, `AML.M0024`). The
novel AI-specific rows (`MIT-C1A3648D` "treat all model output as
untrusted", `MIT-2ABE476D` "constrain model behavior", `MIT-7D386CCC`
"adversarial prompt testing in CI") have empty Family / D3FEND /
validation_test columns. **The architect needs concreteness on the
AI-specific mitigations exactly because they're novel; the IAM hygiene
is what we already know how to ship.**

### A-02 — `kendra.T_RAG_001` (top ALE contributor at $200M–$10B/yr) has no decisive mitigation

The single highest-ALE risk in the AWS RAG report is indirect prompt
injection via retrieved content. The linked controls are `AML.M0015`
(Adversarial Input Detection — no validation test, family blank),
`MIT-1F8175F1` (treat retrieved content as untrusted), and
`MIT-C3169206` (prompt-injection scanner on retrieved chunks). **None
tells an architect whether to deploy Bedrock Guardrails, put Llama
Guard inline, implement chunk-level signed provenance, or all three
in what sequencing.** The single-highest-ALE risk gets the same generic
treatment as a TLS misconfig.

### A-03 — No structural mitigations — only per-component checklists

The agent_service component in the Azure report has 10 threats; four
are critical with overlapping mitigation lists. None of the
mitigations names the obvious **structural** fix: insert a separate
`policy_engine` component between `agent_service` and tool calls.
That single architectural change addresses T_AGENT_001 (excessive
agency) + T_AGENT_002 (indirect injection) + T_AGENT_006 (memory
poisoning) jointly. **ATMS enumerates threats per component but never
proposes new components.** That's a checklist over the existing DFD,
not a threat model.

### A-04 — No reference-architecture cross-walk

Every AWS component has a canonical control in AWS Security Reference
Architecture (SRA), AWS Well-Architected GenAI Lens, or Bedrock-
secure-by-default. Every Azure component has a counterpart in Azure
Landing Zone Architecture / Azure Well-Architected AI workloads. ATMS
tags none of its mitigations with the equivalent SRA / LZA ID, so a
reviewer can't tell **which mitigations are the delta versus what
the platform already gives them by default**. Result: orphan doc
instead of "what's missing vs. CSP baseline."

### A-05 — Disposition is single-state — every threat is `open`

The `Threat.disposition` field accepts `open / accepted / mitigated /
transferred / deferred` but in practice every threat across all reports
lands as `open` because the user has no UI / CLI to mutate it. Without
lifecycle states (`accepted_with_compensating_control`,
`transferred_to_<vendor>`, `deferred_until_<milestone>`,
`mitigated_by_<commit>`), each re-run regenerates from scratch — every
quarter's review is a 65-threat firehose at the CISO instead of a
6-threat delta against architectural decisions already taken.

### A-06 — Cross-framework tagging is decoration, not navigation

A single threat carries OWASP LLM + OWASP Agentic + OWASP API + ATLAS
+ ATT&CK Cloud + ATT&CK Enterprise + LINDDUN + NIST AI 100-2 + MAESTRO
+ Compliance — five-to-ten frameworks per row with no statement of
which is the **primary lens** for that threat. An architect picks
a lens per stakeholder ("for the CISO, NIST CSF; for the ML platform
team, ATLAS; for the auditor, ISO 27001 + Singapore CSA"), but the
report gives every framework equal weight, so the cross-walk is
labelling — not navigation.

### A-07 — Missing AWS / Azure cloud-IAM lineage threats

The red-team review found that the playbooks have **zero** first-class
cloud-IAM-chain threats — the bread-and-butter of cloud red-teaming:

- **AWS:** cross-account confused-deputy via `AssumeRole`,
  `IAM PassRole → resource-creation`, Lambda role chaining → Bedrock
  invocation impersonation, DynamoDB cross-tenant chat-history
  pollution, CloudWatch log-group ResourcePolicy abuse.
- **Bedrock Agent:** BOLA on action-group invocation
  (`sessionAttributes` tampering), function-name shadowing in tool
  catalog, prompt-extraction via `traceLevel=enabled`,
  cross-account `bedrock:InvokeAgent`.
- **Azure:** Easy Auth bypass via `Microsoft.Web` RP
  `X-MS-CLIENT-PRINCIPAL` header spoofing, managed-identity scope
  creep via App Service `/MSI/token` SSRF, Cosmos DB exfil from the
  MS-managed Agent Service backplane (the YAML even tags this as
  in-scope and the report **misses it entirely** — it's the most
  novel risk that architecture describes), Application Insights as
  exfil channel for prompts, Foundry connection-definition tampering.

These need to land as a first-class IAM-lineage threat family in the
playbooks, mapped to ATT&CK `T1078.004 / T1550.001 / T1098.003`.

### A-08 — Attack-path "novelty" — paths are permutations of one chain

All 10 attack paths emitted for the AWS RAG report begin with the same
sequence: `indirect prompt injection → no rate limit → weak auth →
CloudWatch leak`. They are the same path with permuted ordering, not
diverse attack chains. ATMS needs path-similarity hashing + a
diversity selector that surfaces only chains with different terminal
nodes or different intermediate technique classes. Plus: the engine
should specifically construct paths that **pivot from an AI primary
outward to non-AI infra** — the v0.15.0 adjacency-tagging promise
that the path engine doesn't yet deliver.

## UX / workflow weaknesses

### U-01 — The visual editor is still secondary

`/editor` exists and works (drag-and-drop, type dropdowns, live YAML
sync) but the default landing page is a YAML textarea. New users hit
the YAML edit path first, find type errors hostile, and bounce.
Roadmap `v0.18.0` commits to making the editor the default entry path.

### U-02 — Trust boundaries are inferred but not surfaced as overlays

`engines/boundaries.py` does an inference pass that adds reasonable
trust-zone defaults if the user doesn't model them. But the report
doesn't explicitly say "we inferred these boundaries; here they are."
A reviewer who disagrees with the inference can't see what to override.

### U-03 — Mermaid DFD doesn't match the original diagram

When a user uploads a `.vsdx`, the Mermaid diagram in the report is
rebuilt from parsed components — losing spatial layout and sometimes
losing labels when ATMS classifies a connector as a duplicate. A
visual-fidelity reviewer comparing the report's diagram to the original
will see drift.

### U-04 — Compliance cross-walks are coarse

Threats are tagged with framework-control IDs (`NIS2.21.2.a`,
`PCI_DSS.6.4.1`, etc.) but the underlying `kb/compliance/controls.yaml`
has only headline-level descriptions. There's no per-control evidence
requirement, no per-framework auditor narrative, and no traceability
matrix. Useful for "did we touch the framework" but not for "ready
for an audit."

## Engineering debt

### E-01 — `max_hops=3` blast radius is heuristic

The AI-scope gate considers a non-AI component "adjacent" if it's
within 3 dataflow hops of an AI primary. 3 was chosen by intuition
during v0.15.0 development and validated against the bank-with-LLM
sample. Real-world architectures may need 2 (more conservative) or
configurable. No tuning yet.

### E-02 — Threat-ID uniqueness enforcement is post-hoc

`workflow.analyze` deduplicates Threat IDs after enumeration via a
dropped-with-warning path. A playbook author who copy-pastes a threat
without changing the inner ID still ships, and the user sees a single
warning line they can easily miss. A pre-commit lint that catches this
in the playbook YAML before merge would be cleaner.

### E-03 — KB cross-references are validated by a hand-curated test

Every playbook ATT&CK / ATLAS / OWASP / MAESTRO ID is checked against
the KB catalog by `tests/test_v15_pipelines.py` (and earlier tests).
But adding a new framework or extending an existing one requires
hand-editing the cross-ref check. A reflective check that auto-detects
the framework of every emitted ID would scale better.

### E-04 — Sample fixtures cover western-cloud + IT/OT + agentic, but not federated-government / multi-jurisdiction

We don't have a sample for cross-border data-flow architectures, GDPR
data-subject-rights flows, or APAC data-localisation patterns. A
contributing tester for an EU bank or a Singapore-MAS-regulated
deployment would surface real gaps.

## Scope-deferred (will not fix, by design)

- Multi-user / SaaS hosting
- LLM-as-evaluator (using an LLM to grade or generate threats)
- Generic IT threat modelling for non-AI systems
- Real-time monitoring or alerting
- Bundled SaaS-vendor-specific scanners (we integrate via SARIF instead)
- Visual diff of architecture changes (only threat-level deltas)

## What would change my mind on any of the above

Concrete signal beats abstract requirements. If you have a real
architecture and ATMS produces a wrong / missing threat for it, that
goes to the top of the queue. The v0.15.0 audit is the template:
upload the architecture, name the wrong threat, name the right
threat, name the architecture file. Preferably with an
attacker-narrative one-liner.

## Versioning of this document

This is a living document. The categorical limitations (L-01..L-06)
are stable; the false-positive (FP-*), false-negative (FN-*),
methodology (M-*), UX (U-*), and engineering-debt (E-*) lists are
expected to shrink as releases ship. Roadmap commitments by version
live in `ROADMAP.md`.
