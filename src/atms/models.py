"""Pydantic data models for the ATMS workflow.

These models represent the structured input (user-supplied AI system description),
intermediate state (components, threats, attack paths, scenarios), and output
(reports). All models are JSON-serializable and used by both the CLI and web UI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

ComponentType = Literal[
    # ─── AI / ML / agentic primitives ────────────────────────────────────
    "llm_inference",
    "rag_vector_store",
    "agent",
    "tool",
    "mcp_server",
    "training_pipeline",
    "fine_tuning_pipeline",
    "embedding_service",
    "prompt_template_store",
    "model_registry",
    "guardrails",
    "output_filter",
    "ml_feature_store",          # v0.16 — SageMaker Feature Store / Vertex Feature Store
    "ml_pipeline_orchestrator",  # v0.16 — SageMaker Pipelines / Vertex Pipelines / AML Pipelines
    "ml_data_labeling",          # v0.16 — Ground Truth / Vertex Data Labeling
    "ml_experiment_tracker",     # v0.16 — MLflow / W&B / Comet
    "ml_inference_endpoint",     # v0.16 — SageMaker Endpoint / Azure ML Endpoint / Vertex AI Endpoint (managed)
    "vision_pipeline",           # v0.16 — multimodal vision processing
    "speech_pipeline",            # v0.16 — STT/TTS, voice agents
    "content_safety_classifier", # v0.16 — Azure Content Safety / Bedrock Guardrails / Perspective
    "data_source",
    "external_api",
    "user",
    # ─── Cloud compute + serverless + container ─────────────────────────
    "cloud_compute",             # v0.16 — generic VM (EC2 / Azure VM / GCE / OCI Compute)
    "serverless_function",        # Lambda / Azure Functions / Cloud Functions / OCI Functions
    "container_runtime",          # EKS pod / GKE pod / AKS pod / ECS task / Cloud Run / OCI OKE
    "container_orchestrator",    # v0.16 — control plane (EKS / GKE / AKS / OpenShift)
    "container_registry",        # v0.16 — ECR / ACR / GAR / OCI Container Registry
    "edge_compute",              # v0.16 — Lambda@Edge / Cloudflare Workers / Akamai EdgeWorkers
    "batch_compute",             # v0.16 — AWS Batch / Azure Batch / GCP Batch / OCI Batch
    "high_performance_compute",  # v0.16 — HPC / AI super-pod / Nvidia DGX
    # ─── Cloud storage families ─────────────────────────────────────────
    "object_storage",            # S3 / Blob / GCS / OCI Object Storage / Alibaba OSS
    "block_storage",             # v0.16 — EBS / Managed Disk / Persistent Disk / OCI Block Volume
    "file_storage",              # v0.16 — EFS / Azure Files / Filestore / OCI File Storage
    "data_lake",                 # v0.16 — Lake Formation / ADLS Gen2 / GCS data lake
    "data_warehouse",            # v0.16 — Redshift / Synapse / BigQuery / Snowflake on cloud
    "cache_store",               # v0.16 — ElastiCache / Azure Cache for Redis / Memorystore
    "backup_service",            # v0.16 — AWS Backup / Azure Backup / GCP Backup and DR
    # ─── Databases + streaming + ETL ────────────────────────────────────
    "database",                   # generic relational (RDS / Azure SQL / Cloud SQL / Oracle)
    "nosql_database",            # v0.16 — DynamoDB / Cosmos DB / Firestore / DocumentDB
    "graph_database",            # v0.16 — Neptune / Cosmos Gremlin / Spanner Graph
    "time_series_database",      # v0.16 — Timestream / Azure Data Explorer / InfluxDB Cloud
    "message_queue",             # SQS / SNS / Service Bus / Pub/Sub / Kafka / Event Hubs
    "stream_processor",          # v0.16 — Kinesis / Flink / Dataflow / Stream Analytics
    "etl_orchestrator",          # v0.16 — Glue / Data Factory / Dataflow / OCI Data Integration
    # ─── Cloud network + delivery + edge ────────────────────────────────
    "load_balancer",              # ALB / NLB / Front Door / App Gateway / Cloud LB / OCI LB
    "cdn",                       # v0.16 — CloudFront / Front Door CDN / Cloud CDN / Akamai / Fastly
    "api_gateway",                # API Gateway / API Management / Apigee / OCI API Gateway
    "service_mesh",              # v0.16 — App Mesh / Service Mesh / Istio / Linkerd / Consul
    "private_link",              # v0.16 — PrivateLink / Private Endpoint / Private Service Connect
    "network_segment",            # VPC / VNet / VPC / VCN — segment / subnet
    "transit_gateway",           # v0.16 — Transit Gateway / VWAN / Network Connectivity Center
    "dns_service",               # v0.16 — Route 53 / Azure DNS / Cloud DNS / OCI DNS
    # ─── Network appliances (on-prem + virtual + managed) ───────────────
    "firewall",                   # generic firewall (NGFW / managed cloud / appliance)
    "waf",                       # v0.16 — AWS WAF / Azure WAF / Cloud Armor / Cloudflare / F5 ASM / Imperva
    "ids_ips",                   # v0.16 — Snort / Suricata / Firepower / Defender for Cloud
    "ddos_mitigation",           # v0.16 — Shield Advanced / Azure DDoS / Cloud Armor / Cloudflare
    "web_proxy",                 # v0.16 — Squid / Zscaler / Netskope / McAfee Web Gateway
    "reverse_proxy",             # v0.16 — NGINX / HAProxy / Traefik / Envoy
    "vpn_gateway",                # GlobalProtect / AnyConnect / OpenVPN / Site-to-Site VPN
    "router",                    # v0.16 — Cisco IOS / Juniper / MikroTik / Edge router
    "network_switch",             # L2 switch
    "switch_l3",                 # v0.16 — L3 switch (Catalyst / Aruba CX)
    "sdwan_edge",                # v0.16 — Velocloud / Viptela / Silver Peak / Fortinet Secure SD-WAN
    "network_access_control",    # v0.16 — Cisco ISE / Aruba ClearPass / Forescout
    "bastion_host",              # v0.16 — SSM Session Manager / Bastion / IAP / Teleport
    "pam_vault",                 # v0.16 — CyberArk / BeyondTrust / Delinea / HashiCorp Vault PAM
    # ─── Identity / secrets / key management ────────────────────────────
    "iam_principal",
    "directory_service",
    "identity_provider",         # v0.16 — Cognito / Entra External ID / Okta / Auth0 / B2C
    "mfa_service",
    "sso_service",               # v0.16 — IAM Identity Center / Entra ID SSO / Ping / OneLogin
    "ciam_platform",             # v0.16 — Cognito User Pool / B2C / Auth0 customer-IAM
    "secrets_vault",
    "kms_key",
    "certificate_manager",       # v0.16 — ACM / Key Vault Certs / Certificate Manager
    "hsm",                       # v0.16 — CloudHSM / Azure Dedicated HSM / Cloud HSM
    # ─── Security tooling ───────────────────────────────────────────────
    "siem",                      # v0.16 — Sentinel / Chronicle / Splunk / Sumo Logic / QRadar
    "soar",                      # v0.16 — XSOAR / Sentinel SOAR / Tines / Torq
    "edr_agent",                 # v0.16 — CrowdStrike / SentinelOne / Defender for Endpoint
    "vulnerability_scanner",     # v0.16 — Nessus / Qualys / Defender Vuln Mgmt / Inspector
    "casb",                      # v0.16 — Defender for Cloud Apps / Netskope / Palo Alto
    "dlp",                       # v0.16 — Microsoft Purview / Symantec DLP / Forcepoint
    "cspm",                      # v0.16 — Wiz / Prisma / Defender for Cloud / Security Hub
    "container_security",        # v0.16 — Aqua / Sysdig / Prisma / Twistlock / Snyk
    "security_data_lake",        # v0.16 — Snowflake security data lake / Panther / Hunters
    # ─── Observability ──────────────────────────────────────────────────
    "observability_stack",        # generic logs+metrics+traces
    "log_aggregator",            # v0.16 — CloudWatch Logs / Log Analytics / Cloud Logging / Splunk
    "metrics_platform",          # v0.16 — Prometheus / CloudWatch Metrics / Azure Monitor / Datadog
    "tracing_platform",          # v0.16 — X-Ray / App Insights / Cloud Trace / Tempo / Honeycomb
    "alerting_platform",         # v0.16 — PagerDuty / Opsgenie / VictorOps / Splunk On-Call
    # ─── Endpoints + servers ────────────────────────────────────────────
    "endpoint",                   # generic — Windows / macOS / Linux workstation
    "server_windows",            # v0.16 — Windows Server
    "server_linux",              # v0.16 — Linux server
    "server_unix",               # v0.16 — Solaris / AIX / HP-UX
    "mainframe",                 # v0.16 — IBM Z / zOS
    "legacy_mainframe",           # v0.10 alias kept for back-compat
    "virtual_desktop",           # v0.16 — AVD / WorkSpaces / Citrix Cloud / Horizon
    "mobile_device",             # v0.16 — iOS / Android phone or tablet
    "mdm_emm",                   # v0.16 — Intune / Jamf / Workspace ONE / Kandji
    # ─── OT / SCADA / industrial / IoT ──────────────────────────────────
    "plc",                        # programmable logic controller
    "rtu",                       # v0.16 — remote terminal unit
    "ied",                       # v0.16 — intelligent electronic device (substation automation)
    "hmi",                       # v0.16 — human-machine interface
    "scada",                      # SCADA master / historian collector
    "dcs",                       # v0.16 — distributed control system
    "sis",                       # v0.16 — safety instrumented system (Triconex / DeltaV SIS)
    "industrial_protocol",
    "iot_device",                 # generic IoT sensor / actuator
    "iot_gateway",               # v0.16 — IoT Greengrass / Azure IoT Edge / Cloud IoT Edge
    "ot_jumphost",               # v0.16 — engineering workstation / jump host inside OT zone
    # ─── Application-tier components ────────────────────────────────────
    "web_application",
    "email_server",
    "file_transfer_service",     # v0.16 — SFTP / Transfer Family / managed FTP / MFT
    "code_repository",           # v0.16 — GitHub / GitLab / Bitbucket / Azure Repos / CodeCommit
    "ci_cd_pipeline",            # v0.16 — Jenkins / GitHub Actions / GitLab CI / CodePipeline / Cloud Build
    "artifact_registry",         # v0.16 — Artifactory / Nexus / GitHub Packages / generic
    "build_runner",              # v0.16 — self-hosted runner / hosted Build agent
    "feature_flag_service",      # v0.16 — LaunchDarkly / Split / GrowthBook / Flagsmith
    "iac_template_registry",     # v0.16 — CloudFormation StackSet / ARM templates / Terraform module
    # ─── Fallback ───────────────────────────────────────────────────────
    "other",
]

StrideAI = Literal[
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information_Disclosure",
    "Denial_of_Service",
    "Elevation_of_Privilege",
    "Defense_Evasion",
    # v1.0.4 — STRIDE-LM. The CSA Singapore "Guide to Cyber Threat
    # Modelling" (Feb 2021) adopts STRIDE-LM (Muckin & Fitch 2019): the
    # classic six plus Lateral Movement, because pivoting between
    # components is its own distinct adversary objective the original six
    # don't capture. ATMS already models multi-hop pivots in attack paths
    # + the CSA Table of Attack stepping-stones; this gives the threat
    # taxonomy a first-class home for them.
    "Lateral_Movement",   # attacker pivots between components toward a crown jewel
    # v0.16.7 — AI-native threat categories that don't map cleanly to
    # classic STRIDE. Inspired by Microsoft Learn's AI threat-modelling
    # extension + ATLAS coverage gaps identified in the v0.15.0 expert
    # critique.
    "Bias_Fairness",      # discriminatory output / decision parity / disparate impact
    "Emergent_Behavior",  # capabilities not present at training time / out-of-spec actions
]

TrustBoundaryType = Literal[
    "network",
    "identity",
    "data_classification",
    "tenancy",
    "deployment_zone",
]


class Component(BaseModel):
    """A node in the AI system architecture."""

    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    type: ComponentType
    description: str = Field(default="", max_length=1000)
    trust_zone: str = Field(default="default", max_length=64)
    maestro_layers: list[str] = Field(default_factory=list)  # explicit override of default mapping
    # v0.13: `controls` lists controls already in place on this component
    # (e.g. mfa_required, waf, edr, segmentation). The controls engine
    # lowers likelihood for threats those controls plausibly mitigate.
    # Recognised vocabulary in engines/controls.py:CONTROL_EFFECTS.
    controls: list[str] = Field(default_factory=list)
    # `metadata` carries optional asset identification used by the v0.12
    # evidence matcher and the v0.13 device-catalog picker:
    #   vendor / product / version  — picked from kb/devices/catalog.yaml
    #   hostname / ip / fqdn        — exact-match keys for evidence matching
    #   cpe / purl                  — CPE 2.3 / Package URL for high-fidelity match
    metadata: dict = Field(default_factory=dict)


class Dataflow(BaseModel):
    """A directed flow of data between components."""

    source: str
    target: str
    label: str = ""
    crosses_boundary: bool = False
    data_classification: str = "internal"  # public | internal | confidential | restricted


class TrustBoundary(BaseModel):
    """A boundary separating components in different trust zones."""

    id: str
    type: TrustBoundaryType
    components_inside: list[str] = Field(default_factory=list)
    components_outside: list[str] = Field(default_factory=list)
    description: str = ""


class System(BaseModel):
    """The user-supplied AI system description (input to the workflow)."""

    name: str
    description: str = ""
    business_context: str = ""
    components: list[Component]
    dataflows: list[Dataflow] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    # v0.16.1 — Scale-aware FAIR priors. The risk-assessment expert
    # critique of v0.15.1 surfaced the "$10B-on-a-POC defect": every
    # system regardless of scale received the same loss range. These
    # three fields let `engines.quantitative` look up an appropriate
    # prior tier from `kb/priors/loss_priors.yaml`. Defaults keep
    # back-compat by falling back to "midmarket / pilot" priors.
    industry: Literal[
        "tier1_bank", "regional_bank", "fintech", "insurer",
        "healthcare_provider", "pharma_biotech",
        "tech_saas", "ecommerce", "media_entertainment", "telecom",
        "manufacturing", "energy_utility", "critical_infrastructure",
        "government_defense", "education", "smb_other",
        "midmarket_other",
    ] = "midmarket_other"
    revenue_bucket: Literal[
        "under_50m", "50m_to_500m", "500m_to_5b", "over_5b",
        "unknown",
    ] = "unknown"
    deployment_stage: Literal[
        "poc", "pilot", "production",
    ] = "pilot"
    # v0.16.3 — EU AI Act high-risk discriminator. Article 14 (Human
    # Oversight) binds only on Annex III high-risk systems (biometric ID,
    # critical infra, education, employment, essential services,
    # law enforcement, migration, justice). When this is False the
    # compliance enricher MUST NOT tag threats with EU_AI_ACT.14 / .13 etc.
    # — doing so risks discrediting the entire register at a regulator.
    is_high_risk_under_eu_ai_act: bool = False

    # v0.16.9 — input-integrity validation. Caught by Cycle-10 pathological-
    # input testing: duplicate component IDs silently doubled threats,
    # dangling dataflow refs masked user typos.
    @model_validator(mode="after")
    def _validate_integrity(self) -> System:
        # 1. Reject duplicate component IDs
        ids = [c.id for c in self.components]
        dupes = {cid for cid in ids if ids.count(cid) > 1}
        if dupes:
            raise ValueError(
                f"duplicate component ids: {sorted(dupes)}. "
                f"Each component must have a unique id."
            )
        # 2. Reject dangling dataflow source / target references
        valid_ids = set(ids)
        dangling: list[str] = []
        for df in self.dataflows:
            if df.source not in valid_ids:
                dangling.append(f"{df.source} (source of dataflow)")
            if df.target not in valid_ids:
                dangling.append(f"{df.target} (target of dataflow)")
        if dangling:
            raise ValueError(
                f"dataflow references nonexistent component(s): "
                f"{sorted(set(dangling))}. "
                f"Add the component or fix the typo."
            )
        return self


EvidenceSource = Literal["vapt", "red_team", "ti", "compliance"]
EvidenceStatus = Literal["hypothetical", "likely", "observed", "exploited"]
Disposition = Literal[
    "open", "accepted", "mitigated", "transferred", "false_positive", "duplicate",
    # v0.16.6 — additional lifecycle states for delta-aware re-runs.
    # accepted_with_compensating_control: residual accepted given a
    #   countervailing control (e.g. WAF tuning, manual review queue).
    # deferred: scheduled fix; not currently open but not yet mitigated.
    "accepted_with_compensating_control", "deferred"
]

# v0.17.2 (Cycle C) — dispositions that close a threat for rollup
# purposes. The threat still appears in the report (often visibly
# marked as "mitigated"), but it stops contributing to:
#   - severity_breakdown counts
#   - portfolio ALE totals
#   - top-contributors / priority-mitigation lists
# `accepted`, `transferred`, `accepted_with_compensating_control`,
# `deferred` deliberately stay LIVE — they represent ongoing risk
# that's been acknowledged, not eliminated.
CLOSED_DISPOSITIONS: frozenset[str] = frozenset({
    "mitigated", "false_positive", "duplicate",
})


def is_closed(disposition: str | None) -> bool:
    """True when a disposition counts as 'done' for rollup purposes."""
    return disposition in CLOSED_DISPOSITIONS


class Evidence(BaseModel):
    """A single piece of evidence anchoring a threat to a real-world finding.

    Sources (v0.12):
    - vapt        — VAPT / vulnerability scanner finding (.nessus, SARIF, etc.)
    - red_team    — adversary emulation result (Caldera, AttackIQ, ...)
    - ti          — threat-intel signal (CISA KEV, EPSS, STIX bundle, ...)
    - compliance  — auditor / control finding
    """

    source: EvidenceSource
    source_type: str = ""  # nessus | sarif | stix | csv | kev | epss | ...
    source_id: str = ""    # CVE-2024-XXXX, KEV row id, scanner finding id, ...
    title: str = ""
    description: str = ""
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    cve: list[str] = Field(default_factory=list)
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    affected_asset: str = ""  # hostname / IP / product+version that matched
    observed_at: str = ""  # ISO date string, free-form
    references: list[str] = Field(default_factory=list)


class Threat(BaseModel):
    """A single threat identified for a component."""

    id: str
    component_id: str
    component_name: str = ""
    title: str
    description: str
    stride_ai: list[StrideAI] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    owasp_agentic: list[str] = Field(default_factory=list)  # AGT01..AGT15 (OWASP T1..T15) + AGT16/17 ATMS ext
    owasp_api: list[str] = Field(default_factory=list)  # API1:2023..API10:2023
    atlas_techniques: list[str] = Field(default_factory=list)
    attack_cloud: list[str] = Field(default_factory=list)  # MITRE ATT&CK Cloud (T1078, T1530, ...)
    attack_enterprise: list[str] = Field(default_factory=list)  # MITRE ATT&CK Enterprise + ICS (v0.10)
    linddun: list[str] = Field(default_factory=list)  # LINDDUN privacy categories / IDs (v0.10)
    nist_ai_rmf: list[str] = Field(default_factory=list)
    nist_ai_100_2: list[str] = Field(default_factory=list)  # NIST AI 100-2 adversarial-ML taxonomy (v0.11)
    kill_chain_phase: str = ""  # Lockheed Martin Cyber Kill Chain phase (v0.11)
    evidence: list[Evidence] = Field(default_factory=list)  # VAPT / red-team / TI evidence (v0.12)
    evidence_status: EvidenceStatus = "hypothetical"  # hypothetical | likely | observed | exploited (v0.12)
    # v0.13 fields ─────────────────────────────────────────────────────────
    owasp_ml: list[str] = Field(default_factory=list)  # OWASP ML Top 10 2023 (ML01..ML10)
    compliance_controls: list[str] = Field(default_factory=list)  # NIS2.21.2.a, etc.
    # v0.16.1: Singapore CSA AI Guidelines references (CSA_AI.PLAN.01, ...).
    # Cross-walked from kb/playbooks/*.yaml during enumeration; rendered
    # in the Markdown / HTML reports as a separate row alongside NIST /
    # MAESTRO / compliance.
    csa_singapore: list[str] = Field(default_factory=list)
    disposition: Disposition = "open"           # reviewer disposition lifecycle
    # v0.16.6 — disposition lifecycle context fields. Populated when the
    # reviewer changes disposition; surfaced by `atms diff` so a
    # re-run produces a delta against architectural decisions already
    # taken (instead of regenerating the full register every quarter).
    compensating_control_id: str = Field(default="", max_length=200)
    transferred_to_vendor: str = Field(default="", max_length=200)
    mitigated_by_commit: str = Field(default="", max_length=200)
    deferred_until: str = Field(default="", max_length=64)  # ISO date
    decision_rationale: str = Field(default="", max_length=2000)
    reviewed_by: str = Field(default="", max_length=200)
    reviewed_at: str = Field(default="", max_length=64)  # ISO date
    due_date: str = Field(default="", max_length=64)     # ISO date
    owner: str = Field(default="", max_length=200)
    # FAIR-lite quantitative risk
    loss_low: float = 0.0
    loss_high: float = 0.0
    freq_low: float = 0.0
    freq_high: float = 0.0
    ale_low: float = 0.0
    ale_high: float = 0.0
    # ───────────────────────────────────────────────────────────────────────
    maestro_layers: list[str] = Field(default_factory=list)  # M.L1..M.L7
    maestro_threats: list[str] = Field(default_factory=list)  # M.L1.01, M.X.01, ...
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    risk_score: float = 0.0
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    mitigation_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    # v0.15.0: AI-anchored scoping. Every threat carries provenance for
    # *why it's in scope* — empty for AI-primary components, populated
    # with the AI-component IDs in the dataflow blast radius for AI-
    # adjacent components. Reports render this as "Caused by: <name>"
    # so reviewers can see which AI component creates the risk.
    ai_caused_by: list[str] = Field(default_factory=list)
    ai_relevance: Literal["primary", "adjacent", ""] = ""


class AttackPath(BaseModel):
    """A multi-step attack chain across components."""

    id: str
    title: str
    threat_ids: list[str]
    components: list[str]
    tactics_traversed: list[str]
    estimated_difficulty: int = Field(ge=1, le=5)
    business_impact: int = Field(ge=1, le=5)
    narrative: str = ""


class Mitigation(BaseModel):
    """A control that addresses one or more threats."""

    id: str
    title: str = Field(max_length=200)
    description: str = Field(max_length=2000)
    addresses_threat_ids: list[str] = Field(default_factory=list)
    framework_refs: list[str] = Field(default_factory=list)
    effort: Literal["low", "medium", "high"] = "medium"
    risk_reduction: int = Field(ge=1, le=5, default=3)
    # v0.14: actionability metadata so mitigations are a backlog, not a wish list.
    control_family: Literal[
        "preventive", "detective", "responsive", "corrective", "deterrent", ""
    ] = ""
    automatable: bool = False
    validation_test: str = Field(default="", max_length=500)
    d3fend: list[str] = Field(default_factory=list)  # MITRE D3FEND technique IDs (D3-XXX)
    vendor_examples: list[str] = Field(default_factory=list)
    # v0.16.4 — Reference-architecture patterns this mitigation aligns with
    # (AWS_SRA.IAM.3 / AWS_GenAI_Lens.SEC-2 / Azure_LZA.IDENTITY.5 / etc.).
    # Lets a reviewer see "this mitigation is part of AWS SRA pattern X"
    # instead of "another generic recommendation." Filtered to the
    # patterns matching the threat's components + keywords.
    reference_patterns: list[str] = Field(default_factory=list)


class StructuralRecommendation(BaseModel):
    """v0.16.5 — A proposed architecture EDIT (insert / move / split /
    relocate a component) that addresses a cluster of related threats
    jointly.

    The security-architect expert critique of v0.15.1 (finding A-03)
    flagged that ATMS enumerates threats per component but never
    proposes new components. A cluster of 4 critical agent threats
    sharing a root cause often has one structural fix — e.g. "insert
    a policy_engine between agent_service and tool calls" — that
    closes them all jointly. Per-component mitigations enumerate the
    symptom; this layer names the cure.
    """

    id: str
    title: str = Field(max_length=200)
    summary: str = Field(max_length=1500)
    edit_kind: Literal["insert", "split", "relocate", "remove", "harden_in_place"]
    proposed_component_type: str = ""    # if `insert`, the suggested ComponentType
    affected_threats: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    rationale: str = Field(default="", max_length=2000)
    sample_dfd_edit: str = Field(default="", max_length=2000)
    estimated_effort: Literal["low", "medium", "high"] = "medium"


class ThreatModel(BaseModel):
    """Full output of an analysis run."""

    system: System
    threats: list[Threat]
    structural_recommendations: list[StructuralRecommendation] = Field(default_factory=list)  # v0.16.5
    attack_paths: list[AttackPath]
    mitigations: list[Mitigation]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # v0.14.4: dynamically resolve from package version so reports
    # always carry the actual ATMS version that produced them. The
    # previous hard-coded "0.2.0" default leaked into every Markdown /
    # HTML / OTM artefact.
    tool_version: str = Field(default_factory=lambda: _atms_version())
    summary: dict = Field(default_factory=dict)


def _atms_version() -> str:
    # Local import to break the otherwise-circular `models -> __init__`.
    try:
        from . import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"
