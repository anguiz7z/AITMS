"""Visio (.vsdx) diagram → ATMS System.

Deterministic, no LLM. The .vsdx format is OOXML (a zip of XML); the `vsdx`
library parses it. We:

1. Walk every page's shapes, skipping pure connector lines.
2. Use shape text + any data-property text to classify into an ATMS
   `ComponentType` via keyword heuristics. Unrecognised → "other".
3. Build dataflows from `Page.connects`: every connect is (from_shape, to_shape,
   connector_shape). The connector's text becomes the dataflow label.
4. Emit a `System` (Pydantic) — caller can dump to YAML.

Legacy binary `.vsd` is NOT supported. Convert to `.vsdx` in Visio first.

Returns a draft. The user is expected to review and refine the output before
running an analysis. The CLI command `atms ingest` prints YAML to stdout (or
writes to a file with `--out`); the web UI lets users edit before submit.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

import yaml
from vsdx import VisioFile

from ..features import gated
from ..models import Component, ComponentType, Dataflow, System

log = logging.getLogger(__name__)

# Order matters: more specific patterns first.
# Each entry: (component_type, [regex patterns matched against shape text+master text+props])
# Cloud stencil names (AWS Bedrock, Azure OpenAI, Vertex AI, etc.) are surfaced as the
# top-priority match in each category since they're high-signal Visio shape labels.
TYPE_KEYWORDS: list[tuple[str, list[str]]] = [
    # ─── Cloud-identity / security stencils first (highest specificity) ──
    # These names ("IAM role", "Key Vault", "KMS") are unambiguous; we don't
    # want the more-generic AI patterns ("orchestrator" inside agent, etc.)
    # to win against them when both happen to appear in the same shape label
    # (e.g. "IAM role for orchestrator").
    ("iam_principal", [
        r"\b(iam)\s*(role|user|policy|principal)\b",
        r"\bservice\s*principal\b",
        r"\bservice\s*account\b",
        r"\b(managed|workload)\s*identity\b",
        r"\b(sts|assume[-\s]?role)\b",
        r"\b(oidc|federation)\s*(identity|provider)?\b",
    ]),
    ("secrets_vault", [
        r"\bsecrets?\s*manager\b",
        r"\b(azure\s*)?key\s*vault\b",
        r"\bsecret\s*manager\b",
        r"\bhashi(corp)?\s*vault\b",
        r"\bparameter\s*store\b",
        r"\bcredential\s*(store|vault)\b",
    ]),
    ("kms_key", [
        r"\b(aws\s*)?kms\b",
        r"\bcloud\s*kms\b",
        r"\b(key\s*vault\s*)?keys\b",
        r"\b(hsm|cloudhsm|managed\s*hsm)\b",
        r"\bencryption\s*key\b",
        r"\bcmk\b|\bcustomer[-\s]managed\s*key\b",
    ]),

    # ─── IT / Identity / Network / OT stencils (v0.10) ──────────────────
    # Highly specific, kept above generic AI / cloud / data-source patterns
    # so they win on classify-collision (e.g. "Active Directory" must NOT
    # become iam_principal).
    ("mfa_service", [
        r"\bmfa\b",
        r"\bmulti[-\s]?factor\b",
        r"\b2fa\b",
        r"\b(duo|yubikey|rsa\s*securid|securid)\b",
        r"\bauthenticator\s*(app)?\b",
        r"\b(okta|onelogin|jumpcloud|ping\s*identity)\b",
        r"\b(otp|totp|hotp|push\s*notification\s*mfa)\b",
    ]),
    ("directory_service", [
        r"\bactive\s*directory\b",
        r"\bdomain\s*controller\b",
        r"\b(adfs|ad\s*fs)\b",
        r"\bldap\b",
        r"\b(entra\s*id|azure\s*ad)\b",
        r"\b(samba|freeipa|openldap)\b",
        r"\bgoogle\s*workspace\s*directory\b",
        r"\bidp\b|\bidentity\s*provider\b",
    ]),
    ("firewall", [
        r"\b(network|perimeter|edge)\s*firewall\b",
        # Match the literal word "firewall" and standalone vendor names below.
        # Vendor names alone are ambiguous (Fortigate / Palo Alto can do VPN too)
        # but if any of these names appear next to the word "firewall" the
        # firewall classifier should win.
        r"\bfirewall\b",
        r"\b(palo\s*alto|fortinet|checkpoint|sophos|sonicwall|juniper\s*srx)\b",
        r"\b(cisco\s*ftd)\b",
        r"\bngfw\b",
        r"\b(iptables|pf-?sense|opnsense)\b",
        r"\b(security\s*appliance)\b",
    ]),
    ("vpn_gateway", [
        r"\bvpn(\s|-)?(gateway|concentrator|appliance|device|tunnel)?\b",
        r"\b(global\s*protect|anyconnect|always\s*on\s*vpn)\b",
        r"\b(fortivpn|cisco\s*asa\s*vpn|palo\s*alto\s*globalprotect)\b",
        r"\b(openvpn|wireguard|ipsec)\b",
        r"\bremote\s*access\s*(gateway|vpn)\b",
        r"\b(zero[-\s]?trust\s*network\s*access|ztna)\b",
    ]),
    ("email_server", [
        r"\b(microsoft\s*)?exchange(\s*server|\s*online)?\b",
        r"\b(office\s*365|microsoft\s*365|m365)\b",
        r"\bgoogle\s*workspace\b",
        r"\b(postfix|sendmail|qmail|exim)\b",
        r"\bmail\s*(server|relay|gateway)\b",
        r"\bsmtp\s*relay\b",
        r"\b(proofpoint|mimecast|barracuda)\b",
    ]),
    ("legacy_mainframe", [
        r"\b(as[\s/-]?400|iseries|ibm\s*i)\b",
        r"\bz\/?os\b|\bzos\b",
        r"\bmainframe\b",
        r"\b(cics|ims|db2\s*for\s*z)\b",
        r"\b(rpg|cobol)\b",
        r"\b(unisys|tandem|nonstop|openvms|vms)\b",
        r"\b(hp[-\s]?ux|aix|solaris)\b",
    ]),
    ("industrial_protocol", [
        r"\bmodbus(\s*tcp)?\b",
        r"\bopc[-\s]?ua\b|\bopc\s*da\b",
        r"\bdnp3\b",
        r"\bethernet\s*\/?ip\b",
        r"\bprofinet\b|\bprofibus\b",
        r"\biec[-\s]?61850\b",
        r"\biec[-\s]?60870\b",
        r"\bbacnet\b",
        r"\bs7\s*comm\b",  # Siemens S7-comm protocol — NOT the S7 PLC family
        r"\bot\s*(bus|protocol|fieldbus)\b",
    ]),
    ("plc", [
        r"\bplc\b",
        r"\b(siemens\s*)?(s7\-?\d+|simatic)\b",
        r"\b(allen[-\s]?bradley|controllogix|compactlogix|micrologix)\b",
        r"\b(rockwell\s*automation)\b",
        r"\b(schneider\s*modicon|modicon\s*m\d+)\b",
        r"\b(omron|mitsubishi)\s*(plc|controller)?\b",
        r"\bprogrammable\s*logic\s*controller\b",
        r"\brtu\b|\bremote\s*terminal\s*unit\b",
    ]),
    ("scada", [
        r"\bscada\b",
        r"\b(hmi|human[-\s]?machine\s*interface)\b",
        r"\b(historian|data\s*historian)\b",
        r"\b(wonderware|ifix|kepware|citect)\b",
        r"\bdcs\b|\bdistributed\s*control\s*system\b",
        r"\b(engineering|operator)\s*workstation\b",
        r"\bcontrol\s*(server|center|room)\b",
    ]),
    ("iot_device", [
        r"\biot\s*(device|sensor|gateway|hub)?\b",
        r"\b(smart\s*(camera|thermostat|lock|meter|sensor))\b",
        r"\b(cctv|ip\s*camera|surveillance\s*camera)\b",
        r"\b(zigbee|z[-\s]?wave|lorawan|nb[-\s]?iot)\b",
        r"\b(esp32|raspberry\s*pi|arduino)\b",
        r"\b(connected|smart)\s*device\b",
        r"\bbuilding\s*(automation|management)\b",
    ]),
    # Vector / RAG layer — "vector store" should win over "store"
    ("rag_vector_store", [
        r"\bvector(\s|-)?(store|db|database|index|search)\b",
        r"\b(pinecone|weaviate|chroma|faiss|milvus|qdrant|pgvector|elasticsearch|opensearch)\b",
        r"\b(amazon|aws)\s*kendra\b",
        r"\b(azure)?\s*ai\s*search\b",
        r"\bvertex\s*ai\s*matching\s*engine\b",
        r"\brag\b",
        r"\bretriev(er|al)\b",
        r"\b(knowledge|kb)\s*base\b",
    ]),
    ("embedding_service", [
        r"\bembed(ding)?s?(\s|-)?(service|model|api)?\b",
        r"\bsentence(\s|-)?transformer",
        r"\btext-embedding-",
        r"\b(amazon|aws)\s*titan\s*embed",
        r"\b(openai|cohere|voyage)\s*embeddings?\b",
    ]),
    # MCP / A2A — narrow before generic agent/tool
    ("mcp_server", [
        r"\bmcp(\s|-)?(server|host|client)?\b",
        r"\ba2a(\s|-)?(server|protocol)?\b",
        r"\bmodel\s+context\s+protocol\b",
    ]),
    # Agent — react/autogen/langgraph/etc.
    ("agent", [
        r"\b(ai\s+)?agent\b",
        r"\b(react|reflex|reflection)\s+agent\b",
        r"\b(orchestrator|orchestration)\b",
        r"\b(autogen|crewai|langgraph|llamaindex\s*agent|smolagents|agno)\b",
        r"\b(copilot|co-pilot|assistant)\b",
        r"\b(amazon|aws)\s*bedrock\s*agent",
        r"\bazure\s*ai\s*agent",
        r"\bvertex\s*ai\s*agent",
        r"\bgithub\s*copilot\s*workspace\b",
    ]),
    # LLM inference
    ("llm_inference", [
        r"\bllm\b",
        r"\b(claude|gpt-?\d|gpt|gemini|llama|mistral|mixtral|phi|deepseek|qwen|grok)\b",
        r"\b(openai|anthropic|cohere|ai21|together\s*ai|fireworks|groq)\b",
        r"\b(amazon|aws)\s*bedrock\b",
        r"\bazure\s*openai\b",
        r"\bvertex\s*ai\s*(model|endpoint)?\b",
        r"\bsagemaker\s*endpoint\b",
        r"\b(vllm|ollama|tgi|triton)\b",
        r"\bchat\s*model\b",
        r"\binference\s*(endpoint|server|service)?\b",
        r"\bcompletion(s)?\s*api\b",
    ]),
    # Pipelines
    ("training_pipeline", [
        r"\btraining(\s|-)?(pipeline|job|cluster)?\b",
        r"\b(pretrain|pre-train)\b",
        r"\bsagemaker\s*training\b",
        r"\bvertex\s*ai\s*training\b",
        r"\bdistribut(ed|ion)\s+train",
    ]),
    ("fine_tuning_pipeline", [
        r"\bfine(\s|-)?tun(e|ing)\b",
        r"\b(lora|qlora|peft|rlhf|dpo|orpo)\b",
        r"\b(sft|supervised\s+fine)\b",
    ]),
    # Storage / registries
    ("model_registry", [
        r"\bmodel(\s|-)?(registry|hub|store|catalog)\b",
        r"\b(mlflow|hugging\s*face|huggingface|sagemaker\s*model\s*registry)\b",
        r"\b(azure\s*ml\s*registry|vertex\s*ai\s*model\s*registry)\b",
        r"\bweights?\s*(store|registry)?\b",
    ]),
    ("prompt_template_store", [
        r"\bprompt(\s|-)?(store|template|library|repo|catalog)\b",
        r"\bsystem\s*prompt\b",
        r"\bprompt\s*hub\b",
        r"\blangsmith\b",
    ]),
    # Safety
    ("guardrails", [
        r"\b(llama|nemo)\s*guard\b",
        r"\b(amazon|aws)\s*bedrock\s*guardrails?\b",
        r"\bguard(rail)?s?\b",
        r"\b(content|safety)\s*filter\b",
        r"\b(input|output)\s*moderation\b",
        r"\b(prompt\s*shield|prompt\s*injection\s*classifier)\b",
        r"\b(lakera|protectai|robustintelligence)\b",
        r"\b(presidio|pii\s*detect)\b",
    ]),
    ("output_filter", [
        r"\boutput(\s|-)?filter\b",
        r"\bpost(\s|-)?filter\b",
        r"\b(pii|secret|redaction)\s*(filter|scanner|service)?\b",
        r"\bcontent\s*moderation\s*api\b",
    ]),
    # ─── Cloud-platform stencils (v0.9) ─────────────────────────────────
    # Cloud-identity / security stencils (iam_principal, secrets_vault, kms_key)
    # are declared at the top of this list so they win over AI patterns. The
    # rest follow here, before the generic AI / tool / data-source catchalls.

    ("object_storage", [
        r"\b(s3|amazon\s*s3)\b",
        r"\b(azure\s*)?blob\s*storage\b",
        r"\bgcs\b|\bgoogle\s*cloud\s*storage\b",
        r"\bobject\s*storage\b",
        r"\bbucket\b",
        r"\bminio\b",
    ]),
    ("network_segment", [
        r"\bvpc\b",
        r"\b(virtual\s*)?network\b",
        r"\bvnet\b",
        r"\bsubnet\b",
        r"\bsecurity\s*group\b",
        r"\bnacl\b",
        r"\bnsg\b",
        r"\b(transit|nat)\s*gateway\b",
        r"\b(cloudflare|fastly)\b",
    ]),
    ("serverless_function", [
        r"\b(aws\s+)?lambda\b",
        r"\bazure\s+functions?\b",
        r"\bcloud\s+functions?\b",
        r"\bcloud\s+run\s*(job|function)?\b",
        r"\bserverless\s+(function|compute)?\b",
        r"\bfaas\b",
    ]),
    ("api_gateway", [
        r"\bapi\s*gateway\b",
        r"\bapi\s*management\b",
        r"\bcloud\s*endpoints\b",
        r"\b(apigee|kong|tyk)\b",
        r"\b(waf|web\s*application\s*firewall)\b",
        r"\b(alb|application\s*load\s*balancer)\b",
        r"\bfront\s*door\b",
    ]),
    ("container_runtime", [
        r"\b(eks|aks|gke)\b",
        r"\b(ecs|fargate|cloud\s*run|container\s*apps)\b",
        r"\b(kubernetes|k8s)\b",
        r"\b(pod|deployment|daemonset)\b",
        r"\b(docker|containerd)\s*runtime\b",
    ]),
    ("message_queue", [
        r"\b(sqs|sns|eventbridge|kinesis)\b",
        r"\b(service\s*bus|event\s*grid|event\s*hub)\b",
        r"\b(pub[-/\s]?sub|cloud\s*pub\s*sub)\b",
        r"\b(rabbitmq|kafka|nats|redis\s*streams)\b",
        r"\bmessage\s*(queue|broker|bus)\b",
    ]),
    ("observability_stack", [
        r"\bcloudwatch\b",
        r"\b(application\s*insights|app\s*insights|log\s*analytics)\b",
        r"\bcloud\s*(logging|monitoring|trace)\b",
        r"\b(datadog|new\s*relic|splunk|elastic|grafana|prometheus)\b",
        r"\b(opentelemetry|otel)\b",
        r"\b(siem|xdr|sumo\s*logic)\b",
    ]),

    # ─── Remaining IT / Network stencils (v0.10) ────────────────────────
    # Placed AFTER api_gateway / cloud stencils so cloud-specific names win
    # first; these catch on-prem appliance keywords.
    ("load_balancer", [
        r"\b(f5|big[-\s]?ip)\b",
        r"\b(haproxy|nginx\s*plus|nginx\s*lb|envoy)\b",
        r"\b(citrix\s*netscaler|netscaler\s*adc)\b",
        r"\b(load\s*balancer|reverse\s*proxy)\b",
        r"\b(traefik)\b",
    ]),
    ("network_switch", [
        r"\b(cisco\s*catalyst|cisco\s*nexus)\b",
        r"\b(arista\s*7\d+|arista\s*switch)\b",
        r"\b(juniper\s*ex|hpe\s*aruba\s*switch)\b",
        r"\b(top[-\s]?of[-\s]?rack|tor\s*switch|core\s*switch|access\s*switch)\b",
        r"\b(layer\s*[23]\s*switch|l[23]\s*switch)\b",
        r"\b(network\s*switch|managed\s*switch)\b",
    ]),
    ("web_application", [
        r"\b(custom|in[-\s]?house|internal)\s*web\s*(app|application|portal)\b",
        r"\b(spa|single[-\s]?page\s*application)\b",
        r"\b(react|angular|vue|next\.?js|nuxt)\s*(app|application|frontend)\b",
        r"\b(django|flask|fastapi|spring\s*boot|rails|laravel|express)\s*(app|application)?\b",
        r"\bweb\s*(portal|frontend|ui)\b",
        r"\bcustomer\s*portal\b",
        r"\binternal\s*tool\b",
    ]),
    ("database", [
        r"\b(oracle|sql\s*server|mssql|microsoft\s*sql)\b",
        r"\b(mariadb|sybase|teradata|db2)\b",
        r"\b(rdbms|relational\s*database)\b",
        r"\bdatabase\s*server\b",
        r"\b(transactional|oltp|olap|data\s*warehouse)\s*(db|database)?\b",
        r"\b(postgres(?:ql)?|mysql|mongodb)\s*(server|cluster|instance|primary|replica)\b",
    ]),
    ("endpoint", [
        r"\b(workstation|laptop|desktop)\b",
        r"\b(developer|user|admin)\s*(workstation|laptop|machine)\b",
        r"\b(mac\s*book|macbook)\b",
        r"\bwindows\s*(10|11)\s*(pc|machine|host)?\b",
        r"\b(corporate|company|managed)\s*(laptop|device|endpoint)\b",
        r"\bemployee\s*(machine|host|computer)\b",
        r"\bbring[-\s]?your[-\s]?own[-\s]?device\b|\bbyod\b",
    ]),

    # Tools / external
    ("tool", [
        r"\btool\b",
        r"\bfunction(\s|-)?call(s|ing)?\b",
        r"\bplugin\b",
        r"\b(action|skill)\b",
    ]),
    ("data_source", [
        r"\b(data(\s|-)?source|dataset|corpus|database|s3|bucket|table|warehouse|datalake|lakehouse)\b",
        r"\b(salesforce|snowflake|bigquery|postgres|postgresql|mysql|mongodb|dynamodb|cosmos\s*db)\b",
        r"\b(adls|gcs|blob\s*storage)\b",
    ]),
    ("external_api", [
        r"\b(api|webhook|external\s*service|saas|third(\s|-)?party)\b",
        r"\b(slack|teams|discord|github|gitlab|jira|notion|confluence|stripe|salesforce|hubspot)\b",
        r"\b(pagerduty|datadog|grafana|sentry|splunk)\b",
        r"\b(twilio|sendgrid|mailgun)\b",
    ]),
    # User
    ("user", [
        r"\b(user|customer|client|operator|analyst|engineer|reviewer|admin|developer)\b",
        r"\b(end(\s|-)?user|on(\s|-)?call|tester)\b",
        r"\bemployee\b",
    ]),
]

CONNECTOR_TEXT_HINTS = re.compile(
    r"\b(crosses|boundary|trust|dmz|internet|prod|staging|vpc)\b", re.I
)

# Data-classification heuristics from connector label text. Higher-risk first;
# first match wins. None means "leave at the model default (internal)".
DATA_CLASSIFICATION_HINTS: list[tuple[str, list[str]]] = [
    ("restricted", [
        r"\b(secret|credential|token|api[_\s-]?key|password|cert(ificate)?|private[_\s-]?key)\b",
        r"\b(phi|hipaa|pci|payment\s*card)\b",
    ]),
    ("confidential", [
        r"\b(pii|personal|customer|user[_\s-]?data|gdpr|ssn|email\s*address)\b",
        r"\b(confidential|sensitive|nda|proprietary)\b",
        r"\b(financial|salary|invoice|bank)\b",
    ]),
    ("public", [
        r"\b(public|open|published|marketing\s*copy|website|blog)\b",
    ]),
]


def _classify_data(label: str) -> str:
    """Pick a data classification from the connector label text.

    Returns one of: 'public', 'internal' (default), 'confidential', 'restricted'.
    """
    if not label:
        return "internal"
    norm = label.lower()
    for cls, patterns in DATA_CLASSIFICATION_HINTS:
        for pat in patterns:
            if re.search(pat, norm):
                return cls
    return "internal"


# Regex for "vague" / placeholder connector labels.
VAGUE_LABEL_RE = re.compile(r"^[\s\-→\->]*$|^(line|connector|edge)$", re.I)


def is_vague_label(label: str) -> bool:
    """A connector with this label gives the analysis no useful signal."""
    if not label:
        return True
    return bool(VAGUE_LABEL_RE.match(label.strip()))


def _classify(text: str) -> ComponentType:
    """Pick the first matching ATMS component type. Returns 'other' if nothing fits."""
    if not text:
        return "other"
    norm = text.lower()
    for ctype, patterns in TYPE_KEYWORDS:
        for pat in patterns:
            if re.search(pat, norm):
                return ctype  # type: ignore[return-value]
    return "other"


def _slugify(text: str, used: set[str]) -> str:
    """Make a stable, unique component id from text."""
    slug = re.sub(r"[^a-z0-9]+", "_", (text or "node").lower()).strip("_")
    if not slug:
        slug = "node"
    base = slug[:24]
    candidate = base
    i = 2
    while candidate in used:
        candidate = f"{base}_{i}"
        i += 1
    used.add(candidate)
    return candidate


def _shape_text(shape) -> str:
    """Best-effort *display* text — what the user sees on the shape. Used for the
    component name and description. Does NOT include data-property values, which
    are typically metadata (custom property values), not labels."""
    text = (shape.text or "").strip()
    if text:
        return text
    try:
        master = shape.master_shape
        if master is not None:
            mt = (master.text or "").strip()
            if mt:
                return mt
    except Exception:  # noqa: BLE001
        pass
    return ""


def _shape_classification_text(shape) -> str:
    """Broader text used only for *classifying* the component type — includes data
    properties so labels like `type=llm` on a shape can drive the type heuristic."""
    parts: list[str] = []
    t = _shape_text(shape)
    if t:
        parts.append(t)
    try:
        if shape.data_properties:
            for prop in shape.data_properties.values():
                v = (getattr(prop, "value", "") or "").strip()
                if v:
                    parts.append(v)
                lbl = (getattr(prop, "label", "") or "").strip()
                if lbl:
                    parts.append(lbl)
    except Exception:  # noqa: BLE001
        pass
    return " ".join(parts)


def _is_connector(shape) -> bool:
    """Heuristic: a shape is a connector if it has begin/end coordinates."""
    try:
        bx, by = shape.begin_x, shape.begin_y
        ex, ey = shape.end_x, shape.end_y
        if bx is not None and by is not None and ex is not None and ey is not None:
            # Lines, arrows: they have begin and end positions.
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _walk_shapes(root_shapes: Iterable) -> Iterable:
    """Yield every shape (and grandchild) under a list of root shapes."""
    for s in root_shapes:
        yield s
        try:
            for sub in s.child_shapes:
                yield from _walk_shapes([sub])
        except Exception:  # noqa: BLE001
            continue


def _trust_zone(text: str) -> str:
    """Best-effort trust-zone label extracted from shape text."""
    norm = (text or "").lower()
    for kw, label in [
        ("internet", "internet"),
        ("dmz", "dmz"),
        ("prod", "production"),
        ("training", "training"),
        ("vpc", "vpc"),
        ("corp", "corp_internal"),
        ("internal", "corp_internal"),
        ("external", "external_provider"),
    ]:
        if kw in norm:
            return label
    return "default"


@gated("ingest_vsdx")
def vsdx_to_system(path: str | Path, system_name: str | None = None) -> System:
    """Parse a .vsdx into an ATMS `System`. Returns a draft for review."""
    p = Path(path)
    # Check format first — clearer error than FileNotFoundError when user passes
    # a path with the wrong extension.
    if p.suffix.lower() == ".vsd":
        raise ValueError(
            "Legacy binary .vsd files are not supported. Open in Visio (or LibreOffice "
            "Draw) and 'Save As' .vsdx, then retry."
        )
    if p.suffix.lower() != ".vsdx":
        raise ValueError(f"Unsupported diagram format: {p.suffix} (expected .vsdx)")
    if not p.exists():
        raise FileNotFoundError(p)

    components: list[Component] = []
    dataflows: list[Dataflow] = []
    shape_to_component_id: dict[int, str] = {}
    used_ids: set[str] = set()

    with VisioFile(str(p)) as vis:
        for page in vis.pages:
            log.debug("Visio page: %s", page.name)
            # First pass: collect non-connector shapes as components
            for shape in _walk_shapes(page.child_shapes):
                if _is_connector(shape):
                    continue
                display_text = _shape_text(shape)
                if not display_text:
                    continue  # skip purely decorative shapes
                ctype = _classify(_shape_classification_text(shape))
                primary = display_text.split("\n")[0].strip()[:80] or "node"
                cid = _slugify(primary, used_ids)
                # v0.14.9: collapse Visio's shape-text whitespace runs
                # (newlines + leading dashes from bullet shapes like
                # "- VPN Tunnel\n- Encryption") into a single readable
                # sentence so the YAML user reviews isn't littered
                # with quoted multi-line strings.
                desc_clean = re.sub(r"\s+", " ", display_text).strip()
                # Drop obvious bullet-list dashes when they're only
                # there to render as a list in Visio.
                desc_clean = re.sub(r"\s+-\s*", "; ", desc_clean)
                desc_clean = re.sub(r"^-\s*", "", desc_clean)
                comp = Component(
                    id=cid,
                    name=primary,
                    type=ctype,
                    description=desc_clean[:500],
                    trust_zone=_trust_zone(display_text),
                )
                components.append(comp)
                shape_to_component_id[int(shape.ID) if hasattr(shape, "ID") else id(shape)] = cid

            # Second pass: dataflows from connects.
            # In .vsdx, each Connect is one *endpoint* of a connector:
            #   from_id = the connector's shape id
            #   to_id   = the connected component's shape id
            #   from_rel ∈ {BeginX, EndX, ...} tells us which endpoint of the connector.
            # A full edge needs both endpoints (BeginX and EndX) of the same connector.
            by_connector: dict[int, dict[str, int]] = defaultdict(dict)
            try:
                for connect in page.connects:
                    cid_int = int(connect.connector_shape_id)
                    rel = (connect.from_rel or "").lower()
                    if not connect.to_id:
                        continue
                    target_shape_id = int(connect.to_id)
                    if "begin" in rel:
                        by_connector[cid_int]["begin"] = target_shape_id
                    elif "end" in rel:
                        by_connector[cid_int]["end"] = target_shape_id
            except Exception as e:  # noqa: BLE001
                log.warning("vsdx connects parse failed on %s: %s", page.name, e)

            for connector_id, ends in by_connector.items():
                begin_shape = ends.get("begin")
                end_shape = ends.get("end")
                if begin_shape is None or end_shape is None:
                    continue
                src = shape_to_component_id.get(begin_shape)
                tgt = shape_to_component_id.get(end_shape)
                if not src or not tgt or src == tgt:
                    continue
                label = ""
                try:
                    connector_shape = page.find_shape_by_id(str(connector_id))
                    if connector_shape is not None:
                        label = (connector_shape.text or "").strip()[:60]
                except Exception:  # noqa: BLE001
                    pass
                df = Dataflow(
                    source=src,
                    target=tgt,
                    label=label or "->",
                    data_classification=_classify_data(label),
                )
                if not any(d.source == df.source and d.target == df.target and d.label == df.label
                           for d in dataflows):
                    dataflows.append(df)

    if not components:
        raise ValueError(
            "No labelled shapes found in the .vsdx. ATMS uses shape text to identify "
            "components — make sure each box/icon has a label like 'LLM' or 'Agent' or "
            "'Vector store'."
        )

    return System(
        name=system_name or p.stem.replace("_", " ").title(),
        description=f"Imported from {p.name}. Review and edit before running analysis.",
        components=components,
        dataflows=dataflows,
        trust_boundaries=[],  # vsdx has no canonical concept; users add manually
    )


@gated("ingest_vsdx")
def vsdx_to_system_yaml(path: str | Path, system_name: str | None = None) -> str:
    """Convenience wrapper: parse .vsdx and dump to a compact YAML string.

    v0.14.9: skips empty defaults so the user doesn't have to step over
    `controls: []` / `metadata: {}` / `maestro_layers: []` on every
    component when reviewing the parse output.
    """
    system = vsdx_to_system(path, system_name=system_name)
    data = system.model_dump(exclude_defaults=True, exclude_none=True)
    def _prune(d):
        if isinstance(d, dict):
            return {k: _prune(v) for k, v in d.items()
                    if v not in (None, "", [], {})}
        if isinstance(d, list):
            return [_prune(x) for x in d]
        return d
    return yaml.safe_dump(_prune(data), sort_keys=False,
                          default_flow_style=False, width=100)


def vague_dataflows(system: System) -> list[Dataflow]:
    """Return dataflows whose label gives no security-modelling signal.

    Useful for surfacing 'review needed' notices to the user after ingestion.
    """
    return [d for d in system.dataflows if is_vague_label(d.label)]


# Public type list for UI consumption
SUPPORTED_FORMATS = (".vsdx",)
