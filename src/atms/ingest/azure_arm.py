"""Azure Bicep + ARM template → ATMS System (v0.18.14 Cycle DD).

Adds Azure-side IaC ingest parity with the existing CloudFormation
ingester (Cycle T). Two input dialects are supported:

  1. **Bicep DSL** (`*.bicep` — Azure's friendly IaC language)
     A textual DSL whose top-level constructs are `resource`
     declarations. Compiled to ARM JSON at deploy time. We parse
     the source directly via a regex-based tokenizer that is
     correct for the common 80% case (no module-expressions, no
     `for` loops, no conditional resource creation).

  2. **ARM JSON template** (the compiled form, or hand-written ARM)
     Standard JSON with a `resources` array. We parse this via
     `json.loads` — simpler than Bicep DSL.

For each resource we look up its `Microsoft.<NS>/<Type>` against
`_RESOURCE_MAP` and emit an ATMS `Component`. Cross-references
(`<symbolic>.id`, `parent: <symbolic>`) become dataflows.
`Microsoft.Network/virtualNetworks` resources become trust
boundaries.

Security: pure stdlib + regex; no `eval`, no shell-out, no
network. The Bicep DSL is a closed grammar so regex-only parsing
is reasonable; we explicitly do NOT try to evaluate expressions.

Limitations (documented in CHANGELOG so users know what to expect):
  - No support for `for` loops (resource fan-out) — each looped
    resource is emitted once as the symbolic name.
  - No support for conditional creation (`if`) — the resource is
    always emitted.
  - Cross-module references (`module foo 'bar.bicep' = {}`) are
    ignored — bring all resources into a single file for analysis.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..features import gated
from ..models import Component, Dataflow, System, TrustBoundary

log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────
# Azure resource type → ATMS component_type map.
#
# Format: Microsoft.<Namespace>/<Type> → component_type
# (we strip the `@version` qualifier before the lookup)
#
# ~60 entries covering the resources most commonly threat-modeled.
# ────────────────────────────────────────────────────────────────────
_RESOURCE_MAP: dict[str, str] = {
    # ─── Compute ───────────────────────────────────────────────────
    "Microsoft.Compute/virtualMachines": "cloud_compute",
    "Microsoft.Compute/virtualMachineScaleSets": "cloud_compute",
    "Microsoft.ContainerInstance/containerGroups": "container_runtime",
    "Microsoft.ContainerService/managedClusters": "container_orchestrator",
    "Microsoft.ContainerRegistry/registries": "container_registry",
    "Microsoft.Web/sites": "web_application",          # often functionapp; see _refine_web_site
    "Microsoft.Web/serverfarms": "cloud_compute",       # App Service Plan
    "Microsoft.Batch/batchAccounts": "batch_compute",

    # ─── Storage ───────────────────────────────────────────────────
    "Microsoft.Storage/storageAccounts": "object_storage",
    "Microsoft.NetApp/netAppAccounts": "file_storage",
    "Microsoft.RecoveryServices/vaults": "backup_service",

    # ─── Databases ─────────────────────────────────────────────────
    "Microsoft.Sql/servers": "database",
    "Microsoft.Sql/servers/databases": "database",
    "Microsoft.DBforPostgreSQL/servers": "database",
    "Microsoft.DBforPostgreSQL/flexibleServers": "database",
    "Microsoft.DBforMySQL/servers": "database",
    "Microsoft.DBforMySQL/flexibleServers": "database",
    "Microsoft.DBforMariaDB/servers": "database",
    "Microsoft.DocumentDB/databaseAccounts": "nosql_database",
    "Microsoft.Cache/Redis": "cache_store",

    # ─── Messaging / Streaming / Search ────────────────────────────
    "Microsoft.ServiceBus/namespaces": "message_queue",
    "Microsoft.EventHub/namespaces": "stream_processor",
    "Microsoft.EventGrid/topics": "message_queue",
    "Microsoft.SignalRService/SignalR": "stream_processor",
    "Microsoft.Search/searchServices": "rag_vector_store",

    # ─── Networking / Edge ────────────────────────────────────────
    "Microsoft.Network/virtualNetworks": "network_segment",
    "Microsoft.Network/networkSecurityGroups": "firewall",
    "Microsoft.Network/applicationGateways": "waf",        # default; App Gateway w/ WAF SKU
    "Microsoft.Network/loadBalancers": "load_balancer",
    "Microsoft.Network/azureFirewalls": "firewall",
    "Microsoft.Network/frontDoors": "waf",
    "Microsoft.Network/frontdoorWebApplicationFirewallPolicies": "waf",
    "Microsoft.Network/privateEndpoints": "private_link",
    "Microsoft.Network/vpnGateways": "vpn_gateway",
    "Microsoft.Network/expressRouteGateways": "transit_gateway",
    "Microsoft.Cdn/profiles": "cdn",
    "Microsoft.Cdn/profiles/endpoints": "cdn",
    "Microsoft.ApiManagement/service": "api_gateway",
    "Microsoft.Network/dnsZones": "dns_service",
    "Microsoft.Network/privateDnsZones": "dns_service",
    "Microsoft.Network/bastionHosts": "bastion_host",

    # ─── Identity / Secrets / Keys ────────────────────────────────
    "Microsoft.KeyVault/vaults": "secrets_vault",
    "Microsoft.AAD/managedDomains": "directory_service",
    "Microsoft.ManagedIdentity/userAssignedIdentities": "iam_principal",
    "Microsoft.Authorization/roleAssignments": "iam_principal",

    # ─── Observability / Security ─────────────────────────────────
    "Microsoft.OperationalInsights/workspaces": "siem",
    "Microsoft.Insights/components": "observability_stack",
    "Microsoft.Insights/actionGroups": "alerting_platform",
    "Microsoft.SecurityInsights/sentinelOnboardingStates": "siem",
    "Microsoft.Security/iotSecuritySolutions": "ids_ips",

    # ─── AI / ML ──────────────────────────────────────────────────
    "Microsoft.CognitiveServices/accounts": "llm_inference",
    "Microsoft.MachineLearningServices/workspaces": "ml_pipeline_orchestrator",
    "Microsoft.MachineLearningServices/workspaces/endpoints": "ml_inference_endpoint",
    "Microsoft.MachineLearningServices/workspaces/onlineEndpoints": "ml_inference_endpoint",
    # `Microsoft.Search/searchServices` is mapped above (line 88) under
    # the messaging / streaming / search block. Phase 6 cleanup removed
    # the duplicate that ruff F601 flagged here.

    # ─── Integration / Workflow ───────────────────────────────────
    "Microsoft.Logic/workflows": "etl_orchestrator",
    "Microsoft.AppConfiguration/configurationStores": "feature_flag_service",
    "Microsoft.Devices/IotHubs": "iot_gateway",
    "Microsoft.Devices/provisioningServices": "iot_gateway",
    "Microsoft.HealthcareApis/services": "external_api",
    "Microsoft.HealthcareApis/workspaces": "external_api",
}


# Resource types that should also create a TrustBoundary.
_BOUNDARY_TYPES = frozenset({
    "Microsoft.Network/virtualNetworks",
})


# Regex: `resource <symbolic> 'NS/Type[/Child]@version' = ` capturing
# 1) symbolic name, 2) full type (without version).
# Bicep also allows:
#   - `existing` after the type: `resource X 'T@V' existing = {}`
#   - `if (cond)` predicate before the body
#   - `[for item in items: { … }]` loops (v0.18.37 Cycle AAA)
_RESOURCE_RE = re.compile(
    r"""
    resource \s+ (?P<sym>[A-Za-z_][\w]*) \s+
    '(?P<type>[A-Za-z0-9.]+/[A-Za-z0-9./]+)@[^']+'
    (?: \s+ existing )?
    \s* = \s*
    (?:if \s*\([^)]*\) \s*)?      # optional `if (cond)` predicate
    (?P<loop_open> \[ \s* for \s+ [^:]+ : \s* )?   # optional `[for x in y:` loop wrapper
    \{
    """,
    re.VERBOSE,
)

# Bicep module: `module <symbolic> '<path>' = { ... }` or
# `module <symbolic> '<path>' = [for x in y: { ... }]`. Modules can
# carry an `outputs.<name>` reference that other resources consume.
_MODULE_RE = re.compile(
    r"""
    module \s+ (?P<sym>[A-Za-z_][\w]*) \s+
    '(?P<path>[^']+)'
    \s* = \s*
    (?P<loop_open> \[ \s* for \s+ [^:]+ : \s* )?
    \{
    """,
    re.VERBOSE,
)

# Line / block comments stripped before parsing.
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

# Within a resource body, references look like `<symbolic>.id`,
# `<symbolic>.properties.<x>`, or `parent: <symbolic>`. We capture
# `<symbolic>` and require that the symbolic name was declared as a
# resource earlier in the file.
_REFERENCE_RE = re.compile(r"\b([A-Za-z_][\w]*)\.(?:id|name|properties)")
_PARENT_RE = re.compile(r"\bparent\s*:\s*([A-Za-z_][\w]*)")
# `name: 'literal'` — used to give the component a friendly name.
_NAME_RE = re.compile(r"\bname\s*:\s*'([^']+)'")
# `kind: 'literal'` — used to refine Microsoft.Web/sites into
# functionapp / web_application.
_KIND_RE = re.compile(r"\bkind\s*:\s*'([^']+)'")


def _strip_comments(src: str) -> str:
    """Strip `//` line comments and `/* */` block comments from Bicep."""
    src = _BLOCK_COMMENT_RE.sub("", src)
    src = _LINE_COMMENT_RE.sub("", src)
    return src


def _find_matching_brace(text: str, open_pos: int) -> int:
    """Given the index of `{` in `text`, return the index of the
    matching `}` accounting for nested braces. Returns -1 on failure."""
    depth = 0
    in_str = False
    str_char = ""
    i = open_pos
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == str_char:
                in_str = False
        else:
            if ch in ("'", '"'):
                in_str = True
                str_char = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _refine_web_site(body: str) -> str:
    """`Microsoft.Web/sites` covers both App Service and Function Apps.
    Look for a `kind` value of `functionapp` (Bicep DSL uses
    `kind: 'functionapp'`; ARM JSON uses `"kind": "functionapp"`)."""
    # Accept Bicep DSL: `kind: 'val'` AND ARM JSON: `"kind": "val"`.
    m = re.search(r"""['"]?kind['"]?\s*:\s*['"]([^'"]+)['"]""", body)
    if m and "function" in m.group(1).lower():
        return "serverless_function"
    return "web_application"


@gated("ingest_azure")
def bicep_to_system(text: str, name: str = "bicep-import") -> System:
    """Parse a Bicep DSL file into an ATMS `System`.

    Args:
        text: Raw Bicep source.
        name: System name (the file path stem is a sensible default).

    Returns:
        An unvalidated `System` with components + dataflows derived
        from the resource graph. Trust boundaries are emitted for
        `virtualNetworks`.

    Raises:
        ValueError: if `text` contains no `resource` declarations.
    """
    src = _strip_comments(text)
    components: list[Component] = []
    component_index: dict[str, Component] = {}
    edges: list[tuple[str, str, str]] = []  # (src_sym, tgt_sym, edge_label)
    boundaries: list[TrustBoundary] = []
    boundary_members: dict[str, list[str]] = {}

    for m in _RESOURCE_RE.finditer(src):
        sym = m.group("sym")
        rtype = m.group("type")
        # Find the body up to the matching close-brace.
        body_start = m.end() - 1  # at the `{`
        body_end = _find_matching_brace(src, body_start)
        body = src[body_start + 1:body_end] if body_end > 0 else ""

        ctype = _RESOURCE_MAP.get(rtype, "other")
        if rtype == "Microsoft.Web/sites":
            ctype = _refine_web_site(body)

        # Friendly name from the `name: 'literal'` line, falling back
        # to the symbolic name.
        friendly_match = _NAME_RE.search(body)
        friendly = friendly_match.group(1) if friendly_match else sym
        # Sanitise — names are bounded to 200 chars in the model.
        friendly = friendly[:200]

        # v0.18.37 Cycle AAA: detect `for` loop wrapper. The symbolic
        # name expands to multiple instances at deploy time; we tag the
        # component metadata so reports can call out the fan-out.
        is_loop = bool(m.group("loop_open"))

        # Truncate description to model limit (1000 chars).
        desc = f"Azure {rtype} (bicep symbol `{sym}`)"
        if is_loop:
            desc += " — `for` loop fan-out (instance count resolved at deploy time)"
        if len(desc) > 1000:
            desc = desc[:1000]

        meta = {"azure_type": rtype, "source": "bicep"}
        if is_loop:
            meta["bicep_loop"] = "true"
        comp = Component(
            id=sym,
            name=friendly,
            type=ctype,  # type: ignore[arg-type]
            description=desc,
            metadata=meta,
        )
        components.append(comp)
        component_index[sym] = comp

        # Boundary if VNet.
        if rtype in _BOUNDARY_TYPES:
            boundaries.append(TrustBoundary(
                id=f"vnet:{sym}", type="network",
                description=f"Azure VNet (bicep symbol `{sym}`)",
            ))
            boundary_members[sym] = []

        # References inside the body.
        for ref_m in _REFERENCE_RE.finditer(body):
            other = ref_m.group(1)
            if other != sym:
                edges.append((sym, other, "references"))
        for parent_m in _PARENT_RE.finditer(body):
            other = parent_m.group(1)
            if other != sym:
                edges.append((other, sym, "parent-of"))

    # v0.18.37 Cycle AAA: surface `module foo 'bar.bicep' = {…}` declarations
    # as opaque "other" components with a `bicep_module` metadata flag.
    # Previously these references were dropped silently. Module bodies can
    # carry their own references (params + outputs); we capture those edges
    # too so the cross-module call graph isn't invisible.
    for m in _MODULE_RE.finditer(src):
        sym = m.group("sym")
        mod_path = m.group("path")
        body_start = m.end() - 1
        body_end = _find_matching_brace(src, body_start)
        body = src[body_start + 1:body_end] if body_end > 0 else ""
        if sym in component_index:
            continue  # collision with a resource symbol — skip silently
        is_loop = bool(m.group("loop_open"))
        desc = f"Bicep module `{mod_path}` (symbol `{sym}`)"
        if is_loop:
            desc += " — `for` loop fan-out"
        meta = {"source": "bicep", "bicep_module": mod_path}
        if is_loop:
            meta["bicep_loop"] = "true"
        components.append(Component(
            id=sym, name=sym[:200], type="other",
            description=desc[:1000], metadata=meta,
        ))
        component_index[sym] = components[-1]
        # Capture references inside the module's body so the cross-module
        # call graph is visible. References like `existingThing.id` flow
        # into the module → tag as inbound to the module symbol.
        for ref_m in _REFERENCE_RE.finditer(body):
            other = ref_m.group(1)
            if other != sym:
                edges.append((sym, other, "module-uses"))

    if not components:
        raise ValueError(
            "Bicep parse: no `resource` declarations found. "
            "Confirm this is a Bicep file (.bicep) and not pure JSON ARM."
        )

    # Filter edges to those where both endpoints are real components.
    valid_ids = {c.id for c in components}
    dataflows: list[Dataflow] = []
    for s, t, label in edges:
        if s in valid_ids and t in valid_ids and s != t:
            dataflows.append(Dataflow(source=s, target=t, label=label))

    # Deduplicate dataflows by (source, target) — same edge mentioned
    # multiple times collapses.
    seen: set[tuple[str, str]] = set()
    deduped: list[Dataflow] = []
    for df in dataflows:
        key = (df.source, df.target)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(df)

    return System(
        name=name,
        description=(
            f"Imported from Bicep ({len(components)} resources, "
            f"{len(deduped)} dataflows). Review and refine before analyse."
        ),
        components=components,
        dataflows=deduped,
        trust_boundaries=boundaries,
    )


@gated("ingest_azure")
def arm_template_to_system(text: str, name: str = "arm-import") -> System:
    """Parse an ARM JSON template into an ATMS `System`.

    Looks up `$schema` to confirm it's ARM. Walks `resources` recursively
    (ARM allows nested children). Cross-references via `dependsOn`,
    `[reference(...)]`, and `[resourceId(...)]` strings become dataflows
    (best-effort regex sniffing — the ARM expression language is too
    rich to fully resolve without an evaluator).
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"ARM template JSON parse error: {exc}") from exc

    schema = (doc.get("$schema") or "").lower()
    if "armtemplates" not in schema and "deploymenttemplate" not in schema:
        raise ValueError(
            "JSON does not declare an ARM `$schema`. If this is a Bicep "
            "DSL file use `bicep_to_system` instead."
        )

    components: list[Component] = []
    name_to_id: dict[str, str] = {}
    edges: list[tuple[str, str]] = []
    boundaries: list[TrustBoundary] = []

    def _walk(resources: list, parent_id: str = "") -> None:
        for r in resources:
            rtype = (r.get("type") or "").strip()
            rname = (r.get("name") or "").strip()
            if not rtype or not rname:
                continue
            # ARM nested children: type can be "Type/Child" but only
            # the OUTER type is the full namespace; nested has the
            # short form (e.g. "myname/Default") with type "child".
            ctype = _RESOURCE_MAP.get(rtype, "other")
            if rtype == "Microsoft.Web/sites":
                # `kind` sits at the resource level, NOT inside `properties`.
                # Build a haystack covering both.
                ctype = _refine_web_site(json.dumps(r))
            # Use the resource name as ID (sanitised). Bound to 64
            # chars (model limit).
            sym = re.sub(r"[^A-Za-z0-9_]", "_", rname)[:64]
            if not sym:
                continue
            if sym in name_to_id:
                # Duplicate name: skip — ARM allows this for child
                # resources under different parents, but it's safer to
                # dedupe by sym.
                continue
            name_to_id[sym] = sym
            desc = f"Azure {rtype} (ARM name `{rname}`)"
            if len(desc) > 1000:
                desc = desc[:1000]
            comp = Component(
                id=sym, name=rname[:200], type=ctype,  # type: ignore[arg-type]
                description=desc,
                metadata={"azure_type": rtype, "source": "arm-template"},
            )
            components.append(comp)
            if rtype in _BOUNDARY_TYPES:
                boundaries.append(TrustBoundary(
                    id=f"vnet:{sym}", type="network",
                    description=f"Azure VNet (ARM name `{rname}`)",
                ))
            if parent_id:
                edges.append((parent_id, sym))
            # dependsOn refs.
            for dep in r.get("dependsOn") or []:
                if not isinstance(dep, str):
                    continue
                # Each dep is either "type/name" or "[resourceId(...)]"
                # — extract any quoted name that matches an existing sym.
                for ref in re.findall(r"'([^']+)'", dep):
                    if ref in name_to_id and ref != sym:
                        edges.append((sym, ref))
            # Nested resources.
            _walk(r.get("resources") or [], parent_id=sym)

    _walk(doc.get("resources") or [])
    if not components:
        raise ValueError(
            "ARM template parse: empty `resources` array. "
            "Confirm the template is a deployment template."
        )

    seen: set[tuple[str, str]] = set()
    dataflows: list[Dataflow] = []
    for s, t in edges:
        if (s, t) in seen or s == t:
            continue
        seen.add((s, t))
        dataflows.append(Dataflow(source=s, target=t, label="references"))

    return System(
        name=name,
        description=(
            f"Imported from ARM template ({len(components)} resources, "
            f"{len(dataflows)} dataflows). Review and refine before analyse."
        ),
        components=components,
        dataflows=dataflows,
        trust_boundaries=boundaries,
    )


@gated("ingest_azure")
def azure_to_system(text: str, name: str = "azure-import") -> System:
    """Auto-detect Bicep DSL vs ARM JSON and dispatch.

    Detection: if the source parses as JSON AND has a `$schema` /
    `resources` array, treat as ARM. Otherwise treat as Bicep DSL.
    """
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            doc = json.loads(text)
            if isinstance(doc, dict) and "resources" in doc:
                return arm_template_to_system(text, name=name)
        except json.JSONDecodeError:
            pass
    return bicep_to_system(text, name=name)


@gated("ingest_azure")
def azure_to_system_from_path(path: str | Path, name: str | None = None) -> System:
    """Read a Bicep or ARM JSON file from disk and return a System."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    return azure_to_system(text, name=name or p.stem)


__all__ = [
    "bicep_to_system",
    "arm_template_to_system",
    "azure_to_system",
    "azure_to_system_from_path",
    "_RESOURCE_MAP",  # exported for testing the lookup table
]
