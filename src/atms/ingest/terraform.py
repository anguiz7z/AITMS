"""Terraform IaC ingest (v0.14).

Reads a `.tf` file (or a directory of them) and produces a draft ATMS
System YAML. Coverage is pragmatic, not complete:

- AWS:    aws_instance, aws_lambda_function, aws_s3_bucket, aws_db_instance,
          aws_ecs_service, aws_eks_cluster, aws_kms_key, aws_iam_role,
          aws_secretsmanager_secret, aws_apigatewayv2_api, aws_lb,
          aws_security_group, aws_vpc, aws_sqs_queue, aws_sns_topic
- Azure:  azurerm_linux_virtual_machine, azurerm_function_app,
          azurerm_storage_account, azurerm_postgresql_flexible_server,
          azurerm_key_vault, azurerm_kubernetes_cluster
- GCP:    google_compute_instance, google_cloudfunctions_function,
          google_storage_bucket, google_sql_database_instance, google_kms_*

We don't pretend to be a full HCL parser — we strip comments, find every
`resource "<type>" "<name>" { ... }` block via regex, and infer one
ATMS Component per resource. Dependencies are sniffed from `depends_on`
or interpolations like `${aws_lb.front.arn}`.

For anything more sophisticated (modules, count/for_each), the user
should either expand the plan first (`terraform show -json`) or hand-
edit the resulting YAML in the GUI editor.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..features import gated
from ..models import Component, Dataflow, System, TrustBoundary

# Terraform resource type → (atms component_type, default name prefix)
_RESOURCE_MAP: dict[str, str] = {
    # AWS
    "aws_instance": "endpoint",
    "aws_lambda_function": "serverless_function",
    "aws_s3_bucket": "object_storage",
    "aws_db_instance": "database",
    "aws_rds_cluster": "database",
    "aws_dynamodb_table": "database",
    "aws_ecs_service": "container_runtime",
    "aws_ecs_task_definition": "container_runtime",
    "aws_eks_cluster": "container_runtime",
    "aws_kms_key": "kms_key",
    "aws_iam_role": "iam_principal",
    "aws_iam_user": "iam_principal",
    "aws_iam_policy": "iam_principal",
    "aws_secretsmanager_secret": "secrets_vault",
    "aws_apigatewayv2_api": "api_gateway",
    "aws_apigatewayv2_route": "api_gateway",
    "aws_api_gateway_rest_api": "api_gateway",
    "aws_lb": "load_balancer",
    "aws_alb": "load_balancer",
    # v0.18.61 Phase M — surfaced by HashiCorp's two-tier corpus sample.
    # Classic-ELB v1 is functionally the same as v2 (`aws_lb`) for
    # threat modeling purposes: both are externally-facing load
    # balancers terminating HTTP/HTTPS. Without this, real-world `.tf`
    # files using the legacy resource got mapped to "other".
    "aws_elb": "load_balancer",
    "aws_security_group": "firewall",
    "aws_network_acl": "firewall",
    "aws_vpc": "network_segment",
    "aws_subnet": "network_segment",
    "aws_sqs_queue": "message_queue",
    "aws_sns_topic": "message_queue",
    "aws_kinesis_stream": "message_queue",
    "aws_cloudwatch_log_group": "observability_stack",
    "aws_cloudwatch_metric_alarm": "observability_stack",
    "aws_cloudtrail": "observability_stack",
    "aws_bedrock_agent": "agent",
    "aws_bedrock_model_invocation_logging_configuration": "llm_inference",
    "aws_sagemaker_endpoint": "llm_inference",
    "aws_sagemaker_model": "model_registry",
    # Azure
    "azurerm_linux_virtual_machine": "endpoint",
    "azurerm_windows_virtual_machine": "endpoint",
    "azurerm_function_app": "serverless_function",
    "azurerm_linux_function_app": "serverless_function",
    "azurerm_logic_app_workflow": "serverless_function",
    "azurerm_storage_account": "object_storage",
    "azurerm_storage_container": "object_storage",
    "azurerm_postgresql_flexible_server": "database",
    "azurerm_mssql_server": "database",
    "azurerm_cosmosdb_account": "database",
    "azurerm_key_vault": "secrets_vault",
    "azurerm_key_vault_key": "kms_key",
    "azurerm_kubernetes_cluster": "container_runtime",
    "azurerm_container_app": "container_runtime",
    "azurerm_api_management": "api_gateway",
    "azurerm_lb": "load_balancer",
    "azurerm_application_gateway": "load_balancer",
    "azurerm_firewall": "firewall",
    "azurerm_network_security_group": "firewall",
    "azurerm_virtual_network": "network_segment",
    "azurerm_subnet": "network_segment",
    "azurerm_servicebus_queue": "message_queue",
    "azurerm_eventgrid_topic": "message_queue",
    "azurerm_eventhub_namespace": "message_queue",
    "azurerm_log_analytics_workspace": "observability_stack",
    "azurerm_application_insights": "observability_stack",
    "azurerm_user_assigned_identity": "iam_principal",
    "azurerm_role_assignment": "iam_principal",
    "azurerm_active_directory_domain_service": "directory_service",
    "azurerm_machine_learning_inference_cluster": "llm_inference",
    "azurerm_cognitive_account": "llm_inference",
    # GCP
    "google_compute_instance": "endpoint",
    "google_cloudfunctions_function": "serverless_function",
    "google_cloudfunctions2_function": "serverless_function",
    "google_cloud_run_service": "container_runtime",
    "google_cloud_run_v2_service": "container_runtime",
    "google_storage_bucket": "object_storage",
    "google_sql_database_instance": "database",
    "google_bigquery_dataset": "data_source",
    "google_bigquery_table": "data_source",
    "google_kms_crypto_key": "kms_key",
    "google_kms_key_ring": "kms_key",
    "google_secret_manager_secret": "secrets_vault",
    "google_compute_firewall": "firewall",
    "google_compute_network": "network_segment",
    "google_compute_subnetwork": "network_segment",
    "google_compute_global_forwarding_rule": "load_balancer",
    "google_compute_forwarding_rule": "load_balancer",
    "google_pubsub_topic": "message_queue",
    "google_pubsub_subscription": "message_queue",
    "google_logging_project_sink": "observability_stack",
    "google_monitoring_alert_policy": "observability_stack",
    "google_service_account": "iam_principal",
    "google_project_iam_binding": "iam_principal",
    "google_container_cluster": "container_runtime",
    "google_vertex_ai_endpoint": "llm_inference",
}

# `resource "<type>" "<name>" {` … balanced braces
_RESOURCE_RE = re.compile(
    r"resource\s+\"([a-zA-Z0-9_]+)\"\s+\"([a-zA-Z0-9_-]+)\"\s*\{",
)
# `${aws_lb.front.arn}` or `aws_lb.front.id` interpolations
_REF_RE = re.compile(r"([a-z]+_[a-z0-9_]+)\.([a-zA-Z0-9_-]+)(?:\.[a-zA-Z0-9_]+)*")
# `depends_on = [aws_lb.front, ...]`
_DEPENDS_ON_RE = re.compile(
    r"depends_on\s*=\s*\[([^\]]*)\]", re.DOTALL,
)


def _mask_strings(text: str) -> str:
    """Replace contents of double-quoted strings and ``<<-?EOT ... EOT``
    heredocs with same-length spaces so downstream regex/brace counting
    can't be fooled by braces, ``#`` chars, or refs that live inside a
    string literal.

    Returns the masked text — same length as the input, only string
    INSIDES are blanked. Quote characters and braces around strings are
    preserved so we don't break offset arithmetic.
    """
    out: list[str] = list(text)
    n = len(out)
    i = 0
    while i < n:
        ch = out[i]
        # Heredoc: <<EOT, <<-EOT, <<"EOT" — read until the closing
        # marker on its own line.
        if ch == "<" and i + 1 < n and out[i + 1] == "<":
            j = i + 2
            if j < n and out[j] == "-":
                j += 1
            # Optional quoted marker
            if j < n and out[j] in ('"', "'"):
                quote = out[j]
                j += 1
                marker_start = j
                while j < n and out[j] != quote:
                    j += 1
                marker = "".join(out[marker_start:j])
                if j < n:
                    j += 1
            else:
                marker_start = j
                while j < n and (out[j].isalnum() or out[j] == "_"):
                    j += 1
                marker = "".join(out[marker_start:j])
            if not marker:
                i = j
                continue
            # Find marker on its own line
            end_pat = re.compile(r"^[ \t]*" + re.escape(marker) + r"[ \t]*$",
                                 re.MULTILINE)
            m = end_pat.search("".join(out), j)
            if not m:
                # malformed heredoc — bail
                break
            # blank out the heredoc body (from j to m.start())
            for k in range(j, m.start()):
                if out[k] != "\n":
                    out[k] = " "
            i = m.end()
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if out[j] == "\\" and j + 1 < n:
                    out[j] = " "
                    out[j + 1] = " "
                    j += 2
                    continue
                if out[j] == '"':
                    break
                out[j] = " "
                j += 1
            i = j + 1
            continue
        i += 1
    return "".join(out)


def _strip_comments(text: str) -> str:
    """Strip HCL comments using a string-aware scan.

    We can't blindly regex out `#`, `//`, `/* */` because those tokens
    can appear *inside* string literals (e.g. `policy = "{ \"Action\": \"s3:Get*\" }"`
    contains no comment). The scanner walks the text with awareness of
    double-quoted strings and `<<EOT ... EOT` heredocs and only blanks
    comment runs that occur outside them.

    String contents themselves are preserved — `_RESOURCE_RE` needs the
    quoted type/name. Brace counting and `_REF_RE` use ``_mask_strings``
    on the OUTPUT of this function to avoid being fooled by braces or
    underscore-names inside string literals.
    """
    out = list(text)
    n = len(out)
    i = 0
    while i < n:
        ch = out[i]
        # Skip past double-quoted strings (preserving content).
        if ch == '"':
            j = i + 1
            while j < n:
                if out[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if out[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        # Skip past heredocs.
        if ch == "<" and i + 1 < n and out[i + 1] == "<":
            # Identify marker
            j = i + 2
            if j < n and out[j] == "-":
                j += 1
            if j < n and out[j] in ('"', "'"):
                quote = out[j]; j += 1
                m_start = j
                while j < n and out[j] != quote:
                    j += 1
                marker = "".join(out[m_start:j])
                if j < n:
                    j += 1
            else:
                m_start = j
                while j < n and (out[j].isalnum() or out[j] == "_"):
                    j += 1
                marker = "".join(out[m_start:j])
            if marker:
                end = re.compile(r"^[ \t]*" + re.escape(marker) + r"[ \t]*$",
                                 re.MULTILINE).search("".join(out), j)
                i = (end.end() if end else n)
                continue
            i = j
            continue
        # Comments.
        if ch == "#" or (ch == "/" and i + 1 < n and out[i + 1] == "/"):
            while i < n and out[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and out[i + 1] == "*":
            j = i + 2
            while j + 1 < n and not (out[j] == "*" and out[j + 1] == "/"):
                if out[j] != "\n":
                    out[j] = " "
                j += 1
            for k in range(i, min(j + 2, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 2
            continue
        i += 1
    return "".join(out)


def _balanced_block(text: str, open_pos: int) -> tuple[int, int]:
    """Return (start, end) indices of the balanced block beginning at the
    ``{`` indicated by ``open_pos``.

    Caller is expected to pass *masked* text (see ``_mask_strings``) so
    the brace count isn't fooled by ``{`` / ``}`` characters that live
    inside a string literal.
    """
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return open_pos, i + 1
        i += 1
    return open_pos, len(text)


# Directories we never recurse into when scanning a Terraform project — they
# either contain vendored module code (`.terraform/`) or unrelated repo
# bookkeeping that would pollute the parsed System.
_TF_SKIP_DIRS = {".terraform", ".git", ".idea", ".vscode", "node_modules"}

# Hard cap so a hostile / accidentally-huge .tf project can't OOM the CLI.
_TF_MAX_BYTES = 50 * 1024 * 1024  # 50 MB total across all .tf files


import logging  # noqa: E402  (kept top-of-module group above)

_log = logging.getLogger(__name__)


def _read_terraform(path: Path) -> str:
    p = Path(path)
    if p.is_dir():
        parts: list[str] = []
        total = 0
        truncated_at: str | None = None
        for f in sorted(p.rglob("*.tf")):
            # Skip vendored / cache directories anywhere in the path.
            if any(seg in _TF_SKIP_DIRS for seg in f.parts):
                continue
            # Skip symlinks — they can blow the size cap and they can also
            # escape the project root entirely. The user asked us to model
            # the project, not the filesystem.
            try:
                if f.is_symlink():
                    continue
            except OSError:
                continue
            try:
                size = f.stat().st_size
            except OSError:
                continue
            if total + size > _TF_MAX_BYTES:
                truncated_at = str(f)
                break
            total += size
            parts.append(f.read_text(encoding="utf-8-sig"))
        if truncated_at is not None:
            _log.warning(
                "atms.ingest.terraform: 50 MB cap reached at %s; "
                "remaining .tf files were not read. Run `terraform show -json` "
                "first if you need the full plan.",
                truncated_at,
            )
        return "\n".join(parts)
    return p.read_text(encoding="utf-8-sig")


@gated("ingest_terraform")
def parse_terraform(path: Path) -> System:
    # Two text views:
    #   raw_text:    comment-stripped, string contents PRESERVED — used by
    #                `_RESOURCE_RE` which needs to read the type+name strings.
    #   masked_text: same length, but string contents replaced with spaces —
    #                used for `_balanced_block` (so braces inside strings
    #                don't corrupt the count) and for `_REF_RE` sweeps (so
    #                `"my_company_logs.production"` inside a string doesn't
    #                fake-match a resource reference).
    raw_text = _strip_comments(_read_terraform(path))
    masked_text = _mask_strings(raw_text)
    components: list[Component] = []
    component_ids: dict[str, str] = {}  # "aws_lb.front" → cid
    blocks: list[tuple[str, str, str]] = []  # (resource_type, name, body_masked)

    for match in _RESOURCE_RE.finditer(raw_text):
        rtype = match.group(1)
        rname = match.group(2)
        brace_open = match.end() - 1
        _, brace_close = _balanced_block(masked_text, brace_open)
        body = masked_text[brace_open + 1: brace_close - 1]
        blocks.append((rtype, rname, body))

    for rtype, rname, body in blocks:
        ctype = _RESOURCE_MAP.get(rtype, "other")
        cid = f"{rtype}__{rname}"[:64]
        component_ids[f"{rtype}.{rname}"] = cid
        # Sniff vendor from the resource type prefix
        vendor = "AWS" if rtype.startswith("aws_") else \
                 "Microsoft" if rtype.startswith("azurerm_") else \
                 "Google" if rtype.startswith("google_") else ""
        meta = {"terraform_resource": rtype, "terraform_name": rname}
        if vendor:
            meta["vendor"] = vendor
        components.append(Component(
            id=cid,
            name=f"{rtype}.{rname}"[:200],
            type=ctype,  # type: ignore[arg-type]
            description=f"Imported from Terraform: {rtype}.{rname}",
            trust_zone="default",
            metadata=meta,
        ))

    # HCL pseudo-namespaces that look like resource refs but aren't.
    _hcl_pseudo = {"var", "local", "data", "module", "each", "count",
                    "path", "terraform", "self"}

    def _resource_refs(text: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for prefix, name in _REF_RE.findall(text):
            if prefix in _hcl_pseudo:
                continue
            out.append((prefix, name))
        return out

    # Dataflows from depends_on + cross-resource interpolations
    dataflows: list[Dataflow] = []
    seen: set[tuple[str, str]] = set()
    for rtype, rname, body in blocks:
        cid = component_ids.get(f"{rtype}.{rname}")
        if not cid:
            continue
        for dep in _DEPENDS_ON_RE.findall(body):
            for ref in _resource_refs(dep):
                tgt = component_ids.get(f"{ref[0]}.{ref[1]}")
                if tgt and tgt != cid and (cid, tgt) not in seen:
                    dataflows.append(Dataflow(source=cid, target=tgt, label="depends_on"))
                    seen.add((cid, tgt))
        # Cross-resource interpolations everywhere else in the body
        for ref in _resource_refs(body):
            tgt = component_ids.get(f"{ref[0]}.{ref[1]}")
            if tgt and tgt != cid and (cid, tgt) not in seen:
                dataflows.append(Dataflow(source=cid, target=tgt, label="reference"))
                seen.add((cid, tgt))

    return System(
        name=f"terraform-{Path(path).name}"[:200] or "terraform-import",
        description=f"Imported from Terraform IaC at {path}",
        components=components,
        dataflows=dataflows,
        trust_boundaries=[TrustBoundary(
            id="terraform_default",
            type="deployment_zone",
            components_inside=[c.id for c in components],
            components_outside=[],
            description="All resources from the parsed Terraform plan.",
        )] if components else [],
    )


__all__ = ["parse_terraform"]
