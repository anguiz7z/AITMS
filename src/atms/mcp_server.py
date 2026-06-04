"""Model Context Protocol (MCP) stdio server (v0.18.43 Cycle GGG).

Lets Claude Code (and any other MCP client) query the ATMS knowledge
base + run analyses without invoking the CLI. Exposes 5 tools:

  atms_analyze            POST a System YAML, return ThreatModel JSON
  atms_scan_text          Scan an inline blob (drawio/mermaid/bicep/...)
  atms_search_playbook    Get a playbook by component_type
  atms_search_compliance  Search compliance controls (framework + query)
  atms_metrics            KB inventory snapshot (same as GET /api/v1/metrics)

Implementation: pure-stdlib JSON-RPC 2.0 over stdio. The MCP spec
(modelcontextprotocol.io) is minimal — `initialize` handshake,
`tools/list`, `tools/call`. No new runtime dependency.

Claude Code wires this up via a `.mcp.json`:

    {
      "mcpServers": {
        "atms": {
          "command": "atms",
          "args": ["mcp"]
        }
      }
    }

Once registered, the user can ask Claude:
  "Use atms_analyze to find threats in this YAML: …"
  "What's the threat playbook for an llm_inference component?"
  "Which NIST 800-53 controls relate to access management?"
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from . import __version__

log = logging.getLogger(__name__)

# MCP protocol version we speak.
PROTOCOL_VERSION = "2024-11-05"

# JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _tools() -> list[dict]:
    """Tool descriptors returned by tools/list. Each entry follows the
    MCP Tool schema: name, description, inputSchema (JSON Schema)."""
    return [
        {
            "name": "atms_analyze",
            "description": (
                "Analyze an ATMS System YAML and return the full "
                "ThreatModel as JSON (threats, attack paths, "
                "mitigations, compliance, framework coverage)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "yaml": {
                        "type": "string",
                        "description": "The System YAML body.",
                    },
                    "methodology": {
                        "type": "string",
                        "enum": ["stride-ai", "linddun", "pasta"],
                        "default": "stride-ai",
                    },
                    "allow_pure_it": {
                        "type": "boolean",
                        "default": True,
                        "description": (
                            "When false, reject pure-IT systems "
                            "(no AI components)."
                        ),
                    },
                },
                "required": ["yaml"],
            },
        },
        {
            "name": "atms_scan_text",
            "description": (
                "Scan an inline diagram or IaC artefact (Bicep, "
                "Pulumi YAML, Mermaid, draw.io XML, CloudFormation, "
                "Kubernetes manifest, etc.) and return the analysis "
                "JSON. Format is auto-detected from a content sniff."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "content": {"type": "string"},
                    "format": {
                        "type": "string",
                        "enum": [
                            "auto", "drawio", "mermaid", "bicep",
                            "pulumi", "cloudformation", "kubernetes",
                            "otm", "system-yaml", "tm7",
                        ],
                        "default": "auto",
                    },
                    "filename_hint": {
                        "type": "string",
                        "description": (
                            "Original filename — used to pick the "
                            "right parser when format is 'auto' and "
                            "content alone is ambiguous (e.g. "
                            "Pulumi.yaml vs a system YAML)."
                        ),
                    },
                },
                "required": ["content"],
            },
        },
        {
            "name": "atms_search_playbook",
            "description": (
                "Return the threat playbook for a given ATMS "
                "ComponentType (e.g. 'llm_inference', 'database', "
                "'api_gateway'). Each playbook contains 3-13 "
                "templated threats with STRIDE-AI categories, "
                "framework refs, likelihood × impact, and "
                "mitigations."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "component_type": {"type": "string"},
                },
                "required": ["component_type"],
            },
        },
        {
            "name": "atms_search_compliance",
            "description": (
                "Search the bundled compliance-control library. "
                "Filter by framework (NIST_800_53, ISO27001, SOC2, "
                "EU_AI_Act, GDPR, HIPAA, PCI_DSS, NIS2, DORA, "
                "NIST_CSF, SEC_CYBER, ISO27017, ISO27018, "
                "OWASP_MASVS, OWASP_SAMM) and/or substring query."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "framework": {"type": "string"},
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "default": 20},
                },
            },
        },
        {
            "name": "atms_metrics",
            "description": (
                "Return ATMS KB inventory snapshot (playbook count, "
                "compliance frameworks, ATLAS technique count, "
                "device-catalog size, architectural-rule count). "
                "Useful for verifying the bundled KB hasn't drifted."
            ),
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


def _tool_call(name: str, args: dict) -> dict:
    """Dispatch + return MCP `content[]` payload for a tool call."""
    if name == "atms_metrics":
        from .engines.architectural_rules import ARCHITECTURAL_RULES
        from .kb import get_kb
        kb = get_kb()
        fws = sorted({c.get("framework", "")
                       for c in (kb.compliance_controls or {}).values()
                       if c.get("framework")})
        result = {
            "version": __version__,
            "playbooks": len(kb.playbooks or {}),
            "compliance_controls": len(kb.compliance_controls or {}),
            "frameworks": fws,
            "atlas_techniques": len(kb.atlas_techniques or {}),
            "owasp_llm": len(kb.owasp_llm or {}),
            "owasp_agentic": len(kb.owasp_agentic or {}),
            "owasp_api": len(kb.owasp_api or {}),
            "device_catalog": len(kb.devices or []),
            "arch_rules": len(ARCHITECTURAL_RULES),
        }
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

    if name == "atms_analyze":
        yaml_text = args.get("yaml")
        if not isinstance(yaml_text, str) or not yaml_text.strip():
            raise ValueError("yaml argument is required and non-empty")
        methodology = args.get("methodology", "stride-ai")
        allow_pure_it = bool(args.get("allow_pure_it", True))
        import yaml as _yaml

        from .models import System
        from .workflow import analyze
        data = _yaml.safe_load(yaml_text) or {}
        if not isinstance(data, dict):
            raise ValueError("YAML root must be a mapping")
        system = System.model_validate(data)
        model = analyze(system, methodology=methodology,
                        require_ai_components=not allow_pure_it)
        # Slim summary as text (the full model JSON would blow context).
        text = (
            f"ATMS analysis — {system.name}\n"
            f"  Threats:        {len(model.threats)}\n"
            f"  Attack paths:   {len(model.attack_paths)}\n"
            f"  Mitigations:    {len(model.mitigations)}\n"
            f"  Severity:       {dict(model.summary.get('severity_breakdown', {}))}\n"
            f"  OWASP LLM:      {len(model.summary.get('owasp_coverage') or [])}/10\n"
            f"  ATLAS:          {len(model.summary.get('atlas_coverage') or [])}\n"
            f"  Compliance refs:{len(model.summary.get('compliance_coverage') or [])}"
        )
        # Full model JSON in a second content block.
        full = json.loads(model.model_dump_json())
        return {"content": [
            {"type": "text", "text": text},
            {"type": "text", "text": "```json\n" + json.dumps(full, indent=2) + "\n```"},
        ]}

    if name == "atms_scan_text":
        content = args.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("content argument is required and non-empty")
        fmt = (args.get("format") or "auto").lower()
        # Minimal auto-detect using the same content-sniff logic.
        if fmt == "auto":
            if "<mxfile" in content[:200]:
                fmt = "drawio"
            elif content.lstrip().startswith("{") and "Microsoft." in content:
                fmt = "bicep"  # ARM JSON → bicep parser handles both
            elif "AWSTemplateFormatVersion" in content[:500] or "AWS::" in content[:500]:
                fmt = "cloudformation"
            elif "apiVersion:" in content[:500] and "kind:" in content[:500]:
                fmt = "kubernetes"
            elif "<ThreatModel" in content[:500]:
                fmt = "tm7"
            elif "runtime: yaml" in content[:500]:
                fmt = "pulumi"
            elif "flowchart" in content[:300] or "%%" in content[:50]:
                fmt = "mermaid"
            else:
                fmt = "system-yaml"

        # Phase A: helper to write content to a CLOSED temp file and
        # hand the path to a parser. On Windows, NamedTemporaryFile
        # held inside a `with` block keeps the file write-locked, so
        # the parser opens an empty handle and fails with cryptic
        # "no Resources section" / "no documents found" errors.
        # Solution: close the handle BEFORE the parser opens it.
        def _temp_file_dispatch(suffix: str, parser_fn):
            import os
            import tempfile
            from pathlib import Path
            fd, tp = tempfile.mkstemp(suffix=suffix, text=True)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(content)
                # Some ingesters (drawio) demand a Path; others (k8s,
                # cloudformation) accept str | Path. Always pass Path
                # so the strictest contract holds.
                return parser_fn(Path(tp))
            finally:
                try:
                    os.unlink(tp)
                except OSError:
                    pass

        try:
            if fmt == "drawio":
                from .ingest.drawio import drawio_to_system
                system = _temp_file_dispatch(".drawio", drawio_to_system)
            elif fmt == "mermaid":
                from .ingest.mermaid import mermaid_to_system
                system = _temp_file_dispatch(".mmd", mermaid_to_system)
            elif fmt == "bicep":
                from .ingest.azure_arm import azure_to_system
                system = azure_to_system(content)
            elif fmt == "pulumi":
                from .ingest.pulumi_yaml import pulumi_to_system
                system = pulumi_to_system(text=content)
            elif fmt == "cloudformation":
                from .ingest.cloudformation import cloudformation_to_system
                system = _temp_file_dispatch(".yaml", cloudformation_to_system)
            elif fmt == "kubernetes":
                from .ingest.kubernetes import kubernetes_to_system
                system = _temp_file_dispatch(".yaml", kubernetes_to_system)
            elif fmt == "tm7":
                from .ingest.tm7 import tm7_to_system
                system = tm7_to_system(text=content)
            elif fmt == "otm":
                from .ingest.otm import parse_otm
                system = _temp_file_dispatch(".otm", parse_otm)
            elif fmt == "system-yaml":
                import yaml as _yaml

                from .models import System
                data = _yaml.safe_load(content) or {}
                system = System.model_validate(data)
            else:
                raise ValueError(f"unsupported format: {fmt}")
        except Exception as exc:
            raise ValueError(f"ingest failed ({fmt}): {exc}") from exc

        from .engines.ai_scope import find_ai_components
        from .workflow import analyze
        has_ai = bool(find_ai_components(system))
        model = analyze(system, require_ai_components=has_ai)
        text = (
            f"ATMS scan — {system.name} (detected format: {fmt})\n"
            f"  Components:    {len(system.components)}\n"
            f"  Dataflows:     {len(system.dataflows)}\n"
            f"  Threats:       {len(model.threats)}\n"
            f"  Attack paths:  {len(model.attack_paths)}\n"
            f"  Mitigations:   {len(model.mitigations)}"
        )
        return {"content": [{"type": "text", "text": text}]}

    if name == "atms_search_playbook":
        ct = args.get("component_type")
        if not ct:
            raise ValueError("component_type is required")
        from .kb import get_kb
        kb = get_kb()
        pb = (kb.playbooks or {}).get(ct)
        if not pb:
            return {"content": [{"type": "text",
                                   "text": f"No playbook for component_type={ct!r}. "
                                            f"Available types: see /capabilities or "
                                            f"atms list-playbooks."}]}
        import yaml as _yaml
        return {"content": [{"type": "text",
                               "text": _yaml.safe_dump(pb, sort_keys=False)}]}

    if name == "atms_search_compliance":
        from .kb import get_kb
        kb = get_kb()
        rows = list((kb.compliance_controls or {}).values())
        framework = args.get("framework")
        if framework:
            rows = [r for r in rows
                    if r.get("framework", "").lower() == framework.lower()]
        q = (args.get("query") or "").lower()
        if q:
            rows = [r for r in rows
                    if q in str(r.get("title", "")).lower()
                    or q in str(r.get("description", "")).lower()
                    or q in str(r.get("id", "")).lower()]
        limit = max(1, min(int(args.get("limit") or 20), 100))
        rows = rows[:limit]
        text = (f"Compliance — {len(rows)} match(es)"
                + (f" in {framework}" if framework else "")
                + (f' for "{q}"' if q else "")
                + ":\n\n"
                + "\n".join(f'  - {r["id"]}: {r.get("title", "")} ({r.get("framework", "")})'
                              for r in rows))
        return {"content": [{"type": "text", "text": text}]}

    raise ValueError(f"unknown tool: {name}")


def _send(msg: dict) -> None:
    """Write a single JSON-RPC message to stdout (newline-delimited)."""
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _ok(req_id: Any, result: dict) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "result": result})


def _err(req_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": req_id,
           "error": {"code": code, "message": message}})


def serve_stdio() -> None:
    """Run the MCP server reading from stdin, writing to stdout. Blocks
    until EOF on stdin. JSON-RPC line-delimited, one message per line."""
    log.info("ATMS MCP server v%s starting on stdio", __version__)
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            _err(None, PARSE_ERROR, f"JSON parse error: {exc}")
            continue
        if not isinstance(msg, dict):
            _err(None, INVALID_REQUEST, "request must be a JSON object")
            continue
        method = msg.get("method")
        req_id = msg.get("id")  # may be None for notifications
        params = msg.get("params") or {}

        try:
            if method == "initialize":
                _ok(req_id, {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "atms", "version": __version__},
                })
            elif method == "notifications/initialized":
                # No response for notifications.
                continue
            elif method == "tools/list":
                _ok(req_id, {"tools": _tools()})
            elif method == "tools/call":
                tname = params.get("name")
                targs = params.get("arguments") or {}
                if not tname:
                    _err(req_id, INVALID_PARAMS, "tools/call requires `name`")
                    continue
                try:
                    result = _tool_call(tname, targs)
                except ValueError as exc:
                    _err(req_id, INVALID_PARAMS, str(exc))
                    continue
                except Exception as exc:  # noqa: BLE001
                    _err(req_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
                    continue
                _ok(req_id, result)
            elif method == "ping":
                _ok(req_id, {})
            elif method == "shutdown":
                _ok(req_id, {})
                break
            else:
                if req_id is not None:
                    _err(req_id, METHOD_NOT_FOUND, f"method not found: {method}")
        except Exception as exc:  # noqa: BLE001
            log.exception("MCP dispatch error")
            if req_id is not None:
                _err(req_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")


__all__ = ["serve_stdio", "PROTOCOL_VERSION"]
