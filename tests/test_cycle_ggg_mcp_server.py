"""Regression tests for v0.18.43 Cycle GGG — MCP stdio server.

Drives the JSON-RPC 2.0 stdio interface end-to-end via subprocess.
Mirrors what Claude Code's MCP client does: initialize → tools/list
→ tools/call. Pure-stdlib; no `mcp` package required.
"""

from __future__ import annotations

import io
import json
import os
import sys
import textwrap

import pytest

# In-process driver for the MCP server — bypasses subprocess overhead
# while exercising the same code path the stdio entrypoint uses.

def _drive(messages: list[dict]) -> list[dict]:
    """Feed `messages` into the MCP server's stdin and capture all
    responses. Returns the list of decoded JSON-RPC responses."""
    from atms import mcp_server
    input_text = "\n".join(json.dumps(m) for m in messages) + "\n"

    # Redirect stdin/stdout for the duration of the call.
    old_in, old_out = sys.stdin, sys.stdout
    out_buf = io.StringIO()
    sys.stdin = io.StringIO(input_text)
    sys.stdout = out_buf
    try:
        mcp_server.serve_stdio()
    finally:
        sys.stdin = old_in
        sys.stdout = old_out
    out_buf.seek(0)
    responses = []
    for line in out_buf.read().splitlines():
        line = line.strip()
        if not line:
            continue
        responses.append(json.loads(line))
    return responses


def test_initialize_handshake():
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
    ])
    assert len(rs) == 1
    r = rs[0]
    assert r["jsonrpc"] == "2.0"
    assert r["id"] == 1
    assert r["result"]["protocolVersion"] == "2024-11-05"
    assert r["result"]["serverInfo"]["name"] == "atms"
    assert "tools" in r["result"]["capabilities"]


def test_tools_list_returns_expected_schema():
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ])
    assert len(rs) == 2
    tools = rs[1]["result"]["tools"]
    names = {t["name"] for t in tools}
    expected = {"atms_analyze", "atms_scan_text",
                 "atms_search_playbook", "atms_search_compliance",
                 "atms_metrics"}
    assert expected <= names
    for t in tools:
        assert "name" in t and "description" in t and "inputSchema" in t


def test_call_atms_metrics_returns_kb_inventory():
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "atms_metrics", "arguments": {}}},
    ])
    content = rs[1]["result"]["content"]
    assert content[0]["type"] == "text"
    payload = json.loads(content[0]["text"])
    assert payload["playbooks"] >= 120
    assert payload["compliance_controls"] >= 110
    assert payload["arch_rules"] >= 25
    assert "SOC2" in payload["frameworks"]
    assert "OWASP_MASVS" in payload["frameworks"]


def test_call_atms_analyze_with_minimal_yaml():
    yaml_body = textwrap.dedent("""\
        name: mcp-test
        components:
          - id: u
            name: User
            type: user
          - id: llm
            name: LLM
            type: llm_inference
    """)
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "atms_analyze",
                    "arguments": {"yaml": yaml_body}}},
    ])
    assert "result" in rs[1], rs[1]
    content = rs[1]["result"]["content"]
    # First block: human-readable summary.
    assert "Threats:" in content[0]["text"]
    # Second block: model JSON.
    blob = content[1]["text"]
    assert blob.startswith("```json")
    model = json.loads(blob.strip("`\n").lstrip("json\n"))
    assert "threats" in model
    assert len(model["threats"]) > 0


def test_call_atms_search_playbook():
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "atms_search_playbook",
                    "arguments": {"component_type": "llm_inference"}}},
    ])
    text = rs[1]["result"]["content"][0]["text"]
    # YAML body should contain threats: list.
    assert "threats" in text.lower() or "component_type" in text.lower()


def test_call_atms_search_compliance_with_framework_filter():
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "atms_search_compliance",
                    "arguments": {"framework": "SOC2", "limit": 5}}},
    ])
    text = rs[1]["result"]["content"][0]["text"]
    assert "SOC2" in text


def test_unknown_tool_returns_invalid_params():
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "atms_no_such_tool", "arguments": {}}},
    ])
    assert "error" in rs[1]
    assert rs[1]["error"]["code"] == -32602  # INVALID_PARAMS


def test_unknown_method_returns_method_not_found():
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "no_such_method"},
    ])
    assert "error" in rs[1]
    assert rs[1]["error"]["code"] == -32601  # METHOD_NOT_FOUND


def test_initialized_notification_does_not_respond():
    """Per JSON-RPC 2.0, notifications (no `id`) must not get responses."""
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ])
    assert len(rs) == 1  # only the `initialize` response


def test_shutdown_method_exits_loop():
    rs = _drive([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "shutdown"},
        # The server should exit before processing this:
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
    ])
    # 2 responses, not 3.
    assert len(rs) == 2
    assert rs[1]["result"] == {}


@pytest.mark.hibernated  # Phase 4


def test_subprocess_smoke():
    """Spawn the actual `atms mcp` subprocess and exchange one
    initialize round-trip. Verifies the CLI wires up correctly."""
    import subprocess
    proc = subprocess.Popen(
        [sys.executable, "-m", "atms.cli", "mcp"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": str(
            __import__("pathlib").Path(__file__).resolve().parents[1] / "src"
        )},
    )
    try:
        msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2024-11-05"}}) + "\n"
        proc.stdin.write(msg)
        proc.stdin.flush()
        # Wait briefly for the response.
        line = proc.stdout.readline()
        proc.stdin.close()
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert line, "no response from subprocess"
    response = json.loads(line)
    assert response["result"]["serverInfo"]["name"] == "atms"


# ───────────────────────────────────────────────────────────────────
# Phase A — coverage hotspot lift for src/atms/mcp_server.py.
# Targets the previously-uncovered atms_scan_text format dispatch
# (lines 231-329 = ~50% of the module body), all error paths, plus
# the serve_stdio non-tool-call branches (parse errors / ping /
# unknown method). Was 47.4% before Phase A; floor is 80%.
# ───────────────────────────────────────────────────────────────────

# Reusable JSON-RPC initialize prelude.
_INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05"}}


def _call_tool(name: str, arguments: dict, req_id: int = 2) -> dict:
    """Drive one tools/call round-trip and return the response."""
    rs = _drive([
        _INIT,
        {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
         "params": {"name": name, "arguments": arguments}},
    ])
    return rs[1]


# ─── atms_analyze error paths ─────────────────────────────────────
def test_analyze_missing_yaml_returns_invalid_params():
    r = _call_tool("atms_analyze", {})
    assert "error" in r
    assert r["error"]["code"] == -32602
    assert "yaml" in r["error"]["message"].lower()


def test_analyze_non_string_yaml_returns_invalid_params():
    r = _call_tool("atms_analyze", {"yaml": 42})
    assert "error" in r
    assert r["error"]["code"] == -32602


def test_analyze_blank_yaml_returns_invalid_params():
    r = _call_tool("atms_analyze", {"yaml": "   \n  "})
    assert "error" in r
    assert r["error"]["code"] == -32602


def test_analyze_yaml_not_a_mapping_returns_invalid_params():
    r = _call_tool("atms_analyze", {"yaml": "- foo\n- bar\n"})
    assert "error" in r
    # YAML parses but root is a list → ValueError → INVALID_PARAMS
    assert r["error"]["code"] == -32602


# ─── atms_scan_text: every format dispatch (the big coverage gap) ───
def test_scan_text_drawio_auto_detect():
    """Phase A regression: previously the drawio dispatch tried to
    import a non-existent `_drawio_text_to_system` symbol and ALWAYS
    failed. Now it writes to a temp file and parses successfully."""
    drawio = """<mxfile><diagram><mxGraphModel><root>
<mxCell id="0"/><mxCell id="1" parent="0"/>
<mxCell id="u" value="User" style="shape=actor" vertex="1" parent="1"/>
<mxCell id="api" value="API" style="shape=mxgraph.aws4.api_gateway" vertex="1" parent="1"/>
<mxCell id="bedrock" value="Bedrock" style="shape=mxgraph.aws4.bedrock" vertex="1" parent="1"/>
<mxCell id="e1" edge="1" source="u" target="api" parent="1"/>
<mxCell id="e2" edge="1" source="api" target="bedrock" parent="1"/>
</root></mxGraphModel></diagram></mxfile>"""
    r = _call_tool("atms_scan_text", {"content": drawio})
    assert "result" in r, r
    text = r["result"]["content"][0]["text"]
    assert "detected format: drawio" in text
    assert "Components:" in text
    assert "Threats:" in text


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_text_mermaid_auto_detect():
    mermaid = """%% Phase A mermaid test
flowchart LR
  user((Customer)) --> api[API Gateway]
  api --> llm[Anthropic Claude API]
"""
    r = _call_tool("atms_scan_text", {"content": mermaid})
    assert "result" in r, r
    assert "detected format: mermaid" in r["result"]["content"][0]["text"]


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_text_bicep_auto_detect():
    bicep = """{
  "Microsoft.KeyVault/vaults": "kv1",
  "$schema": "https://schema.management.azure.com/2019-04-01/deploymentTemplate.json",
  "resources": [{
    "type": "Microsoft.KeyVault/vaults",
    "name": "kv1",
    "apiVersion": "2022-07-01"
  }]
}"""
    r = _call_tool("atms_scan_text", {"content": bicep})
    assert "result" in r, r
    assert "detected format: bicep" in r["result"]["content"][0]["text"]


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_text_pulumi_auto_detect():
    pulumi = """name: stack
runtime: yaml
resources:
  bucket:
    type: aws:s3:Bucket
  fn:
    type: aws:lambda:Function
"""
    r = _call_tool("atms_scan_text", {"content": pulumi})
    assert "result" in r, r
    assert "detected format: pulumi" in r["result"]["content"][0]["text"]


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_text_cloudformation_auto_detect():
    cfn = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Lam:
    Type: AWS::Lambda::Function
    Properties: {}
  Bucket:
    Type: AWS::S3::Bucket
    Properties: {}
"""
    r = _call_tool("atms_scan_text", {"content": cfn})
    assert "result" in r, r
    assert "detected format: cloudformation" in r["result"]["content"][0]["text"]


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_text_kubernetes_auto_detect():
    k8s = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
spec:
  template:
    metadata:
      labels: { app: web }
    spec:
      containers:
        - name: web
          image: nginx:1.27
"""
    r = _call_tool("atms_scan_text", {"content": k8s})
    assert "result" in r, r
    assert "detected format: kubernetes" in r["result"]["content"][0]["text"]


def test_scan_text_system_yaml_fallback():
    sy = """name: t
components:
  - id: u
    name: User
    type: user
  - id: llm
    name: LLM
    type: llm_inference
"""
    r = _call_tool("atms_scan_text", {"content": sy})
    assert "result" in r, r
    assert "detected format: system-yaml" in r["result"]["content"][0]["text"]


@pytest.mark.hibernated  # v0.18.71 Hibernation Phase 4


def test_scan_text_explicit_format_override():
    """Caller sets format explicitly — auto-detect bypassed."""
    pulumi = "name: stk\nruntime: yaml\nresources:\n  b:\n    type: aws:s3:Bucket\n"
    r = _call_tool("atms_scan_text",
                    {"content": pulumi, "format": "pulumi"})
    assert "result" in r, r
    assert "detected format: pulumi" in r["result"]["content"][0]["text"]


# ─── atms_scan_text error paths ────────────────────────────────────
def test_scan_text_missing_content_invalid_params():
    r = _call_tool("atms_scan_text", {})
    assert "error" in r
    assert r["error"]["code"] == -32602


def test_scan_text_blank_content_invalid_params():
    r = _call_tool("atms_scan_text", {"content": "   "})
    assert "error" in r
    assert r["error"]["code"] == -32602


def test_scan_text_malformed_content_surfaces_ingest_error():
    """Unparseable YAML routed to system-yaml fallback → ingest failure."""
    r = _call_tool("atms_scan_text",
                    {"content": "not: : valid yaml: ["})
    assert "error" in r
    assert r["error"]["code"] == -32602
    assert "ingest failed" in r["error"]["message"].lower()


# ─── atms_search_playbook error paths ──────────────────────────────
def test_search_playbook_missing_component_type():
    r = _call_tool("atms_search_playbook", {})
    assert "error" in r
    assert r["error"]["code"] == -32602
    assert "component_type" in r["error"]["message"]


def test_search_playbook_unknown_component_type():
    """An unknown type returns the 'no playbook' helper text, not an error."""
    r = _call_tool("atms_search_playbook",
                    {"component_type": "no_such_componenttype"})
    assert "result" in r
    text = r["result"]["content"][0]["text"]
    assert "no playbook" in text.lower() or "no_such_componenttype" in text


# ─── atms_search_compliance — branch coverage ──────────────────────
def test_search_compliance_no_filters_returns_recent():
    """No framework + no query: returns the first <limit> rows."""
    r = _call_tool("atms_search_compliance", {"limit": 3})
    assert "result" in r
    text = r["result"]["content"][0]["text"]
    assert "Compliance — 3 match" in text


def test_search_compliance_query_only():
    r = _call_tool("atms_search_compliance",
                    {"query": "encryption", "limit": 5})
    assert "result" in r
    text = r["result"]["content"][0]["text"]
    assert "encryption" in text.lower() or "Compliance" in text


def test_search_compliance_unrealistic_limit_is_capped():
    """limit > 100 is silently clamped to 100."""
    r = _call_tool("atms_search_compliance", {"limit": 1000})
    assert "result" in r
    text = r["result"]["content"][0]["text"]
    # Phase A: KB has 117 controls; limit clamped to 100, so we get
    # exactly 100 lines OR all 117 if the cap isn't enforced.
    # The cap-enforcement assertion: the rendered count is ≤100.
    import re
    m = re.search(r"(\d+) match", text)
    assert m and int(m.group(1)) <= 100


# ─── serve_stdio non-tool-call branches ────────────────────────────
def test_parse_error_in_stdin_returns_error_response():
    """Garbled JSON in stdin must yield a JSON-RPC parse-error response,
    not a crash."""
    # We send raw text (not JSON-encoded) by writing it directly to
    # the mock stdin. _drive sends list[dict] only, so use the lower
    # API.
    from atms import mcp_server
    out_buf = io.StringIO()
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO("{not valid json}\n")
    sys.stdout = out_buf
    try:
        mcp_server.serve_stdio()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    out = out_buf.getvalue().strip()
    assert out, "should have produced a parse-error response"
    msg = json.loads(out)
    assert msg["error"]["code"] == -32700  # PARSE_ERROR


def test_request_not_a_json_object_returns_invalid_request():
    """JSON parses but root isn't an object (e.g. a bare list)."""
    from atms import mcp_server
    out_buf = io.StringIO()
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO('["not", "an", "object"]\n')
    sys.stdout = out_buf
    try:
        mcp_server.serve_stdio()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    out = out_buf.getvalue().strip()
    msg = json.loads(out)
    assert msg["error"]["code"] == -32600  # INVALID_REQUEST


def test_ping_method():
    rs = _drive([_INIT, {"jsonrpc": "2.0", "id": 2, "method": "ping"}])
    assert rs[1]["result"] == {}


def test_tools_call_missing_name_returns_invalid_params():
    rs = _drive([_INIT,
                 {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {}}])
    assert rs[1]["error"]["code"] == -32602
    assert "name" in rs[1]["error"]["message"]


def test_empty_lines_ignored_in_stdin():
    """Blank lines between requests must not crash the parser."""
    from atms import mcp_server
    out_buf = io.StringIO()
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO("\n\n" + json.dumps(_INIT) + "\n\n\n")
    sys.stdout = out_buf
    try:
        mcp_server.serve_stdio()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    # Should produce exactly one initialize response.
    lines = [l for l in out_buf.getvalue().splitlines() if l.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["result"]["serverInfo"]["name"] == "atms"
