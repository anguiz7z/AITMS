# ATMS MCP server — Claude Code integration

ATMS exposes itself as a [Model Context Protocol](https://modelcontextprotocol.io)
server so Claude Code (and any MCP client) can query the bundled
knowledge base and run threat analyses **without** invoking the
CLI or hitting the REST API.

## Wire-up

Add the following to your Claude Code `.mcp.json` (workspace) or
`~/.claude/mcp.json` (global):

```json
{
  "mcpServers": {
    "atms": {
      "command": "atms",
      "args": ["mcp"]
    }
  }
}
```

If you're running the portable .exe instead of a pip-installed
`atms`, swap in the absolute path:

```json
{
  "mcpServers": {
    "atms": {
      "command": "C:\\Users\\you\\AppData\\Local\\Programs\\ATMS\\atms.exe",
      "args": ["mcp"]
    }
  }
}
```

Restart Claude Code. The next conversation has 5 new tools available.

## Tools exposed

| Tool                     | What it does |
|--------------------------|--------------|
| `atms_analyze`           | POST a System YAML, get the full ThreatModel JSON back (threats, attack paths, mitigations, framework coverage, ALE). Honours `methodology` (stride-ai / linddun / pasta) and `allow_pure_it` flags. |
| `atms_scan_text`         | Pass an inline diagram or IaC artefact (Bicep, Pulumi YAML, Mermaid, draw.io XML, CloudFormation, Kubernetes manifest, TM7, OTM, System YAML). Format is auto-detected from a content sniff. |
| `atms_search_playbook`   | Fetch the threat playbook for a given ComponentType (e.g. `llm_inference`, `database`, `api_gateway`). |
| `atms_search_compliance` | Search the 117-control compliance library across 15 frameworks (NIST 800-53, ISO 27001, SOC 2, EU AI Act, GDPR, HIPAA, PCI DSS, …). Filter by framework + substring query. |
| `atms_metrics`           | Snapshot of the bundled KB (playbook count, framework count, ATLAS technique count, etc.). |

## Example prompts

> Use `atms_analyze` on this system YAML:
>
> ```yaml
> name: my-rag
> components:
>   - id: u
>     name: User
>     type: user
>   - id: llm
>     name: LLM
>     type: llm_inference
> ```

> What's the threat playbook for an `api_gateway` component?

> Search NIST 800-53 controls for "encryption at rest".

> Show me the current ATMS KB inventory.

## Protocol details

- JSON-RPC 2.0 over stdio (line-delimited).
- Protocol version: `2024-11-05`.
- No new runtime dependency — pure Python stdlib.
- The server speaks `initialize`, `tools/list`, `tools/call`,
  `notifications/initialized`, `ping`, and `shutdown`.

## Testing the server directly

```bash
# Spawn the server and pipe an initialize handshake.
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
  | atms mcp
```

## Security model

The MCP server runs as a child process of the MCP client (Claude
Code), reading stdin and writing stdout. No network listener is
opened. Threat analyses operate on the YAML the client passes in;
no filesystem reads beyond the bundled KB (which is read-only).
