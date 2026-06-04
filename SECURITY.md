# Security Policy

ATMS is a local-first workflow tool. The shipped product has zero outbound
network calls in its default flow (see [AI_DEPENDENCIES.md](AI_DEPENDENCIES.md)),
no AI/LLM SDKs bundled in the .exe, and the deterministic core is built
to be auditable end-to-end.

That doesn't make it bug-free. If you find a security issue, please tell us.

## Reporting a vulnerability

**Do not file a public GitHub issue for security bugs.**

Please report privately through GitHub's **private security advisories**:
go to the repository's **Security** tab and click **"Report a
vulnerability"**, or use the direct link:
<https://github.com/anguiz7z/AITMS/security/advisories/new>.

This keeps the report confidential between you and the maintainer until a
fix is ready, and lets us coordinate disclosure and credit through the
same thread.

When you report, please include:

1. Affected version(s) — output of `atms version` is enough.
2. Reproduction steps. A minimal `system.yaml` + the exact CLI command
   or web-UI action is ideal.
3. Expected vs. observed behaviour. If it's a write/exfil/RCE, say so
   plainly.
4. Whether the issue is in the deterministic core, the bundled web UI,
   the .exe, or the optional opt-in vision module.

We aim to acknowledge within **5 business days** and ship a patched
release within **30 days** for HIGH/CRITICAL findings.

## In-scope vulnerabilities

The bar is "could a careless or malicious input file harm the user
running ATMS, or could a careless deployment of the web UI expose data
unintentionally?"

Examples that are clearly in scope:

- **Code execution** in the CLI, web UI, or any frozen-build entry point
  triggered by a crafted system YAML, evidence file, OTM document,
  Visio diagram, Terraform project, docker-compose file, or
  red-team artefact.
- **Path traversal** in any web-UI route or CLI argument.
- **HTML / DOM XSS** in rendered reports or in the editor.
- **SSRF** via any URL input or feed-refresh path.
- **XML-external-entity** processing in `vsdx` / Nessus / SARIF parsers
  (we use `defusedxml` — if you find a bypass, that's a real bug).
- **Any way to make the deterministic core do an outbound HTTP call**
  outside `atms refresh-feeds` and `atms cve-lookup`.
- **Dependency confusion / supply chain** issues in the published
  wheel or the .exe.

## Out of scope

- Theoretical attacks requiring a malicious Python package already
  installed on the user's machine.
- "The threat model says X is a threat" — that's the *output*; we
  don't ship a fixed list of acceptable risks.
- Issues in the optional `vision/` module that depend on the user
  having explicitly installed `anthropic` and set `ANTHROPIC_API_KEY`.
- Findings in third-party tools we link to from reports
  (https://attack.mitre.org/, etc.).

## Security-critical contracts

Documented in [THREAT_MODEL.md](THREAT_MODEL.md). The current load-bearing
ones are:

| Contract | Where | Rationale |
|---|---|---|
| `yaml.safe_load` only | every YAML read | Block YAML deserialisation RCE (TM_001). |
| `defusedxml.ElementTree` | Nessus + .vsdx parsers | Block XXE / billion-laughs (TM_011). |
| HTML escape on every user value | report templates + web responses | Block stored XSS in rendered reports (TM_003). |
| Mermaid `securityLevel: 'strict'` | report.html.j2 + atms-mermaid.js | Defeat HTML-in-label injection (TM_012). |
| DOM-API editor builds (no `innerHTML`) | static/atms-editor.js | Block DOM XSS in the dataflow editor (TM_013). |
| Methodology allow-list on `/redteam/ingest` | web.py | Reject arbitrary methodology strings (TM_014). |
| `excludes` list in atms.spec | PyInstaller build | Enforce the AI-free contract for the .exe (TM_015). |

If a PR weakens any of those contracts, the reviewer should treat it
as a security regression by default.

## Disclosure

We coordinate disclosure with the reporter. The reporter is credited
in the CHANGELOG (or anonymously by request). We do not pay bounties.
