# ATMS CLI reference

28 commands. The reference is `atms <cmd> --help`; this doc adds
the why + recipe.

## Top three you'll use

### `atms scan <file>` — auto-detect + analyse + write reports

```powershell
atms scan samples\rag_system.yaml --out output
atms scan diagram.drawio --out output
atms scan Pulumi.yaml --format md --format html
atms scan infra.bicep --format all
```

Detects the format from suffix (`.drawio`, `.mmd`, `.bicep`, `.tm7`,
`.tf`, `.otm`) or content-sniff (CFN vs K8s vs system-YAML inside
`.yaml`). Calls the right ingester, runs the full analysis pipeline,
writes ~14 export artefacts to `--out`.

### `atms web` — run the FastAPI server

```powershell
atms web                          # http://127.0.0.1:8000
atms web --host 0.0.0.0 --port 8080
```

In dev mode the running tree imports work via `PYTHONPATH=src`;
PyInstaller frozen builds embed everything.

### `atms watch <file>` — re-analyse on every file save

```powershell
atms watch samples\rag_system.yaml --interval 2
```

Polls the YAML for mtime changes; re-runs `analyze()`; prints the
threat-count + severity delta. Edit-save-see-impact in seconds.

## Ingest helpers (output System YAML for hand-editing)

Each writes a System YAML to stdout (or `--out file.yaml`) without
running analyse unless you add `--analyze`. Use when you want to
review the converted topology before threat modelling.

```powershell
atms ingest <diagram.drawio>     # auto-detect drawio/mermaid/vsdx/md
atms ingest-cfn <stack.yaml>
atms ingest-k8s <manifest.yaml>
atms ingest-azure <infra.bicep | template.json>
atms ingest-pulumi <Pulumi.yaml>
atms ingest-iac <main.tf | docker-compose.yml>
atms ingest-otm <model.otm>
atms ingest-tm7 <model.tm7>
```

Each accepts:

- `<path>` — file or directory (per ingester)
- `--out path.yaml` — write to file instead of stdout
- `--name "My System"` — override the System.name field
- `--analyze` — run analyse immediately after conversion

## Evidence-driven analysis

Layer real-world findings (scanner output, red-team chains) onto
the threat model so threats flip from `hypothetical` → `likely` /
`observed` / `exploited`.

```powershell
atms ingest-evidence system.yaml scan.nessus --format nessus
atms ingest-evidence system.yaml findings.sarif --format sarif
atms ingest-evidence system.yaml stix.json --format stix
atms ingest-evidence system.yaml csv-export.csv --format csv

atms ingest-redteam system.yaml caldera-ops.yaml --format caldera
atms ingest-redteam system.yaml atomic-results.json --format atomic
atms ingest-redteam system.yaml safebreach-report.csv --format bas
```

Matching is by CPE / pURL / hostname / IP / vendor+product+version
across the bundled 274-entry device catalog.

## Threat-intel feeds (offline-first; opt-in refresh)

```powershell
atms refresh-feeds                # pulls CISA KEV + EPSS top-N snapshot
atms cve-lookup CVE-2024-12345    # NVD + OSV fallback, 10s timeout
```

ATMS ships a curated snapshot of KEV + EPSS at install time; the
refresh is optional and never auto-runs.

## CI integration

```powershell
atms ci system.yaml --max-severity high
atms ci system.yaml --methodology pasta --strict
```

Exits non-zero on any threat above `--max-severity`, after which
the CI pipeline can fail the build. Pair with `--prior-run` to
suppress threats already triaged in a previous analysis.

## Run comparison

```powershell
atms diff old-run.json new-run.json --format markdown
```

Two JSON dumps from prior `atms analyze --format json` runs. Lists
added / removed / severity-changed threats. The web `/diff` route
renders the same data in HTML.

## MCP server (for Claude Code)

```powershell
atms mcp
```

Reads JSON-RPC 2.0 from stdin, writes responses to stdout. Five
tools: `atms_analyze`, `atms_scan_text`, `atms_search_playbook`,
`atms_search_compliance`, `atms_metrics`. Wire-up + example
prompts in `docs/MCP.md`.

## Browsing the bundled knowledge base

```powershell
atms compliance                                  # browse all 117 controls
atms compliance --framework SOC2
atms compliance --framework NIST_800_53 --query "encryption"
atms devices --type llm_inference --query Claude
atms kb-search "prompt injection"
atms list-playbooks --type api_gateway
```

## Init + validate

```powershell
atms init --name my-system --template rag --out my-system.yaml
atms validate my-system.yaml --strict
```

`init` scaffolds a starter YAML from templates (`rag`, `agent`,
`pure-it`, etc.). `validate` confirms the System schema is
honoured and that auto-classifier confidence is above thresholds.

## Maintenance

```powershell
atms selftest         # exercise every bundled sample; assert invariants
atms version          # print the running version
```

## Format choices (every report-emitting command)

`md` · `html` · `stix` · `navigator` · `csv` · `json` · `sarif` ·
`otm` · `exec` · `compliance` · `jira` · `roadmap` · `sbom` · `all`

Use `--format all` to emit every artefact in one shot. The web
`/report/{run_id}` page surfaces them as download buttons.
