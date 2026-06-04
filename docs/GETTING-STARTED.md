# ATMS — getting started in 5 minutes

> AI Threat Modeling Studio. Drop in a diagram or YAML; get a
> threat-model report mapped to OWASP LLM / ATLAS / NIST AI RMF /
> 15 compliance frameworks.

## Install (one of)

```powershell
# Windows: portable installer (no Python required)
Start-Process dist\ATMS-Setup-1.0.6.exe -ArgumentList "/VERYSILENT","/CURRENTUSER" -Wait

# Or — pip install from a clone (requires Python 3.11+)
git clone https://github.com/anguiz7z/AITMS.git
cd AITMS
pip install -e ".[dev]"
```

Add the install dir to PATH so `atms` works directly (one-time):

```powershell
$p = "$env:LOCALAPPDATA\Programs\ATMS"
[Environment]::SetEnvironmentVariable("Path",
  "$([Environment]::GetEnvironmentVariable('Path','User'));$p",
  'User')
# Open a fresh terminal and `atms version` should work.
```

## Sanity check (30 seconds)

```powershell
atms version              # → ATMS v0.18.50
atms selftest             # → runs every bundled sample, asserts invariants
```

You should see every sample analyse cleanly with threat / severity rollups.

## Three things to try (90 seconds each)

### 1. Spin up the web UI

```powershell
atms web                  # listens on http://127.0.0.1:8000
```

Open http://127.0.0.1:8000. Worth clicking through:

- `/` — paste any System YAML or upload a diagram.
- `/samples` — one-click "Analyze" on every bundled sample.
- `/capabilities` — live KB inventory (proves the bundle didn't drift).
- `/architecture` — interactive map of how ATMS works internally.

### 2. Scan a real-world threat model

```powershell
# The OWASP Threat Dragon demo (their canonical hand-authored example):
atms scan samples\corpus\owasp_threat_dragon_demo.yaml --out output --format all

# OR — the Kubernetes Guestbook reference architecture:
atms scan samples\corpus\k8s_guestbook.yaml --out output --format all
```

Both produce ~10 artefacts under `output\`: HTML report, exec summary,
compliance matrix, SBOM (CycloneDX), JIRA-importable CSV, mitigation
roadmap, STIX 2.1, etc. `docs/BENCHMARKS.md` has the comparison numbers
versus the hand-authored originals.

### 3. Wire ATMS into Claude Code (MCP)

Add to `.mcp.json` (workspace) or `~/.claude/mcp.json` (global):

```json
{
  "mcpServers": {
    "atms": {
      "command": "C:\\Users\\<you>\\AppData\\Local\\Programs\\ATMS\\atms.exe",
      "args": ["mcp"]
    }
  }
}
```

Restart Claude Code. In your next conversation:

> Use `atms_analyze` on this YAML: …
>
> What's the threat playbook for an `llm_inference` component?
>
> Search NIST 800-53 controls for "encryption at rest".

Five MCP tools surface; details in `docs/MCP.md`.

## What ATMS does (one paragraph)

You feed it a system description — System YAML, draw.io diagram,
Mermaid flowchart, Visio file, Terraform / CloudFormation / Bicep /
ARM / Pulumi / Kubernetes manifest, OTM JSON, or a `.tm7` Microsoft
Threat Modeling Tool file. It auto-classifies components against a
121-type catalogue, fires per-component threat playbooks, runs 25
architectural-pattern rules (cross-walked to OWASP LLM Top 10,
MITRE ATLAS, EU AI Act, NIST 800-53, SOC 2, ISO 27001, OWASP MASVS,
SAMM…), computes multi-step attack paths with NetworkX, ranks
mitigations against MITRE D3FEND + AWS SRA / Azure LZA reference
architectures, prices the residual risk via FAIR-lite ALE, and
hands you ~14 export formats from a one-page exec summary to a
CycloneDX 1.5 SBOM for procurement.

## Where to go next

- `docs/CLI.md` — every CLI command with example invocations
- `docs/MCP.md` — full MCP tool reference + protocol details
- `docs/ARCHITECTURE.mmd` — comprehensive mermaid diagram of every subsystem
- `docs/BENCHMARKS.md` — head-to-head vs OWASP Threat Dragon
- `docs/PERFORMANCE.md` — cold-start / KB cache / memory budget
- `docs/COVERAGE.md` — test-suite coverage report
- `docs/CONTRIBUTING.md` — dev setup, test conventions, drift guard
- `docs/ROADMAP.md` — 6-month consolidation plan + cross-cutting principles
- `README.md` — capabilities overview + real-world benchmark teaser
