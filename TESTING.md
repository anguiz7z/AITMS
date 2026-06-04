# Tester onboarding — your first 30 minutes with ATMS

You've got the installer (`ATMS-Setup-X.Y.Z.exe`) on a USB stick or via
the GitHub release page. This guide walks you through what to verify in
the first 30 minutes so the maintainer hears about real problems
instead of installation friction.

## 0. Install (~2 minutes)

Double-click `ATMS-Setup-X.Y.Z.exe`. The wizard installs to
`%LOCALAPPDATA%\Programs\ATMS` — no admin rights, no internet, no Python
needed. Two tick-boxes you may want:

- **Add `atms` to PATH** — recommended for CLI use.
- **Create a desktop shortcut** — optional.

Verify:

```powershell
atms version           # should print: ATMS v0.14.8 (or whatever's installed)
atms selftest          # should run all 10 bundled samples; expected output is 10x "OK"
```

If `atms` isn't on PATH, the installer dropped a Start Menu shortcut
**ATMS Command Prompt** that opens a shell in the install dir.

## 1. The web UI (~5 minutes)

```powershell
atms web
```

Opens a local web server on `http://127.0.0.1:8765`. The browser tab
this opens has 14 routes. The ones to actually try:

- **`/`** — paste any sample YAML (or write your own), click `Analyze`.
  Reports render inline with download buttons for every output format.
- **`/editor`** — drag-and-drop dataflow editor. Add a component, draw
  an edge, save back to YAML.
- **`/samples`** — jump straight to one of the 10 bundled samples.
- **`/iac`** — drop a `docker-compose.yml` or a Terraform `.tf` file
  in. ATMS converts it to a System YAML you can review before analysis.
- **`/redteam`** — drop a Caldera operations export, an Atomic Red Team
  log, or an AttackIQ / Cymulate / SafeBreach BAS CSV. Threats matched
  against the artefact get flipped to `evidence_status: exploited`.
- **`/evidence`** — same idea for VAPT findings (Nessus / SARIF / STIX
  / generic CSV). KEV-tagged CVEs force `severity: critical`.

Stop the server with `Ctrl-C` in the terminal.

## 2. Try it on a real system you know (~10 minutes)

Pick a system you understand — a recent project, a SaaS your team
runs, a hackathon prototype — and describe it in YAML. Easiest path:

1. Copy `samples\rag_system.yaml` to a new file.
2. Edit names, types, and dataflows to reflect your system.
3. `atms analyze my_system.yaml --out output`.
4. Open `output\my_system.md` (Markdown) or `.html` (browser-friendly).

Things to look for:

- Are the threats reasonable? (Some will be over-cautious; that's by
  design. Real-world risk tuning is a manual step.)
- Are any threats obviously wrong? (e.g. a `database` component flagged
  for `prompt-injection` would be a bug.)
- Are the mitigations specific enough to act on?
- Does the Mermaid diagram render cleanly?
- Does the SARIF output (`.sarif`) load in your IDE? (VS Code SARIF
  Viewer extension reads it directly.)

## 3. CI integration (~5 minutes)

If you use GitHub Actions or GitLab CI:

```yaml
# .github/workflows/threat-model.yml (example — paste into your repo)
- name: Threat-model the platform
  run: |
    atms ci system.yaml --max-severity high --sarif-out report.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

`atms ci` exits non-zero if any threat is at or above
`--max-severity`. The SARIF feeds GitHub's code-scanning UI.

## 4. Where to file feedback

The thing the maintainer most wants to hear:

- **"This finding is wrong because…"** — name a specific threat row.
- **"This was confusing"** — name the page / output / CLI message.
- **"I expected X and got Y"** — name what you tried.

File at:
- GitHub Issues: <https://github.com/anguiz7z/AITMS/issues>
- For security-relevant findings (path traversal, XSS, SSRF in the web
  UI, anything that lets a crafted input file harm the user): see
  [SECURITY.md](SECURITY.md) — there's a private-disclosure path.

## 5. What this tool is NOT

- **Not a replacement for a human security review.** ATMS produces
  decision-support output. Hand the report to a human security
  professional before treating it as actionable.
- **Not network-aware.** ATMS analyses what you describe, not what's
  actually deployed. Two opt-in CLI commands (`atms refresh-feeds`,
  `atms cve-lookup`) are the only outbound network egress points.
- **Not multi-user.** Local-first, no auth. If you want to share, run
  it behind your team's existing auth proxy or write a wrapper.

## 6. Known surface I'd appreciate stress-testing

Things v0.14 changed that haven't seen real-tester miles:

- `atms ingest-iac` against a large, real Terraform repo (the parser
  caps cumulative input at 50 MB; ping me if you hit that).
- `atms ingest-redteam` with hand-rolled Caldera fixtures (we just
  shipped flat-shape `link.technique_id` support in v0.14.6).
- Multi-tenant LLM platform sample (`samples\multi_tenant_llm_platform.yaml`)
  — does the threat output match what your platform team would expect?
- The web `/editor` for systems with 30+ components — does it stay
  responsive?

Thanks for testing. — the maintainer
