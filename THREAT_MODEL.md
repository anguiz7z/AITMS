# THREAT_MODEL.md — ATMS modelling itself

ATMS is a tool used by security professionals. Its output is read and trusted. So we threat-model the tool itself, eat our own dog food, and document the result here.

## Scope

- The ATMS Python package (`src/atms/`).
- The bundled knowledge base (`kb/`).
- The local web UI (`atms web`, single-process Uvicorn).
- Sample inputs (`samples/`).
- The optional vision module (`vision/analyzer.py`).

Out of scope: production hosting (you bring your own), integrations beyond local CLI/web, third-party LLM providers' security.

## Assumptions

- Single user runs ATMS on their own machine; `127.0.0.1` only by default.
- The user trusts the knowledge base data committed to the repo (they can audit it).
- The user reviews vision-generated YAML before running analysis.

## Components

- **CLI** (`cli.py`) — `click`-based, single-process, exits after the command finishes.
- **Web UI** (`web.py`) — FastAPI + Uvicorn. In-memory cache of recent runs.
- **Engines** — pure-Python deterministic logic.
- **Reporting** — Jinja2 templates rendering Markdown/HTML/STIX/CSV.
- **Vision** — opt-in, only loads `anthropic` if both the package and the API key are present.
- **KB** — bundled YAML files, loaded into memory once.

## Threats and mitigations

### TM_001 — Malicious system YAML triggers code execution

- **Vector.** User loads a YAML from an untrusted source. Could embed Python objects via unsafe loaders.
- **Severity.** High if exploitable.
- **Status.** **Mitigated.** All YAML loading uses `yaml.safe_load`. We never call `yaml.load` or `yaml.unsafe_load` anywhere.
- **Test.** Covered by the engines tests; `safe_load` is the only loader imported in `kb.py` and `cli.py`.

### TM_002 — Web UI path traversal via `?sample=`

- **Vector.** `GET /?sample=../../etc/passwd` reads files outside `samples/`.
- **Severity.** High.
- **Status.** **Mitigated.** `web.py` checks `Path(sample).name == sample`, requires `candidate.is_file()`, and verifies `candidate.resolve().parent == _SAMPLES_DIR.resolve()`. Error message does not echo user input back. Test `test_load_sample_path_traversal_blocked` enforces this.

### TM_003 — XSS via user-supplied YAML reflected in web UI

- **Vector.** YAML body contains `<script>` tags; rendered as part of the report page.
- **Severity.** Medium (local-only by default).
- **Status.** **Mitigated.** Jinja2 autoescape is on for all `web/*.html` templates. No template uses `|safe` on user-supplied input.

### TM_004 — Resource exhaustion via huge YAML / huge component count

- **Vector.** User uploads a YAML with 10K components → quadratic-ish work in attack-path search.
- **Severity.** Low (local single-user).
- **Status.** **Partially mitigated.** Attack-path DFS is bounded by `max_path_length=5` and `top_n=10`. No hard cap on component count. **Recommendation:** for shared deployments add per-request size limits in front of FastAPI.

### TM_005 — Malicious playbook in fork / supply chain

- **Vector.** Someone forks the repo, adds a playbook with a misleading mitigation that suggests `chmod 777 /`.
- **Severity.** Medium.
- **Status.** **Documented.** Playbooks are static YAML — no code. They cannot execute anything. They can mislead a reviewer with bad advice. Mitigation: only run analyses with playbooks from trusted forks; review playbook diffs.

### TM_006 — Anthropic API key leak via the optional vision module

- **Vector.** User pastes the wrong key, includes it in a stack trace, or commits it.
- **Severity.** High (financial).
- **Status.** **Mitigated.** Key is read from `ANTHROPIC_API_KEY` env var only. Never logged. Vision module is opt-in.
- **Recommendation.** Add a pre-commit hook (gitleaks) before contributing.

### TM_007 — STIX/Navigator export contains no provenance

- **Vector.** A reviewer downstream can't tell which ATMS version + which input produced the bundle.
- **Severity.** Low.
- **Status.** **Mitigated.** STIX and Navigator JSON include `tool_version` / `description` with the timestamp. Markdown and HTML reports include the same.

### TM_008 — Misinformation in KB (wrong technique ID, wrong mapping)

- **Vector.** A typo in `kb/mitre_atlas/techniques.yaml` causes the engine to emit a non-existent `AML.T1234`. Reviewer trusts it.
- **Severity.** Medium.
- **Status.** **Partially mitigated.** Tests check that key well-known IDs are present. Spot-check the KB before each release. Future: schema-validate KB entries against an upstream STIX bundle in CI.

### TM_009 — Vision-generated YAML is hallucinated

- **Vector.** Vision model invents components or misclassifies types. User runs analyze without reviewing.
- **Severity.** Medium (decision-support, not authoritative).
- **Status.** **Documented.** README and USAGE explicitly tell users to review vision output. The vision prompt is restrictive (only listed types allowed). The CLI does not chain vision → analyze automatically — the user must save the YAML and re-invoke.

### TM_010 — Web UI exposed to LAN/internet without auth

- **Vector.** User runs `atms web --host 0.0.0.0` and exposes the box. ATMS has no auth.
- **Severity.** High in that scenario.
- **Status.** **Documented.** README and USAGE warn against this. Default bind is `127.0.0.1`.

### TM_011 — XXE / billion-laughs in XML evidence inputs

- **Vector.** A crafted Nessus `.nessus` (XML), SARIF embedded XML, or Visio `.vsdx` (zipped OOXML) fed to `atms ingest` / `atms ingest-evidence` could trigger XML External Entity expansion and exfiltrate local files or DoS the parser.
- **Severity.** High — the `ingest-evidence` flow is exactly where users feed in adversarial files.
- **Status.** **Mitigated.** Every XML read uses `defusedxml.ElementTree` (`src/atms/evidence/nessus.py`, `src/atms/ingest/vsdx.py`). The `defusedxml` dependency is pinned at `>=0.7` in `pyproject.toml`. `vsdx` zip extraction is bounded by the underlying library's archive-size guard. If a future change re-introduces stdlib `xml.etree`, that's a security regression.

### TM_012 — HTML injection in rendered Mermaid diagrams

- **Vector.** A component name like `<img src=x onerror=alert(1)>` flows into the Mermaid label string in the HTML report or `/editor` view. With Mermaid running in `securityLevel: 'loose'`, the `<img>` tag would render as live HTML.
- **Severity.** High — XSS in a self-contained HTML report that reviewers open from email.
- **Status.** **Mitigated.** Two layers: `src/atms/reporting/mermaid.py` HTML-escapes `<`, `>`, `&` in `_label()`, and the bundled `static/atms-mermaid.js` plus `templates/report.html.j2` initialise Mermaid with `securityLevel: 'strict'`. If a future change downgrades to `loose`, that's a regression — the escaping alone is not enough because Mermaid's own parser interprets some escapes.

### TM_013 — DOM XSS in the dataflow editor

- **Vector.** The web `/editor` page builds dataflow rows in JavaScript. Setting row HTML via `innerHTML` with a component name string gives an attacker a direct DOM XSS sink the moment any user pastes a YAML containing `<script>` in a name field.
- **Severity.** High.
- **Status.** **Mitigated.** `src/atms/static/atms-editor.js` builds rows with `document.createElement` + `textContent` (the safe pair). `escapeAttr()` escapes `<`, `>`, `'` for the few attribute writes that remain. If a PR re-introduces `innerHTML` for any user-controlled string, that's a regression.

### TM_014 — Unconstrained methodology string on `/redteam/ingest`

- **Vector.** A POST to `/redteam/ingest` with a `methodology` field of arbitrary length / value bypasses validation at the form layer and reaches `analyze()` where it's only validated by an `if methodology not in SUPPORTED_METHODOLOGIES`. Some platforms compare against the value pre-validation.
- **Severity.** Low/Medium — primarily a defence-in-depth concern.
- **Status.** **Mitigated.** `src/atms/web.py` enforces `_METHODOLOGY_ALLOWLIST = {"stride-ai", "linddun", "pasta"}` before `analyze()` is reached. Mismatches return a friendly HTML 400 instead of a stack trace.

### TM_015 — AI SDK accidentally bundled in the .exe

- **Vector.** A future contributor adds `import anthropic` to a non-vision module, or a transitive dependency drags one in. The PyInstaller frozen build silently grows by ~50 MB and ships an AI dependency to tester laptops, defeating the AI-free contract.
- **Severity.** Medium (contract violation, not direct exploit).
- **Status.** **Mitigated.** `atms.spec` declares `excludes` listing `anthropic`, `openai`, `voyageai`, and the major HTTP clients those drag in. The `selftest` confirms the .exe runs all 8 samples without any of those imports being present. CI (when merged) lints this on every push.

## Residual risks

| Risk | Status | Notes |
|---|---|---|
| Resource exhaustion at scale | Open | Local single-user use case is fine. Deployers add limits. |
| KB drift from upstream sources | Open | Manual updates today. Future: scheduled CI to diff against ATLAS STIX. |
| Vision hallucinations | Documented | User-review gate is the control. |
| Lack of auth on web UI | By design | Local-first tool. Deployers add auth in front. |

## Decisions

- **No DB.** Stays simple, no migrations, no leak vectors. Downside: web-UI run cache resets on restart.
- **No multi-user auth.** Local-first; auth is the deployer's choice.
- **No telemetry.** ATMS does not phone home. Period.
- **Optional vision only.** Hard dependency on Anthropic would create cost, lock-in, and rate-limit attack vectors on a tool that should run on a laptop.

## How to report a security issue

Open a private security advisory at <https://github.com/anguiz7z/AITMS/security/advisories/new>, or open an issue marked `security:` if you cannot. We treat audit findings on the tool itself as priority bugs.
