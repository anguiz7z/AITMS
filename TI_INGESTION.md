# Threat-intelligence ingestion (offline-first)

ATMS treats threats as **rebuttable hypotheses** — every threat starts as
`evidence_status: hypothetical`, and only gets promoted to
`likely`, `observed`, or `exploited` when you feed it real evidence
from your environment. This document covers every input format, the
matching logic that routes evidence to components, and the offline-only
workflow if your build laptop never touches the internet.

The contract: **the deterministic core never makes outbound HTTP
calls.** Two opt-in CLI commands (`atms refresh-feeds`, `atms cve-lookup`)
do — they're the only egress points in the entire shipped product. If
you don't run them, nothing leaves the box.

## What ATMS calls "evidence"

Every input format below produces `Evidence` rows, normalised into a
common schema (see `src/atms/models.py`):

```yaml
- source: vapt | red_team | ti | compliance      # where it came from
  source_type: nessus | sarif | stix | csv | caldera | atomic | bas_csv | kev | epss
  source_id: <CVE | CWE | technique_id | finding_id>
  title: <short>
  description: <full text>
  severity: info | low | medium | high | critical
  affected_asset: <hostname | IP | CIDR | CPE | pURL | empty>
  observed_at: <ISO date>
  references: [attack:T1234, cwe:79, cve:2024-3400, url:..., kev:true]
  cve: CVE-YYYY-NNNNN          # set if the row references a CVE
  cwe: CWE-NN                  # set if the row references a CWE
  cvss: 0.0..10.0              # CVSS score (any version)
  epss: 0.0..1.0               # FIRST EPSS probability of exploitation
  kev: true / false             # CISA Known Exploited Vulnerabilities flag
```

Then the engine runs the matcher (`src/atms/evidence/matcher.py`) to
route each row onto the component(s) it actually applies to.

## Status-promotion model

| Source | Severity rule | Resulting threat status |
|---|---|---|
| `vapt` (Nessus / SARIF / generic CSV) — no KEV hit | observed only on the matched threat | `likely` |
| `vapt` — KEV hit (CVE on CISA Known Exploited Vulnerabilities) | **forces severity = critical**, overrides qualitative bucket | `observed` |
| `red_team` (Caldera success / Atomic success / BAS Successful) | full severity preserved | **`exploited`** + likelihood = 5 |
| `red_team` — low / info severity (e.g. partial / blocked-but-executed) | preserved | `observed` (downgraded — see `engines/evidence.py`) |
| `ti` (STIX 2.1 indicators) | preserved | `likely` |
| `compliance` | preserved | doesn't change `evidence_status`; tags `compliance_controls` |

Once a row is on KEV the severity-override survives subsequent stages
by design. Maintainers: do NOT insert a re-score after `apply_evidence`
in `workflow.analyze` — that would erase the override.

## The matcher (how rows route to components)

The order is "first heuristic that produces ≥1 match wins":

1. **CPE 2.3 exact match** against `component.metadata.cpe` —
   highest fidelity, picks vendor/product/version.
2. **pURL exact match** against `component.metadata.purl` —
   same idea for package-level evidence (Trivy / Snyk / Dependabot).
3. **CIDR / IP-range containment.** A Nessus row reporting
   `affected_asset: 10.0.0.0/24` matches a component whose
   `metadata.ip` is `10.0.0.5`. Component-level
   `metadata.cidr` is also honoured (overlap).
4. **Hostname / IP / FQDN exact match** against
   `metadata.hostname` / `metadata.ip` / `metadata.fqdn`.
5. **Product + version substring match** across the evidence's
   title + description + asset.
6. **Vendor token** anywhere in title or description.
7. **Component-name substring** as a last-resort.

If nothing matches, the row is reported as `evidence_unmatched` in
the summary so you know your evidence input had blind spots.

## Input formats

### 1. VAPT scanner output

#### Nessus `.nessus` (XML)

```bash
atms ingest-evidence findings.nessus system.yaml --out output
```

Parses the `ReportItem` rows: `severity`, `host_fqdn` / `host-ip`,
`pluginName`, `cve`, `cvss_base_score`. XXE-safe via `defusedxml`.

#### SARIF 2.1 (CodeQL / Semgrep / Trivy / Snyk / Bandit)

```bash
atms ingest-evidence semgrep.sarif system.yaml --out output
```

Reads `runs[].results[]`: `ruleId`, `level`, `message.text`,
`locations[].physicalLocation.artifactLocation.uri`, plus any
`partialFingerprints.cve` / `properties.cwe`. Works with every SARIF
producer that follows the 2.1 spec.

#### Generic CSV

```bash
atms ingest-evidence findings.csv system.yaml --out output
```

Auto-sniffs columns. Recognised header aliases (case-insensitive):

| Field | Aliases |
|---|---|
| `cve` | CVE, CVE ID, Vulnerability |
| `severity` | Severity, Risk, Criticality |
| `affected_asset` | Asset, Host, Hostname, Target, IP |
| `title` | Title, Vulnerability Name, Plugin Name, Issue |
| `description` | Description, Details, Summary |

If your scanner exports something more exotic, normalise to one of
the alias columns.

### 2. STIX 2.1 threat-intel bundles

```bash
atms ingest-evidence ti-bundle.json system.yaml --out output
```

Parses an `indicator` / `attack-pattern` / `malware` / `vulnerability`
SDO bundle. Pulls `external_references` (CVE, ATT&CK technique IDs,
CWEs), `valid_from`, `description`, `name`. Use case: a MISP export, an
OpenCTI bundle, a vendor's commercial threat-intel feed dropped into
your file system.

### 3. CISA Known Exploited Vulnerabilities (KEV)

ATMS ships a snapshot of the KEV catalog at `kb/threat_intel/cisa_kev.yaml`.
Every `Evidence` row whose `cve` matches a KEV entry gets
`kev=true`, severity forced to `critical`, and the matched threat
promoted to `evidence_status=observed`.

To refresh on an internet-connected box (this is the only way to update
KEV — by design, the deterministic core can't fetch):

```bash
atms refresh-feeds              # updates KEV + EPSS
atms refresh-feeds --no-epss    # KEV only, no EPSS download
atms refresh-feeds --top-n 500  # take more EPSS rows
```

Honours `HTTP_PROXY` / `HTTPS_PROXY` env vars. The fetched YAMLs are
written to `kb/threat_intel/`. Ship that directory along with your
.exe / wheel and everything stays offline at the analysis box.

### 4. FIRST EPSS scores

`kb/threat_intel/epss_top.yaml` ships with the top-N EPSS scores
(default 250). Every CVE-tagged row picks up `epss: 0.0..1.0` if the
score is in the snapshot. Use it as a prioritisation signal in addition
to severity / KEV.

### 5. Red-team / BAS artefacts

Promotes matched threats to **`exploited`** + `likelihood=5`:

```bash
atms ingest-redteam ops.json system.yaml         # Caldera operations export
atms ingest-redteam invocation-log.json system.yaml  # Atomic Red Team
atms ingest-redteam scenarios.csv system.yaml    # AttackIQ / Cymulate / SafeBreach BAS
```

The Caldera parser is tolerant of v1 / v2 / v4 success markers and
both nested (`link.ability.technique_id`) and flat
(`link.technique_id` / `link.attack_id`) shapes.

## Web UI evidence ingest

Drop a file at:

- `/evidence` for VAPT / TI evidence (`.nessus`, `.sarif`, `.json`, `.csv`)
- `/redteam` for red-team / BAS artefacts (`.json`, `.jsonl`, `.csv`)

Both pages validate the file extension server-side and reject
unknown formats with a friendly error. Methodology choice (`STRIDE for
AI` / PASTA / LINDDUN) is preserved through the form.

## Air-gapped workflow (zero outbound HTTP)

If your analysis box is on an isolated network:

1. **Build / refresh once on a connected box** with
   `atms refresh-feeds` to populate `kb/threat_intel/`.
2. **Bake the refreshed YAMLs into the wheel / installer.** The
   wheel includes everything under `kb/`; rebuild via
   `python scripts/build_exe.py --clean` or `python -m build --wheel`.
3. **Move the resulting `dist/atms.exe` (or `dist/atms-*.whl`) and
   `kb/threat_intel/*.yaml` to the air-gapped box.** The .exe bundles
   the YAMLs internally; for a Python install, the YAMLs ship as
   package data — `pip install` puts them in the right place.
4. **Pull TI from your existing feed** (MISP / OpenCTI / ThreatConnect /
   Recorded Future / a vendor SOC) **as a STIX 2.1 bundle file** and
   feed via `atms ingest-evidence`.

If you also want to ingest VAPT findings from your scanner, copy the
.nessus / .sarif / .csv from your scanner host onto the same air-gapped
box and `atms ingest-evidence` against your System YAML. No outbound
network at any step.

## Pre-canned evidence wiring

Looking for a starter template? The `tests/test_v12_evidence.py` and
`tests/test_v14_pipelines.py` files contain runnable fixtures for every
format above. The smallest end-to-end wiring is in
`samples/bank_with_llm_fraud.yaml` (System YAML) plus a one-line CSV:

```csv
CVE,Severity,Asset,Title
CVE-2024-3400,Critical,vpn01.corp,PAN-OS pre-auth RCE
```

Run:

```bash
atms ingest-evidence findings.csv samples/bank_with_llm_fraud.yaml --out output
```

Output: a Markdown / HTML report with the VPN's threats promoted to
`observed` and the KEV banner at the top of the report.

## Unmatched-row triage

After every run the summary prints `evidence_unmatched: N`. To see
which rows didn't match:

```bash
atms ingest-evidence findings.csv system.yaml --out output --verbose
```

Common causes:
- Asset is a CIDR but no component has `metadata.ip` or
  `metadata.cidr` populated → add the field.
- Asset is a CPE the System YAML doesn't reference → set
  `metadata.cpe` on the right component.
- Scanner emits a vendor name like `pan-os` while your System YAML
  uses `palo_alto_networks` → normalise one of them.

The `atms review` command walks `other`-typed components after a parse
and is a good place to add metadata that improves matcher hit-rate.
