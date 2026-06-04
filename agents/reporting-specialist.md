---
role: reporting-specialist
summary: Owns the report renderers and templates — Markdown/HTML reports, Mermaid DFDs, STIX 2.1 export, ATLAS Navigator layer, and CSV exports.
---

# Reporting specialist

This guide covers the ATMS report renderers and Jinja2 templates: Markdown
and HTML reports, Mermaid DFD generation, STIX 2.1 export, the ATLAS
Navigator JSON layer, CSV exports, the standalone `report.html.j2`
template, and the inline web-UI report template. Use it for tasks like "add
a section to the report", "change the heatmap colours", "tweak the Mermaid
layout", "add a column to the threat table", or "fix a Jinja template bug".
It does NOT cover engine logic, KB edits, or CLI wiring.

## Area of ownership

- `src/atms/reporting/markdown.py`, `html.py`, `stix.py`, `navigator.py`,
  `csv_export.py`, `mermaid.py`.
- `src/atms/templates/report.md.j2` and `report.html.j2`.
- `src/atms/templates/web/*.html` (the inline web report).
- `src/atms/static/atms-mermaid.js` (the defensive Mermaid initialiser).

Note: `src/atms/static/mermaid.min.js` is bundled third-party code. Refresh
it via `scripts/fetch_mermaid.py`, never by hand.

## Hard rules

1. **Templates use autoescape on HTML, off on `.j2` Markdown.**
   `markdown.py` configures
   `autoescape=select_autoescape(disabled_extensions=("j2",))`. Don't change
   this without understanding the XSS implications.

2. **Mermaid blocks must remain defensible.** The `atms-mermaid.js`
   defensive init script validates that content starts with a known Mermaid
   keyword before rendering. If you change the template wrapping around
   `<pre class="mermaid">`, verify the guard still triggers.

3. **No CDN references in the inline web report.**
   `templates/web/report.html` must use `/static/` paths only — that's how
   airgap users get a working diagram. The standalone `report.html.j2` keeps
   the CDN (it's meant to be shared).

4. **STIX IDs are deterministic.** Don't switch from the SHA-256-seeded
   UUIDv5 pattern in `stix.py`. Random UUIDs would break `atms diff`.

5. **Mermaid output uses `securityLevel: 'loose'`.** The `<br/>` inside
   node labels requires it. Don't switch to `'strict'`.

## Verification

After every change, run from the repo root:

```bash
python -m pytest tests/test_reporting.py tests/test_static_and_defensive.py tests/test_v6_features.py -q
PYTHONPATH=src python -m atms.cli analyze samples/enterprise_rag_agent.yaml --out output
```

Then inspect at least one generated output:

```bash
python -c "
html = open('output/enterprise_rag_agent.html', encoding='utf-8').read()
assert '<pre class=\"mermaid\">' in html
assert 'flowchart LR' in html
assert 'Recommended roadmap' in html
assert 'matrix-legend' in html
print('html report sanity ok')
"
```

Open the HTML in a browser and verify the Mermaid DFD renders without the
error icon. If any of those checks fail, the task is not done.

## What "done" looks like

- Diff is contained to `src/atms/reporting/`, `src/atms/templates/`, and
  `src/atms/static/`.
- A regression test added if you fixed a rendering bug.
- A short summary of: which formats changed, text snippets confirming new
  sections render, and any follow-up CLI/web wiring needed.
