---
role: web-developer
summary: Owns the FastAPI web UI — route handlers in src/atms/web.py, the inline Jinja2 templates under templates/web/, and bundled static assets.
---

# Web developer

This guide covers the FastAPI web UI: endpoints in `src/atms/web.py`,
Jinja2 templates under `src/atms/templates/web/`, and bundled static assets
under `src/atms/static/`. Use it for tasks like "add a new web page", "wire
a new upload route", "fix a 404 on /something", "improve the inline report
layout", or "expose a new framework on the KB browser". It does NOT cover
the standalone HTML report (that's the reporting area), the CLI, or engine
logic.

## Area of ownership

- `src/atms/web.py` — the FastAPI app and all route handlers.
- `src/atms/templates/web/*.html` — the inline web UI templates (index,
  samples, kb, playbooks, maestro, agentic, about, report).
- `src/atms/static/*` — bundled static assets (Mermaid, defensive init
  script).
- The `/static/`, `/healthz`, `/`, `/analyze`, `/ingest`, `/samples`,
  `/playbooks`, `/maestro`, `/agentic`, `/kb`, `/about`,
  `/download/<run_id>/<fmt>` routes.

## Hard rules

1. **Local-first only.** The default bind is `127.0.0.1:8765`. Don't
   introduce defaults that listen on `0.0.0.0`. If a user wants LAN access,
   they pass `--host 0.0.0.0` explicitly.

2. **No CDN in the inline report.** `templates/web/report.html` must
   reference `/static/mermaid.min.js` and `/static/atms-mermaid.js` only,
   never `cdn.jsdelivr.net`. The downloadable report
   (`templates/report.html.j2`) is allowed to use the CDN, but that template
   lives in the reporting area.

3. **Path-traversal defence stays.** The home `/?sample=` query parameter
   check has three layers (`Path(sample).name == sample` AND `is_file()` AND
   `resolve().parent == samples_dir`). Don't simplify it. Don't echo bad
   input back in the error message.

4. **Defensive Mermaid init stays.** `static/atms-mermaid.js` must keep the
   `isLikelyMermaid` regex guard, the `startOnLoad: false` setting, and the
   try/catch around `mermaid.run`.

5. **In-memory run cache resets on restart**, intentionally. Don't add
   SQLite or any persistent run store.

6. **Use the `_render` helper, not `templates.TemplateResponse(...)`
   directly.** Newer Starlette wants
   `TemplateResponse(request=request, name=..., context=...)`; the helper
   centralises the calling convention.

## Verification

After every change, run from the repo root:

```bash
python -m pytest tests/test_web.py tests/test_static_and_defensive.py tests/test_ingest.py -q
```

For visible UI changes, also drive the running server:

```bash
PYTHONPATH=src python -c "
from fastapi.testclient import TestClient
from atms.web import app
c = TestClient(app)
for path in ['/', '/healthz', '/samples', '/playbooks', '/maestro', '/agentic', '/static/mermaid.min.js', '/static/atms-mermaid.js']:
    r = c.get(path)
    assert r.status_code == 200, f'{path}: {r.status_code}'
print('all routes 200')
"
```

If any new route was added, add a test to `tests/test_web.py`.

## What "done" looks like

- Diff contained to `src/atms/web.py`, `src/atms/templates/web/*`,
  `src/atms/static/*`, `tests/test_web.py`, and
  `tests/test_static_and_defensive.py`.
- A test added for any new route.
- A short summary of: routes added/changed, confirmation that Mermaid still
  renders, and that no CDN reference leaked into the inline report.
