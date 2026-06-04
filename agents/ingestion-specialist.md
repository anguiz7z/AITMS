---
role: ingestion-specialist
summary: Owns diagram ingestion under src/atms/ingest/ — the Visio (.vsdx) parser and any new format adapters (draw.io, Lucidchart, Excalidraw, Mermaid-text).
---

# Ingestion specialist

This guide covers diagram-ingestion work: maintaining the Visio (`.vsdx`)
parser and adding new format adapters (draw.io, Lucidchart, Excalidraw,
Mermaid-text, etc.). Use it for tasks like "improve the .vsdx classifier",
"add cloud stencil keywords", "ingest a draw.io file", or "support PNG
diagrams via vision". It does NOT cover engine work, KB edits, or web/CLI
wiring (those are separate areas).

## Area of ownership

`src/atms/ingest/*.py` and any new format-parser modules under that folder.
Currently:

- `ingest/__init__.py` — exports.
- `ingest/vsdx.py` — Visio OOXML parser; produces a draft `System` model.

Adapters you might add later — `drawio.py`, `lucidchart.py`,
`excalidraw.py`, `mermaid_text.py`, etc. — each follow the same shape:
`<format>_to_system(path) -> System` plus an optional
`<format>_to_system_yaml(path) -> str`.

## Hard rules

1. **Output a `System` model** validated through Pydantic. Every adapter
   must produce something `System.model_validate(adapter_output.model_dump())`
   succeeds on. If you can't classify a component, use `type: other` —
   don't skip it.

2. **Order matters in `TYPE_KEYWORDS`.** `rag_vector_store` must come before
   `data_source`; `mcp_server` must come before generic `agent` patterns.
   When adding new keyword groups, place them deliberately.

3. **Use `\b` word boundaries in regexes** so `agent` doesn't match
   `manager`. Test cases for ambiguous shape labels go in
   `tests/test_ingest.py`.

4. **Display name vs classification text are separate.** `_shape_text`
   returns what the user sees (the label only). `_shape_classification_text`
   may include data-property values for type inference. Don't mix them.

5. **Reject legacy formats clearly.** `.vsd` (binary Visio) is unsupported —
   the user must convert to `.vsdx`. Check the extension first, give a clear
   error, and exit before opening the file.

6. **Handle malformed input gracefully.** A non-Visio ZIP, a corrupted
   OOXML, an empty file — each should raise `ValueError` with a helpful
   message, never crash the caller.

## Verification

After every change, run from the repo root:

```bash
python -m pytest tests/test_ingest.py -q
PYTHONPATH=src python -m atms.cli ingest samples/test_diagram.vsdx
PYTHONPATH=src python -m atms.cli ingest samples/test_diagram.vsdx --out /tmp/parsed.yaml --analyze
```

The first run must produce `3 components, 2 dataflows`; the analyze chain
must complete with `selftest`-equivalent counts.

## Adding a new format

1. Create `src/atms/ingest/<format>.py` with `<format>_to_system` +
   `<format>_to_system_yaml`.
2. Wire it into `cli.py:ingest` (extend the format detection).
3. Wire it into `web.py:/ingest` (extend `ALLOWED_DIAGRAM_EXTS`).
4. Add a sample file to `samples/` (handcraft if needed).
5. Add tests for the parser, the CLI, and the web upload path.

Steps 2-3 belong to the CLI and web areas — note them as follow-ups.

## What "done" looks like

- Diff contained to `src/atms/ingest/` and `tests/test_ingest.py`.
- A sample test artifact added under `samples/` for any new format.
- A short summary of: files added/modified, parsed component/dataflow
  counts, and follow-ups for the CLI and web areas.
