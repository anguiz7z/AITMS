---
role: cli-developer
summary: Owns the Click-based CLI in src/atms/cli.py — subcommands, flags, exit-code semantics, and wiring new formats/frameworks into existing commands.
---

# CLI developer

This guide covers the Click-based CLI in `src/atms/cli.py`: adding a new
subcommand, modifying flags, fixing exit-code behaviour, or wiring a new
format / framework into existing commands like `analyze`, `ingest`,
`kb-search`, `review`, `diff`, and `selftest`. Use it for tasks like "add
an `atms <command>` subcommand", "expose `--strict` on this command", or
"fix the `--framework` choice list". It does NOT cover the web UI, engines,
or KB.

## Area of ownership

`src/atms/cli.py` and `src/atms/__main__.py`. Commands currently exposed:

- `version` — print the package version.
- `analyze` — run the pipeline against a System YAML.
- `ingest` — parse a `.vsdx` into a draft System YAML.
- `review` — interactive prompt to fix `other`-typed components.
- `diff` — compare two analysis JSON dumps.
- `kb-search` — keyword search over the KB.
- `list-playbooks` — show all bundled playbooks.
- `validate` — check a System YAML against the schema.
- `selftest` — run all bundled samples and assert basic invariants.
- `web` — start the FastAPI server.

## Hard rules

1. **Click decorators, not argparse.** Add subcommands with
   `@cli.command()`. Use `click.argument`, `click.option`, `click.Choice`.
   Keep type hints on parameter signatures.

2. **Exit codes are a contract.**
   - `0` success.
   - `1` runtime failure (parse error, exception).
   - `2` usage error (Click default).
   - `3` `--strict` tripped (any `other`-typed component) — `analyze` only.

   Don't introduce new exit codes without thinking through CI semantics.

3. **Rich output, but works in pipes.** `console.print(...)` from Rich
   auto-strips colours when stdout is not a TTY. Don't manually strip; trust
   Rich.

4. **`atms.cli.cli` is the entry point** for `python -m atms` (via
   `__main__.py`) and the packaged binary. Don't change the function name or
   how it's invoked.

5. **Frozen-mode awareness in the `web` command.** When `sys.frozen` is True
   (packaged binary), uvicorn must be passed the `app` object, not the
   import-string `"atms.web:app"`. Don't simplify this.

6. **`--framework` choice list mirrors the KB.** Whenever the KB gains a new
   framework filter, the CLI's `kb-search --framework` `click.Choice([...])`
   must include it. The current list: `all`, `atlas`, `owasp`, `owasp_llm`,
   `owasp_agentic`, `maestro`, `nist`.

## Verification

After every change, run from the repo root:

```bash
python -m pytest tests/test_v6_features.py tests/test_ingest.py -q

PYTHONPATH=src python -m atms.cli --help            # subcommand registered
PYTHONPATH=src python -m atms.cli <new-cmd> --help  # if new
PYTHONPATH=src python -m atms.cli selftest          # nothing else broke
```

For each new subcommand, add a `CliRunner.invoke(cli, [...])` test to
`tests/test_v6_features.py`.

## What "done" looks like

- Diff is contained to `src/atms/cli.py` and `tests/`.
- A new subcommand has a docstring (it becomes its `--help`).
- A test added that exercises every flag combination introduced.
- A short summary of: command added/changed, exit-code semantics, and
  follow-up doc updates needed in `USAGE.md` / `README.md` / `CHANGELOG.md`.
