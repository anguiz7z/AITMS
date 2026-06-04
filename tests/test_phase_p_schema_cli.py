"""Phase P — `atms schema` CLI command (v0.18.64).

Phase O shipped `docs/system.schema.json` for VSCode pinning, but
offline / scripted access required either reading the docs file or
calling Pydantic directly. Phase P closes that gap with a first-class
CLI command:

    atms schema                       # print JSON to stdout
    atms schema --out path/to.json    # write to a file
    atms schema --indent 0            # compact (no whitespace)

This test file pins:
  * The command exists and is documented in `atms --help`.
  * stdout output is valid JSON matching the System model.
  * `--out` writes the file with trailing newline.
  * `--indent 0` produces compact JSON (no extra whitespace).
  * The CLI output is byte-identical to `docs/system.schema.json`
    content (modulo a final newline) — guards against the CLI
    diverging from the committed schema file.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from atms.cli import cli

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_FILE = ROOT / "docs" / "system.schema.json"


def test_schema_command_listed_in_help():
    """`atms --help` should mention the new command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "schema" in result.output, (
        "expected 'schema' to appear in the CLI help output"
    )


def test_schema_command_prints_valid_json():
    """`atms schema` (no args) → JSON on stdout, exit 0."""
    runner = CliRunner()
    result = runner.invoke(cli, ["schema"])
    assert result.exit_code == 0, f"failed: {result.output}"
    data = json.loads(result.output)
    # Top-level is the System schema dict.
    assert data.get("title") == "System"
    assert "$defs" in data
    assert "Component" in data["$defs"]


def test_schema_command_declares_canonical_urls():
    """The CLI output should carry the same `$schema` + `$id` as the
    committed file — so tooling that reads `atms schema` gets the same
    refs as tooling that reads the committed JSON file."""
    runner = CliRunner()
    result = runner.invoke(cli, ["schema"])
    data = json.loads(result.output)
    assert data["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert "raw.githubusercontent.com" in data["$id"]
    assert "system.schema.json" in data["$id"]


def test_schema_command_writes_to_file(tmp_path):
    """`atms schema --out path` writes the JSON to a file and prints a
    confirmation line."""
    out = tmp_path / "my.schema.json"
    runner = CliRunner()
    result = runner.invoke(cli, ["schema", "--out", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert f"Wrote {out}" in result.output
    # File parses as JSON.
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data.get("title") == "System"
    # Trailing newline (the committed schema file has one).
    assert out.read_text(encoding="utf-8").endswith("\n")


def test_schema_command_compact_mode():
    """`--indent 0` produces compact JSON (no spaces around `:` or `,`)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["schema", "--indent", "0"])
    assert result.exit_code == 0
    text = result.output.strip()
    # No `"key": "value"` spaces — compact uses `"key":"value"`.
    assert '": ' not in text, "expected compact JSON without spaces after colons"
    assert ', "' not in text, "expected compact JSON without spaces after commas"
    # Still valid JSON.
    data = json.loads(text)
    assert data.get("title") == "System"


def test_schema_cli_output_matches_committed_schema_file():
    """`atms schema` and `docs/system.schema.json` must produce the
    same content — guards against the CLI's schema diverging from the
    committed file (which is what VSCode users pin)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["schema"])
    assert result.exit_code == 0
    # The CliRunner output has a trailing newline from click.echo; the
    # committed file also ends with a newline. Compare structurally as
    # parsed JSON to be robust to whitespace.
    cli_json = json.loads(result.output)
    file_json = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    assert cli_json == file_json, (
        "`atms schema` output diverges from docs/system.schema.json. "
        "Run `make schema` to regenerate the committed file, or update "
        "the CLI handler so they stay in sync."
    )


def test_schema_command_writes_compact_when_indent_zero(tmp_path):
    """`--out path --indent 0` → file contains compact JSON, NO trailing
    newline (since the compact form is intended for streaming /
    embedding contexts)."""
    out = tmp_path / "compact.json"
    runner = CliRunner()
    result = runner.invoke(cli, ["schema", "--out", str(out), "--indent", "0"])
    assert result.exit_code == 0
    raw = out.read_text(encoding="utf-8")
    # Compact mode: no trailing newline.
    assert not raw.endswith("\n"), \
        f"compact-mode file unexpectedly ends with newline: {raw[-10:]!r}"
    # Still valid JSON.
    data = json.loads(raw)
    assert data.get("title") == "System"
