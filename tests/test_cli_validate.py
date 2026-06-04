"""Regression tests for v0.17.3 Cycle H — `atms validate` CI-grade upgrade.

Pins the CI-stable contract:
  exit 0 — valid (+ AI scope OK if checked)
  exit 2 — invalid YAML
  exit 3 — --strict and a component has type='other'
  exit 4 — --check-ai-scope and zero AI components

Plus the --json output shape (for CI tooling integration).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import yaml
from click.testing import CliRunner

from atms.cli import cli


def _write_yaml(data: dict) -> Path:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8",
    )
    yaml.safe_dump(data, f)
    f.close()
    return Path(f.name)


def _valid_system() -> dict:
    return {
        "name": "t",
        "components": [
            {"id": "u", "name": "U", "type": "user"},
            {"id": "llm", "name": "LLM", "type": "llm_inference"},
        ],
    }


# ─── Exit codes ─────────────────────────────────────────────────────
def test_validate_exit_0_on_valid_system():
    p = _write_yaml(_valid_system())
    try:
        res = CliRunner().invoke(cli, ["validate", str(p)])
        assert res.exit_code == 0, res.output
        assert "OK" in res.output
    finally:
        p.unlink(missing_ok=True)


def test_validate_exit_2_on_invalid_yaml():
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8",
    )
    f.write("not: { valid: yaml [")
    f.close()
    try:
        res = CliRunner().invoke(cli, ["validate", f.name])
        # Existing _load_system_yaml exits with code 2 on bad YAML.
        assert res.exit_code == 2, f"got {res.exit_code}: {res.output}"
    finally:
        Path(f.name).unlink(missing_ok=True)


def test_validate_strict_exit_3_on_other_type():
    data = _valid_system()
    data["components"].append({"id": "x", "name": "Mystery", "type": "other"})
    p = _write_yaml(data)
    try:
        res = CliRunner().invoke(cli, ["validate", str(p), "--strict"])
        assert res.exit_code == 3, f"got {res.exit_code}: {res.output}"
        assert "other" in res.output.lower()
    finally:
        p.unlink(missing_ok=True)


def test_validate_strict_exit_0_when_no_other_components():
    """--strict must NOT fail a clean system without `other` types."""
    p = _write_yaml(_valid_system())
    try:
        res = CliRunner().invoke(cli, ["validate", str(p), "--strict"])
        assert res.exit_code == 0, res.output
    finally:
        p.unlink(missing_ok=True)


def test_validate_check_ai_scope_exit_4_on_zero_ai():
    """A pure-IT system with --check-ai-scope (default on) → exit 4."""
    data = {
        "name": "no-ai",
        "components": [
            {"id": "fw", "name": "Firewall", "type": "firewall"},
            {"id": "db", "name": "DB", "type": "database"},
        ],
    }
    p = _write_yaml(data)
    try:
        res = CliRunner().invoke(cli, ["validate", str(p)])
        assert res.exit_code == 4, f"got {res.exit_code}: {res.output}"
        assert "ai" in res.output.lower() or "scope" in res.output.lower()
    finally:
        p.unlink(missing_ok=True)


def test_validate_no_check_ai_scope_bypasses_the_gate():
    """`--no-check-ai-scope` lets a pure-IT system pass with exit 0
    (useful for schema-only validation in CI without business
    constraints)."""
    data = {
        "name": "no-ai",
        "components": [
            {"id": "fw", "name": "Firewall", "type": "firewall"},
        ],
    }
    p = _write_yaml(data)
    try:
        res = CliRunner().invoke(cli, ["validate", str(p), "--no-check-ai-scope"])
        assert res.exit_code == 0, res.output
    finally:
        p.unlink(missing_ok=True)


# ─── --json output ──────────────────────────────────────────────────
def test_validate_json_emits_machine_readable_report():
    p = _write_yaml(_valid_system())
    try:
        res = CliRunner().invoke(cli, ["validate", str(p), "--json"])
        assert res.exit_code == 0, res.output
        # The JSON payload appears in stdout. Click's invoke captures
        # both stdout (console.print) and stderr — the JSON line is
        # the last machine-readable chunk.
        payload = None
        for line in res.output.splitlines():
            line = line.strip()
            if line.startswith("{"):
                # Reconstruct: --json calls click.echo with indented JSON.
                payload_text = res.output[res.output.index("{"):]
                payload = json.loads(payload_text)
                break
        assert payload is not None, f"no JSON in output: {res.output!r}"
        assert payload["valid"] is True
        assert payload["exit_code"] == 0
        assert payload["components"] == 2
        assert payload["ai_components_present"] is True
    finally:
        p.unlink(missing_ok=True)


def test_validate_json_on_strict_failure():
    data = _valid_system()
    data["components"].append({"id": "x", "name": "Mystery", "type": "other"})
    p = _write_yaml(data)
    try:
        res = CliRunner().invoke(cli, ["validate", str(p), "--strict", "--json"])
        assert res.exit_code == 3
        payload_text = res.output[res.output.index("{"):]
        payload = json.loads(payload_text)
        assert payload["valid"] is False
        assert payload["exit_code"] == 3
        assert payload["other_components"] == ["x"]
    finally:
        p.unlink(missing_ok=True)


def test_validate_help_documents_exit_codes():
    """The --help must mention the exit codes for CI authors."""
    res = CliRunner().invoke(cli, ["validate", "--help"])
    assert res.exit_code == 0
    out = res.output
    assert "--strict" in out
    assert "--check-ai-scope" in out
    assert "--json" in out
    assert "Exit" in out or "exit" in out
