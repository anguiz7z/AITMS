"""Vision module tests (v0.14.8).

The vision module is optional: it only does real work when both
`anthropic` is installed AND `ANTHROPIC_API_KEY` is set. These tests
exercise the import + the no-key / no-package fail-friendly paths so a
future refactor doesn't accidentally break the contract that the
deterministic core never touches `anthropic`.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def test_vision_module_imports_without_anthropic_installed():
    """The module must import cleanly even when `anthropic` is not
    installed. The import is deferred to call-time inside
    `diagram_to_system_yaml`, so just importing the module must not
    fail. This guards the AI-free contract: a future refactor that
    moves `import anthropic` to module top-level would silently break
    the .exe build (which `excludes` anthropic) at runtime."""
    import importlib
    mod = importlib.import_module("atms.vision.analyzer")
    assert hasattr(mod, "diagram_to_system_yaml")
    assert hasattr(mod, "VISION_PROMPT")


def test_vision_friendly_error_when_no_api_key(tmp_path, monkeypatch):
    """No ANTHROPIC_API_KEY → friendly RuntimeError, NOT a crash that
    leaks the missing-env-var detail to a tester."""
    from atms.vision.analyzer import diagram_to_system_yaml
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    img = tmp_path / "diagram.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    with pytest.raises(RuntimeError) as exc:
        diagram_to_system_yaml(img)
    msg = str(exc.value).lower()
    assert "anthropic_api_key" in msg or "vision is opt-in" in msg


def test_vision_friendly_error_when_anthropic_not_installed(tmp_path, monkeypatch):
    """When ANTHROPIC_API_KEY is set but `anthropic` isn't installed,
    we should produce the install-hint error rather than ImportError.

    To exercise this path without uninstalling the package, we shadow
    the import via `sys.modules`."""
    import sys

    from atms.vision.analyzer import diagram_to_system_yaml
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    # Force `import anthropic` to fail by shadowing sys.modules.
    monkeypatch.setitem(sys.modules, "anthropic", None)
    img = tmp_path / "diagram.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    with pytest.raises(RuntimeError) as exc:
        diagram_to_system_yaml(img)
    msg = str(exc.value).lower()
    assert "anthropic" in msg and "install" in msg


def test_vision_excluded_from_exe_spec():
    """v0.14.8: the AI-free contract for the .exe is enforced by the
    `excludes` list in atms.spec. This test reads the spec file as
    text and asserts the names that MUST be excluded are present.
    A regression here means the .exe build silently grew an AI SDK."""
    spec = Path(__file__).resolve().parents[1] / "atms.spec"
    if not spec.exists():
        pytest.skip("atms.spec not present (running from wheel install?)")
    text = spec.read_text(encoding="utf-8")
    for forbidden in ["anthropic", "openai", "voyageai"]:
        assert forbidden in text, (
            f"`{forbidden}` not declared in atms.spec excludes — AI-free "
            "contract regression"
        )
