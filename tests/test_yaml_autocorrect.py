"""Tests for v0.14.9 web-UI autocorrect + friendly errors.

The /analyze flow now best-effort fixes common authoring mistakes
(free-text component types like 'IoT Device') so a stray typo doesn't
bounce the user out of the analysis. These tests pin that behaviour
plus the invariant that .vsdx parsing never produces a type outside
the ComponentType literal.
"""

from __future__ import annotations

from typing import get_args

import pytest

from atms.models import ComponentType

_VALID = frozenset(get_args(ComponentType))


# ─── _coerce_component_type ────────────────────────────────────────────────
def test_coerce_passes_through_valid_types():
    from atms.yaml_autocorrect import coerce_component_type as _coerce_component_type
    for t in ["llm_inference", "iot_device", "other", "vpn_gateway"]:
        coerced, was_corrected = _coerce_component_type(t)
        assert coerced == t
        assert was_corrected is False


def test_coerce_slugifies_human_friendly_input():
    """The exact bug from the v0.14.8 screenshot: 'IoT Device' must
    auto-correct to 'iot_device' rather than blow up the analysis."""
    from atms.yaml_autocorrect import coerce_component_type as _coerce_component_type
    coerced, was_corrected = _coerce_component_type("IoT Device")
    assert coerced == "iot_device"
    assert was_corrected is True


@pytest.mark.parametrize("input_str,expected", [
    ("Web Application", "web_application"),
    ("LLM Inference", "llm_inference"),
    ("VPN Gateway", "vpn_gateway"),
    ("Object Storage", "object_storage"),
    ("API Gateway", "api_gateway"),
    ("Industrial Protocol", "industrial_protocol"),
])
def test_coerce_slugifies_common_capitalised_inputs(input_str, expected):
    from atms.yaml_autocorrect import coerce_component_type as _coerce_component_type
    coerced, was_corrected = _coerce_component_type(input_str)
    assert coerced == expected
    assert was_corrected is True


@pytest.mark.parametrize("synonym,expected", [
    ("LLM", "llm_inference"),
    ("vault", "secrets_vault"),
    ("kafka", "message_queue"),
    ("S3", "object_storage"),
    ("kubernetes", "container_runtime"),
    ("ldap", "directory_service"),
    ("vpn", "vpn_gateway"),
    ("sensor", "iot_device"),
    ("mainframe", "mainframe"),     # v0.16: `mainframe` is now a first-class type
])
def test_coerce_resolves_synonyms(synonym, expected):
    from atms.yaml_autocorrect import coerce_component_type as _coerce_component_type
    coerced, _ = _coerce_component_type(synonym)
    assert coerced == expected


def test_coerce_unknown_falls_back_to_other():
    from atms.yaml_autocorrect import coerce_component_type as _coerce_component_type
    coerced, was_corrected = _coerce_component_type("Magic Cloud Box")
    assert coerced == "other"
    assert was_corrected is True


def test_coerce_handles_non_string_input():
    from atms.yaml_autocorrect import coerce_component_type as _coerce_component_type
    for bad in [None, 42, ["llm"], {"type": "x"}]:
        coerced, was_corrected = _coerce_component_type(bad)
        assert coerced == "other"
        assert was_corrected is True


# ─── _autocorrect_system_yaml ──────────────────────────────────────────────
def test_autocorrect_walks_components_list():
    """End-to-end: a System YAML dict with a mix of valid + free-text
    types should come back valid against `ComponentType`."""
    from atms.models import System
    from atms.yaml_autocorrect import autocorrect_system_yaml as _autocorrect_system_yaml
    raw = {
        "name": "test",
        "components": [
            {"id": "u", "name": "User", "type": "user"},
            {"id": "iot", "name": "Sensor", "type": "IoT Device"},
            {"id": "db", "name": "DB", "type": "Database"},
            {"id": "?", "name": "Mystery", "type": "Magic Cloud Box"},
        ],
    }
    fixed, corrections = _autocorrect_system_yaml(raw)
    assert len(corrections) == 3, corrections
    sys = System.model_validate(fixed)
    types = [c.type for c in sys.components]
    assert types == ["user", "iot_device", "database", "other"]


def test_autocorrect_leaves_already_valid_yaml_alone():
    from atms.yaml_autocorrect import autocorrect_system_yaml as _autocorrect_system_yaml
    raw = {
        "name": "test",
        "components": [
            {"id": "u", "name": "User", "type": "user"},
            {"id": "iot", "name": "Sensor", "type": "iot_device"},
        ],
    }
    fixed, corrections = _autocorrect_system_yaml(raw)
    assert corrections == []
    assert fixed["components"][0]["type"] == "user"
    assert fixed["components"][1]["type"] == "iot_device"


# ─── _format_validation_error ──────────────────────────────────────────────
def test_format_error_translates_literal_error_into_plain_english():
    """A Pydantic literal_error must produce a one-line English message
    pointing at the offending row, not the raw error blob."""
    from atms.models import System
    from atms.yaml_autocorrect import format_validation_error as _format_validation_error
    raw = {"name": "x", "components": [
        {"id": "iot", "name": "Sensor", "type": "IoT Device"}]}
    try:
        System.model_validate(raw)
    except Exception as e:
        msg = _format_validation_error(e, raw)
    assert "Unknown component type" in msg
    assert "IoT Device" in msg
    # Must hint at the snake-case form
    assert "iot_device" in msg.lower()
    # And must mention which component (label resolution)
    assert "Sensor" in msg


# ─── _system_to_yaml ───────────────────────────────────────────────────────
def test_system_to_yaml_drops_empty_defaults():
    """The compact dump must NOT emit `controls: []`, `metadata: {}`,
    `maestro_layers: []` — those are noise on a freshly-parsed system
    and made the post-parse YAML hard to read."""
    from atms.models import Component, System
    from atms.web import _system_to_yaml
    sys = System(
        name="x",
        components=[Component(id="u", name="User", type="user")],
    )
    out = _system_to_yaml(sys)
    assert "controls:" not in out
    assert "metadata:" not in out
    assert "maestro_layers:" not in out
    assert "components:" in out
    assert "type: user" in out


# ─── VSDX invariant ────────────────────────────────────────────────────────
def test_vsdx_classifier_only_emits_valid_component_types():
    """Stronger than parsing a real .vsdx: assert that every value in
    TYPE_KEYWORDS' first column is a valid ComponentType. This catches
    the failure mode where someone adds a new heuristic with the
    display label ('IoT Device') instead of the enum slug."""
    from atms.ingest.vsdx import TYPE_KEYWORDS
    for ctype, _patterns in TYPE_KEYWORDS:
        assert ctype in _VALID, (
            f"vsdx.TYPE_KEYWORDS contains {ctype!r} which is not a valid "
            f"ComponentType — would crash analyse on parse"
        )


def test_vsdx_classifier_resolves_iot_keywords_to_iot_device():
    """Lock in: the VSDX classifier must produce the snake_case slug
    for the very thing that broke v0.14.8 in production."""
    from atms.ingest.vsdx import _classify
    for label in ["iot device", "IoT Device", "smart sensor",
                  "industrial iot endpoint"]:
        assert _classify(label) == "iot_device", (
            f"_classify({label!r}) → {_classify(label)!r}, expected 'iot_device'"
        )
