"""Web-surface security regressions (audit F048/F049/F050/F051).

- The /diff and /methodology routes resolved a user-supplied path literally,
  so ?a= / ?path= could read ANY JSON file on the host (arbitrary file read).
- The /analyze route used yaml.safe_load, which is not safe against an
  alias-expansion 'billion laughs' payload (OOM DoS).
"""

from __future__ import annotations

import json

import pytest
import yaml

from atms.web import _resolve_saved_json
from atms.yaml_autocorrect import safe_load_system_yaml


def test_resolve_saved_json_rejects_absolute_and_traversal(tmp_path, monkeypatch):
    """F048/F049/F050: absolute paths and ../ traversal must not resolve;
    only a JSON basename inside output/ or cwd is honoured."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "output").mkdir()
    legit = tmp_path / "output" / "saved.json"
    legit.write_text('{"threats": []}', encoding="utf-8")
    # secret file OUTSIDE the allowed dirs
    secret = tmp_path.parent / "secret.json"
    secret.write_text('{"threats": []}', encoding="utf-8")

    # legit basename resolves
    assert _resolve_saved_json("saved.json") == legit.resolve()
    assert _resolve_saved_json("output/saved.json") == legit.resolve()
    # attacks are rejected
    assert _resolve_saved_json(str(secret)) is None                # absolute
    assert _resolve_saved_json("../secret.json") is None           # traversal
    assert _resolve_saved_json("../../etc/passwd") is None         # traversal+nonjson
    assert _resolve_saved_json("/etc/passwd") is None              # absolute nonjson
    assert _resolve_saved_json(r"C:\Windows\win.ini") is None      # windows absolute
    assert _resolve_saved_json("saved.txt") is None                # non-json


def test_safe_load_system_yaml_rejects_alias_bomb():
    """F051: nested-alias 'billion laughs' must be rejected before it can be
    expanded by model_validate / serialization."""
    bomb = "l0: &l0 [x,x]\nl1: &l1 [*l0,*l0]\nl2: &l2 [*l1,*l1]\nl3: [*l2,*l2]"
    with pytest.raises(yaml.YAMLError):
        safe_load_system_yaml(bomb)


def test_safe_load_system_yaml_accepts_normal_yaml():
    """A legitimate System YAML (no aliases) loads exactly like safe_load."""
    text = (
        "name: T\n"
        "components:\n"
        "  - {id: a, name: A, type: user}\n"
        "  - {id: b, name: B, type: llm_inference}\n"
        "dataflows:\n"
        "  - {source: a, target: b}\n"
    )
    got = safe_load_system_yaml(text)
    assert got == yaml.safe_load(text)
    assert got["name"] == "T" and len(got["components"]) == 2


def test_round_trip_saved_json_is_loadable(tmp_path, monkeypatch):
    """A resolved saved analysis is read as JSON (sanity for the diff route)."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "output").mkdir()
    (tmp_path / "output" / "a.json").write_text(json.dumps({"threats": [{"id": "t1"}]}), encoding="utf-8")
    p = _resolve_saved_json("a.json")
    assert p is not None
    assert json.loads(p.read_text(encoding="utf-8"))["threats"][0]["id"] == "t1"
