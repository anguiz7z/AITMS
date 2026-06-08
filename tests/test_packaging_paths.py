"""Packaging-path regressions (audit F009 / F010).

A pip-installed wheel maps top-level ``kb/`` and ``samples/`` to
``<sys.prefix>/atms/...`` via hatch shared-data. ``paths._candidates`` must
include that location, or ``kb_dir()`` / ``samples_dir()`` resolve to a
nonexistent path: the KB then loads EMPTY (0 playbooks) with no error and
``atms selftest`` reports a false GREEN over zero sample files.
"""

from __future__ import annotations

import sys
from pathlib import Path

from click.testing import CliRunner

from atms import paths


def test_candidates_include_shared_data_prefix_location():
    """audit F009: _candidates('kb') must offer <sys.prefix>/atms/kb so a
    pip-installed wheel (hatch shared-data) resolves the bundled KB instead of
    silently loading an empty knowledge base."""
    cands = paths._candidates("kb")
    expected = Path(sys.prefix) / "atms" / "kb"
    assert expected in cands, (
        f"{expected} not among kb candidates {cands} -- a wheel install would "
        "load an EMPTY KB"
    )
    # samples must be resolvable the same way (selftest depends on it).
    s_cands = paths._candidates("samples")
    assert (Path(sys.prefix) / "atms" / "samples") in s_cands


def test_selftest_fails_loudly_on_empty_samples(tmp_path, monkeypatch):
    """audit F010: selftest must EXIT NONZERO when no sample systems are
    found, not fall through to 'All sample analyses passed.' over zero files
    (the false-GREEN that masked the wheel shipping no samples)."""
    from atms.cli import cli

    empty = tmp_path / "empty_samples"
    empty.mkdir()
    monkeypatch.setenv("ATMS_SAMPLES_DIR", str(empty))
    res = CliRunner().invoke(cli, ["selftest"])
    assert res.exit_code == 1, res.output
    assert "no sample systems" in res.output.lower()
    assert "passed" not in res.output.lower()
