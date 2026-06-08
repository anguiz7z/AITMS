"""Regression: a non-ASCII system name must not break file downloads.

v1.0.2 Bug-fix. The Azure OpenAI RAG sample is named
``Azure OpenAI RAG — Internal Knowledge Assistant`` — the em-dash (U+2014)
is not latin-1 encodable. Starlette encodes ``Content-Disposition`` header
values as latin-1 (RFC 7230 §3.2.4), so EVERY ``/download/<run>/<fmt>``
export AND the ``/editor/save`` YAML download raised ``UnicodeEncodeError``
→ HTTP 500. Symptom the owner reported: "these aren't workable" — none of
the report's download buttons did anything.

The fix slugs the header filename down to ASCII at both sites (the
downloaded file's *content* is unchanged). These tests pin it:

  * a unicode-named system downloads every export format (200);
  * every ``Content-Disposition`` value is latin-1 encodable + ASCII;
  * the ``/editor/save`` YAML download survives a unicode name too.

This is the test that was missing — the whole suite was green while the
feature was 100% broken, because every sample name happened to be ASCII.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

# Access atms.web live (not `from ... import`): sibling tests reload the module,
# which rebinds _RUNS/app; a captured ref would be stranded on an empty _RUNS.
import atms.web as _web

_SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "azure_openai_rag.yaml"

# Every downloadable export format the report page links to.
_FORMATS = [
    "md", "html", "exec", "stix", "navigator", "csv", "sbom",
    "compliance", "compliance_csv", "jira_csv", "jira_json",
    "roadmap_md", "roadmap_json",
]


@pytest.fixture(scope="module")
def analyzed():
    """Analyse the unicode-named sample once; reuse the run for every
    format assertion (one analysis, not one-per-format)."""
    client = TestClient(_web.app, raise_server_exceptions=False)
    yaml_text = _SAMPLE.read_text(encoding="utf-8")
    resp = client.post("/analyze", data={"yaml": yaml_text, "methodology": "stride-ai"})
    assert resp.status_code == 200, f"analyze failed: {resp.status_code}"
    run_id = list(_web._RUNS.keys())[-1]
    return client, run_id


def test_sample_really_has_a_non_latin1_name():
    """Guard the guard: if someone renames the sample to ASCII, this whole
    regression file would silently stop testing anything."""
    data = yaml.safe_load(_SAMPLE.read_text(encoding="utf-8"))
    assert any(ord(ch) > 255 for ch in data["name"]), (
        f"sample name is no longer non-latin-1: {data['name']!r}. "
        f"Pick a sample with an em-dash/accent or this test is a no-op."
    )


@pytest.mark.parametrize("fmt", _FORMATS)
def test_unicode_named_system_downloads_every_format(analyzed, fmt):
    """The crux: every export returns 200 (not the old 500) for a system
    whose name carries an em-dash."""
    client, run_id = analyzed
    resp = client.get(f"/download/{run_id}/{fmt}")
    assert resp.status_code == 200, (
        f"format {fmt!r} returned {resp.status_code} for a unicode-named "
        f"system — Content-Disposition latin-1 regression?"
    )
    assert len(resp.content) > 0, f"format {fmt!r} downloaded empty body"


@pytest.mark.parametrize("fmt", _FORMATS)
def test_content_disposition_header_is_latin1_safe(analyzed, fmt):
    """The header value must be latin-1 encodable (what Starlette does) and,
    given our slug, pure ASCII."""
    client, run_id = analyzed
    resp = client.get(f"/download/{run_id}/{fmt}")
    cd = resp.headers["content-disposition"]
    cd.encode("latin-1")  # must not raise — this is the exact failing op
    assert cd.isascii(), f"Content-Disposition not ASCII for {fmt!r}: {cd!r}"
    assert "attachment" in cd and "filename=" in cd


def test_editor_save_yaml_download_survives_unicode_name():
    """The second header site: /editor/save builds the same kind of header
    from the system name."""
    client = TestClient(_web.app, raise_server_exceptions=False)
    payload = yaml.safe_load(_SAMPLE.read_text(encoding="utf-8"))
    resp = client.post("/editor/save", json=payload)
    assert resp.status_code == 200, f"/editor/save failed: {resp.text[:200]}"
    cd = resp.headers["content-disposition"]
    cd.encode("latin-1")
    assert cd.isascii(), f"/editor/save Content-Disposition not ASCII: {cd!r}"
