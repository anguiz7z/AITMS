"""Regression tests for v0.17.3 Cycle F polish — review findings M1 + M2.

Pins two minor-but-real UX contracts:
  M1. The /architecture page has a "← ATMS" link in its header that's
      hidden when the file is opened as file:// (so the standalone
      copy doesn't show a broken link).
  M2. Components of type `other` log a stderr `INFO` line when their
      catch-all playbook fires — so re-runs surface type-detection
      drift instead of silently emitting fallback threats.

M3 from the original review (CLI autocorrect notice) was already
implemented in cli.py:113-118 — no test needed.
"""

from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from atms.engines.stride_ai import enumerate_threats
from atms.models import Component
from atms.web import app


# ─── M1: /architecture back-to-ATMS link ─────────────────────────────
def test_architecture_page_has_back_link_markup():
    """The link element exists in the rendered HTML. Visibility is
    controlled by the JS that checks `window.location.protocol`."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/architecture")
    assert r.status_code == 200
    html = r.text
    assert 'class="nav-back"' in html
    assert 'href="/"' in html
    assert 'id="nav-back"' in html


def test_architecture_page_hides_back_link_on_file_protocol():
    """The hide-on-file:// JS check must be present so the standalone
    docs/architecture.html copy doesn't show a broken link."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/architecture")
    html = r.text
    # The protocol-detection logic must be in the rendered JS.
    assert 'window.location.protocol' in html
    assert '"file:"' in html


# ─── M2: `other` playbook logs INFO ──────────────────────────────────
def test_other_playbook_logs_info_message(caplog):
    """When a component of type `other` is analysed, the engine emits
    an INFO log noting that the catch-all playbook fired. Lets
    operators audit type-detection drift."""
    caplog.set_level(logging.INFO, logger="atms.engines.stride_ai")
    comp = Component(id="weird", name="A mystery box", type="other")
    enumerate_threats([comp])
    messages = [r.getMessage() for r in caplog.records]
    assert any(
        "catch-all" in m and "weird" in m
        for m in messages
    ), f"expected 'other' playbook INFO log; got: {messages}"


def test_other_playbook_log_does_not_fire_for_known_types(caplog):
    """The log line is type-gated to `other`; known types must not
    trigger it."""
    caplog.set_level(logging.INFO, logger="atms.engines.stride_ai")
    comp = Component(id="ok", name="LLM", type="llm_inference")
    enumerate_threats([comp])
    messages = [r.getMessage() for r in caplog.records]
    assert not any("catch-all" in m for m in messages), (
        "known-type component must not log the catch-all warning"
    )
