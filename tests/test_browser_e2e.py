"""Browser-driven end-to-end tests (real headless Chromium via Playwright).

These complement the FastAPI TestClient tests (test_web*.py) by exercising the
UI the way a human does: a real browser renders the pages, runs the client-side
JS, and submits the analyze form. They catch client-side/render bugs (uncaught
JS exceptions, broken interactive elements, empty renders) that HTTP-level tests
cannot see.

Skips cleanly if Playwright or the Chromium browser is not installed
(`pip install playwright pytest-playwright && python -m playwright install chromium`).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
KEEP_NAV = ["/", "/samples", "/editor", "/docs", "/playbooks"]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    """Start a real `atms web` server in a subprocess; yield its base URL."""
    port = _free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src")
    env["ATMS_KB_NO_CACHE"] = "1"
    log = tmp_path_factory.mktemp("srv") / "web.log"
    with open(log, "wb") as fh:
        proc = subprocess.Popen(
            [sys.executable, "-m", "atms", "web", "--port", str(port)],
            cwd=str(REPO), env=env, stdout=fh, stderr=subprocess.STDOUT,
        )
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        if proc.poll() is not None:
            pytest.fail(f"web server exited early:\n{log.read_text(errors='replace')}")
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=1) as r:
                if r.status == 200:
                    break
        except Exception:
            time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail(f"web server did not become healthy:\n{log.read_text(errors='replace')}")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        try:
            b = p.chromium.launch(headless=True)
        except Exception as e:  # browser binary not installed
            pytest.skip(f"chromium not available: {e}")
        yield b
        b.close()


def _new_page(browser):
    """A page that records uncaught JS exceptions (pageerror)."""
    ctx = browser.new_context()
    page = ctx.new_page()
    page_errors: list[str] = []
    page.on("pageerror", lambda e: page_errors.append(str(e)))
    return ctx, page, page_errors


@pytest.mark.parametrize("path", KEEP_NAV)
def test_nav_page_renders_in_browser(live_server, browser, path):
    """Each KEEP nav surface renders in a real browser with no uncaught JS error."""
    ctx, page, page_errors = _new_page(browser)
    try:
        resp = page.goto(live_server + path, wait_until="load")
        assert resp is not None and resp.status == 200, f"{path} -> {resp.status if resp else 'no response'}"
        assert page.locator("body").inner_text().strip(), f"{path}: empty body in browser"
        assert not page_errors, f"{path}: uncaught JS errors: {page_errors}"
    finally:
        ctx.close()


def test_analyze_flow_end_to_end_in_browser(live_server, browser, tmp_path):
    """The real user flow: open a prefilled sample, click Analyze, see the report."""
    ctx, page, page_errors = _new_page(browser)
    try:
        page.goto(live_server + "/?sample=rag_system.yaml", wait_until="load")
        prefilled = page.locator("#yaml").input_value()
        assert prefilled.strip(), "sample YAML did not prefill the editor"

        page.locator("form[action='/analyze'] button[type='submit']").click()
        page.wait_for_load_state("load")

        body = page.locator("body").inner_text()
        assert "Threat" in body, "analyze did not render a threat model in the browser"
        # the report should carry the analysed system's name through
        assert "Customer Support RAG Assistant" in body or "RAG" in body

        page.screenshot(path=str(tmp_path / "report.png"))
        assert (tmp_path / "report.png").exists()
        assert not page_errors, f"analyze flow uncaught JS errors: {page_errors}"
    finally:
        ctx.close()


def test_editor_visual_builder_is_interactive(live_server, browser):
    """The /editor visual builder loads its palette/canvas and accepts input.

    /editor is a drag-and-drop builder (palette + canvas + props), not a plain
    textarea — so we assert its real interactive surface: the system-name field
    accepts text, and the palette + analyze button are present.
    """
    ctx, page, page_errors = _new_page(browser)
    try:
        page.goto(live_server + "/editor", wait_until="load")
        name = page.locator("#sys-name")
        assert name.count() >= 1, "editor #sys-name field missing"
        name.first.fill("browser-probe-system")
        assert name.first.input_value() == "browser-probe-system"
        assert page.locator("#palette").count() >= 1, "component palette missing"
        assert page.locator("#canvas").count() >= 1, "editor canvas missing"
        assert page.locator("#analyze-btn").count() >= 1, "editor analyze button missing"
        assert not page_errors, f"editor JS errors: {page_errors}"
    finally:
        ctx.close()
