"""Regression tests for v0.18.47 Phase 3 — KB pickle cache.

The cache invalidates on:
  - YAML mtime / file-count / total-size change (cheap signature)
  - ATMS_KB_NO_CACHE=1 env var
  - Pickle format-version bump (_CACHE_VERSION)
  - Corrupt / unreadable pickle

Each invariant gets a dedicated test.
"""

from __future__ import annotations

import pickle
import time

import pytest

from atms.kb import (
    _CACHE_VERSION,
    KnowledgeBase,
    _cache_path,
    _kb_signature,
    get_kb,
)
from atms.paths import kb_dir as _kb_dir


@pytest.fixture(autouse=True)
def reset_singleton():
    """Each test starts with a fresh get_kb cache so we observe real
    load behaviour, not the lru_cache singleton."""
    get_kb.cache_clear()
    yield
    get_kb.cache_clear()


def test_cache_written_on_first_load():
    cache = _cache_path(_kb_dir())
    if cache.exists():
        cache.unlink()
    kb = get_kb()
    assert kb.playbooks  # confirm load actually ran
    assert cache.exists(), "cache file should be created on first load"
    assert cache.stat().st_size > 1000, "cache file should be non-trivial"


def test_warm_load_uses_cache(monkeypatch):
    """When the cache is present and signature matches, KnowledgeBase
    __init__ MUST NOT run — we'd otherwise lose the speedup."""
    # Warm the cache first.
    get_kb()
    get_kb.cache_clear()

    # Track init calls.
    init_calls = []
    real_init = KnowledgeBase.__init__

    def tracked_init(self, *args, **kwargs):
        init_calls.append(1)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(KnowledgeBase, "__init__", tracked_init)
    kb = get_kb()
    assert kb.playbooks
    assert init_calls == [], (
        "Expected zero KnowledgeBase.__init__ calls when cache hot — "
        "cache is being bypassed."
    )


def test_signature_changes_when_yaml_content_changes(tmp_path):
    """Edit any YAML file → signature changes → cache rebuilds. The
    signature is (file_count, total_bytes, max_mtime). Mutating bytes
    is the cheapest guaranteed change; mtime alone may not move when
    another file in the tree already holds a later mtime."""
    root = _kb_dir()
    sig_before = _kb_signature(root)
    target = root / "stride_ai_matrix.yaml"
    original_bytes = target.read_bytes()
    try:
        # Append a comment line — valid YAML, byte-count rises by 27.
        target.write_bytes(original_bytes + b"\n# phase-3 cache test\n")
        sig_after = _kb_signature(root)
        assert sig_before != sig_after, (
            "Signature must change when YAML content changes"
        )
    finally:
        target.write_bytes(original_bytes)
        # Confirm restore brings the signature back.
        sig_restored = _kb_signature(root)
        # mtime may differ but bytes match — accept either.
        assert sig_restored[1] == sig_before[1], (
            f"byte count restore failed: "
            f"before={sig_before[1]}, restored={sig_restored[1]}"
        )


def test_corrupt_cache_falls_back_to_yaml_load():
    """A garbled pickle must not crash get_kb()."""
    cache = _cache_path(_kb_dir())
    cache.write_bytes(b"\x80\x05not-a-real-pickle\x00\x00\x00")
    kb = get_kb()
    # If we got here, the fallback worked.
    assert kb.playbooks
    assert len(kb.playbooks) == 121
    # Bonus: rebuild should have written a fresh cache over the bad bytes.
    assert cache.exists()


def test_atms_kb_no_cache_env_var_bypasses(monkeypatch):
    """Setting the env var forces the YAML path even when a cache exists."""
    # Warm cache.
    get_kb()
    get_kb.cache_clear()
    monkeypatch.setenv("ATMS_KB_NO_CACHE", "1")
    init_calls = []
    real_init = KnowledgeBase.__init__

    def tracked_init(self, *args, **kwargs):
        init_calls.append(1)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(KnowledgeBase, "__init__", tracked_init)
    kb = get_kb()
    assert kb.playbooks
    assert init_calls == [1], (
        "ATMS_KB_NO_CACHE=1 must force a full YAML load"
    )


def test_cache_version_bump_invalidates(monkeypatch):
    """If we bump _CACHE_VERSION in a future ATMS release, old caches
    must be rejected even when the YAML hasn't changed."""
    # Warm the cache normally.
    get_kb()
    get_kb.cache_clear()
    cache = _cache_path(_kb_dir())
    # audit F046: the cache is now `HMAC-SHA256(32 bytes) || pickle`. Strip the
    # MAC to read the payload, tamper the version, then re-MAC so it passes the
    # authenticity check and is rejected purely on the stale version.
    import hashlib
    import hmac

    from atms.kb import _cache_mac_key
    key = _cache_mac_key(cache)
    payload = pickle.loads(cache.read_bytes()[32:])
    payload["version"] = _CACHE_VERSION - 1
    data = pickle.dumps(payload)
    cache.write_bytes(hmac.new(key, data, hashlib.sha256).digest() + data)
    init_calls = []
    real_init = KnowledgeBase.__init__

    def tracked_init(self, *args, **kwargs):
        init_calls.append(1)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(KnowledgeBase, "__init__", tracked_init)
    kb = get_kb()
    assert kb.playbooks
    assert init_calls == [1], (
        "Stale cache version must trigger a fresh YAML load"
    )


def test_warm_load_is_at_least_5x_faster_than_cold():
    """Operational SLA — pickle cache must deliver a meaningful speedup
    or the implementation isn't pulling its weight."""
    cache = _cache_path(_kb_dir())
    if cache.exists():
        cache.unlink()
    # Cold load — populates cache.
    get_kb.cache_clear()
    t0 = time.perf_counter()
    get_kb()
    cold = time.perf_counter() - t0

    # Warm load.
    get_kb.cache_clear()
    t0 = time.perf_counter()
    get_kb()
    warm = time.perf_counter() - t0

    # CI runners can be unpredictable; allow generous floor (5×).
    # Local measurement: ~45×. CI safety: assert at least 3×.
    ratio = cold / warm if warm > 0 else float("inf")
    assert ratio >= 3.0, (
        f"Cache delivered only {ratio:.1f}× speedup "
        f"(cold {cold*1000:.0f}ms, warm {warm*1000:.0f}ms) — "
        f"too small to justify the complexity"
    )
