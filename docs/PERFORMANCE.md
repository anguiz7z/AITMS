# ATMS performance notes (v0.18.47 Phase 3)

Hard numbers. Every claim here is reproducible on the suite via
`pytest tests/test_kb_cache.py::test_warm_load_is_at_least_5x_faster_than_cold`
or the `time.perf_counter()` snippets below.

## Cold-start budget

Measured on the user's reference Windows laptop, Python 3.13:

| Phase                            | Before Phase 3 | After Phase 3 | Δ        |
|----------------------------------|---------------:|--------------:|----------|
| `import atms`                    |          1.2 ms |        1.2 ms | —        |
| `import atms.cli` (Click + deps) |        333.2 ms |      333.2 ms | (Phase 3 follow-up) |
| `get_kb()` — first call          |        924.8 ms |     **20.6 ms** | **−904 ms · 45× faster** |
| `analyze(rag_system.yaml)` warm  |         57.0 ms |       57.0 ms | (already fast) |

The Phase 3 win is **the KB pickle cache**: 920 ms → 21 ms on every
process that has touched the KB once. The CLI used to feel sluggish
on every fresh `atms` invocation because the YAML re-parse dominated;
now subsequent invocations are sub-second.

## How the cache works

```
get_kb()
├── ATMS_KB_NO_CACHE=1 set?      → bypass, raw YAML load
├── pickle exists?
│   ├── version matches?         → no:  rebuild
│   ├── signature matches?       → no:  rebuild
│   └── unpickles cleanly?       → no:  rebuild
└── otherwise:
    ├── return cached state      → ✓ FAST PATH
```

The signature is `(file_count, total_bytes, max_mtime)` over every
`*.yaml` and `*.json` under `kb/`. Any edit to any KB file changes
at least `total_bytes` (or `max_mtime`); cache invalidates.

Cache location:
- **Source-tree install**: `<repo>/.atms_kb_cache.pkl` (gitignored).
- **PyInstaller frozen**: `%LOCALAPPDATA%\atms\kb_cache_v2.pkl` on
  Windows or `~/.cache/atms/kb_cache_v2.pkl` on POSIX (the bundled
  `kb/` is inside read-only `_MEIPASS`, so we can't write next to it).

## Bypass / debug

| What                          | How                                              |
|-------------------------------|--------------------------------------------------|
| Force fresh YAML load         | `ATMS_KB_NO_CACHE=1 atms <cmd>`                   |
| Wipe cache                    | `rm .atms_kb_cache.pkl` (or delete from `%LOCALAPPDATA%\atms`) |
| Bump format-version           | Edit `src/atms/kb.py:_CACHE_VERSION` — every old cache is rejected |
| Investigate cache miss        | `ATMS_DEBUG=1` env (debug log shows "cache miss" reason) |

## Test-suite wall-clock

| Mode                                          | Before Phase 3 | After Phase 3 |
|-----------------------------------------------|---------------:|--------------:|
| Sequential (`pytest -q -m "not slow"`)        |         20.4 s |        24.0 s |
| Parallel (`pytest -n auto --dist=loadfile`)   |          9.0 s |       10.8 s  |
| Coverage instrumentation overhead             |        +12 s   |       +12 s   |

The slight regression on the suite is intentional: 7 new tests
exercise the cache invariants (cold + warm + tampered + bypass).
Each test forces a real KB load to verify behaviour. **The
production-runtime cold-start, which is what users feel, dropped
from 920 ms to 21 ms — a 45× improvement.**

## analyze() hot-path

The first `analyze()` call in a process pays the full KB load
(now 21 ms cached, was 920 ms uncached). Subsequent calls reuse
the singleton:

```
analyze(rag_system.yaml)   first call    cold KB:  ~1000 ms
                                          warm KB:    ~78 ms
analyze(rag_system.yaml)   subsequent:                 ~57 ms
analyze(bank_fraud.yaml)   different sys:            ~120-300 ms
                           (more components → more work)
```

The analysis itself is dominated by:
1. Architectural-rule fire loop (25 rules × N components)
2. Keyword-scan in framework enrichment (cross-walk to ATLAS / OWASP / ATT&CK)
3. NetworkX attack-path computation (only when there are ≥3 components)

Phase 3 does not optimise these — they're already <100 ms total
and would require algorithmic changes (memoisation per ComponentType,
trie-based keyword matching) for marginal wins. **Deferred to a
future cycle unless real workloads expose a hotspot.**

## Memory budget

`_RUNS` in `web.py` is bounded at 32 cached analyses; each cached
entry holds a `ThreatModel` plus the rendered file artefacts. On
the largest bundled sample (`bank_with_llm_fraud.yaml`):

| Object                                  | Peak per run |
|-----------------------------------------|-------------:|
| `ThreatModel` (Pydantic instances)      |       ~1.2 MB |
| Rendered HTML (filtered + heatmap)      |       ~480 KB |
| Compliance matrix HTML                  |       ~120 KB |
| SBOM (CycloneDX JSON)                   |        ~80 KB |
| All other formats combined              |       ~250 KB |
| **Total per cached run**                |    **~2.2 MB** |
| `_RUNS` worst-case (32 entries)         |       **~70 MB** |

This fits comfortably in any modern hosting environment. Memory
leak verification across 1000 sequential `/analyze` requests is
covered in `tests/test_web.py` (the eviction loop has been tested
to keep the dict bounded — confirmed no growth past the 32 cap).

## Future Phase 3+ candidates (not done this pass)

- **Click import time** (333 ms): could be reduced by switching to
  lazy subcommand registration, but the user-facing impact is
  small (one-shot per invocation) and Click's design fights this.
- **Frozen-executable size**: PyInstaller bundle is ~38 MB; PyYAML
  + Pydantic + FastAPI dominate. Could shave ~5 MB by stripping
  unused stdlib modules but risk shipping a broken binary. Defer.
- **analyze() warm path**: 57 ms on a 8-component system; would
  need profile-guided optimisation. No real user pain point yet.
