# AITMS — context capsule

## Global constraints
- Owner on a **Singapore Employment Pass** — no personal operate/earn. AITMS stays free/open-source (Apache-2.0) for now; it's the hero free tool of the brand.
- Strategy: free AI-security brand → distribute → monetize later. See Jarvis vault `E:\Jarvis\memory\MOC.md`.

## This repo
- **Role:** flagship free TOOL — a local, deterministic, fully-offline AI threat modeler (maps to OWASP LLM/Agentic, MITRE ATLAS, NIST AI RMF). Python.
- **Source of truth:** github `anguiz7z/AITMS` (PUBLIC). Owner's canonical working copy = `E:\AI_Projects\4Project\atms`. This Jarvis clone is secondary.
- **Deploy:** N/A (CLI tool + Windows installer). Distribution = GitHub + a launch (Show HN / r/netsec / LinkedIn) — that's the open opportunity (0 stars).

## DO NOT BREAK
- The **AI-free deterministic core** is the whole pitch: no LLM/API in the analysis path. The ONLY AI touchpoint is the opt-in `vision` feature (`ATMS_FEATURE_VISION=1`, default OFF), which runs on **LOCAL Ollama — zero API cost** (it once needed a paid Anthropic key but was re-implemented on Ollama; `src/atms/features.py:89-91` is canonical — do NOT "correct" it back to Anthropic).
- "No real attack payloads in this repo" trust story — preserve it.
- Positioning/capability framing in the README is the OWNER's decision; don't unilaterally rewrite it.

## Gated (owner)
- Public launch posts (first-contact), any spend.

## Current state
- **2026-06-11 — FINALIZED. DO NOT RESUME build work without an explicit owner request.** CSA-alignment + GitHub-survey adoption program complete and **merged to main** (PR #3 → b0fa427). Added: causal attack-graph (A-08 fix), choke-point ranking, CBRA capabilities risk, AICM control+ownership mapping, `tm-from-image` skill, docs/CSA-ALIGNMENT.md. Then PR #4 → e18213c (report-diagrams): the standalone HTML report is now **fully self-contained/offline** (bundled Mermaid inlined — no jsDelivr CDN; verified rendering with the browser forced offline) and the Attack-paths section carries a **visual combined attack-path graph** (entry/target/choke colour-coding, funnel arrows) on top of the choke-point table. Suite 1231 passed/0 fail; full CI matrix green (3.11–3.13 × ubuntu/windows, wheel-install, pip-audit, coverage≥86%, ruff strict). Demo delivered to owner as ONE comprehensive HTML report (aws_portfolio_agent → 113 threats / 10 paths / 380 mitigations / OWASP 10/10 / CBRA-High) + rendered diagram PNGs. Owner directive: focus on other areas.
- 2026-06-11 (earlier) — honesty doc-fixes (Ollama comment, stale LIMITATIONS). Validated: real tool, 121 playbooks.
