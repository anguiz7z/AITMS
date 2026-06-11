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
- 2026-06-11 — honesty doc-fixes staged on a Jarvis branch (Ollama comment, stale LIMITATIONS). Validated: real tool, ~85% complete, 121 playbooks.
