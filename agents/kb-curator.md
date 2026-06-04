---
role: kb-curator
summary: Owns the curated knowledge base under kb/ — OWASP LLM/Agentic, MITRE ATLAS, MAESTRO, NIST AI RMF entries, and the per-component-type playbooks.
---

# Knowledge-base curator

This guide covers work in `kb/`: adding or editing framework entries
(OWASP LLM Top 10, OWASP Agentic, MITRE ATLAS, MAESTRO, NIST AI RMF),
maintaining the per-component playbooks under `kb/playbooks/`, and
refreshing curated knowledge against upstream sources. Use it for tasks
like "add a playbook", "add a framework", "refresh the KB", or "add a new
threat to component type X". It does NOT cover changes outside `kb/`.

## Area of ownership

- `kb/owasp_llm/*.yaml` — OWASP LLM Top 10 (2025).
- `kb/owasp_agentic/*.yaml` — OWASP Agentic AI Threats and Mitigations.
- `kb/mitre_atlas/{tactics,techniques,mitigations}.yaml` — MITRE ATLAS
  curated subset.
- `kb/maestro/{layers,threats}.yaml` — CSA MAESTRO framework.
- `kb/nist_ai_rmf/genai_profile.yaml` — NIST AI 600-1.
- `kb/playbooks/<component_type>.yaml` — per-component-type threat
  catalogues.
- `kb/stride_ai_matrix.yaml` — STRIDE-AI per-element subcategories.

This does NOT include anything in `src/`, `tests/`, or other folders. If a
change requires a Python edit (e.g. adding a new component type to
`models.py:ComponentType`), that is a separate task — note it and stop.

## Hard rules

1. **Every YAML must round-trip through `yaml.safe_load`.** Verify with
   `python -c "import yaml; yaml.safe_load(open('kb/<your-file>.yaml'))"`.

2. **Cite sources.** Every framework entry references an authoritative
   source. Add a `## Sources` footer or a `source:` field with the
   canonical URL and the retrieval date.

3. **Never invent IDs.** Every ATLAS technique ID, OWASP LLM ID, OWASP
   Agentic ID, and MAESTRO threat ID you reference must exist in the
   published catalogue. If unsure, mark it with `# needs verification` so
   the framework validator can confirm.

4. **Match the existing schema.** Open an existing playbook (e.g.
   `kb/playbooks/agent.yaml`) and mirror its shape exactly — keys,
   ordering, indentation, multiline-`|` style.

5. **Component-type literal.** A new playbook for component type `X`
   requires `X` to also exist in `src/atms/models.py:ComponentType`. If your
   task implies a new type and the literal doesn't already include it, that
   addition is a separate Python task that must land first.

## Verification

After every change, run from the repo root:

```bash
python -c "import yaml, glob; [yaml.safe_load(open(p)) for p in glob.glob('kb/**/*.yaml', recursive=True)]; print('all yaml ok')"
python -m pytest tests/test_kb.py tests/test_engines.py -q
PYTHONPATH=src python -m atms.cli selftest
```

All three must pass before the task is complete. If any sample's threat
count drops unexpectedly, that's a regression — investigate first.

## What "done" looks like

- Diff is contained to `kb/`.
- New playbooks have at least 3 threats, each with `stride_ai`, `owasp_llm`
  (or `owasp_agentic`), `atlas`, `likelihood`, `impact`, `description`,
  `mitigations`, and `refs`.
- A short summary of: files added/modified, threat-count delta on the
  affected sample(s), and follow-ups elsewhere (Python edits, doc updates).
