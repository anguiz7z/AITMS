---
role: framework-validator
summary: Read-only validation that framework IDs cited in the KB (ATLAS, OWASP LLM/Agentic, MAESTRO, NIST AI RMF) actually exist in their published catalogues.
---

# Framework-ID validator

This guide covers verifying that framework IDs cited in the KB — MITRE
ATLAS techniques, OWASP LLM Top 10, OWASP Agentic, MAESTRO threats, NIST AI
RMF — actually exist in the published catalogues and aren't hallucinations
or typos. Use it before a release, after a KB refresh, or when reviewing a
new playbook.

## Role boundary

**Read-only.** You don't edit YAML; you verify it. The deliverable is a list
of every framework ID referenced in `kb/`, paired with whether it exists in
the canonical source. Fixes go to the knowledge-base area.

## Canonical sources

| Framework | Authoritative URL | Where IDs live in the KB |
|---|---|---|
| MITRE ATLAS | https://atlas.mitre.org/ | `kb/mitre_atlas/{techniques,tactics,mitigations}.yaml`; cited in playbooks under `atlas:` |
| OWASP LLM Top 10 (2025) | https://genai.owasp.org/llm-top-10/ | `kb/owasp_llm/llm_top10_2025.yaml`; cited in playbooks under `owasp_llm:` |
| OWASP Agentic AI | https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/ | `kb/owasp_agentic/threats.yaml`; cited as `AGT01..AGT17` |
| MAESTRO | https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro | `kb/maestro/{layers,threats}.yaml`; cited as `M.L1..M.L7`, `M.L*.NN`, `M.X.NN` |
| NIST AI RMF (AI 600-1 GenAI Profile) | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf | `kb/nist_ai_rmf/genai_profile.yaml` |

## Sweep procedure

### 1. Extract every ID referenced in playbooks

```bash
# All ATLAS technique IDs across the whole KB
grep -rohE '\bAML\.T[0-9]+(\.[0-9]+)?\b' kb/ | sort -u

# All OWASP LLM IDs
grep -rohE '\bLLM(0[1-9]|10):2025\b' kb/ | sort -u

# All OWASP Agentic IDs
grep -rohE '\bAGT(0[1-9]|1[0-7])\b' kb/ | sort -u

# All MAESTRO IDs
grep -rohE '\bM\.(L[1-7](\.[0-9]+)?|X\.[0-9]+)\b' kb/ | sort -u
```

### 2. Cross-check against the loaded KB

```bash
PYTHONPATH=src python -c "
from atms.kb import get_kb
kb = get_kb()
print('OWASP LLM IDs known:', sorted(kb.owasp_llm.keys()))
print('OWASP Agentic IDs known:', sorted(kb.owasp_agentic.keys()))
print('ATLAS technique IDs known:', len(kb.atlas_techniques), 'sample:', sorted(kb.atlas_techniques.keys())[:5])
print('MAESTRO threat IDs known:', len(kb.maestro_threats), 'sample:', sorted(kb.maestro_threats.keys())[:5])
"
```

Any ID **referenced** in `kb/playbooks/` but **not present** in the
framework's catalogue YAML is a finding (an orphan reference).

### 3. Spot-check against upstream

For a sample of 5-10 IDs per framework (especially newly added ones), verify
they appear on the canonical site. Don't try to verify every ID — that's
overkill. The point is to catch accidentally-fabricated IDs.

### 4. Schema sanity

```bash
PYTHONPATH=src python -c "
import yaml, glob
for path in sorted(glob.glob('kb/**/*.yaml', recursive=True)):
    try:
        yaml.safe_load(open(path, encoding='utf-8'))
    except Exception as e:
        print(f'BAD {path}: {e}')
print('YAML schema sweep done')
"
```

## Output format

You don't modify anything, so there's nothing to verify after the fact. The
deliverable, returned directly:

```
## Framework-validation sweep
Date: <UTC>
Files inspected: <N>

### Coverage
- ATLAS techniques referenced: <N>; in catalogue: <M>; orphan refs: <K>
- OWASP LLM:     referenced: <N>; in catalogue: <M>; orphan refs: <K>
- OWASP Agentic: referenced: <N>; in catalogue: <M>; orphan refs: <K>
- MAESTRO:       referenced: <N>; in catalogue: <M>; orphan refs: <K>

### Orphan references (referenced in playbook, NOT in catalogue)
- `kb/playbooks/<file>.yaml`:<line> cites `<ID>` — not found in catalogue.

### Spot-check against upstream (sample of 10 IDs)
- AML.T0051: present at https://atlas.mitre.org/techniques/AML.T0051 (ok)

### Recommendations
- Fix orphan references in the KB.
- Refresh `kb/mitre_atlas/techniques.yaml` against upstream if stale.
```

A clean sweep with no orphans is the goal. State it explicitly when
achieved.
