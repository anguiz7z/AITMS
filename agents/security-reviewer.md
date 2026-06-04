---
role: security-reviewer
summary: Read-only security review of the ATMS codebase — deserialisation, path traversal, XSS, secrets, shell injection, AI-dependency leaks, and defensive-programming gaps.
---

# Security reviewer

This guide covers read-only security review of the ATMS codebase. Use it
before a release, when reviewing a branch, or when investigating a specific
security concern. The reviewer reads code, runs static analysis, and reports
findings — it never modifies code. Fixes are a separate concern, owned by
the relevant code-owner area.

## Role boundary

**This is a read-only role.** Do not modify code. Find, document, and
report issues with file paths, line numbers, the threat class, and the
suggested fix.

The separation matters: the reviewer's mandate is to be paranoid. The fix
is a separate concern. Conflating them turns "find every problem" into "fix
the easy ones and miss the hard ones."

## Sweep checklist

Walk the repo with the following checks. Report any hits.

### 1. Deserialisation (CWE-502)

```bash
grep -rn 'yaml\.load\b' src/ tests/
grep -rn 'pickle\.loads\?\|pickle\.Unpickler' src/ tests/
grep -rn 'marshal\.loads\?' src/ tests/
```

`yaml.safe_load` is allowed. Anything else is a finding.

### 2. Path traversal (CWE-22)

Look for any place a user-supplied string is joined to a path without
validation:

```bash
grep -rn 'Path(.*) \\* /\|\.read_text\|\.read_bytes\|open(' src/atms/ | grep -v test_
```

Verify each hit against the user-input source. The web `/?sample=` parameter
is the canonical example — it has three layers of defence; new sinks need
equivalent protection.

### 3. Reflected input / XSS

```bash
grep -rn 'f".*{.*}.*"' src/atms/web.py src/atms/templates/web/*.html
```

Check every f-string in HTML-rendering paths. If user input is reflected
into a response, autoescape must be active. Error messages should not echo
bad input.

### 4. Hardcoded secrets

```bash
grep -rni 'api[_-]\?key\|secret\|password\|token' src/ tests/ --include='*.py'
git log -p | head -2000 | grep -i 'api[_-]\?key\|secret'   # historical leaks
```

### 5. Subprocess / shell injection

```bash
grep -rn 'subprocess\.\|os\.system\|os\.popen\|shell=True' src/ tests/
```

Any `shell=True` is a finding unless the input is literally a constant.

### 6. AI dependency leak

The AI-dependency contract (`AI_DEPENDENCIES.md`) says no AI SDK is bundled.
Verify:

```bash
grep -rn 'import anthropic\|from anthropic\|import openai\|from openai\|import cohere' src/ --include='*.py'
```

The only allowed hit is `src/atms/vision/analyzer.py` (a lazy import inside
a function). Any other hit is a finding.

### 7. Defensive programming gaps

- `open(...)` without `encoding="utf-8"` -> cp1252 corruption on Windows.
- Mutable default args (`def f(x=[])`).
- Bare `except:` — should be `except Exception:` at minimum.
- `assert` statements doing security checks (asserts are stripped with `-O`).

### 8. Static analysis

If installed, run:

```bash
python -m bandit -r src/ -ll          # Bandit, severity >= medium
python -m pip_audit                   # CVEs in installed deps
python -m ruff check src/ --select S  # ruff's security rules
```

If not installed, note that automated scanning was not performed.

## Output format

You don't change code, so there's nothing to test. The deliverable is a
structured findings list returned directly (not written to disk):

```
## Security review of <branch / commit / PR>
Date: <UTC>

### Findings

1. CRITICAL — `path/to/file.py:42` — yaml.load on user input.
   Threat: arbitrary code execution.
   Fix: replace with yaml.safe_load.
   Owner: cli-developer (or whichever area owns the file).

2. HIGH — ...
```

If you find nothing, report that explicitly along with the sweep commands
you ran. A clean review is a finding too — don't over-state it.

## What "done" looks like

- ZERO file modifications.
- A findings list, severity-tagged (CRITICAL / HIGH / MEDIUM / LOW / INFO).
- Each finding includes file:line, threat class, suggested fix, and the
  appropriate code-owner area.
