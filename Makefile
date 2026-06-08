# ATMS — Make targets for common developer + CI tasks.
#
# All targets that touch Python set PYTHONPATH=src so the editable
# `atms` package resolves without needing `pip install -e .`. Tested
# with GNU make on Linux/macOS and mingw32-make / Git Bash on Windows.
#
# Try `make help` to discover available targets.
# v0.18.62 Phase N — Makefile surfaces what pyproject.toml comments
# used to hide. Run `make help` once and you'll never need to remember
# the right pytest flags again.

.DEFAULT_GOAL := help

PY ?= python
PYTHONPATH := src

# ─── Canonical pytest invocations ─────────────────────────────────────────
# Sourced from pyproject.toml's addopts comment (kept there too so the
# pytest config remains self-documenting if you skip the Makefile).
PYTEST_FAST     := $(PY) -m pytest -q -m "not slow"
PYTEST_PARALLEL := $(PY) -m pytest -q -m "not slow" -n auto --dist=loadfile

# ─── Help / discovery ─────────────────────────────────────────────────────

help: ## Show this help (target list + one-line descriptions)
	@awk 'BEGIN{FS=":.*?## "; printf "ATMS — make targets\n\n"} \
	  /^[a-zA-Z_-]+:.*?##/{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}' \
	  $(MAKEFILE_LIST) | sort
	@echo
	@echo "Tips:"
	@echo "  - Set PY=python3 to override the Python binary."
	@echo "  - For one-shot analyse: make analyze SAMPLE=samples/rag_system.yaml"

# ─── Testing ──────────────────────────────────────────────────────────────

test: ## Run the fast test suite sequentially (default — best for dev iteration)
	PYTHONPATH=$(PYTHONPATH) $(PYTEST_FAST)

test-parallel: ## Run the fast suite in parallel via xdist (fastest CI form)
	PYTHONPATH=$(PYTHONPATH) $(PYTEST_PARALLEL)

test-all: ## Run the FULL suite incl. slow + perf-regression tests
	PYTHONPATH=$(PYTHONPATH) $(PY) -m pytest -q

test-changed: ## Run only tests whose files changed since last commit
	PYTHONPATH=$(PYTHONPATH) $(PY) -m pytest -q -m "not slow" --picked

# ─── Coverage ─────────────────────────────────────────────────────────────

coverage: ## Run the fast suite with coverage reporting (local dev)
	PYTHONPATH=$(PYTHONPATH) $(PY) -m pytest --cov -m "not slow"

coverage-ci: ## Run coverage + enforce the 86% floor (matches CI)
	PYTHONPATH=$(PYTHONPATH) $(PY) -m pytest --cov -m "not slow" --cov-fail-under=86

coverage-html: ## Generate an HTML coverage report under htmlcov/
	PYTHONPATH=$(PYTHONPATH) $(PY) -m pytest --cov --cov-report=html -m "not slow"
	@echo "Open htmlcov/index.html in your browser."

coverage-keep: ## KEEP-path coverage (excludes hibernated modules) — the honest v1.0 floor
	$(PY) scripts/keep_coverage.py

coverage-keep-ci: ## KEEP-path coverage + enforce the 75% floor (Roadmap V5)
	$(PY) scripts/keep_coverage.py --fail-under 75

# ─── Linting / typing ─────────────────────────────────────────────────────

lint: ## Lint src/ + tests/ with ruff
	$(PY) -m ruff check src tests

lint-fix: ## Auto-fix ruff issues where the fix is safe
	$(PY) -m ruff check src tests --fix

mypy: ## Run mypy (non-strict — see pyproject.toml [tool.mypy])
	$(PY) -m mypy src

# ─── ATMS CLI shortcuts ───────────────────────────────────────────────────

selftest: ## Run `atms selftest` on the bundled sample fleet (11 samples)
	PYTHONPATH=$(PYTHONPATH) $(PY) -m atms.cli selftest

web: ## Start the local web UI (http://127.0.0.1:8765)
	PYTHONPATH=$(PYTHONPATH) $(PY) -m atms.cli web

analyze: ## Analyse one sample (usage: make analyze SAMPLE=path/to.yaml)
	@if [ -z "$(SAMPLE)" ]; then \
	  echo "Usage: make analyze SAMPLE=samples/rag_system.yaml"; exit 1; \
	fi
	PYTHONPATH=$(PYTHONPATH) $(PY) -m atms.cli analyze $(SAMPLE) --out output

version: ## Print the current ATMS version
	@PYTHONPATH=$(PYTHONPATH) $(PY) -m atms.cli version

# ─── Generated artefacts + CI drift guards ────────────────────────────────

palette: ## Regenerate static/palette-data.json from models + KB synonyms
	PYTHONPATH=$(PYTHONPATH) $(PY) scripts/gen_palette.py

palette-check: ## CI guard — fail if palette-data.json is stale vs. models
	PYTHONPATH=$(PYTHONPATH) $(PY) scripts/gen_palette.py --check

schema: ## Regenerate docs/system.schema.json from atms.models.System
	PYTHONPATH=$(PYTHONPATH) $(PY) scripts/gen_schema.py

schema-check: ## CI guard — fail if system.schema.json is stale vs. models
	PYTHONPATH=$(PYTHONPATH) $(PY) scripts/gen_schema.py --check

drift-check: ## CI guard — fail if docs/ARCHITECTURE.mmd is stale vs. src/
	PYTHONPATH=$(PYTHONPATH) $(PY) scripts/check_architecture_drift.py

# ─── Build + release ──────────────────────────────────────────────────────

build: palette ## Build the Python wheel (regenerates palette first)
	$(PY) -m build

verify-wheel: ## Build the wheel, install into a throwaway venv, run selftest
	$(PY) scripts/verify_wheel.py

build-exe: ## Build the standalone Windows .exe via PyInstaller
	$(PY) scripts/build_exe.py

build-installer: ## Build the Windows installer (.exe -> ATMS-Setup-<ver>.exe)
	$(PY) scripts/build_installer.py

# ─── Maintenance ──────────────────────────────────────────────────────────

install: ## Install ATMS + dev dependencies in editable mode
	$(PY) -m pip install -e ".[dev]"

clean: ## Remove all generated artefacts (caches, output/, build, htmlcov)
	rm -rf output/* .pytest_cache .mypy_cache .ruff_cache \
	       dist build htmlcov .coverage coverage.json \
	       .atms_kb_cache.pkl .atms_kb_cache.pkl.tmp .atms_kb_cache.key
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned."

# ─── Phase pipeline (used by CI) ──────────────────────────

ci: lint test-parallel coverage-ci selftest ## Run the full local CI bundle

.PHONY: help test test-parallel test-all test-changed \
        coverage coverage-ci coverage-html coverage-keep coverage-keep-ci \
        lint lint-fix mypy \
        selftest web analyze version \
        palette palette-check schema schema-check drift-check \
        build verify-wheel build-exe build-installer \
        install clean ci
