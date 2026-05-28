.PHONY: smoke eval eval-subset eval-expanded paper replay clean install check all lint compile-check artifact-check

PYTHON ?= python
RESULTS_DIR ?= eval/results
SEED ?= 42

install:
	$(PYTHON) -m pip install -r requirements.txt

check:
	$(PYTHON) -m pytest tests/ -q --tb=short

lint:
	$(PYTHON) -m pytest tests/ -q --tb=short

# ---------------------------------------------------------------------------
# Compile check — all Python scripts must compile cleanly
# ---------------------------------------------------------------------------
compile-check:
	@echo "Checking eval scripts..."
	@for f in eval/scripts/*.py; do $(PYTHON) -m py_compile "$$f" || exit 1; done
	@echo "Checking artifact scripts..."
	@for f in artifact/scripts/*.py; do $(PYTHON) -m py_compile "$$f" || exit 1; done
	@echo "Checking tools..."
	@for f in tools/*.py; do $(PYTHON) -m py_compile "$$f" || exit 1; done
	@echo "Checking tests..."
	@for f in tests/*.py; do $(PYTHON) -m py_compile "$$f" || exit 1; done
	@echo "All scripts compile cleanly."

# ---------------------------------------------------------------------------
# Artifact check — full validation for submission
# ---------------------------------------------------------------------------
artifact-check: check compile-check
	@echo "Running smoke test..."
	$(PYTHON) artifact/scripts/run_smoke_test.py
	@echo "Running table generation..."
	$(PYTHON) artifact/scripts/analyze_results.py \
		--results-dir $(RESULTS_DIR) \
		--output-dir $(RESULTS_DIR)/tables
	@echo "Running audit replay..."
	@if [ -f "$(RESULTS_DIR)/traces.jsonl" ]; then \
		$(PYTHON) tools/replay_audit.py --trace $(RESULTS_DIR)/traces.jsonl --policy artifact/configs/default_policy.yaml; \
	else \
		echo "No traces.jsonl found — skipping replay."; \
	fi
	@echo "Artifact check complete."

# ---------------------------------------------------------------------------
# Level 1: Smoke test — 10 scenarios, ~10s
# ---------------------------------------------------------------------------
smoke:
	$(PYTHON) artifact/scripts/run_smoke_test.py

# ---------------------------------------------------------------------------
# Level 2: Standard evaluation — 32 scenarios + baselines
# ---------------------------------------------------------------------------
eval:
	$(PYTHON) eval/scripts/run_evaluation.py

# ---------------------------------------------------------------------------
# Level 2: Subset evaluation — standard eval + smoke test
# ---------------------------------------------------------------------------
eval-subset:
	$(PYTHON) eval/scripts/run_evaluation.py
	$(PYTHON) artifact/scripts/run_smoke_test.py

# ---------------------------------------------------------------------------
# Level 3: Expanded evaluation — 780 scenarios
# ---------------------------------------------------------------------------
eval-expanded:
	$(PYTHON) eval/scripts/generate_llm_scenarios.py 500 200
	$(PYTHON) eval/scripts/run_expanded_eval.py

# ---------------------------------------------------------------------------
# Analysis — generate tables from completed results
# ---------------------------------------------------------------------------
paper:
	$(PYTHON) artifact/scripts/analyze_results.py \
		--results-dir $(RESULTS_DIR) \
		--output-dir $(RESULTS_DIR)/tables

# ---------------------------------------------------------------------------
# Deterministic audit replay
# ---------------------------------------------------------------------------
replay:
	@if [ -f "$(RESULTS_DIR)/traces.jsonl" ]; then \
		$(PYTHON) tools/replay_audit.py --trace $(RESULTS_DIR)/traces.jsonl --policy artifact/configs/default_policy.yaml; \
	else \
		echo "No traces.jsonl found — skipping replay (run eval-expanded first)."; \
	fi
# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------
all: check smoke eval paper replay

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
clean:
	rm -rf $(RESULTS_DIR)
	rm -rf eval/results/tables
	rm -rf artifact/results
	@echo "Cleaned generated artifacts."
