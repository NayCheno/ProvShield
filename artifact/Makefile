.PHONY: smoke eval eval-subset eval-expanded paper replay clean install check all

PYTHON ?= python
RESULTS_DIR ?= eval/results
SEED ?= 42

install:
	$(PYTHON) -m pip install -r requirements.txt

check:
	$(PYTHON) -m pytest tests/ -v --tb=short

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
# Level 3: Expanded evaluation — 700+ scenarios
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
	$(PYTHON) tools/replay_audit.py --trace $(RESULTS_DIR)/traces.jsonl --policy artifact/configs/default_policy.yaml

# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------
all: smoke eval paper replay

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
clean:
	rm -rf $(RESULTS_DIR)
	rm -rf eval/results/tables
	rm -rf artifact/results
	@echo "Cleaned generated artifacts."
