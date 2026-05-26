.PHONY: smoke attack benign ablation paper clean install check eval

PYTHON ?= python
RESULTS_DIR ?= eval/results
SEED ?= 42

install:
	$(PYTHON) -m pip install -r requirements.txt

check:
	$(PYTHON) -m pytest tests/ -v --tb=short

# ---------------------------------------------------------------------------
# Level 1: Smoke test — 5 attacks + 5 benign, ~10s
# ---------------------------------------------------------------------------
smoke:
	$(PYTHON) artifact/scripts/run_smoke_test.py

# ---------------------------------------------------------------------------
# Level 2+3: Full evaluation via harness
# ---------------------------------------------------------------------------
eval:
	$(PYTHON) eval/scripts/run_evaluation.py

# ---------------------------------------------------------------------------
# Analysis — generate tables from completed results
# ---------------------------------------------------------------------------
paper:
	$(PYTHON) artifact/scripts/analyze_results.py \
		--results-dir $(RESULTS_DIR) \
		--output-dir $(RESULTS_DIR)/tables

# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------
all: smoke eval paper

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
clean:
	rm -rf $(RESULTS_DIR)
	rm -rf eval/results/tables
	rm -rf artifact/results
	@echo "Cleaned generated artifacts."
