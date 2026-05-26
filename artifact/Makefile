.PHONY: smoke attack benign ablation paper clean install check

PYTHON ?= python
RESULTS_DIR ?= artifact/results
POLICY ?= artifact/configs/default_policy.yaml
SEED ?= 42

install:
	$(PYTHON) -m pip install -r requirements.txt

check:
	$(PYTHON) -m pytest tests/ -v --tb=short

# ---------------------------------------------------------------------------
# Level 1: Smoke test — 5 attacks + 5 benign, ~2 min
# ---------------------------------------------------------------------------
smoke: install
	bash artifact/scripts/run_smoke_test.sh --policy $(POLICY) --seed $(SEED) --results-dir $(RESULTS_DIR)/smoke

# ---------------------------------------------------------------------------
# Level 2: Paper subsets
# ---------------------------------------------------------------------------
attack: install
	$(PYTHON) -m provshield.run_suite \
		--suite-type attack \
		--scenarios-dir eval/attack_suite_plan.yaml \
		--policy $(POLICY) \
		--seed $(SEED) \
		--results-dir $(RESULTS_DIR)/attacks

benign: install
	$(PYTHON) -m provshield.run_suite \
		--suite-type benign \
		--scenarios-dir eval/benign_tasks.yaml \
		--policy $(POLICY) \
		--seed $(SEED) \
		--results-dir $(RESULTS_DIR)/benign

# ---------------------------------------------------------------------------
# Level 3: Full evaluation — attacks + benign + ablations
# ---------------------------------------------------------------------------
ablation: install
	$(PYTHON) -m provshield.run_suite \
		--suite-type ablation \
		--scenarios-dir eval/attack_suite_plan.yaml \
		--ablation-plan eval/ablation_plan.md \
		--policy $(POLICY) \
		--seed $(SEED) \
		--results-dir $(RESULTS_DIR)/ablation

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
all: smoke attack benign ablation paper

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
clean:
	rm -rf $(RESULTS_DIR)
	rm -rf artifact/data/attacks artifact/data/benign
	@echo "Cleaned generated artifacts."
