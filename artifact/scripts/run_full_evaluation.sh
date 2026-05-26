#!/usr/bin/env bash
# ProvShield Full Evaluation
# ==========================
# Runs all attack suites, benign tasks, ablation study, and generates tables.
# This is the Level 3 reproducibility script that produces paper-ready results.
#
# Usage:
#   bash artifact/scripts/run_full_evaluation.sh [--policy PATH] [--seed N] [--results-dir PATH]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Defaults
POLICY="${REPO_ROOT}/artifact/configs/default_policy.yaml"
SEED=42
RESULTS_DIR="${REPO_ROOT}/artifact/results/full"
PYTHON="${PYTHON:-python}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --policy)       POLICY="$2"; shift 2 ;;
        --seed)         SEED="$2"; shift 2 ;;
        --results-dir)  RESULTS_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

export PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH:-}"

echo "========================================================"
echo " ProvShield Full Evaluation"
echo "========================================================"
echo "Policy:        ${POLICY}"
echo "Seed:          ${SEED}"
echo "Results dir:   ${RESULTS_DIR}"
echo "Python:        ${PYTHON}"
echo "========================================================"
echo ""

mkdir -p "${RESULTS_DIR}"

# Track timing
EVAL_START=$(date +%s)

# -----------------------------------------------------------------------
# Phase 1: Attack Suites
# -----------------------------------------------------------------------
echo "=== Phase 1: Attack Suites ==="
ATTACK_DIR="${RESULTS_DIR}/attacks"
mkdir -p "${ATTACK_DIR}"

SUITES=("skill_injection" "mcp_metadata_poisoning" "mcp_safety" "web_email_injection" "rag_injection" "adaptive_white_box")

for suite in "${SUITES[@]}"; do
    echo ""
    echo "--- Suite: ${suite} ---"
    ${PYTHON} -m provshield.run_suite \
        --suite-type attack \
        --suite-name "${suite}" \
        --scenarios-dir eval/attack_suite_plan.yaml \
        --policy "${POLICY}" \
        --seed "${SEED}" \
        --results-dir "${ATTACK_DIR}/${suite}" \
        2>&1 | tee "${ATTACK_DIR}/${suite}.log"
done

# -----------------------------------------------------------------------
# Phase 2: Benign Tasks
# -----------------------------------------------------------------------
echo ""
echo "=== Phase 2: Benign Tasks ==="
BENIGN_DIR="${RESULTS_DIR}/benign"
mkdir -p "${BENIGN_DIR}"

CATEGORIES=("browser" "email" "mcp" "skills" "mixed")

for category in "${CATEGORIES[@]}"; do
    echo ""
    echo "--- Category: ${category} ---"
    ${PYTHON} -m provshield.run_suite \
        --suite-type benign \
        --category "${category}" \
        --scenarios-dir eval/benign_tasks.yaml \
        --policy "${POLICY}" \
        --seed "${SEED}" \
        --results-dir "${BENIGN_DIR}/${category}" \
        2>&1 | tee "${BENIGN_DIR}/${category}.log"
done

# -----------------------------------------------------------------------
# Phase 3: Ablation Study (A0-A8)
# -----------------------------------------------------------------------
echo ""
echo "=== Phase 3: Ablation Study ==="
ABLATION_DIR="${RESULTS_DIR}/ablation"
mkdir -p "${ABLATION_DIR}"

ABLATIONS=("A0_full" "A1_no_labels" "A2_no_monitor" "A3_no_bridge_binding"
           "A4_trust_metadata" "A5_no_capability_token"
           "A6_confidentiality_only" "A7_integrity_only" "A8_no_audit")

for ablation in "${ABLATIONS[@]}"; do
    echo ""
    echo "--- Ablation: ${ablation} ---"
    ${PYTHON} -m provshield.run_suite \
        --suite-type ablation \
        --ablation "${ablation}" \
        --scenarios-dir eval/attack_suite_plan.yaml \
        --policy "${POLICY}" \
        --seed "${SEED}" \
        --results-dir "${ABLATION_DIR}/${ablation}" \
        2>&1 | tee "${ABLATION_DIR}/${ablation}.log"
done

# -----------------------------------------------------------------------
# Phase 4: Baseline Comparisons
# -----------------------------------------------------------------------
echo ""
echo "=== Phase 4: Baseline Comparisons ==="
BASELINE_DIR="${RESULTS_DIR}/baselines"
mkdir -p "${BASELINE_DIR}"

BASELINES=("no_defense" "prompt_hardening" "input_firewall" "generic_confirmation")

for baseline in "${BASELINES[@]}"; do
    echo ""
    echo "--- Baseline: ${baseline} ---"
    ${PYTHON} -m provshield.run_suite \
        --suite-type baseline \
        --baseline "${baseline}" \
        --scenarios-dir eval/attack_suite_plan.yaml \
        --policy "${POLICY}" \
        --seed "${SEED}" \
        --results-dir "${BASELINE_DIR}/${baseline}" \
        2>&1 | tee "${BASELINE_DIR}/${baseline}.log"
done

# -----------------------------------------------------------------------
# Phase 5: Analysis and Table Generation
# -----------------------------------------------------------------------
echo ""
echo "=== Phase 5: Analysis ==="
${PYTHON} "${SCRIPT_DIR}/analyze_results.py" \
    --results-dir "${RESULTS_DIR}" \
    --output-dir "${RESULTS_DIR}/tables"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
EVAL_END=$(date +%s)
ELAPSED=$((EVAL_END - EVAL_START))
ELAPSED_MIN=$((ELAPSED / 60))
ELAPSED_SEC=$((ELAPSED % 60))

echo ""
echo "========================================================"
echo " Full Evaluation Complete"
echo "========================================================"
echo "Elapsed:       ${ELAPSED_MIN}m ${ELAPSED_SEC}s"
echo "Results:       ${RESULTS_DIR}"
echo "Tables:        ${RESULTS_DIR}/tables/"
echo "========================================================"

# Write manifest
cat > "${RESULTS_DIR}/manifest.json" <<EOF
{
  "policy": "${POLICY}",
  "seed": ${SEED},
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "elapsed_seconds": ${ELAPSED},
  "suites": ["${SUITES[*]}"],
  "ablations": ["${ABLATIONS[*]}"],
  "baselines": ["${BASELINES[*]}"]
}
EOF

echo "Manifest written to ${RESULTS_DIR}/manifest.json"
