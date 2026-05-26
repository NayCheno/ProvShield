"""Run LLM-based evaluation across multiple models.

Supports 3 model tiers:
- Frontier: mimo-v2.5-pro
- Mid-tier: mimo-v2.5
- Open/Local: mimo-v2-pro (or mimo-v2-omni)

Usage:
    python eval/scripts/run_multi_model_eval.py
    python eval/scripts/run_multi_model_eval.py --models mimo-v2.5-pro mimo-v2.5 mimo-v2-pro
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent

DEFAULT_MODELS = ["mimo-v2.5-pro", "mimo-v2.5", "mimo-v2-pro"]


def run_eval_for_model(model: str) -> dict:
    """Run LLM evaluation for a single model."""
    print(f"\n{'='*60}")
    print(f" Running evaluation for: {model}")
    print(f"{'='*60}\n")

    result = subprocess.run(
        [sys.executable, str(_root / "eval" / "scripts" / "llm_eval_harness.py"), "--model", model],
        cwd=str(_root),
        capture_output=True,
        text=True,
        timeout=600,
    )

    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    # Load results
    results_path = _root / "eval" / "results" / "llm_evaluation_results.json"
    if results_path.exists():
        data = json.loads(results_path.read_text())
        return {
            "model": model,
            "summary": data.get("summary", {}),
            "results_count": len(data.get("results", [])),
        }
    return {"model": model, "error": "no results file"}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    args = parser.parse_args()

    all_results = []
    for model in args.models:
        result = run_eval_for_model(model)
        all_results.append(result)

    # Print comparison table
    print("\n" + "=" * 60)
    print(" MULTI-MODEL EVALUATION COMPARISON")
    print("=" * 60)
    print(f"\n{'Model':<20} {'ASR':>8} {'Manip%':>8} {'Block%':>8} {'BTCR':>8}")
    print("-" * 52)

    for r in all_results:
        s = r.get("summary", {})
        print(f"{r['model']:<20} "
              f"{s.get('overall_asr', 0):>7.1%} "
              f"{s.get('llm_manipulation_rate', 0):>7.1%} "
              f"{s.get('ps_block_rate', 0):>7.1%} "
              f"{s.get('benign_completion', 0):>7.1%}")

    # Save combined results
    output_path = _root / "eval" / "results" / "multi_model_results.json"
    with open(output_path, "w") as f:
        json.dump({"models": all_results}, f, indent=2)
    print(f"\nCombined results saved to {output_path}")


if __name__ == "__main__":
    main()
