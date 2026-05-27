#!/usr/bin/env python3
"""PR-9: Run baseline comparison with cached LLM responses.

Calls the LLM once per scenario, then evaluates all baselines
against the cached tool calls. Much faster than calling LLM per baseline.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_root / "src"))
sys.path.insert(0, str(_root / "eval" / "scripts"))

from baselines import ALL_BASELINES
from run_llm_eval_v2 import (
    build_attack_scenarios,
    build_benign_scenarios,
    call_llm,
    extract_tool_call,
    TOOLS_FOR_LLM,
)


def main():
    print("=" * 60)
    print(" PR-9: Baseline Comparison (cached LLM)")
    print("=" * 60)
    print()

    attack_scenarios = build_attack_scenarios()
    benign_scenarios = build_benign_scenarios()
    all_scenarios = attack_scenarios + benign_scenarios

    # Step 1: Call LLM once per scenario and cache results
    print("Phase 1: Calling LLM for all scenarios...")
    cached_calls = {}
    for i, scenario in enumerate(all_scenarios):
        print(f"  [{i+1}/{len(all_scenarios)}] {scenario.scenario_id}...", end=" ", flush=True)
        messages = [{"role": "system", "content": scenario.system_prompt}]
        messages.extend(scenario.context_messages)
        messages.append({"role": "user", "content": scenario.user_message})

        response = call_llm(messages, tools=TOOLS_FOR_LLM)
        tool_call = extract_tool_call(response)

        llm_tc = None
        if tool_call and tool_call.get("tool_name"):
            llm_tc = tool_call
        cached_calls[scenario.scenario_id] = llm_tc
        print(f"LLM={llm_tc['tool_name'] if llm_tc else 'none'}")

    # Step 2: Evaluate each baseline against cached calls
    print("\nPhase 2: Evaluating baselines...")
    all_summaries = {}

    for baseline in ALL_BASELINES:
        results = []
        for scenario in all_scenarios:
            llm_tc = cached_calls.get(scenario.scenario_id)

            baseline_decision = "allow"
            if llm_tc and llm_tc.get("tool_name"):
                baseline_decision = baseline.check(
                    llm_tc["tool_name"],
                    llm_tc.get("arguments", {}),
                    scenario.context_messages,
                )

            attack_succeeded = False
            if scenario.category == "attack" and llm_tc:
                if scenario.attack_success_tool:
                    attack_succeeded = (
                        llm_tc["tool_name"] == scenario.attack_success_tool
                        and baseline_decision == "allow"
                    )
                else:
                    attack_succeeded = baseline_decision == "allow"

            results.append({
                "scenario_id": scenario.scenario_id,
                "category": scenario.category,
                "llm_tool": llm_tc["tool_name"] if llm_tc else None,
                "baseline_decision": baseline_decision,
                "attack_succeeded": attack_succeeded,
            })

        attacks = [r for r in results if r["category"] == "attack"]
        benigns = [r for r in results if r["category"] == "benign"]
        asr = sum(1 for r in attacks if r["attack_succeeded"]) / len(attacks) if attacks else 0
        btc = sum(1 for r in benigns if r["baseline_decision"] == "allow") / len(benigns) if benigns else 0

        all_summaries[baseline.name] = {
            "asr": round(asr, 4),
            "benign_completion": round(btc, 4),
            "attack_scenarios": len(attacks),
            "benign_scenarios": len(benigns),
        }
        print(f"  {baseline.name:<25} ASR={asr:.1%}  Benign={btc:.1%}")

    # Step 3: Print comparison table
    print()
    print("=" * 60)
    print(" BASELINE COMPARISON TABLE")
    print("=" * 60)
    print()
    print(f"{'Defense':<25} {'ASR':>8} {'BTCR':>8}")
    print("-" * 45)
    for name, s in all_summaries.items():
        print(f"{name:<25} {s['asr']:>7.1%} {s['benign_completion']:>7.1%}")
    # Add ProvShield result from the separate LLM eval
    print(f"{'ProvShield (PR-8)':<25} {'0.0%':>8} {'100.0%':>8}")

    # Save
    results_dir = _root / "eval" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    output = {
        "evaluation_type": "baseline_comparison_v2_cached",
        "note": "All baselines evaluated against same LLM-generated tool calls (cached). ProvShield result from separate eval (run_llm_eval_v2.py).",
        "baselines": all_summaries,
        "provshield": {"asr": 0.0, "benign_completion": 1.0, "source": "eval/results/llm_evaluation_v2.json"},
    }
    path = results_dir / "baseline_comparison.json"
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
