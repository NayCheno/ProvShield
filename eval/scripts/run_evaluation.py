#!/usr/bin/env python3
"""Run the full ProvShield evaluation and generate result tables."""

import json
import sys
from pathlib import Path

# Ensure src and project root are importable
_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_root / "src"))
sys.path.insert(0, str(_root / "eval" / "scripts"))

from harness import EvaluationHarness


def main():
    harness = EvaluationHarness(results_dir=Path("eval/results"))

    # Load scenarios
    scenarios_path = Path("eval/data/scenarios.json")
    harness.load_scenarios_from_file(scenarios_path)
    print(f"Loaded {len(harness.scenarios)} scenarios")

    # Run all scenarios
    results = harness.run_all()
    print(f"Completed {len(results)} scenarios")

    # Save raw results
    output_path = harness.save_results()
    print(f"Results saved to {output_path}")

    # Compute and print summary
    summary = harness.compute_summary()
    print("\n" + "=" * 70)
    print("EVALUATION SUMMARY")
    print("=" * 70)
    print(f"Total scenarios: {summary['total_scenarios']}")
    print(f"Attack scenarios: {summary['attack_scenarios']}")
    print(f"Benign scenarios: {summary['benign_scenarios']}")
    print()
    print("Attack Success Rate (ASR):")
    print(f"  No defense (overall): {summary['overall_asr_no_defense']:.1%}")
    print(f"  ProvShield (overall): {summary['overall_asr_provshield']:.1%}")
    print()
    print("ASR by suite:")
    for suite, data in summary['asr_by_suite'].items():
        print(f"  {suite}:")
        print(f"    No defense:        {data['no_defense']:.1%}")
        print(f"    Prompt hardening:  {data.get('prompt_hardening', 0):.1%}")
        print(f"    Input firewall:    {data.get('input_firewall', 0):.1%}")
        print(f"    Static allowlist:  {data.get('static_allowlist', 0):.1%}")
        print(f"    Gen. confirmation: {data.get('generic_confirmation', 0):.1%}")
        print(f"    ProvShield:        {data['provshield']:.1%}")
    print()
    print("Utility:")
    print(f"  BTCR (ProvShield):  {summary['btcr_provshield']:.1%}")
    print(f"  BTCR (no defense):  {summary['btcr_no_defense']:.1%}")
    print(f"  False block rate:   {summary['false_block_rate']:.1%}")
    print(f"  Bridge burden:      {summary['bridge_burden']:.1%}")
    print()
    print("Performance:")
    print(f"  Latency p50: {summary['latency_p50_ms']:.2f} ms")
    print(f"  Latency p95: {summary['latency_p95_ms']:.2f} ms")
    print(f"  Latency mean: {summary['latency_mean_ms']:.2f} ms")

    # Generate markdown tables
    generate_markdown_tables(summary, results)


def generate_markdown_tables(summary, results):
    """Generate markdown result tables for the paper."""
    tables_dir = Path("eval/results")
    tables_dir.mkdir(parents=True, exist_ok=True)

    # Table 1: ASR by attack suite
    asr_table = "| Defense | SkillInject | MCPTox | MCP Safety | Web/Email | RAG | Adaptive |\n"
    asr_table += "|---|---|---|---|---|---|---|\n"

    suite_order = [
        "skill_injection", "mcp_metadata_poisoning", "mcp_safety",
        "web_email_injection", "rag_injection", "adaptive_white_box"
    ]
    defense_order = ["no_defense", "prompt_hardening", "input_firewall",
                     "generic_confirmation", "provshield"]
    defense_labels = {
        "no_defense": "No defense",
        "prompt_hardening": "Prompt hardening",
        "input_firewall": "Input firewall",
        "static_allowlist": "Static allowlist",
        "generic_confirmation": "Generic confirmation",
        "provshield": "ProvShield",
    }

    for defense in defense_order:
        row = f"| {defense_labels[defense]} |"
        for suite in suite_order:
            data = summary['asr_by_suite'].get(suite, {})
            if defense == "provshield":
                val = data.get("provshield", 0)
            else:
                val = data.get(defense, 0)
            row += f" {val:.0%} |"
        asr_table += row + "\n"

    # Table 2: Utility and overhead
    util_table = "| Defense | BTCR | False Block | Bridge Burden | p50 Latency | p95 Latency |\n"
    util_table += "|---|---|---|---|---|---|\n"
    util_table += f"| No defense | {summary['btcr_no_defense']:.0%} | 0% | 0% | {summary['latency_p50_ms']:.1f} ms | {summary['latency_p95_ms']:.1f} ms |\n"
    util_table += f"| ProvShield | {summary['btcr_provshield']:.0%} | {summary['false_block_rate']:.0%} | {summary['bridge_burden']:.0%} | {summary['latency_p50_ms']:.1f} ms | {summary['latency_p95_ms']:.1f} ms |\n"

    # Table 3: Ablation results (from ASR data)
    # Since we have the full ProvShield result, ablations can be derived from the harness

    # Write tables
    output = "# Evaluation Results\n\n"
    output += "## Table 1: Attack Success Rate by Suite\n\n"
    output += asr_table + "\n"
    output += "## Table 2: Utility and Performance\n\n"
    output += util_table + "\n"

    # ASR reduction calculation
    asr_nd = summary['overall_asr_no_defense']
    asr_ps = summary['overall_asr_provshield']
    if asr_nd > 0:
        reduction = (asr_nd - asr_ps) / asr_nd
        output += f"\n## Overall ASR Reduction: {reduction:.1%}\n\n"
    else:
        output += "\n## Overall ASR Reduction: N/A (no attacks succeeded without defense)\n\n"

    with open(tables_dir / "result_tables.md", "w") as f:
        f.write(output)
    print(f"\nResult tables written to {tables_dir / 'result_tables.md'}")


if __name__ == "__main__":
    main()
