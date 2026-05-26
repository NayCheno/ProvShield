#!/usr/bin/env python3
"""
ProvShield Results Analyzer
============================
Reads evaluation results JSON files and generates:
  - LaTeX tables for the paper (attack, utility, ablation)
  - CSV summary of all metrics
  - Markdown summary for quick inspection

Usage:
    python artifact/scripts/analyze_results.py \
        --results-dir artifact/results \
        --output-dir artifact/results/tables
"""

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Metric computation helpers
# ---------------------------------------------------------------------------

ATTACK_SUITES = [
    "skill_injection",
    "mcp_metadata_poisoning",
    "mcp_safety",
    "web_email_injection",
    "rag_injection",
    "adaptive_white_box",
]

ATTACK_SUITE_LABELS = {
    "skill_injection": "SkillInject",
    "mcp_metadata_poisoning": "MCPTox",
    "mcp_safety": "MCP Safety",
    "web_email_injection": "Web/Email",
    "rag_injection": "RAG",
    "adaptive_white_box": "Adaptive",
}

BENIGN_CATEGORIES = ["browser", "email", "mcp", "skills", "mixed"]

BENIGN_CATEGORY_LABELS = {
    "browser": "Browser",
    "email": "Email",
    "mcp": "MCP",
    "skills": "Skills",
    "mixed": "Mixed",
}

BASELINES = ["no_defense", "prompt_hardening", "input_firewall", "generic_confirmation"]

BASELINE_LABELS = {
    "no_defense": "No defense",
    "prompt_hardening": "Prompt hardening",
    "input_firewall": "Input firewall",
    "generic_confirmation": "Generic conf.",
}

ABLATIONS = [
    "A0_full", "A1_no_labels", "A2_no_monitor", "A3_no_bridge_binding",
    "A4_trust_metadata", "A5_no_capability_token",
    "A6_confidentiality_only", "A7_integrity_only", "A8_no_audit",
]

ABLATION_LABELS = {
    "A0_full": "Full ProvShield",
    "A1_no_labels": "No labels",
    "A2_no_monitor": "No monitor",
    "A3_no_bridge_binding": "No bridge bind",
    "A4_trust_metadata": "Trust metadata",
    "A5_no_capability_token": "No cap token",
    "A6_confidentiality_only": "Conf. only",
    "A7_integrity_only": "Integ. only",
    "A8_no_audit": "No audit",
}


def load_json(path: Path) -> dict | None:
    """Load a JSON file, returning None on any error."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def load_suite_results(results_dir: Path, suite_type: str, suite_name: str) -> list[dict]:
    """Load all scenario result JSON files for a given suite."""
    suite_dir = results_dir / suite_type / suite_name
    if not suite_dir.is_dir():
        return []
    results = []
    for p in sorted(suite_dir.glob("*.json")):
        data = load_json(p)
        if data is not None:
            results.append(data)
    return results


def compute_asr(results: list[dict]) -> float:
    """Compute Attack Success Rate: fraction of attacks that succeeded."""
    if not results:
        return float("nan")
    successes = sum(
        1 for r in results
        if r.get("decision", {}).get("kind") == "allow"
        and r.get("attack_succeeded", False)
    )
    return successes / len(results)


def compute_ser(results: list[dict]) -> float:
    """Compute Secret Exfiltration Rate."""
    secret_tasks = [
        r for r in results
        if r.get("scenario", {}).get("targets_secret", False)
    ]
    if not secret_tasks:
        return float("nan")
    exfiltrated = sum(
        1 for r in secret_tasks
        if r.get("secret_reached_external_sink", False)
    )
    return exfiltrated / len(secret_tasks)


def compute_btcr(results: list[dict]) -> float:
    """Compute Benign Task Completion Rate."""
    if not results:
        return float("nan")
    completed = sum(
        1 for r in results
        if r.get("task_completed", False)
    )
    return completed / len(results)


def compute_false_blocking(results: list[dict]) -> float:
    """Compute False Blocking Rate for benign tasks."""
    if not results:
        return float("nan")
    blocked = sum(
        1 for r in results
        if r.get("decision", {}).get("kind") == "deny"
        and not r.get("should_have_been_denied", False)
    )
    return blocked / len(results)


def compute_bridge_burden(results: list[dict]) -> float:
    """Compute average bridge prompts per benign task."""
    if not results:
        return float("nan")
    total_bridges = sum(r.get("bridge_requests", 0) for r in results)
    return total_bridges / len(results)


def compute_latency(results: list[dict]) -> tuple[float, float]:
    """Compute p50 and p95 monitor latency in ms."""
    latencies = sorted(r.get("monitor_latency_ms", 0) for r in results)
    if not latencies:
        return float("nan"), float("nan")
    n = len(latencies)
    p50 = latencies[n // 2]
    p95 = latencies[int(n * 0.95)]
    return p50, p95


# ---------------------------------------------------------------------------
# Table generation
# ---------------------------------------------------------------------------

def fmt_pct(val: float) -> str:
    """Format a float as a percentage string, or TBD if NaN."""
    if val != val:  # NaN check
        return "TBD"
    return f"{val * 100:.1f}\\%"


def fmt_ms(val: float) -> str:
    """Format latency in ms, or TBD if NaN."""
    if val != val:
        return "TBD"
    return f"{val:.1f}"


def generate_attack_table(results_dir: Path) -> str:
    """Generate LaTeX table: ASR by suite and defense."""
    lines = [
        "% Auto-generated by analyze_results.py",
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Attack Success Rate (\\%) by suite and defense.}",
        "\\label{tab:attack-results}",
        "\\small",
        "\\begin{tabular}{l" + "r" * (len(BASELINES) + 1) + "}",
        "\\toprule",
        "Suite & " + " & ".join(BASELINE_LABELS[b] for b in BASELINES) + " & ProvShield \\\\",
        "\\midrule",
    ]

    for suite in ATTACK_SUITES:
        row = [ATTACK_SUITE_LABELS[suite]]

        # Baselines
        for baseline in BASELINES:
            bl_dir = results_dir / "baselines" / baseline
            results = load_suite_results(bl_dir, "attacks", suite)
            row.append(fmt_pct(compute_asr(results)))

        # ProvShield
        results = load_suite_results(results_dir, "attacks", suite)
        row.append(fmt_pct(compute_asr(results)))

        lines.append(" & ".join(row) + " \\\\")

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return "\n".join(lines)


def generate_utility_table(results_dir: Path) -> str:
    """Generate LaTeX table: benign task metrics."""
    lines = [
        "% Auto-generated by analyze_results.py",
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Utility metrics by task category (ProvShield).}",
        "\\label{tab:utility-results}",
        "\\small",
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "Category & BTCR & False Block & Bridge Burden & p95 Latency \\\\",
        "\\midrule",
    ]

    for category in BENIGN_CATEGORIES:
        results = load_suite_results(results_dir, "benign", category)
        btcr = compute_btcr(results)
        fb = compute_false_blocking(results)
        bb = compute_bridge_burden(results)
        _, p95 = compute_latency(results)

        lines.append(
            f"{BENIGN_CATEGORY_LABELS[category]} & "
            f"{fmt_pct(btcr)} & {fmt_pct(fb)} & "
            f"{bb:.1f} & {fmt_ms(p95)} \\\\"
            if results
            else f"{BENIGN_CATEGORY_LABELS[category]} & TBD & TBD & TBD & TBD \\\\"
        )

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return "\n".join(lines)


def generate_ablation_table(results_dir: Path) -> str:
    """Generate LaTeX table: ablation study ASR."""
    lines = [
        "% Auto-generated by analyze_results.py",
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Ablation study: Attack Success Rate (\\%) across all suites.}",
        "\\label{tab:ablation-results}",
        "\\small",
        "\\begin{tabular}{l" + "r" * len(ATTACK_SUITES) + "}",
        "\\toprule",
        "Configuration & " + " & ".join(ATTACK_SUITE_LABELS[s] for s in ATTACK_SUITES) + " \\\\",
        "\\midrule",
    ]

    for ablation in ABLATIONS:
        row = [ABLATION_LABELS[ablation]]

        for suite in ATTACK_SUITES:
            results = load_suite_results(results_dir, "ablation", ablation)
            # Filter to this suite if results are mixed
            suite_results = [
                r for r in results
                if r.get("scenario", {}).get("suite") == suite
            ] if results else []
            if not suite_results:
                suite_results = results  # fallback
            row.append(fmt_pct(compute_asr(suite_results)))

        lines.append(" & ".join(row) + " \\\\")

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return "\n".join(lines)


def generate_csv_summary(results_dir: Path) -> list[dict]:
    """Generate a flat CSV of all metrics."""
    rows = []

    # Attack results per suite
    for suite in ATTACK_SUITES:
        results = load_suite_results(results_dir, "attacks", suite)
        p50, p95 = compute_latency(results)
        rows.append({
            "category": "attack",
            "suite": suite,
            "defense": "ProvShield",
            "n_scenarios": len(results),
            "ASR": compute_asr(results),
            "SER": compute_ser(results),
            "BTCR": float("nan"),
            "false_blocking": float("nan"),
            "bridge_burden": float("nan"),
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
        })

    # Baseline attack results
    for baseline in BASELINES:
        for suite in ATTACK_SUITES:
            results = load_suite_results(results_dir, "baselines", baseline)
            rows.append({
                "category": "attack",
                "suite": suite,
                "defense": baseline,
                "n_scenarios": len(results),
                "ASR": compute_asr(results),
                "SER": compute_ser(results),
                "BTCR": float("nan"),
                "false_blocking": float("nan"),
                "bridge_burden": float("nan"),
                "latency_p50_ms": float("nan"),
                "latency_p95_ms": float("nan"),
            })

    # Benign results per category
    for category in BENIGN_CATEGORIES:
        results = load_suite_results(results_dir, "benign", category)
        p50, p95 = compute_latency(results)
        rows.append({
            "category": "benign",
            "suite": category,
            "defense": "ProvShield",
            "n_scenarios": len(results),
            "ASR": float("nan"),
            "SER": float("nan"),
            "BTCR": compute_btcr(results),
            "false_blocking": compute_false_blocking(results),
            "bridge_burden": compute_bridge_burden(results),
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
        })

    # Ablation results
    for ablation in ABLATIONS:
        results = load_suite_results(results_dir, "ablation", ablation)
        rows.append({
            "category": "ablation",
            "suite": ablation,
            "defense": "ProvShield",
            "n_scenarios": len(results),
            "ASR": compute_asr(results),
            "SER": compute_ser(results),
            "BTCR": float("nan"),
            "false_blocking": float("nan"),
            "bridge_burden": float("nan"),
            "latency_p50_ms": float("nan"),
            "latency_p95_ms": float("nan"),
        })

    return rows


def generate_markdown_summary(results_dir: Path) -> str:
    """Generate a Markdown summary for quick inspection."""
    lines = [
        "# ProvShield Evaluation Results",
        "",
        "## Attack Success Rate (%)",
        "",
        "| Suite | ProvShield |",
        "|---|---:|",
    ]

    for suite in ATTACK_SUITES:
        results = load_suite_results(results_dir, "attacks", suite)
        lines.append(f"| {ATTACK_SUITE_LABELS[suite]} | {fmt_pct(compute_asr(results))} |")

    lines.extend([
        "",
        "## Benign Task Metrics",
        "",
        "| Category | BTCR | False Block | Bridge Burden |",
        "|---|---:|---:|---:|",
    ])

    for category in BENIGN_CATEGORIES:
        results = load_suite_results(results_dir, "benign", category)
        bb = compute_bridge_burden(results)
        bb_str = f"{bb:.1f}" if bb == bb else "TBD"
        lines.append(
            f"| {BENIGN_CATEGORY_LABELS[category]} | "
            f"{fmt_pct(compute_btcr(results))} | "
            f"{fmt_pct(compute_false_blocking(results))} | "
            f"{bb_str} |"
        )

    lines.extend([
        "",
        "## Ablation Study (ASR %)",
        "",
        "| Configuration | ASR |",
        "|---|---:|",
    ])

    for ablation in ABLATIONS:
        results = load_suite_results(results_dir, "ablation", ablation)
        lines.append(f"| {ABLATION_LABELS[ablation]} | {fmt_pct(compute_asr(results))} |")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze ProvShield evaluation results and generate tables."
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path("artifact/results"),
        help="Root directory containing evaluation results.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for generated tables. Defaults to <results-dir>/tables.",
    )
    args = parser.parse_args()

    results_dir = args.results_dir.resolve()
    output_dir = (args.output_dir or results_dir / "tables").resolve()

    if not results_dir.is_dir():
        print(f"Error: Results directory not found: {results_dir}", file=sys.stderr)
        print("Run evaluation first: make smoke / make ablation / run_full_evaluation.sh", file=sys.stderr)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate LaTeX tables
    attack_tex = generate_attack_table(results_dir)
    utility_tex = generate_utility_table(results_dir)
    ablation_tex = generate_ablation_table(results_dir)

    (output_dir / "attack_results_table.tex").write_text(attack_tex, encoding="utf-8")
    (output_dir / "utility_results_table.tex").write_text(utility_tex, encoding="utf-8")
    (output_dir / "ablation_results_table.tex").write_text(ablation_tex, encoding="utf-8")

    # Generate CSV summary
    csv_rows = generate_csv_summary(results_dir)
    csv_path = output_dir / "metrics_summary.csv"
    if csv_rows:
        fieldnames = list(csv_rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)

    # Generate Markdown summary
    md_summary = generate_markdown_summary(results_dir)
    (output_dir / "results_summary.md").write_text(md_summary, encoding="utf-8")

    print(f"Tables generated in {output_dir}/")
    print(f"  - attack_results_table.tex")
    print(f"  - utility_results_table.tex")
    print(f"  - ablation_results_table.tex")
    print(f"  - metrics_summary.csv")
    print(f"  - results_summary.md")


if __name__ == "__main__":
    main()
