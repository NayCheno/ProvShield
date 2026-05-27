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


# Cache for combined evaluation results (run_evaluation.py format)
_COMBINED_RESULTS: dict[str, list[dict]] | None = None


def _load_combined_results(results_dir: Path) -> dict[str, list[dict]]:
    """Load combined evaluation_results.json and index by (category, suite)."""
    global _COMBINED_RESULTS
    if _COMBINED_RESULTS is not None:
        return _COMBINED_RESULTS
    combined_path = results_dir / "evaluation_results.json"
    data = load_json(combined_path)
    if data is None or "results" not in data:
        _COMBINED_RESULTS = {}
        return _COMBINED_RESULTS
    indexed: dict[str, list[dict]] = {}
    for r in data["results"]:
        key = f"{r.get('category', '')}/{r.get('suite', '')}"
        indexed.setdefault(key, []).append(r)
    _COMBINED_RESULTS = indexed
    return _COMBINED_RESULTS


def load_suite_results(results_dir: Path, suite_type: str, suite_name: str) -> list[dict]:
    """Load all scenario result JSON files for a given suite.

    Supports two formats:
    1. Individual files: results_dir/{suite_type}/{suite_name}/*.json
    2. Combined file: results_dir/evaluation_results.json (from run_evaluation.py)
    """
    # Try individual files first
    suite_dir = results_dir / suite_type / suite_name
    if suite_dir.is_dir():
        results = []
        for p in sorted(suite_dir.glob("*.json")):
            data = load_json(p)
            if data is not None:
                results.append(data)
        if results:
            return results
    # Fall back to combined file — try multiple key patterns
    combined = _load_combined_results(results_dir)
    # Direct match
    key = f"{suite_type}/{suite_name}"
    if key in combined:
        return combined[key]
    # Try singular category (e.g. "attacks" -> "attack")
    singular = suite_type.rstrip("s")
    key2 = f"{singular}/{suite_name}"
    if key2 in combined:
        return combined[key2]
    # Try prefixed suite name (e.g. "benign_browser" for suite "browser")
    key3 = f"{singular}/{singular}_{suite_name}"
    if key3 in combined:
        return combined[key3]
    return []


def compute_asr(results: list[dict]) -> float:
    """Compute Attack Success Rate: fraction of attacks that succeeded.

    Supports both individual-file and combined JSON formats.
    """
    if not results:
        return float("nan")
    successes = sum(1 for r in results if _attack_succeeded(r))
    return successes / len(results)


def _attack_succeeded(r: dict) -> bool:
    """Check if an attack succeeded (supports both result formats)."""
    # Combined format (run_evaluation.py)
    if "attack_succeeded_provshield" in r:
        return r["attack_succeeded_provshield"]
    # Individual format
    return (
        r.get("decision", {}).get("kind") == "allow"
        and r.get("attack_succeeded", False)
    )


def _baseline_asr(results: list[dict], baseline: str) -> float:
    """Compute ASR for a specific baseline."""
    if not results:
        return float("nan")
    successes = 0
    for r in results:
        # Combined format
        if "attack_succeeded_baselines" in r:
            if r["attack_succeeded_baselines"].get(baseline, False):
                successes += 1
        elif "attack_succeeded_no_defense" in r and baseline == "no_defense":
            if r["attack_succeeded_no_defense"]:
                successes += 1
        else:
            # Individual format
            if r.get("baseline", "") == baseline and r.get("attack_succeeded", False):
                successes += 1
    return successes / len(results)


def compute_ser(results: list[dict]) -> float:
    """Compute Secret Exfiltration Rate."""
    secret_tasks = [
        r for r in results
        if r.get("scenario", {}).get("targets_secret", False)
        or "Secret" in r.get("scenario_id", "")
        or "secret" in r.get("scenario_id", "").lower()
    ]
    if not secret_tasks:
        return float("nan")
    exfiltrated = sum(
        1 for r in secret_tasks
        if r.get("secret_reached_external_sink", False)
        or r.get("attack_succeeded_provshield", False)
    )
    return exfiltrated / len(secret_tasks)


def compute_btcr(results: list[dict]) -> float:
    """Compute Benign Task Completion Rate.

    Supports both individual-file and combined JSON formats.
    """
    if not results:
        return float("nan")
    completed = sum(
        1 for r in results
        if r.get("task_completed", False) or r.get("provshield_executed", False)
    )
    return completed / len(results)


def compute_false_blocking(results: list[dict]) -> float:
    """Compute False Blocking Rate for benign tasks.

    A false block: ProvShield denied a benign task that should have been allowed.
    Supports both formats.
    """
    if not results:
        return float("nan")
    blocked = 0
    for r in results:
        is_denied = (
            r.get("decision", {}).get("kind") == "deny"
            or r.get("provshield_decision") == "deny"
        )
        should_not_block = not r.get("should_have_been_denied", True)
        # Combined format: benign task that no-defense executed but ProvShield denied
        if "no_defense_executed" in r and "provshield_executed" in r:
            should_not_block = r["no_defense_executed"] and not r["provshield_executed"]
        if is_denied and should_not_block:
            blocked += 1
    return blocked / len(results)


def compute_bridge_burden(results: list[dict]) -> float:
    """Compute average bridge prompts per benign task.

    Supports both formats.
    """
    if not results:
        return float("nan")
    total = 0
    for r in results:
        total += r.get("bridge_requests", 0)
        if r.get("provshield_bridge_requested", False):
            total += 1
    # Avoid double-counting: prefer bridge_requests field if present
    if any("bridge_requests" in r for r in results):
        total = sum(r.get("bridge_requests", 0) for r in results)
    return total / len(results)


def compute_latency(results: list[dict]) -> tuple[float, float]:
    """Compute p50 and p95 monitor latency in ms.

    Supports both formats.
    """
    latencies = sorted(
        r.get("monitor_latency_ms", r.get("latency_ms", 0)) for r in results
    )
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

    # Check if combined format exists
    combined_path = results_dir / "evaluation_results.json"
    use_combined = combined_path.is_file()

    for suite in ATTACK_SUITES:
        row = [ATTACK_SUITE_LABELS[suite]]

        # Get attack results for this suite
        results = load_suite_results(results_dir, "attacks", suite)

        if use_combined and results:
            # Combined format: baseline data embedded in each scenario
            for baseline in BASELINES:
                row.append(fmt_pct(_baseline_asr(results, baseline)))
            row.append(fmt_pct(compute_asr(results)))
        else:
            # Individual file format: separate baseline directories
            for baseline in BASELINES:
                bl_dir = results_dir / "baselines" / baseline
                bl_results = load_suite_results(bl_dir, "attacks", suite)
                row.append(fmt_pct(compute_asr(bl_results)))
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


def generate_per_suite_table(results_dir: Path) -> str:
    """Generate LaTeX table: per-suite ASR for ProvShield vs no-defense."""
    # Load summary.json for per-suite data
    summary_path = results_dir / "summary.json"
    summary = load_json(summary_path)
    if not summary:
        return "% No summary.json found — run evaluation first."

    defenses = {d["defense"]: d for d in summary.get("defenses", [])}
    ps = defenses.get("ProvShield", {})
    nd = defenses.get("no_defense", {})

    ps_per = ps.get("per_suite_asr", {})
    nd_per = nd.get("per_suite_asr", {})

    # Only include attack suites (n > 0)
    attack_suites = [
        k for k in ATTACK_SUITES
        if ps_per.get(k, {}).get("n", 0) > 0
    ]

    lines = [
        "% Auto-generated by analyze_results.py",
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Per-suite attack success rate (\\%) for ProvShield vs.\\ no defense.}",
        "\\label{tab:per-suite}",
        "\\small",
        "\\begin{tabular}{@{}lccr@{}}",
        "\\toprule",
        "\\textbf{Suite} & \\textbf{No Defense} & \\textbf{ProvShield} & \\textbf{$n$} \\\\",
        "\\midrule",
    ]

    total_ps_n = 0
    total_ps_succeeded = 0
    total_nd_succeeded = 0

    for suite in attack_suites:
        ps_data = ps_per.get(suite, {})
        nd_data = nd_per.get(suite, {})
        n = ps_data.get("n", 0)
        ps_asr = ps_data.get("asr", 0.0) * 100
        nd_asr = nd_data.get("asr", 0.0) * 100

        total_ps_n += n
        total_ps_succeeded += ps_data.get("attacks_succeeded", 0)
        total_nd_succeeded += nd_data.get("attacks_succeeded", 0)

        label = ATTACK_SUITE_LABELS.get(suite, suite)
        lines.append(f"{label} & {nd_asr:.1f} & {ps_asr:.1f} & {n} \\\\")

    # Overall row
    overall_ps = (total_ps_succeeded / total_ps_n * 100) if total_ps_n else 0
    overall_nd = (total_nd_succeeded / total_ps_n * 100) if total_ps_n else 0
    lines.append("\\midrule")
    lines.append(f"\\textbf{{Overall}} & \\textbf{{{overall_nd:.1f}}} & \\textbf{{{overall_ps:.1f}}} & \\textbf{{{total_ps_n}}} \\\\")

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ])
    return "\n".join(lines)



def generate_csv_summary(results_dir: Path) -> list[dict]:
    """Generate a flat CSV of all metrics."""
    rows = []

    # Check if combined format
    combined_path = results_dir / "evaluation_results.json"
    use_combined = combined_path.is_file()

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
            if use_combined:
                # Combined format: compute from embedded baseline data
                attack_results = load_suite_results(results_dir, "attacks", suite)
                asr_val = _baseline_asr(attack_results, baseline)
                n = len(attack_results)
            else:
                bl_results = load_suite_results(
                    results_dir / "baselines" / baseline, "attacks", suite
                )
                asr_val = compute_asr(bl_results)
                n = len(bl_results)
            rows.append({
                "category": "attack",
                "suite": suite,
                "defense": baseline,
                "n_scenarios": n,
                "ASR": asr_val,
                "SER": float("nan"),
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
    per_suite_tex = generate_per_suite_table(results_dir)

    (output_dir / "attack_results_table.tex").write_text(attack_tex, encoding="utf-8")
    (output_dir / "utility_results_table.tex").write_text(utility_tex, encoding="utf-8")
    (output_dir / "ablation_results_table.tex").write_text(ablation_tex, encoding="utf-8")
    (output_dir / "per_suite_table.tex").write_text(per_suite_tex, encoding="utf-8")

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
    print(f"  - per_suite_table.tex")
    print(f"  - metrics_summary.csv")
    print(f"  - results_summary.md")

if __name__ == "__main__":
    main()
