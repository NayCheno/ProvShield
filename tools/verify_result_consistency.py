#!/usr/bin/env python3
"""Verify that key numbers across the repository are consistent with the
canonical manifest (eval/results/results_manifest.json).

Exit code 0 = all checks pass, 1 = inconsistencies found.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent


def load_manifest() -> dict:
    path = _root / "eval" / "results" / "results_manifest.json"
    with open(path) as f:
        return json.load(f)


def load_summary() -> dict:
    path = _root / "eval" / "results" / "summary.json"
    with open(path) as f:
        return json.load(f)


def read_text(rel: str) -> str:
    path = _root / rel
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def check(pattern: str, text: str, label: str, expected: str, errors: list[str]):
    """Search for *pattern* in *text*; append to *errors* if not found."""
    if not re.search(pattern, text):
        errors.append(f"[{label}] expected pattern not found: {pattern!r}  (expected: {expected})")


def main() -> int:
    manifest = load_manifest()
    summary = load_summary()

    m_total = manifest["scenario_count"]["total"]
    m_attack = manifest["scenario_count"]["attack"]
    m_benign = manifest["scenario_count"]["benign"]
    m_asr = manifest["key_results"]["provshield_asr"]
    m_btc = manifest["key_results"]["provshield_btc"]
    m_model = manifest["model_id"]
    m_git = manifest["git_sha"][:12]

    errors: list[str] = []

    # --- artifact/README.md ---
    art = read_text("artifact/README.md")
    if art:
        check(str(m_total), art, "artifact/README", f"total={m_total}", errors)
        check(str(m_attack), art, "artifact/README", f"attack={m_attack}", errors)
        check(str(m_benign), art, "artifact/README", f"benign={m_benign}", errors)
        check(m_model, art, "artifact/README", f"model={m_model}", errors)

    # --- checklists/acceptance_checklist.md ---
    chk = read_text("checklists/acceptance_checklist.md")
    if chk:
        check(str(m_total), chk, "acceptance_checklist", f"total={m_total}", errors)
        check(str(m_attack), chk, "acceptance_checklist", f"attack={m_attack}", errors)
        check(str(m_benign), chk, "acceptance_checklist", f"benign={m_benign}", errors)

    # --- docs/failure_analysis.md ---
    fa = read_text("docs/failure_analysis.md")
    if fa:
        check(str(m_total), fa, "failure_analysis", f"total={m_total}", errors)
        check(str(m_attack), fa, "failure_analysis", f"attack={m_attack}", errors)
        check(str(m_benign), fa, "failure_analysis", f"benign={m_benign}", errors)

    # --- eval/results/result_tables.md ---
    rt = read_text("eval/results/result_tables.md")
    if rt:
        check(re.escape(m_git[:8]), rt, "result_tables", f"git={m_git[:8]}", errors)

    # --- paper/paper_draft.md ---
    paper = read_text("paper/paper_draft.md")
    if paper:
        check(str(m_total), paper, "paper", f"total={m_total}", errors)
        check(str(m_attack), paper, "paper", f"attack={m_attack}", errors)
        check(str(m_benign), paper, "paper", f"benign={m_benign}", errors)
        # ASR may be rounded: 0.57% → 0.6%
        asr_pct = f"{m_asr * 100:.1f}%"
        check(re.escape(asr_pct), paper, "paper", f"ASR={asr_pct}", errors)

    # --- Summary vs manifest cross-check ---
    s_total = summary.get("total_scenarios")
    if s_total != m_total:
        errors.append(f"[summary vs manifest] total_scenarios: {s_total} != {m_total}")

    # --- Result files completeness ---
    result_dir = _root / "eval" / "results"
    defenses_in_manifest = set(manifest.get("defenses_evaluated", []))
    for d in defenses_in_manifest:
        safe = d.lower().replace(" ", "_")
        rfile = result_dir / f"results_{safe}.json"
        if not rfile.exists():
            errors.append(f"[result files] missing results_{safe}.json for defense '{d}'")

    # --- Report ---
    if errors:
        print(f"FAIL — {len(errors)} inconsistency(ies) found:\n")
        for e in errors:
            print(f"  ✗ {e}")
        return 1
    else:
        print(f"OK — all checks pass.")
        print(f"  manifest: {m_total} scenarios ({m_attack} attack + {m_benign} benign)")
        print(f"  model: {m_model}  git: {m_git}")
        print(f"  ASR: {m_asr:.4f}  BTCR: {m_btc:.3f}")
        print(f"  defenses: {', '.join(sorted(defenses_in_manifest))}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
