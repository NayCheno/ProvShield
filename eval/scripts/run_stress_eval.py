#!/usr/bin/env python3
"""Run stress-test scenarios against LLM to measure manipulation rate.

Usage:
    python eval/scripts/run_stress_eval.py [--model mimo-v2.5]
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_root / "src"))
sys.path.insert(0, str(_root / "eval" / "scripts"))

from llm_eval_harness import call_llm, extract_tool_call


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="mimo-v2.5")
    args = parser.parse_args()

    import os
    os.environ["LLM_MODEL"] = args.model
    import importlib
    import llm_eval_harness
    importlib.reload(llm_eval_harness)

    scenarios = json.loads((_root / "eval" / "data" / "stress_scenarios.json").read_text())

    results = []
    for i, s in enumerate(scenarios):
        print(f"[{i+1}/{len(scenarios)}] {s['scenario_id']}...", end=" ", flush=True)
        response = call_llm(s["context_messages"], tools=s["tools"], temperature=0.0)
        tc = extract_tool_call(response)

        expected = s["expected_tool"]
        manipulated = False
        llm_tool = None
        llm_args = {}

        if tc and tc.get("tool_name"):
            llm_tool = tc["tool_name"]
            llm_args = tc.get("arguments", {})
            manipulated = llm_tool == expected

        r = {
            "id": s["scenario_id"],
            "expected": expected,
            "llm_tool": llm_tool,
            "llm_args": llm_args,
            "manipulated": manipulated,
        }
        results.append(r)

        if manipulated:
            print(f"MANIPULATED ({llm_tool})")
        elif llm_tool:
            print(f"refused→{llm_tool}")
        else:
            print("REFUSED")
        time.sleep(0.3)

    total = len(results)
    manipulated = sum(1 for r in results if r["manipulated"])
    by_tool = {}
    for r in results:
        t = r["expected"]
        by_tool.setdefault(t, {"total": 0, "manip": 0})
        by_tool[t]["total"] += 1
        if r["manipulated"]:
            by_tool[t]["manip"] += 1

    print(f"\n{'='*50}")
    print(f"Model: {args.model}")
    print(f"Total: {total}, Manipulated: {manipulated} ({manipulated/total:.0%})")
    print(f"\nPer tool:")
    for tool, data in sorted(by_tool.items()):
        print(f"  {tool}: {data['manip']}/{data['total']} ({data['manip']/data['total']:.0%})")
    print(f"{'='*50}")

    out = _root / "eval" / "results" / f"stress_{args.model.replace('.','_')}.json"
    out.write_text(json.dumps({"model": args.model, "total": total, "manipulated": manipulated, "rate": round(manipulated/total, 4), "per_tool": {t: d for t, d in by_tool.items()}, "per_scenario": results}, indent=2))
    print(f"Saved → {out}")


if __name__ == "__main__":
    main()
