"""Ablation study runner: tests ProvShield with components selectively disabled.

A0: Full ProvShield (baseline)
A1: No provenance labels
A2: No runtime monitor (labels only, no enforcement)
A3: No bridge binding (generic confirmation)
A4: Trust tool metadata by default
A5: No capability token
A6: Confidentiality only (no integrity checks)
A7: Integrity only (no confidentiality checks)
A8: No audit replay
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_root / "src"))

from provshield import (
    Decision,
    DecisionKind,
    RuntimeMonitor,
)
from provshield.policy import PolicyEngine
from provshield.store import SidecarProvenanceStore
from provshield.tokens import CapabilityTokenStore
from provshield.audit import AuditLogger
from provshield.bridge import BridgeManager
from provshield.labels import Integrity
from provshield.types import Effect, HIGH_RISK_EFFECTS


# ---------------------------------------------------------------------------
# Ablation configurations
# ---------------------------------------------------------------------------

def create_monitor_full() -> RuntimeMonitor:
    """A0: Full ProvShield."""
    return RuntimeMonitor()


def create_monitor_no_labels() -> RuntimeMonitor:
    """A1: No provenance labels - everything gets UserIntent."""
    store = SidecarProvenanceStore()
    # Override ingest to always use UserIntent
    original_ingest = store.ingest

    def patched_ingest(value, integrity="UserIntent", confidentiality="Public", origin="user", **kwargs):
        return original_ingest(value, "UserIntent", "Public", origin, **kwargs)

    store.ingest = patched_ingest
    return RuntimeMonitor(provenance_store=store)


def create_monitor_no_enforcement() -> RuntimeMonitor:
    """A2: No runtime monitor - always allow."""
    class NoOpPolicyEngine:
        def evaluate(self, **kwargs):
            from provshield.types import Decision, DecisionKind
            return Decision(kind=DecisionKind.ALLOW, reason="No enforcement")

    return RuntimeMonitor(policy_engine=NoOpPolicyEngine())


def create_monitor_no_bridge_binding() -> RuntimeMonitor:
    """A3: No bridge binding - generic confirmation always succeeds."""
    monitor = RuntimeMonitor()
    # Override bridge to auto-confirm
    original_check = monitor.check_and_execute

    def patched_check(proposed_call, executor):
        call = monitor.normalize_call(proposed_call)
        graph = monitor.provenance_store.build_argument_graph(call)
        decision = monitor.policy_engine.evaluate(
            call=call, provenance_graph=graph, capability_token=None
        )
        if decision.kind == DecisionKind.REQUIRE_BRIDGE:
            # Auto-confirm: treat as allow
            output = executor(call)
            return monitor.provenance_store.label_tool_output(call, output)
        return original_check(proposed_call, executor)

    monitor.check_and_execute = patched_check
    return monitor


def create_monitor_trust_metadata() -> RuntimeMonitor:
    """A4: Trust tool metadata by default."""
    monitor = RuntimeMonitor()
    # Override ingest to treat ToolMetadata as AttestedToolMetadata
    original_ingest = monitor.provenance_store.ingest

    def patched_ingest(value, integrity="ExternalContent", confidentiality="Public", origin="unknown", **kwargs):
        if integrity == "ToolMetadata":
            integrity = "AttestedToolMetadata"
        return original_ingest(value, integrity, confidentiality, origin, **kwargs)

    monitor.provenance_store.ingest = patched_ingest
    return monitor


def create_monitor_no_capability_token() -> RuntimeMonitor:
    """A5: No capability token - bridge confirm doesn't create token."""
    monitor = RuntimeMonitor()
    # Override mint_token to always return None
    monitor.bridge_manager.mint_token = lambda bridge_id: None
    return monitor


def create_monitor_confidentiality_only() -> RuntimeMonitor:
    """A6: Confidentiality only - no integrity checks."""
    monitor = RuntimeMonitor()
    original_evaluate = monitor.policy_engine.evaluate

    def patched_evaluate(call, provenance_graph, capability_token=None):
        decision = original_evaluate(call, provenance_graph, capability_token)
        # If denied due to integrity, allow it
        if decision.kind == DecisionKind.DENY and "integrity" in (decision.reason or "").lower():
            return Decision(kind=DecisionKind.ALLOW, reason="Integrity check disabled (ablation A6)")
        return decision

    monitor.policy_engine.evaluate = patched_evaluate
    return monitor


def create_monitor_integrity_only() -> RuntimeMonitor:
    """A7: Integrity only - no confidentiality checks."""
    monitor = RuntimeMonitor()
    original_evaluate = monitor.policy_engine.evaluate

    def patched_evaluate(call, provenance_graph, capability_token=None):
        decision = original_evaluate(call, provenance_graph, capability_token)
        # If denied due to confidentiality/secret, allow it
        if decision.kind == DecisionKind.DENY and "secret" in (decision.reason or "").lower():
            return Decision(kind=DecisionKind.ALLOW, reason="Confidentiality check disabled (ablation A7")
        return decision

    monitor.policy_engine.evaluate = patched_evaluate
    return monitor


def create_monitor_no_audit() -> RuntimeMonitor:
    """A8: No audit replay."""
    class NoOpAuditLogger:
        def record_decision(self, *args, **kwargs): pass
        def record_execution(self, *args, **kwargs): pass
        def record_bridge_request(self, *args, **kwargs): pass
        def query(self, *args, **kwargs): return []

    return RuntimeMonitor(audit_log=NoOpAuditLogger())


ABLATIONS = {
    "A0_full": create_monitor_full,
    "A1_no_labels": create_monitor_no_labels,
    "A2_no_monitor": create_monitor_no_enforcement,
    "A3_no_bridge_binding": create_monitor_no_bridge_binding,
    "A4_trust_metadata": create_monitor_trust_metadata,
    "A5_no_capability_token": create_monitor_no_capability_token,
    "A6_confidentiality_only": create_monitor_confidentiality_only,
    "A7_integrity_only": create_monitor_integrity_only,
    "A8_no_audit": create_monitor_no_audit,
}


# ---------------------------------------------------------------------------
# Attack scenarios (reuse from evaluation harness)
# ---------------------------------------------------------------------------

def load_scenarios() -> list[dict]:
    """Load attack scenarios from the evaluation data."""
    scenarios_path = _root / "eval" / "data" / "scenarios.json"
    with open(scenarios_path) as f:
        data = json.load(f)
    return [s for s in data["scenarios"] if s["category"] == "attack"]


def run_scenario_with_monitor(scenario: dict, monitor_factory) -> dict:
    """Run a single scenario with a given monitor factory."""
    monitor = monitor_factory()

    for step in scenario["steps"]:
        if step["action"] == "ingest":
            monitor.provenance_store.ingest(
                step.get("content", ""),
                step.get("integrity", "ExternalContent"),
                step.get("confidentiality", "Public"),
                step.get("origin", "unknown"),
            )
        elif step["action"] == "call":
            proposed = {
                "tool_name": step["tool_name"],
                "arguments": step.get("arguments", {}),
            }
            try:
                result = monitor.check_and_execute(
                    proposed, lambda call: f"executed_{call.tool_name}"
                )
                if isinstance(result, Decision):
                    if result.kind == DecisionKind.DENY:
                        return {"decision": "deny", "executed": False}
                    elif result.kind == DecisionKind.REQUIRE_BRIDGE:
                        return {"decision": "require_bridge", "executed": False}
                return {"decision": "allow", "executed": True}
            except PermissionError:
                return {"decision": "deny", "executed": False}

    return {"decision": "allow", "executed": False}


def main():
    print("=" * 60)
    print(" ProvShield Ablation Study")
    print("=" * 60)
    print()

    scenarios = load_scenarios()
    print(f"Loaded {len(scenarios)} attack scenarios")
    print()

    results = {}

    for ablation_name, monitor_factory in ABLATIONS.items():
        print(f"--- {ablation_name} ---")
        suite_results = {}

        for scenario in scenarios:
            suite = scenario["suite"]
            r = run_scenario_with_monitor(scenario, monitor_factory)
            attack_succeeded = r["executed"] and r["decision"] == "allow"
            suite_results.setdefault(suite, []).append({
                "scenario_id": scenario["scenario_id"],
                "decision": r["decision"],
                "executed": r["executed"],
                "attack_succeeded": attack_succeeded,
            })

        # Compute ASR by suite
        asr_by_suite = {}
        for suite, suite_r in suite_results.items():
            n = len(suite_r)
            succeeded = sum(1 for r in suite_r if r["attack_succeeded"])
            asr_by_suite[suite] = succeeded / n if n else 0

        overall_n = sum(len(v) for v in suite_results.values())
        overall_succeeded = sum(
            sum(1 for r in v if r["attack_succeeded"])
            for v in suite_results.values()
        )
        overall_asr = overall_succeeded / overall_n if overall_n else 0

        results[ablation_name] = {
            "overall_asr": overall_asr,
            "asr_by_suite": asr_by_suite,
            "total_scenarios": overall_n,
            "attacks_succeeded": overall_succeeded,
        }

        suite_str = ", ".join(f"{s}: {v:.0%}" for s, v in asr_by_suite.items())
        print(f"  Overall ASR: {overall_asr:.1%} ({overall_succeeded}/{overall_n})")
        print(f"  By suite: {suite_str}")
        print()

    # Print comparison table
    print("=" * 60)
    print(" ABLATION RESULTS TABLE")
    print("=" * 60)

    suites = sorted(set(
        suite for r in results.values() for suite in r["asr_by_suite"]
    ))
    suite_labels = {
        "skill_injection": "Skill",
        "mcp_metadata_poisoning": "MCPTox",
        "mcp_safety": "MCP Safe.",
        "web_email_injection": "Web/Email",
        "rag_injection": "RAG",
        "adaptive_white_box": "Adaptive",
    }

    header = f"{'Config':<25}" + "".join(f"{suite_labels.get(s, s):>10}" for s in suites) + f"{'Overall':>10}"
    print(header)
    print("-" * len(header))

    for ablation_name, r in results.items():
        row = f"{ablation_name:<25}"
        for suite in suites:
            asr = r["asr_by_suite"].get(suite, 0)
            row += f"{asr:>9.0%} "
        row += f"{r['overall_asr']:>9.1%}"
        print(row)

    # Save results
    output_path = _root / "eval" / "results" / "ablation_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
