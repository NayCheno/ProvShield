#!/usr/bin/env python3
"""Deterministic audit replay verifier.

Replays audit trace entries through the policy engine and verifies
that each recorded decision matches the replayed decision.

Usage:
    python tools/replay_audit.py --trace eval/results/current/traces.jsonl \
                                  --policy artifact/configs/default_policy.yaml

Output:
    - replayed decision count
    - mismatch count
    - per-mismatch normalized call details
    - policy version hash
    - deterministic replay hash
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "src"))

from provshield.labels import (
    Integrity, Confidentiality, ProvenanceLabel, make_label, NAME_TO_INTEGRITY, NAME_TO_CONFIDENTIALITY,
)
from provshield.policy import PolicyEngine
from provshield.store import ProvenanceGraph, SidecarProvenanceStore
from provshield.types import (
    Decision, DecisionKind, Effect, NormalizedToolCall, Sink, EFFECT_SINK_MAP,
)


def load_trace(path: Path) -> list[dict[str, Any]]:
    """Load JSONL trace file."""
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def reconstruct_call(entry: dict[str, Any]) -> NormalizedToolCall:
    """Reconstruct a NormalizedToolCall from an audit entry."""
    effect = Effect(entry.get("effect", "ReadPublic"))
    sink_str = entry.get("sink", "LocalReadSink")
    try:
        sink = Sink(sink_str)
    except ValueError:
        sink = EFFECT_SINK_MAP.get(effect, Sink.LOCAL_READ)

    # Extract argument_sources from extra if present
    raw_sources = entry.get("extra", {}).get("argument_sources")
    argument_sources = None
    if raw_sources:
        if isinstance(raw_sources, dict):
            pairs = []
            for k, v in raw_sources.items():
                if isinstance(v, (list, tuple)):
                    for oid in v:
                        pairs.append((str(k), str(oid)))
                else:
                    pairs.append((str(k), str(v)))
            argument_sources = tuple(pairs) if pairs else None
        elif isinstance(raw_sources, list):
            argument_sources = tuple((str(k), str(v)) for k, v in raw_sources) or None

    return NormalizedToolCall(
        tool_name=entry.get("tool_name", "unknown"),
        arguments=entry.get("extra", {}).get("arguments", {}),
        effect=effect,
        sink=sink,
        destination=entry.get("destination"),
        payload_digest=entry.get("payload_digest"),
        principal=entry.get("extra", {}).get("principal", "user"),
        argument_sources=argument_sources,
        tool_registered=entry.get("extra", {}).get("tool_registered", True),
    )


def reconstruct_graph(
    entry: dict[str, Any],
    store: SidecarProvenanceStore,
    call: NormalizedToolCall,
) -> ProvenanceGraph:
    """Reconstruct a ProvenanceGraph from audit entry source info."""
    source_integrities = entry.get("source_integrities", [])
    max_conf_str = entry.get("max_confidentiality", "Public")

    # Rebuild source labels from recorded integrities
    source_labels = []
    for int_name in source_integrities:
        integrity = NAME_TO_INTEGRITY.get(int_name, Integrity.EXTERNAL)
        conf = NAME_TO_CONFIDENTIALITY.get(max_conf_str, Confidentiality.PUBLIC)
        lbl = make_label(integrity, conf, "replay")
        source_labels.append(lbl)

    return ProvenanceGraph(
        call=call,
        source_labels=tuple(source_labels),
        payload_labels=(),
        all_labels=tuple(source_labels),
    )


def compute_policy_hash(policy_path: Path | None) -> str:
    """Compute hash of policy configuration."""
    if policy_path and policy_path.exists():
        return "sha256:" + hashlib.sha256(policy_path.read_bytes()).hexdigest()[:16]
    return "no-policy-file"


def main():
    parser = argparse.ArgumentParser(description="ProvShield deterministic audit replay verifier")
    parser.add_argument("--trace", required=True, help="Path to JSONL trace file")
    parser.add_argument("--policy", default=None, help="Path to policy YAML for hash")
    parser.add_argument("--verbose", action="store_true", help="Print per-entry details")
    args = parser.parse_args()

    trace_path = Path(args.trace)
    if not trace_path.exists():
        print(f"ERROR: trace file not found: {trace_path}", file=sys.stderr)
        return 1

    policy_path = Path(args.policy) if args.policy else None
    policy_hash = compute_policy_hash(policy_path)

    entries = load_trace(trace_path)
    decision_entries = [e for e in entries if e.get("entry_type") == "decision"]

    if not decision_entries:
        print("WARNING: no decision entries found in trace")
        return 0

    engine = PolicyEngine()
    store = SidecarProvenanceStore()

    mismatches: list[dict[str, Any]] = []
    replay_hashes: list[str] = []

    for entry in decision_entries:
        call = reconstruct_call(entry)
        graph = reconstruct_graph(entry, store, call)

        replayed = engine.evaluate(call=call, provenance_graph=graph)

        recorded_kind = entry.get("decision_kind", "unknown")
        replayed_kind = replayed.kind.value

        # Compute deterministic hash of this replay
        entry_hash = hashlib.sha256(
            json.dumps({
                "tool": call.tool_name,
                "effect": call.effect.value,
                "sink": call.sink.value,
                "dest": call.destination,
                "payload": call.payload_digest,
                "recorded": recorded_kind,
                "replayed": replayed_kind,
            }, sort_keys=True).encode()
        ).hexdigest()[:16]
        replay_hashes.append(entry_hash)

        if recorded_kind != replayed_kind:
            mismatch = {
                "tool_name": call.tool_name,
                "effect": call.effect.value,
                "sink": call.sink.value,
                "destination": call.destination,
                "payload_digest": call.payload_digest,
                "recorded_decision": recorded_kind,
                "replayed_decision": replayed_kind,
                "entry_index": entries.index(entry),
            }
            mismatches.append(mismatch)

            if args.verbose:
                print(f"MISMATCH at entry {mismatch['entry_index']}:")
                print(f"  tool={call.tool_name} effect={call.effect.value}")
                print(f"  recorded={recorded_kind} replayed={replayed_kind}")

    # Compute overall replay hash
    replay_hash = hashlib.sha256(
        "".join(replay_hashes).encode()
    ).hexdigest()[:32]

    # Output
    result = {
        "replayed_decisions": len(decision_entries),
        "mismatches": len(mismatches),
        "mismatch_rate": len(mismatches) / len(decision_entries) if decision_entries else 0,
        "policy_hash": policy_hash,
        "deterministic_replay_hash": replay_hash,
        "per_mismatch_details": mismatches,
    }

    print(json.dumps(result, indent=2))

    if mismatches:
        print(f"\nFAILED: {len(mismatches)} / {len(decision_entries)} decisions mismatched", file=sys.stderr)
        return 1
    else:
        print(f"\nPASSED: all {len(decision_entries)} decisions replay deterministically", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
