"""
ProvShield runtime monitor pseudocode.
This file is not production code. It defines the intended control flow.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class DecisionKind(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_BRIDGE = "require_bridge"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"


@dataclass
class NormalizedToolCall:
    tool_name: str
    arguments: Dict[str, Any]
    effect: str
    sink: str
    destination: Optional[str]
    payload_digest: Optional[str]
    principal: str


@dataclass
class Decision:
    kind: DecisionKind
    reason: str
    bridge_request: Optional[Dict[str, Any]] = None


class RuntimeMonitor:
    def __init__(self, policy_engine, provenance_store, token_store, audit_log):
        self.policy_engine = policy_engine
        self.provenance_store = provenance_store
        self.token_store = token_store
        self.audit_log = audit_log

    def check_and_execute(self, proposed_call: Dict[str, Any], executor):
        call = self.normalize_call(proposed_call)
        graph = self.provenance_store.build_argument_graph(call)
        token = self.token_store.lookup_matching_token(call)

        decision = self.policy_engine.evaluate(
            call=call,
            provenance_graph=graph,
            capability_token=token,
        )

        self.audit_log.record_decision(call, graph, decision)

        if decision.kind == DecisionKind.ALLOW:
            output = executor.execute(call)
            labeled_output = self.provenance_store.label_tool_output(call, output)
            self.audit_log.record_execution(call, labeled_output)
            return labeled_output

        if decision.kind == DecisionKind.REQUIRE_BRIDGE:
            return decision

        if decision.kind == DecisionKind.SANITIZE:
            sanitized = self.apply_sanitizer(call, decision)
            return self.check_and_execute(sanitized, executor)

        raise PermissionError(decision.reason)

    def normalize_call(self, proposed_call: Dict[str, Any]) -> NormalizedToolCall:
        # Resolve aliases, canonicalize tool name, canonicalize destination,
        # compute payload digest, infer tool effect from tool profile.
        raise NotImplementedError

    def apply_sanitizer(self, call: NormalizedToolCall, decision: Decision) -> Dict[str, Any]:
        raise NotImplementedError
