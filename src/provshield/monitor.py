"""Runtime monitor: intercepts all tool calls, enforces policy, manages bridges."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable, Optional

from .audit import AuditLogger
from .bridge import BridgeManager
from .labels import (
    Integrity,
    Confidentiality,
    ProvenanceLabel,
    INTEGRITY_NAMES,
    CONFIDENTIALITY_NAMES,
)
from .policy import PolicyEngine
from .store import SidecarProvenanceStore, LabeledObject, ProvenanceGraph
from .tokens import CapabilityTokenStore
from .types import (
    EFFECT_SINK_MAP,
    Decision,
    DecisionKind,
    Effect,
    NormalizedToolCall,
    Sink,
)


# Tool profile registry (maps tool names to their declared effects)
TOOL_PROFILES: dict[str, dict[str, Any]] = {
    "send_email": {
        "effects": [Effect.SEND_NETWORK],
        "sink": Sink.NETWORK_SEND,
        "destination_arg": "to",
        "payload_args": ["subject", "body", "attachments"],
    },
    "write_file": {
        "effects": [Effect.WRITE_LOCAL],
        "sink": Sink.LOCAL_WRITE,
        "destination_arg": "path",
        "payload_args": ["content"],
    },
    "delete_file": {
        "effects": [Effect.DELETE_LOCAL],
        "sink": Sink.LOCAL_WRITE,
        "destination_arg": "path",
        "payload_args": [],
    },
    "execute_shell": {
        "effects": [Effect.EXECUTE_CODE],
        "sink": Sink.CODE_EXECUTION,
        "destination_arg": None,
        "payload_args": ["command"],
    },
    "read_webpage": {
        "effects": [Effect.READ_PUBLIC],
        "sink": Sink.LOCAL_READ,
        "destination_arg": None,
        "payload_args": [],
    },
    "read_email": {
        "effects": [Effect.READ_PRIVATE],
        "sink": Sink.PRIVATE_READ,
        "destination_arg": None,
        "payload_args": [],
    },
    "create_oauth_token": {
        "effects": [Effect.CREATE_CREDENTIAL],
        "sink": Sink.CREDENTIAL,
        "destination_arg": None,
        "payload_args": [],
    },
    "validate_session": {
        "effects": [Effect.READ_PUBLIC],
        "sink": Sink.LOCAL_READ,
        "destination_arg": None,
        "payload_args": ["session_id"],
    },
    "query_github_issues": {
        "effects": [Effect.READ_PUBLIC],
        "sink": Sink.LOCAL_READ,
        "destination_arg": None,
        "payload_args": [],
    },
    "create_calendar_invite": {
        "effects": [Effect.CALENDAR_INVITE],
        "sink": Sink.CALENDAR,
        "destination_arg": "participants",
        "payload_args": ["title", "description"],
    },
}


def register_tool(name: str, profile: dict[str, Any]) -> None:
    """Register a custom tool profile."""
    TOOL_PROFILES[name] = profile


class RuntimeMonitor:
    """Central enforcement point: intercepts, normalizes, checks, and logs tool calls.

    Flow:
      1. Normalize proposed call
      2. Build provenance graph
      3. Lookup matching capability token
      4. Evaluate policy
      5. Record decision in audit log
      6. If allowed: execute and label output
      7. If bridge required: create bridge request
      8. If denied: raise PermissionError
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        provenance_store: Optional[SidecarProvenanceStore] = None,
        token_store: Optional[CapabilityTokenStore] = None,
        audit_log: Optional[AuditLogger] = None,
        bridge_manager: Optional[BridgeManager] = None,
    ) -> None:
        self.policy_engine = policy_engine or PolicyEngine()
        self.provenance_store = provenance_store or SidecarProvenanceStore()
        self.token_store = token_store or CapabilityTokenStore()
        self.audit_log = audit_log or AuditLogger()
        self.bridge_manager = bridge_manager or BridgeManager(self.token_store)
        self._latencies: list[float] = []

    def check_and_execute(
        self,
        proposed_call: dict[str, Any],
        executor: Callable[[NormalizedToolCall], Any],
    ) -> Any:
        """Main entry point: check policy and execute if allowed."""
        start = time.perf_counter()

        call = self.normalize_call(proposed_call)
        graph = self.provenance_store.build_argument_graph(call)
        token = self.token_store.lookup_matching_token(call)

        decision = self.policy_engine.evaluate(
            call=call,
            provenance_graph=graph,
            capability_token=token,
        )

        bridge_id = None
        token_id = None

        if decision.kind == DecisionKind.ALLOW:
            if token:
                token.consume()
                token_id = token.token_id
            self.audit_log.record_decision(call, graph, decision, bridge_id, token_id)

            output = executor(call)
            labeled = self.provenance_store.label_tool_output(call, output)
            self.audit_log.record_execution(call, type(output).__name__)
            self._record_latency(start)
            return labeled

        if decision.kind == DecisionKind.REQUIRE_BRIDGE:
            # Create bridge request
            source_names = [
                INTEGRITY_NAMES.get(lbl.integrity, "?")
                for lbl in graph.source_labels
            ]
            untrusted = [
                n for n in source_names
                if n in {"ExternalContent", "ToolOutput", "ToolMetadata", "UntrustedSkill"}
            ]
            bridge_req = self.bridge_manager.create_request(
                call, source_names, untrusted
            )
            bridge_id = bridge_req.bridge_id
            self.audit_log.record_decision(call, graph, decision, bridge_id)
            self.audit_log.record_bridge_request(bridge_id, call)
            self._record_latency(start)
            # Attach bridge request info to the decision for the caller
            from .types import Decision
            enriched = Decision(
                kind=decision.kind,
                reason=decision.reason,
                bridge_request={
                    "bridge_id": bridge_req.bridge_id,
                    "action": bridge_req.action,
                    "destination": bridge_req.destination,
                    "payload_digest": bridge_req.payload_digest,
                    "sources_used": bridge_req.sources_used,
                    "blocked_or_untrusted_sources": bridge_req.blocked_or_untrusted_sources,
                },
            )
            return enriched

        if decision.kind == DecisionKind.DENY:
            self.audit_log.record_decision(call, graph, decision)
            self._record_latency(start)
            raise PermissionError(decision.reason)

        if decision.kind == DecisionKind.SANITIZE:
            self.audit_log.record_decision(call, graph, decision)
            self._record_latency(start)
            sanitized = self.apply_sanitizer(call, decision)
            return self.check_and_execute(sanitized, executor)

        self._record_latency(start)
        return decision

    def normalize_call(self, proposed_call: dict[str, Any]) -> NormalizedToolCall:
        """Normalize a raw proposed call into a canonical form."""
        tool_name = proposed_call.get("tool_name", proposed_call.get("tool", "unknown"))
        arguments = proposed_call.get("arguments", proposed_call.get("args", {}))

        profile = TOOL_PROFILES.get(tool_name)
        is_registered = profile is not None
        if profile is None:
            # PR-2: Unknown tools default to high-risk — must be explicitly registered
            profile = {}
        effects = profile.get("effects", [Effect.READ_PUBLIC])
        effect = effects[0] if effects else Effect.READ_PUBLIC
        sink = profile.get("sink", EFFECT_SINK_MAP.get(effect, Sink.LOCAL_READ))

        # Extract destination
        destination = None
        dest_arg = profile.get("destination_arg")
        if dest_arg and dest_arg in arguments:
            destination = str(arguments[dest_arg])

        # Compute payload digest
        payload_digest = None
        payload_args = profile.get("payload_args", [])
        if payload_args:
            payload_data = {
                k: arguments[k] for k in payload_args if k in arguments
            }
            if payload_data:
                payload_str = json.dumps(payload_data, sort_keys=True, default=str)
                payload_digest = "sha256:" + hashlib.sha256(payload_str.encode()).hexdigest()

        principal = proposed_call.get("principal", "user")

        # PR-1: Wire explicit argument sources from proposed_call
        raw_sources = proposed_call.get("argument_sources")
        argument_sources: Optional[tuple[tuple[str, str], ...]] = None
        if isinstance(raw_sources, dict):
            # Convert {arg_key: [obj_ids...]} to flat tuple of (arg_key, obj_id)
            pairs: list[tuple[str, str]] = []
            for arg_key, obj_ids in raw_sources.items():
                if isinstance(obj_ids, (list, tuple)):
                    for oid in obj_ids:
                        pairs.append((str(arg_key), str(oid)))
                else:
                    pairs.append((str(arg_key), str(obj_ids)))
            argument_sources = tuple(pairs) if pairs else None
        elif isinstance(raw_sources, (list, tuple)):
            argument_sources = tuple(
                (str(k), str(v)) for k, v in raw_sources
            ) or None

        return NormalizedToolCall(
            tool_name=tool_name,
            arguments=arguments,
            effect=effect,
            sink=sink,
            destination=destination,
            payload_digest=payload_digest,
            principal=principal,
            argument_sources=argument_sources,
            tool_registered=is_registered,
        )

    def apply_sanitizer(
        self,
        call: NormalizedToolCall,
        decision: Decision,
    ) -> dict[str, Any]:
        """Apply sanitization transform (placeholder)."""
        return {
            "tool_name": call.tool_name,
            "arguments": call.arguments,
            "principal": call.principal,
        }

    def complete_bridge(
        self,
        bridge_id: str,
        accepted: bool,
        user_id: str = "user",
        executor: Optional[Callable[[NormalizedToolCall], Any]] = None,
    ) -> Any:
        """Complete a bridge interaction: confirm, mint token, and optionally re-execute.

        Returns the minted CapabilityToken. If executor is provided, also
        re-checks the original call with the new token and executes.
        """
        confirmation = self.bridge_manager.confirm(bridge_id, accepted, user_id)
        if confirmation is None:
            raise ValueError(f"Bridge {bridge_id} not found or expired")

        self.audit_log.record_bridge_confirmation(bridge_id, accepted)

        if not accepted:
            self.bridge_manager.reject_and_cleanup(bridge_id)
            return None

        # Snapshot the request before mint_token cleans it up
        request = self.bridge_manager.get_request(bridge_id)

        token = self.bridge_manager.mint_token(bridge_id)
        if token is None:
            raise RuntimeError(f"Failed to mint token for bridge {bridge_id}")

        # PR-3: Re-execute with the minted token if executor provided
        if executor and request:
            # Reconstruct the normalized call from the bridge request
            effect = Effect(request.effect)
            sink = Sink(request.sink)
            original_call = NormalizedToolCall(
                tool_name=request.action,
                arguments={},  # arguments were in the original proposed_call, not stored
                effect=effect,
                sink=sink,
                destination=request.destination,
                payload_digest=request.payload_digest,
                principal=user_id,
            )
            # Re-enter check_and_execute — token is now in the store
            # and should match, allowing execution
            graph = self.provenance_store.build_argument_graph(original_call)
            decision = self.policy_engine.evaluate(
                call=original_call,
                provenance_graph=graph,
                capability_token=token,
            )
            if decision.kind == DecisionKind.ALLOW:
                token.consume()
                self.audit_log.record_decision(
                    original_call, graph, decision, bridge_id, token.token_id
                )
                output = executor(original_call)
                labeled = self.provenance_store.label_tool_output(original_call, output)
                self.audit_log.record_execution(original_call, type(output).__name__)
                return labeled

        return token

    def _record_latency(self, start: float) -> None:
        elapsed = (time.perf_counter() - start) * 1000  # ms
        self._latencies.append(elapsed)

    def get_latency_stats(self) -> dict[str, float]:
        """Get latency statistics in milliseconds."""
        if not self._latencies:
            return {"p50": 0, "p95": 0, "mean": 0, "count": 0}
        sorted_lat = sorted(self._latencies)
        n = len(sorted_lat)
        return {
            "p50": sorted_lat[n // 2],
            "p95": sorted_lat[int(n * 0.95)],
            "mean": sum(sorted_lat) / n,
            "count": n,
            "min": sorted_lat[0],
            "max": sorted_lat[-1],
        }
