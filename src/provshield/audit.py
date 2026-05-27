"""Audit logger: records all policy decisions and tool executions for replay."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

from .store import ProvenanceGraph
from .types import Decision, DecisionKind, NormalizedToolCall


@dataclass
class AuditEntry:
    """A single audit log entry."""
    timestamp: float
    entry_type: str         # "decision", "execution", "bridge_request", "bridge_confirm"
    tool_name: str
    effect: str
    sink: str
    destination: Optional[str]
    payload_digest: Optional[str]
    decision_kind: str
    decision_reason: str
    source_integrities: list[str] = field(default_factory=list)
    max_confidentiality: str = ""
    bridge_id: Optional[str] = None
    token_id: Optional[str] = None
    execution_output_type: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """Deterministic audit logger with replay support."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._decision_index: dict[str, list[int]] = {}  # tool_name -> entry indices

    def record_decision(
        self,
        call: NormalizedToolCall,
        graph: ProvenanceGraph,
        decision: Decision,
        bridge_id: Optional[str] = None,
        token_id: Optional[str] = None,
    ) -> AuditEntry:
        """Record a policy decision."""
        from .labels import INTEGRITY_NAMES, CONFIDENTIALITY_NAMES

        # PR-C4: Store call details for deterministic replay
        extra = {
            "arguments": call.arguments,
            "argument_sources": dict(call.argument_sources) if call.argument_sources else None,
            "principal": call.principal,
            "tool_registered": call.tool_registered,
        }

        entry = AuditEntry(
            timestamp=time.time(),
            entry_type="decision",
            tool_name=call.tool_name,
            effect=call.effect.value,
            sink=call.sink.value,
            destination=call.destination,
            payload_digest=call.payload_digest,
            decision_kind=decision.kind.value,
            decision_reason=decision.reason,
            source_integrities=[
                INTEGRITY_NAMES.get(lbl.integrity, "?")
                for lbl in graph.source_labels
            ],
            max_confidentiality=CONFIDENTIALITY_NAMES.get(
                graph.max_confidentiality(), "?"
            ),
            bridge_id=bridge_id,
            token_id=token_id,
            extra=extra,
        )
        self._append(entry)
        return entry

    def record_execution(
        self,
        call: NormalizedToolCall,
        output_type: str = "unknown",
    ) -> AuditEntry:
        """Record a tool execution."""
        entry = AuditEntry(
            timestamp=time.time(),
            entry_type="execution",
            tool_name=call.tool_name,
            effect=call.effect.value,
            sink=call.sink.value,
            destination=call.destination,
            payload_digest=call.payload_digest,
            decision_kind="executed",
            decision_reason="Tool executed after policy approval.",
            execution_output_type=output_type,
        )
        self._append(entry)
        return entry

    def record_bridge_request(self, bridge_id: str, call: NormalizedToolCall) -> AuditEntry:
        entry = AuditEntry(
            timestamp=time.time(),
            entry_type="bridge_request",
            tool_name=call.tool_name,
            effect=call.effect.value,
            sink=call.sink.value,
            destination=call.destination,
            payload_digest=call.payload_digest,
            decision_kind="bridge_requested",
            decision_reason="User-intent bridge requested.",
            bridge_id=bridge_id,
        )
        self._append(entry)
        return entry

    def record_bridge_confirmation(
        self, bridge_id: str, accepted: bool
    ) -> AuditEntry:
        entry = AuditEntry(
            timestamp=time.time(),
            entry_type="bridge_confirm",
            tool_name="",
            effect="",
            sink="",
            destination=None,
            payload_digest=None,
            decision_kind="bridge_confirmed" if accepted else "bridge_rejected",
            decision_reason=(
                "User confirmed bridge." if accepted else "User rejected bridge."
            ),
            bridge_id=bridge_id,
        )
        self._append(entry)
        return entry

    def _append(self, entry: AuditEntry) -> None:
        idx = len(self._entries)
        self._entries.append(entry)
        if entry.tool_name:
            self._decision_index.setdefault(entry.tool_name, []).append(idx)

    def get_entries(
        self,
        tool_name: Optional[str] = None,
        entry_type: Optional[str] = None,
        decision_kind: Optional[str] = None,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters."""
        entries = self._entries
        if tool_name:
            indices = self._decision_index.get(tool_name, [])
            entries = [self._entries[i] for i in indices]
        if entry_type:
            entries = [e for e in entries if e.entry_type == entry_type]
        if decision_kind:
            entries = [e for e in entries if e.decision_kind == decision_kind]
        return entries

    def replay_decisions(self) -> list[dict[str, Any]]:
        """Return all decision entries for deterministic replay."""
        return [
            e.to_dict() for e in self._entries if e.entry_type == "decision"
        ]

    def export_trace_jsonl(self, path: str | Path) -> None:
        """Export all entries as JSONL for deterministic replay."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            for entry in self._entries:
                f.write(entry.to_json() + "\n")

    def export_trace_dict(self) -> list[dict[str, Any]]:
        """Export all entries as list of dicts."""
        return [e.to_dict() for e in self._entries]

    @property
    def total_entries(self) -> int:
        return len(self._entries)

    @property
    def deny_count(self) -> int:
        return sum(
            1 for e in self._entries
            if e.decision_kind == DecisionKind.DENY.value
        )

    @property
    def allow_count(self) -> int:
        return sum(
            1 for e in self._entries
            if e.decision_kind == DecisionKind.ALLOW.value
        )

    @property
    def bridge_count(self) -> int:
        return sum(
            1 for e in self._entries
            if e.decision_kind == DecisionKind.REQUIRE_BRIDGE.value
        )