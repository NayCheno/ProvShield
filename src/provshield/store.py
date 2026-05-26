"""Sidecar provenance store: tracks labeled objects and builds argument provenance graphs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .labels import (
    Confidentiality,
    Integrity,
    ProvenanceLabel,
    join_confidentiality,
    join_integrity,
    join_labels,
    make_label,
)
from .types import NormalizedToolCall


@dataclass(frozen=True)
class LabeledObject:
    """An object with its runtime-side provenance label."""
    object_id: str
    value: Any
    label: ProvenanceLabel


@dataclass(frozen=True)
class ProvenanceGraph:
    """Argument provenance graph for a tool call."""
    call: NormalizedToolCall
    source_labels: tuple[ProvenanceLabel, ...]
    payload_labels: tuple[ProvenanceLabel, ...]
    all_labels: tuple[ProvenanceLabel, ...]

    def labels(self) -> list[ProvenanceLabel]:
        return list(self.all_labels)

    def max_confidentiality(self) -> Confidentiality:
        if not self.all_labels:
            return Confidentiality.PUBLIC
        return max(lbl.confidentiality for lbl in self.all_labels)

    def min_integrity(self) -> Integrity:
        if not self.all_labels:
            return Integrity.EXTERNAL
        return min(lbl.integrity for lbl in self.all_labels)

    def has_low_integrity_influence(self) -> bool:
        return any(lbl.is_low_integrity() for lbl in self.all_labels)

    def has_direct_user_intent(self, call: NormalizedToolCall | None = None) -> bool:
        return any(
            lbl.integrity == Integrity.USER_INTENT for lbl in self.source_labels
        )

    def influenced_by(self, integrity_name: str) -> bool:
        from .labels import NAME_TO_INTEGRITY
        if integrity_name not in NAME_TO_INTEGRITY:
            return False
        target = NAME_TO_INTEGRITY[integrity_name]
        return any(lbl.integrity == target for lbl in self.all_labels)


class SidecarProvenanceStore:
    """Runtime-side store for provenance labels attached to context objects."""

    def __init__(self) -> None:
        self._objects: dict[str, LabeledObject] = {}
        self._counter: int = 0

    def ingest(
        self,
        value: Any,
        integrity: str | Integrity,
        confidentiality: str | Confidentiality,
        origin: str,
        **kwargs: Any,
    ) -> LabeledObject:
        """Ingest a new object with provenance label."""
        self._counter += 1
        obj_id = f"obj_{self._counter:06d}"
        label = make_label(integrity, confidentiality, origin, **kwargs)
        obj = LabeledObject(object_id=obj_id, value=value, label=label)
        self._objects[obj_id] = obj
        return obj

    def get(self, object_id: str) -> Optional[LabeledObject]:
        return self._objects.get(object_id)

    def build_argument_graph(self, call: NormalizedToolCall) -> ProvenanceGraph:
        """Build provenance graph for a tool call from stored labels."""
        # In a real system, this would trace which context objects
        # contributed to the call's arguments. For the prototype,
        # we scan all stored labels to simulate provenance tracking.
        all_labels = [obj.label for obj in self._objects.values()]

        # Source labels: those that could have influenced the call
        source_labels = []
        for obj in self._objects.values():
            if self._object_contributed_to_call(obj, call):
                source_labels.append(obj.label)

        # Payload labels: labels on the data being sent/written
        payload_labels = self._extract_payload_labels(call)

        return ProvenanceGraph(
            call=call,
            source_labels=tuple(source_labels),
            payload_labels=tuple(payload_labels),
            all_labels=tuple(all_labels or source_labels),
        )

    def label_tool_output(
        self,
        call: NormalizedToolCall,
        output: Any,
        source_integrity: Integrity = Integrity.TOOL_OUTPUT,
    ) -> LabeledObject:
        """Label a tool output and store it."""
        return self.ingest(
            value=output,
            integrity=source_integrity,
            confidentiality=Confidentiality.PUBLIC,
            origin=f"tool:{call.tool_name}",
        )

    def _object_contributed_to_call(
        self, obj: LabeledObject, call: NormalizedToolCall
    ) -> bool:
        """Heuristic: check if an object likely contributed to the call."""
        # Check if object value appears in call arguments
        val_str = str(obj.value)
        for arg_val in call.arguments.values():
            if val_str and val_str in str(arg_val):
                return True
        return False

    def _extract_payload_labels(self, call: NormalizedToolCall) -> list[ProvenanceLabel]:
        """Extract labels for payload data in the call."""
        payload_keys = {"body", "content", "message", "data", "payload", "text"}
        labels = []
        for key in payload_keys:
            if key in call.arguments:
                # Try to find matching stored objects
                val = str(call.arguments[key])
                for obj in self._objects.values():
                    if str(obj.value) in val or val in str(obj.value):
                        labels.append(obj.label)
        return labels

    def compute_payload_digest(self, data: Any) -> str:
        """Compute SHA-256 digest of payload data."""
        if isinstance(data, str):
            raw = data.encode()
        elif isinstance(data, bytes):
            raw = data
        else:
            raw = json.dumps(data, sort_keys=True, default=str).encode()
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    @property
    def object_count(self) -> int:
        return len(self._objects)
