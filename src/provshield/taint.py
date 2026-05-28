"""Argument builder / taint propagation for provenance tracking.

PR-C3: Ensures every tool call argument has explicit source object IDs,
rather than relying on string matching heuristics.

Three provenance modes for evaluation sensitivity analysis:
  oracle-source:          scenario provides ground-truth source IDs
  conservative-all-context: all context objects bound to all arguments
  runtime-heuristic:      content-overlap inference (default)

Taint propagation rules (runtime-heuristic mode):
  copy:           source labels → destination
  summarize:      source labels → summary output
  template fill:  template + fill sources → output
  retrieval join: query sources + retrieved doc sources → result
  tool output:    tool input sources → next tool input
  skill instruction: skill label → proposed action
  email/web/RAG:  external content → destination/payload/path
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .labels import Integrity, Confidentiality, ProvenanceLabel, join_labels, make_label
from .store import LabeledObject, SidecarProvenanceStore


class ProvenanceMode(str, Enum):
    """Provenance tracking modes for evaluation ablation.

    ORACLE: Scenario generator provides ground-truth source IDs in
            the proposed call's ``argument_sources`` field. Best-case
            provenance precision.
    CONSERVATIVE: Every context object is linked to every argument.
            Maximises false blocking, minimises false negatives.
    HEURISTIC: Content-overlap inference via ArgumentBuilder.
            Default production mode.
    """
    ORACLE = "oracle"
    CONSERVATIVE = "conservative"
    HEURISTIC = "heuristic"


@dataclass
class TaintEdge:
    """A single taint propagation edge."""
    source_obj_id: str
    target_field: str
    transform: str  # "copy", "summarize", "template_fill", "retrieval_join", etc.


@dataclass
class ArgumentTrace:
    """Traces how each argument field was constructed from context objects."""
    field_name: str
    source_obj_ids: list[str]
    transform: str = "copy"
    confidence: float = 1.0  # 1.0 = certain, <1.0 = heuristic


class ArgumentBuilder:
    """Builds argument_sources for tool calls by tracking taint propagation.

    Supports three provenance modes for evaluation ablation:
      - ORACLE: use explicit ground-truth sources from scenario
      - CONSERVATIVE: bind all context objects to all arguments
      - HEURISTIC: content-overlap inference (default)

    PR-C3: This is the mandatory argument source tracing system.
    """

    def __init__(
        self,
        store: SidecarProvenanceStore,
        mode: ProvenanceMode = ProvenanceMode.HEURISTIC,
    ) -> None:
        self._store = store
        self._mode = mode
        self._traces: dict[str, list[ArgumentTrace]] = {}

    def build_sources(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context_obj_ids: Optional[list[str]] = None,
        explicit_sources: Optional[dict[str, list[str]]] = None,
    ) -> dict[str, list[str]]:
        """Build argument_sources for a proposed tool call.

        Dispatches to the appropriate mode:
          ORACLE → use explicit_sources if provided
          CONSERVATIVE → bind all context to all arguments
          HEURISTIC → content-overlap inference

        Returns: {arg_key: [source_obj_id, ...]}
        """
        if context_obj_ids is None:
            context_obj_ids = list(self._store._objects.keys())

        if self._mode == ProvenanceMode.ORACLE:
            return self._build_oracle_sources(
                arguments, context_obj_ids, explicit_sources,
            )

        if self._mode == ProvenanceMode.CONSERVATIVE:
            return self._build_conservative_sources(arguments, context_obj_ids)

        # Default: HEURISTIC mode
        sources: dict[str, list[str]] = {}
        for arg_key, arg_value in arguments.items():
            field_sources = self._trace_field(arg_key, arg_value, context_obj_ids)
            if field_sources:
                sources[arg_key] = field_sources
        return sources

    def _build_oracle_sources(
        self,
        arguments: dict[str, Any],
        context_obj_ids: list[str],
        explicit_sources: Optional[dict[str, list[str]]],
    ) -> dict[str, list[str]]:
        """Oracle mode: use ground-truth source IDs if provided.

        Falls back to conservative when no ground-truth is available.
        """
        if explicit_sources:
            # Validate that referenced IDs exist in the store
            valid: dict[str, list[str]] = {}
            for arg_key, obj_ids in explicit_sources.items():
                valid_ids = [oid for oid in obj_ids if oid in self._store._objects]
                if valid_ids:
                    valid[arg_key] = valid_ids
            if valid:
                return valid
        # No ground-truth available — fall back to conservative
        return self._build_conservative_sources(arguments, context_obj_ids)

    def _build_conservative_sources(
        self,
        arguments: dict[str, Any],
        context_obj_ids: list[str],
    ) -> dict[str, list[str]]:
        """Conservative mode: bind all context objects to every argument.

        Maximises provenance coverage at the cost of precision.
        Useful as an upper-bound sensitivity analysis.
        """
        return {arg_key: list(context_obj_ids) for arg_key in arguments}

    def _trace_field(
        self,
        field_name: str,
        field_value: Any,
        context_obj_ids: list[str],
    ) -> list[str]:
        """Trace which context objects contributed to a field value."""
        sources: list[str] = []
        field_str = str(field_value).lower()

        for obj_id in context_obj_ids:
            obj = self._store.get(obj_id)
            if obj is None:
                continue

            obj_str = str(obj.value).lower()

            # Rule 1: Direct copy — object value appears in field
            if obj_str and obj_str in field_str:
                sources.append(obj_id)
                continue

            # Rule 2: Summarize — significant substring overlap
            if self._is_likely_summarized(obj_str, field_str):
                sources.append(obj_id)
                continue

            # Rule 3: Template fill — field contains key phrases from object
            if self._is_template_fill(obj_str, field_str):
                sources.append(obj_id)
                continue

            # Rule 4: Retrieval join — field references object content
            if self._is_retrieval_join(obj_str, field_str):
                sources.append(obj_id)
                continue

            # Rule 5: External content influence — detect injected instructions
            if self._has_external_influence(obj, field_name, field_str):
                sources.append(obj_id)
                continue

        return sources

    def _is_likely_summarized(self, source: str, target: str) -> bool:
        """Check if target is likely a summary of source."""
        if len(source) < 20 or len(target) < 10:
            return False
        # Check for significant word overlap
        source_words = set(re.findall(r'\w{4,}', source))
        target_words = set(re.findall(r'\w{4,}', target))
        if not source_words:
            return False
        overlap = len(source_words & target_words)
        return overlap / len(source_words) > 0.3

    def _is_template_fill(self, source: str, target: str) -> bool:
        """Check if target is a template fill from source."""
        # Look for extracted facts: emails, URLs, names, numbers
        source_facts = set(re.findall(r'[\w.-]+@[\w.-]+|https?://\S+|\d+', source))
        target_facts = set(re.findall(r'[\w.-]+@[\w.-]+|https?://\S+|\d+', target))
        if not source_facts:
            return False
        return bool(source_facts & target_facts)

    def _is_retrieval_join(self, source: str, target: str) -> bool:
        """Check if target references source via retrieval."""
        # Check for quoted content or direct references
        if '"' in target:
            quoted = re.findall(r'"([^"]+)"', target)
            for q in quoted:
                if q.lower() in source:
                    return True
        return False

    def _has_external_influence(
        self, obj: LabeledObject, field_name: str, field_str: str
    ) -> bool:
        """Check if an external content object influences this field."""
        if obj.label.integrity not in {Integrity.EXTERNAL, Integrity.TOOL_OUTPUT}:
            return False

        obj_str = str(obj.value).lower()

        # External content with hidden instructions
        if "ignore" in obj_str and "instruction" in obj_str:
            return True
        # External content mentioning the field name
        if field_name in {"to", "destination", "path"}:
            emails = re.findall(r'[\w.-]+@[\w.-]+', obj_str)
            urls = re.findall(r'https?://\S+', obj_str)
            paths = re.findall(r'/[\w/]+', obj_str)
            targets = set(re.findall(r'[\w.-]+@[\w.-]+|https?://\S+|/[\w/]+', field_str))
            if (set(emails) | set(urls) | set(paths)) & targets:
                return True

        return False

    def trace_and_build(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        proposed_call: dict[str, Any],
    ) -> dict[str, list[str]]:
        """Build sources from a proposed_call dict, respecting explicit sources.

        If proposed_call already has argument_sources, use those.
        Otherwise, infer from the provenance store.
        """
        explicit = proposed_call.get("argument_sources")
        if explicit:
            # Already has explicit sources — normalize format
            if isinstance(explicit, dict):
                return {k: list(v) if isinstance(v, (list, tuple)) else [v]
                        for k, v in explicit.items()}
            return explicit

        # PR-C3: Infer sources via taint propagation
        return self.build_sources(tool_name, arguments)
