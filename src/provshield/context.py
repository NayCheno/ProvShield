"""Context builder: ingests content, assigns labels, builds labeled prompt context."""

from __future__ import annotations

from typing import Any, Optional

from .labels import Confidentiality, Integrity, ProvenanceLabel, make_label
from .store import LabeledObject, SidecarProvenanceStore


class ContextBuilder:
    """Builds a labeled context for the LLM planner.

    Responsibilities:
      - Ingest content from various sources
      - Assign appropriate provenance labels
      - Store sidecar metadata
      - Render prompt with human-readable boundaries
      - Maintain context slice IDs
    """

    def __init__(self, store: Optional[SidecarProvenanceStore] = None) -> None:
        self.store = store or SidecarProvenanceStore()
        self._context_parts: list[dict[str, Any]] = []

    def ingest_system_policy(self, text: str) -> LabeledObject:
        """Ingest a system policy instruction."""
        obj = self.store.ingest(
            text,
            integrity=Integrity.SYSTEM_POLICY,
            confidentiality=Confidentiality.PUBLIC,
            origin="system",
        )
        self._context_parts.append({
            "type": "system_policy",
            "text": text,
            "object_id": obj.object_id,
            "rendered": f"[SystemPolicy] {text}",
        })
        return obj

    def ingest_user_goal(self, text: str) -> LabeledObject:
        """Ingest a user goal/instruction."""
        obj = self.store.ingest(
            text,
            integrity=Integrity.USER_INTENT,
            confidentiality=Confidentiality.PUBLIC,
            origin="user",
        )
        self._context_parts.append({
            "type": "user_goal",
            "text": text,
            "object_id": obj.object_id,
            "rendered": f"[UserIntent] {text}",
        })
        return obj

    def ingest_external_content(
        self,
        text: str,
        source: str = "web",
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
    ) -> LabeledObject:
        """Ingest external content (web, email, RAG, etc.)."""
        obj = self.store.ingest(
            text,
            integrity=Integrity.EXTERNAL,
            confidentiality=confidentiality,
            origin=source,
        )
        self._context_parts.append({
            "type": "external",
            "text": text,
            "source": source,
            "object_id": obj.object_id,
            "rendered": f"[ExternalContent:{source}] {text}",
        })
        return obj

    def ingest_tool_output(
        self,
        text: str,
        tool_name: str,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
    ) -> LabeledObject:
        """Ingest tool output."""
        obj = self.store.ingest(
            text,
            integrity=Integrity.TOOL_OUTPUT,
            confidentiality=confidentiality,
            origin=f"tool:{tool_name}",
        )
        self._context_parts.append({
            "type": "tool_output",
            "text": text,
            "tool": tool_name,
            "object_id": obj.object_id,
            "rendered": f"[ToolOutput:{tool_name}] {text}",
        })
        return obj

    def ingest_tool_metadata(
        self,
        metadata: dict[str, Any],
        tool_name: str,
        attested: bool = False,
    ) -> LabeledObject:
        """Ingest MCP tool metadata."""
        integrity = (
            Integrity.ATTESTED_META if attested else Integrity.TOOL_META
        )
        obj = self.store.ingest(
            metadata,
            integrity=integrity,
            confidentiality=Confidentiality.PUBLIC,
            origin=f"mcp:{tool_name}",
        )
        integrity_name = "AttestedToolMetadata" if attested else "ToolMetadata"
        self._context_parts.append({
            "type": "tool_metadata",
            "metadata": metadata,
            "tool": tool_name,
            "object_id": obj.object_id,
            "rendered": f"[{integrity_name}:{tool_name}] Tool registered.",
        })
        return obj

    def ingest_skill_instruction(
        self,
        instruction: str,
        skill_name: str,
        trusted: bool = False,
    ) -> LabeledObject:
        """Ingest skill instructions."""
        integrity = Integrity.TRUSTED_SKILL if trusted else Integrity.UNSKILLED
        obj = self.store.ingest(
            instruction,
            integrity=integrity,
            confidentiality=Confidentiality.PUBLIC,
            origin=f"skill:{skill_name}",
        )
        integrity_name = "TrustedSkill" if trusted else "UntrustedSkill"
        self._context_parts.append({
            "type": "skill_instruction",
            "instruction": instruction,
            "skill": skill_name,
            "object_id": obj.object_id,
            "rendered": f"[{integrity_name}:{skill_name}] {instruction}",
        })
        return obj

    def ingest_secret(
        self,
        value: str,
        name: str = "secret",
    ) -> LabeledObject:
        """Ingest a secret value."""
        obj = self.store.ingest(
            value,
            integrity=Integrity.USER_INTENT,
            confidentiality=Confidentiality.SECRET,
            origin=f"secret:{name}",
        )
        self._context_parts.append({
            "type": "secret",
            "name": name,
            "object_id": obj.object_id,
            "rendered": f"[Secret:{name}] <redacted>",
        })
        return obj

    def ingest_private_data(
        self,
        text: str,
        source: str = "email",
    ) -> LabeledObject:
        """Ingest private user data."""
        obj = self.store.ingest(
            text,
            integrity=Integrity.USER_INTENT,
            confidentiality=Confidentiality.USER_PRIVATE,
            origin=source,
        )
        self._context_parts.append({
            "type": "private_data",
            "text": text,
            "source": source,
            "object_id": obj.object_id,
            "rendered": f"[UserPrivate:{source}] {text}",
        })
        return obj

    def render_context(self) -> str:
        """Render the full context as a prompt with provenance boundaries."""
        parts = []
        for part in self._context_parts:
            parts.append(part.get("rendered", str(part.get("text", ""))))
        return "\n\n".join(parts)

    def get_context_parts(self) -> list[dict[str, Any]]:
        """Get all context parts with metadata."""
        return list(self._context_parts)

    def clear(self) -> None:
        """Clear the context (does not clear the store)."""
        self._context_parts.clear()

    @property
    def object_count(self) -> int:
        return self.store.object_count
