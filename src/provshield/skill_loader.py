"""Skill loader: provenance-aware skill ingestion and labeling.

This is a skeleton implementation that demonstrates skill loading
with provenance classification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .context import ContextBuilder
from .store import LabeledObject


@dataclass(frozen=True)
class SkillManifest:
    """Skill package manifest."""
    name: str
    version: str
    instructions: str
    trusted: bool = False
    signature: Optional[str] = None
    dependencies: tuple[str, ...] = ()


class SkillLoader:
    """Loads and labels skill packages with provenance.

    Responsibilities:
      - Classify skill as trusted or untrusted
      - Verify signatures if available
      - Label skill instructions
      - Prevent skill from modifying policy
    """

    def __init__(self, context_builder: ContextBuilder) -> None:
        self.context = context_builder
        self._loaded_skills: dict[str, SkillManifest] = {}

    def load_skill(
        self,
        manifest: SkillManifest,
        verify_signature: bool = True,
    ) -> LabeledObject:
        """Load a skill package and label its instructions."""
        # Verify signature if skill claims to be trusted
        is_trusted = manifest.trusted
        if is_trusted and verify_signature:
            is_trusted = self._verify_signature(manifest)
            if not is_trusted:
                # Signature verification failed; downgrade to untrusted
                is_trusted = False

        obj = self.context.ingest_skill_instruction(
            instruction=manifest.instructions,
            skill_name=manifest.name,
            trusted=is_trusted,
        )

        self._loaded_skills[manifest.name] = manifest
        return obj

    def _verify_signature(self, manifest: SkillManifest) -> bool:
        """Verify skill package signature. Stub: returns False if no signature."""
        if manifest.signature is None:
            return False
        # In production: verify cryptographic signature against trusted registry
        return len(manifest.signature) > 0

    def is_loaded(self, skill_name: str) -> bool:
        return skill_name in self._loaded_skills

    def get_skill(self, skill_name: str) -> Optional[SkillManifest]:
        return self._loaded_skills.get(skill_name)

    @property
    def loaded_count(self) -> int:
        return len(self._loaded_skills)
