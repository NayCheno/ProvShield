"""Skill loader: provenance-aware skill ingestion and labeling.

Supports HMAC-based signature verification for trusted skills.
Untrusted skills are labeled with low-integrity provenance.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
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
    signature: Optional[str] = None  # HMAC hex digest
    signer: Optional[str] = None  # who signed this skill
    dependencies: tuple[str, ...] = ()


class SkillLoader:
    """Loads and labels skill packages with provenance.

    Responsibilities:
      - Classify skill as trusted or untrusted
      - Verify HMAC signatures against trusted keys
      - Label skill instructions
      - Prevent skill from modifying policy
    """

    def __init__(
        self,
        context_builder: ContextBuilder,
        trusted_keys: Optional[dict[str, str]] = None,
    ) -> None:
        self.context = context_builder
        self._loaded_skills: dict[str, SkillManifest] = {}
        # PR-6: trusted signer registry (signer_name -> hmac_key)
        self._trusted_keys: dict[str, str] = trusted_keys or {}

    def add_trusted_signer(self, name: str, key: str) -> None:
        """Register a trusted signer with their HMAC key."""
        self._trusted_keys[name] = key

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
        """Verify skill package HMAC signature against trusted keys.

        Returns True only if:
        1. The manifest has a signature and signer
        2. The signer is in the trusted keys registry
        3. The HMAC matches the computed value
        """
        if manifest.signature is None or manifest.signer is None:
            return False

        key = self._trusted_keys.get(manifest.signer)
        if key is None:
            return False  # Unknown signer

        # Compute expected HMAC over skill content
        content = f"{manifest.name}:{manifest.version}:{manifest.instructions}"
        expected = hmac.new(
            key.encode(), content.encode(), hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, manifest.signature)

    def is_loaded(self, skill_name: str) -> bool:
        return skill_name in self._loaded_skills

    def get_skill(self, skill_name: str) -> Optional[SkillManifest]:
        return self._loaded_skills.get(skill_name)

    @property
    def loaded_count(self) -> int:
        return len(self._loaded_skills)
