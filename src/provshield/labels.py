"""Provenance labels, integrity lattice, and confidentiality lattice."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Integrity lattice  (higher value = higher trust)
# ---------------------------------------------------------------------------

class Integrity(IntEnum):
    UNSKILLED = 0        # UntrustedSkill
    EXTERNAL = 1         # ExternalContent
    TOOL_OUTPUT = 2      # ToolOutput
    TOOL_META = 3        # ToolMetadata
    ATTESTED_META = 4    # AttestedToolMetadata
    TRUSTED_SKILL = 5    # TrustedSkill
    USER_INTENT = 6      # UserIntent
    SYSTEM_POLICY = 7    # SystemPolicy


INTEGRITY_NAMES: dict[Integrity, str] = {
    Integrity.UNSKILLED: "UntrustedSkill",
    Integrity.EXTERNAL: "ExternalContent",
    Integrity.TOOL_OUTPUT: "ToolOutput",
    Integrity.TOOL_META: "ToolMetadata",
    Integrity.ATTESTED_META: "AttestedToolMetadata",
    Integrity.TRUSTED_SKILL: "TrustedSkill",
    Integrity.USER_INTENT: "UserIntent",
    Integrity.SYSTEM_POLICY: "SystemPolicy",
}

NAME_TO_INTEGRITY: dict[str, Integrity] = {v: k for k, v in INTEGRITY_NAMES.items()}


def parse_integrity(name: str) -> Integrity:
    """Parse an integrity label name into its enum value."""
    if name in NAME_TO_INTEGRITY:
        return NAME_TO_INTEGRITY[name]
    raise ValueError(f"Unknown integrity label: {name!r}")


def join_integrity(a: Integrity, b: Integrity) -> Integrity:
    """Meet (lower) of two integrity labels — conservatively trust the lower one."""
    return min(a, b)


# ---------------------------------------------------------------------------
# Confidentiality lattice  (higher value = more sensitive)
# ---------------------------------------------------------------------------

class Confidentiality(IntEnum):
    PUBLIC = 0
    USER_PRIVATE = 1
    SECRET = 2
    CAPABILITY_TOKEN = 3


CONFIDENTIALITY_NAMES: dict[Confidentiality, str] = {
    Confidentiality.PUBLIC: "Public",
    Confidentiality.USER_PRIVATE: "UserPrivate",
    Confidentiality.SECRET: "Secret",
    Confidentiality.CAPABILITY_TOKEN: "CapabilityToken",
}

NAME_TO_CONFIDENTIALITY: dict[str, Confidentiality] = {
    v: k for k, v in CONFIDENTIALITY_NAMES.items()
}


def parse_confidentiality(name: str) -> Confidentiality:
    """Parse a confidentiality label name into its enum value."""
    if name in NAME_TO_CONFIDENTIALITY:
        return NAME_TO_CONFIDENTIALITY[name]
    raise ValueError(f"Unknown confidentiality label: {name!r}")


def join_confidentiality(a: Confidentiality, b: Confidentiality) -> Confidentiality:
    """Join (raise) of two confidentiality labels — conservatively raise."""
    return max(a, b)


# ---------------------------------------------------------------------------
# Provenance label
# ---------------------------------------------------------------------------

LOW_INTEGRITY_SOURCES = frozenset({
    Integrity.EXTERNAL,
    Integrity.TOOL_OUTPUT,
    Integrity.TOOL_META,
    Integrity.UNSKILLED,
})


@dataclass(frozen=True)
class ProvenanceLabel:
    """Immutable provenance label bound to a context object."""

    integrity: Integrity
    confidentiality: Confidentiality
    origin: str                              # e.g. "web", "email", "mcp", "skill", "user"
    principals: tuple[str, ...] = ()         # responsible principals
    transform_history: tuple[str, ...] = ()  # transformation chain
    runtime_signature: str = ""              # HMAC or similar
    nonce: str = ""
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.nonce:
            object.__setattr__(self, "nonce", secrets.token_hex(16))
        if not self.created_at:
            object.__setattr__(self, "created_at", time.time())
        if not self.runtime_signature:
            object.__setattr__(
                self,
                "runtime_signature",
                self._compute_signature(),
            )

    def _compute_signature(self) -> str:
        """Compute a deterministic signature over label fields."""
        payload = (
            f"{self.integrity.value}|"
            f"{self.confidentiality.value}|"
            f"{self.origin}|"
            f"{','.join(self.principals)}|"
            f"{','.join(self.transform_history)}|"
            f"{self.nonce}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    def is_low_integrity(self) -> bool:
        return self.integrity in LOW_INTEGRITY_SOURCES

    def dominates(self, other: ProvenanceLabel) -> bool:
        """True if this label has >= integrity and <= confidentiality."""
        return (
            self.integrity >= other.integrity
            and self.confidentiality <= other.confidentiality
        )

    def with_transform(self, step: str) -> ProvenanceLabel:
        """Return a new label with an appended transformation step."""
        return ProvenanceLabel(
            integrity=self.integrity,
            confidentiality=self.confidentiality,
            origin=self.origin,
            principals=self.principals,
            transform_history=self.transform_history + (step,),
            runtime_signature="",  # will be recomputed
            nonce=self.nonce,
            created_at=self.created_at,
        )


def join_labels(labels: list[ProvenanceLabel]) -> ProvenanceLabel:
    """Conservatively join multiple labels: lowest integrity, highest confidentiality."""
    if not labels:
        raise ValueError("Cannot join empty label set")
    result = labels[0]
    for lbl in labels[1:]:
        result = ProvenanceLabel(
            integrity=join_integrity(result.integrity, lbl.integrity),
            confidentiality=join_confidentiality(result.confidentiality, lbl.confidentiality),
            origin=f"join({result.origin},{lbl.origin})",
            principals=tuple(set(result.principals) | set(lbl.principals)),
            transform_history=result.transform_history + ("join",),
        )
    return result


# ---------------------------------------------------------------------------
# Convenience constructors
# ---------------------------------------------------------------------------

def make_label(
    integrity: str | Integrity,
    confidentiality: str | Confidentiality,
    origin: str,
    **kwargs: object,
) -> ProvenanceLabel:
    """Create a label from string or enum values."""
    if isinstance(integrity, str):
        integrity = parse_integrity(integrity)
    if isinstance(confidentiality, str):
        confidentiality = parse_confidentiality(confidentiality)
    return ProvenanceLabel(
        integrity=integrity,
        confidentiality=confidentiality,
        origin=origin,
        **kwargs,  # type: ignore[arg-type]
    )
