"""Capability tokens: non-forgeable, one-time, scope-bound runtime credentials."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# Shared HMAC key for token signing — same key as label signing.
# In production this is injected via PROVSHIELD_HMAC_KEY env var.
_TOKEN_HMAC_KEY: bytes = (
    bytes.fromhex(k) if (k := os.environ.get("PROVSHIELD_HMAC_KEY"))
    else secrets.token_bytes(32)
)


@dataclass
class CapabilityToken:
    """A one-time capability token minted by the bridge manager.
    
    Each token carries an HMAC-SHA256 signature over all normalized call
    fields. The signature binds the token to the exact action, sink,
    destination, payload digest, principal, nonce, expiry, and bridge ID
    for which it was minted. Any field mismatch causes signature
    verification to fail, preventing replay, destination swap, and
    payload swap attacks.
    """

    token_id: str
    action: str              # effect class name
    sink: str                # sink class name
    destination: Optional[str]
    payload_digest: Optional[str]
    principal: str
    expires_at: float        # unix timestamp
    nonce: str
    one_time: bool = True
    has_declassification: bool = False
    bridge_id: Optional[str] = None
    used: bool = False
    created_at: float = field(default_factory=time.time)
    signature: str = ""      # HMAC-SHA256 hex digest

    def _canonical_message(self) -> bytes:
        """Produce the canonical byte string for HMAC signing.
        
        Format: action|sink|destination|payload_digest|principal|nonce|expires_at|bridge_id
        """
        parts = [
            self.action,
            self.sink,
            self.destination or "",
            self.payload_digest or "",
            self.principal,
            self.nonce,
            f"{self.expires_at:.6f}",
            self.bridge_id or "",
        ]
        return "|".join(parts).encode("utf-8")

    def compute_signature(self, key: Optional[bytes] = None) -> str:
        """Compute HMAC-SHA256 signature over canonical message."""
        k = key if key is not None else _TOKEN_HMAC_KEY
        return hmac.new(k, self._canonical_message(), hashlib.sha256).hexdigest()

    def verify_signature(self, key: Optional[bytes] = None) -> bool:
        """Verify that the stored signature is valid for this token's fields.
        
        Returns False if signature is empty or does not match.
        """
        if not self.signature:
            return False
        expected = self.compute_signature(key)
        return hmac.compare_digest(self.signature, expected)

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    def matches(self, call: Any) -> bool:
        """Check if this token authorizes a NormalizedToolCall.
        
        Verifies: field match, not expired, not used, and valid signature.
        """
        from .types import NormalizedToolCall
        if not isinstance(call, NormalizedToolCall):
            return False
        return (
            self.action == call.effect.value
            and self.sink == call.sink.value
            and self.destination == call.destination
            and self.payload_digest == call.payload_digest
            and self.principal == call.principal
            and not self.expired
            and not self.used
            and self.verify_signature()
        )

    def consume(self) -> None:
        """Mark this token as used (one-time consumption)."""
        if self.used:
            raise RuntimeError(f"Token {self.token_id} already consumed")
        if self.expired:
            raise RuntimeError(f"Token {self.token_id} expired")
        self.used = True


class CapabilityTokenStore:
    """Runtime store for active capability tokens."""

    def __init__(self) -> None:
        self._tokens: dict[str, CapabilityToken] = {}

    def mint(
        self,
        action: str,
        sink: str,
        destination: Optional[str],
        payload_digest: Optional[str],
        principal: str,
        ttl_seconds: float = 300.0,
        has_declassification: bool = False,
        bridge_id: Optional[str] = None,
    ) -> CapabilityToken:
        """Mint a new one-time capability token with HMAC-SHA256 signature."""
        token = CapabilityToken(
            token_id=secrets.token_urlsafe(32),
            action=action,
            sink=sink,
            destination=destination,
            payload_digest=payload_digest,
            principal=principal,
            expires_at=time.time() + ttl_seconds,
            nonce=secrets.token_hex(16),
            has_declassification=has_declassification,
            bridge_id=bridge_id,
        )
        # Compute and attach HMAC signature over all normalized fields
        token.signature = token.compute_signature()
        self._tokens[token.token_id] = token
        return token

    def lookup_matching_token(self, call: Any) -> Optional[CapabilityToken]:
        """Find a valid, unused token matching the given call."""
        for token in self._tokens.values():
            if token.matches(call):
                return token
        return None

    def consume_token(self, token_id: str) -> None:
        """Consume a token by ID."""
        token = self._tokens.get(token_id)
        if token is None:
            raise KeyError(f"Token {token_id} not found")
        token.consume()

    def revoke_expired(self) -> int:
        """Remove expired tokens. Returns count removed."""
        expired = [
            tid for tid, t in self._tokens.items() if t.expired
        ]
        for tid in expired:
            del self._tokens[tid]
        return len(expired)

    def get_token(self, token_id: str) -> Optional[CapabilityToken]:
        return self._tokens.get(token_id)
