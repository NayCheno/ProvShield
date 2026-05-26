"""Bridge manager: constructs bound user-intent bridges and mints capability tokens."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .tokens import CapabilityToken, CapabilityTokenStore
from .types import Effect, NormalizedToolCall, Sink


@dataclass(frozen=True)
class BridgeRequest:
    """A request for user confirmation, sent to the UI."""
    bridge_id: str
    action: str
    effect: str
    sink: str
    destination: Optional[str]
    payload_digest: Optional[str]
    visible_diff_digest: Optional[str]
    sources_used: tuple[str, ...]
    blocked_or_untrusted_sources: tuple[str, ...]
    declassification: tuple[str, ...]
    expires_at: float
    nonce: str
    one_time: bool = True


@dataclass(frozen=True)
class BridgeConfirmation:
    """User's confirmation response."""
    bridge_id: str
    accepted: bool
    user_id: str = "user"


class BridgeManager:
    """Manages user-intent bridges: requests, confirmations, and token issuance.

    Bridge rules:
      B1: No vague bridge — must bind action, destination, payload
      B2: No destination swap
      B3: No payload swap
      B4: No effect broadening
      B5: No replay (one-time nonce)
      B6: No expired bridge
      B7: Explicit declassification when private/secret crosses to external
    """

    def __init__(self, token_store: CapabilityTokenStore) -> None:
        self._token_store = token_store
        self._pending: dict[str, BridgeRequest] = {}
        self._confirmed: dict[str, BridgeConfirmation] = {}
        self._used_nonces: set[str] = set()

    def create_request(
        self,
        call: NormalizedToolCall,
        source_labels: list[str],
        untrusted_sources: list[str],
        ttl_seconds: float = 300.0,
    ) -> BridgeRequest:
        """Create a bridge request for a high-risk tool call."""
        bridge_id = secrets.token_urlsafe(16)
        nonce = secrets.token_hex(16)

        # Compute declassification needs
        declassification = []
        if call.sink in {Sink.EXTERNAL_WRITE, Sink.NETWORK_SEND}:
            declassification.append("UserPrivate -> ExternalWriteSink")

        payload_digest = call.payload_digest
        if not payload_digest and call.arguments:
            payload_str = json.dumps(call.arguments, sort_keys=True, default=str)
            payload_digest = "sha256:" + hashlib.sha256(payload_str.encode()).hexdigest()

        request = BridgeRequest(
            bridge_id=bridge_id,
            action=call.tool_name,
            effect=call.effect.value,
            sink=call.sink.value,
            destination=call.destination,
            payload_digest=payload_digest,
            visible_diff_digest=None,
            sources_used=tuple(source_labels),
            blocked_or_untrusted_sources=tuple(untrusted_sources),
            declassification=tuple(declassification),
            expires_at=time.time() + ttl_seconds,
            nonce=nonce,
        )
        self._pending[bridge_id] = request
        return request

    def confirm(
        self,
        bridge_id: str,
        accepted: bool,
        user_id: str = "user",
    ) -> Optional[BridgeConfirmation]:
        """Process user confirmation for a bridge request."""
        request = self._pending.get(bridge_id)
        if request is None:
            return None

        # B6: No expired bridge
        if time.time() > request.expires_at:
            del self._pending[bridge_id]
            return None

        # B5: No replay
        if request.nonce in self._used_nonces:
            return None

        confirmation = BridgeConfirmation(
            bridge_id=bridge_id,
            accepted=accepted,
            user_id=user_id,
        )
        self._confirmed[bridge_id] = confirmation

        if accepted:
            self._used_nonces.add(request.nonce)

        return confirmation

    def mint_token(self, bridge_id: str) -> Optional[CapabilityToken]:
        """Mint a capability token after successful bridge confirmation."""
        confirmation = self._confirmed.get(bridge_id)
        if confirmation is None or not confirmation.accepted:
            return None

        request = self._pending.get(bridge_id)
        if request is None:
            return None

        # B7: Check declassification
        has_declassification = len(request.declassification) > 0

        token = self._token_store.mint(
            action=request.effect,
            sink=request.sink,
            destination=request.destination,
            payload_digest=request.payload_digest,
            principal=confirmation.user_id,
            has_declassification=has_declassification,
            bridge_id=bridge_id,
        )

        # Clean up
        del self._pending[bridge_id]
        return token

    def get_request(self, bridge_id: str) -> Optional[BridgeRequest]:
        return self._pending.get(bridge_id)

    def reject_and_cleanup(self, bridge_id: str) -> None:
        """Clean up a rejected or expired bridge."""
        self._pending.pop(bridge_id, None)

    @property
    def pending_count(self) -> int:
        return len(self._pending)
