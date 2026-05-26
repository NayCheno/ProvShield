"""Core types: effects, sinks, normalized tool calls, and policy decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Effect classes
# ---------------------------------------------------------------------------

class Effect(str, Enum):
    READ_PUBLIC = "ReadPublic"
    READ_PRIVATE = "ReadPrivate"
    READ_SECRET = "ReadSecret"
    WRITE_LOCAL = "WriteLocal"
    WRITE_EXTERNAL = "WriteExternal"
    DELETE_LOCAL = "DeleteLocal"
    DELETE_EXTERNAL = "DeleteExternal"
    SEND_NETWORK = "SendNetwork"
    EXECUTE_CODE = "ExecuteCode"
    INSTALL_PACKAGE = "InstallPackage"
    MODIFY_AUTH = "ModifyAuth"
    CREATE_CREDENTIAL = "CreateCredential"
    FINANCIAL_ACTION = "FinancialAction"
    CALENDAR_INVITE = "CalendarInvite"


# Risk levels
EFFECT_RISK: dict[Effect, str] = {
    Effect.READ_PUBLIC: "low",
    Effect.READ_PRIVATE: "medium",
    Effect.READ_SECRET: "high",
    Effect.WRITE_LOCAL: "medium",
    Effect.WRITE_EXTERNAL: "high",
    Effect.DELETE_LOCAL: "high",
    Effect.DELETE_EXTERNAL: "high",
    Effect.SEND_NETWORK: "high",
    Effect.EXECUTE_CODE: "critical",
    Effect.INSTALL_PACKAGE: "critical",
    Effect.MODIFY_AUTH: "critical",
    Effect.CREATE_CREDENTIAL: "critical",
    Effect.FINANCIAL_ACTION: "critical",
    Effect.CALENDAR_INVITE: "high",
}

HIGH_RISK_EFFECTS = frozenset(
    eff for eff, risk in EFFECT_RISK.items() if risk in ("high", "critical")
)

CRITICAL_EFFECTS = frozenset(
    eff for eff, risk in EFFECT_RISK.items() if risk == "critical"
)


def effect_risk_at_least(effect: Effect, threshold: str) -> bool:
    """Check if an effect's risk level meets or exceeds a threshold."""
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return order.get(EFFECT_RISK.get(effect, "low"), 0) >= order.get(threshold, 0)


# ---------------------------------------------------------------------------
# Sink classes
# ---------------------------------------------------------------------------

class Sink(str, Enum):
    LOCAL_READ = "LocalReadSink"
    PRIVATE_READ = "PrivateReadSink"
    SECRET_READ = "SecretReadSink"
    LOCAL_WRITE = "LocalWriteSink"
    EXTERNAL_WRITE = "ExternalWriteSink"
    NETWORK_SEND = "NetworkSendSink"
    CODE_EXECUTION = "CodeExecutionSink"
    AUTH_MODIFICATION = "AuthModificationSink"
    CREDENTIAL = "CredentialSink"
    FINANCIAL = "FinancialSink"
    CALENDAR = "CalendarSink"


EXTERNAL_SINKS = frozenset({Sink.EXTERNAL_WRITE, Sink.NETWORK_SEND})
READ_SINKS = frozenset({Sink.LOCAL_READ, Sink.PRIVATE_READ, Sink.SECRET_READ})


# Effect -> default sink mapping
EFFECT_SINK_MAP: dict[Effect, Sink] = {
    Effect.READ_PUBLIC: Sink.LOCAL_READ,
    Effect.READ_PRIVATE: Sink.PRIVATE_READ,
    Effect.READ_SECRET: Sink.SECRET_READ,
    Effect.WRITE_LOCAL: Sink.LOCAL_WRITE,
    Effect.WRITE_EXTERNAL: Sink.EXTERNAL_WRITE,
    Effect.DELETE_LOCAL: Sink.LOCAL_WRITE,
    Effect.DELETE_EXTERNAL: Sink.EXTERNAL_WRITE,
    Effect.SEND_NETWORK: Sink.NETWORK_SEND,
    Effect.EXECUTE_CODE: Sink.CODE_EXECUTION,
    Effect.INSTALL_PACKAGE: Sink.CODE_EXECUTION,
    Effect.MODIFY_AUTH: Sink.AUTH_MODIFICATION,
    Effect.CREATE_CREDENTIAL: Sink.CREDENTIAL,
    Effect.FINANCIAL_ACTION: Sink.FINANCIAL,
    Effect.CALENDAR_INVITE: Sink.CALENDAR,
}


# ---------------------------------------------------------------------------
# Normalized tool call
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NormalizedToolCall:
    """Canonical representation of a proposed tool call."""
    tool_name: str
    arguments: dict[str, Any]
    effect: Effect
    sink: Sink
    destination: Optional[str] = None
    payload_digest: Optional[str] = None
    principal: str = "user"
    argument_sources: Optional[tuple[tuple[str, str], ...]] = None  # ((arg_key, obj_id), ...)
    tool_registered: bool = True  # PR-2: False when tool not in registry

    def matches_token(self, token: CapabilityToken) -> bool:  # noqa: F821
        """Check if a capability token authorizes this exact call."""
        return (
            token.action == self.effect.value
            and token.sink == self.sink.value
            and token.destination == self.destination
            and token.payload_digest == self.payload_digest
            and token.principal == self.principal
            and not token.expired
            and not token.used
        )

    def get_source_ids(self, arg_key: str) -> list[str]:
        """Get source object IDs for a specific argument key."""
        if self.argument_sources is None:
            return []
        return [oid for key, oid in self.argument_sources if key == arg_key]


# ---------------------------------------------------------------------------
# Decision types
# ---------------------------------------------------------------------------

class DecisionKind(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_BRIDGE = "require_bridge"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class Decision:
    """Policy decision for a proposed tool call."""
    kind: DecisionKind
    reason: str
    bridge_request: Optional[dict[str, Any]] = None
