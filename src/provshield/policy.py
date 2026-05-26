"""Policy engine: evaluates source-to-sink rules for proposed tool calls."""

from __future__ import annotations

from typing import Any, Optional

from .labels import Integrity, ProvenanceLabel
from .store import ProvenanceGraph
from .tokens import CapabilityToken
from .types import (
    CRITICAL_EFFECTS,
    HIGH_RISK_EFFECTS,
    Decision,
    DecisionKind,
    Effect,
    NormalizedToolCall,
    Sink,
    effect_risk_at_least,
)

# Labels that cannot directly authorize high-risk effects
LOW_INTEGRITY_NAMES = frozenset({
    "ExternalContent", "ToolOutput", "ToolMetadata", "UntrustedSkill",
})

# Privileged actions that metadata/skills cannot grant
PRIVILEGED_ACTIONS = frozenset({
    Effect.MODIFY_AUTH, Effect.CREATE_CREDENTIAL,
})


class PolicyEngine:
    """Evaluates source-to-sink policy rules for proposed tool calls.

    Core rules:
      P1: No low-integrity control of high-risk effects (require bridge)
      P2: No secret exfiltration without declassification
      P3: Tool metadata cannot authorize itself
      P4: Untrusted skill cannot modify policy
      P5: Execution requires direct user intent
      P6: Capability token unforgeability (enforced by token store)
      P7: Label preservation (enforced by store.join)
    """

    def evaluate(
        self,
        call: NormalizedToolCall,
        provenance_graph: ProvenanceGraph,
        capability_token: Optional[CapabilityToken] = None,
    ) -> Decision:
        """Evaluate a proposed tool call against policy rules."""
        labels = provenance_graph.labels()
        integrity_names = {self._integrity_name(lbl) for lbl in labels}
        max_conf = provenance_graph.max_confidentiality()

        # P2: No secret exfiltration without declassification
        if call.sink in {Sink.EXTERNAL_WRITE, Sink.NETWORK_SEND}:
            from .labels import Confidentiality
            if max_conf in {Confidentiality.SECRET, Confidentiality.CAPABILITY_TOKEN}:
                if not self._valid_declassification(call, capability_token):
                    return Decision(
                        kind=DecisionKind.DENY,
                        reason=(
                            f"Secret (confidentiality={max_conf.name}) cannot flow "
                            f"to external sink {call.sink.value} without "
                            f"declassification bridge."
                        ),
                    )

        # P3: Tool metadata cannot authorize privileged effects
        if "ToolMetadata" in integrity_names and call.effect in PRIVILEGED_ACTIONS:
            return Decision(
                kind=DecisionKind.DENY,
                reason=(
                    f"ToolMetadata cannot authorize privileged effect "
                    f"{call.effect.value}."
                ),
            )
        # P4: Untrusted skill cannot modify policy or authority
        if "UntrustedSkill" in integrity_names and call.effect in PRIVILEGED_ACTIONS:
            return Decision(
                kind=DecisionKind.DENY,
                reason=(
                    f"UntrustedSkill cannot authorize privileged effect "
                    f"{call.effect.value}."
                ),
            )

        # P5: Code execution requires direct user intent (check before P1)
        if call.effect in {Effect.EXECUTE_CODE, Effect.INSTALL_PACKAGE}:
            if not provenance_graph.has_direct_user_intent(call):
                # No user intent at all — deny outright, no bridge offered
                if not self._valid_user_intent_bridge(call, capability_token):
                    return Decision(
                        kind=DecisionKind.DENY,
                        reason="Code execution requires direct user intent.",
                    )

        # P1: No low-integrity control of high-risk effects
        if call.effect in HIGH_RISK_EFFECTS:
            low_int_influence = integrity_names & LOW_INTEGRITY_NAMES
            if low_int_influence:
                if self._valid_user_intent_bridge(call, capability_token):
                    return Decision(
                        kind=DecisionKind.ALLOW,
                        reason="High-risk effect authorized by bound bridge.",
                    )
                return Decision(
                    kind=DecisionKind.REQUIRE_BRIDGE,
                    reason=(
                        f"Low-integrity sources {low_int_influence} influenced "
                        f"high-risk effect {call.effect.value}. "
                        f"User-intent bridge required."
                    ),
                )

        # Default: allow
        return Decision(
            kind=DecisionKind.ALLOW,
            reason="Policy permits call.",
        )

    def _valid_declassification(
        self,
        call: NormalizedToolCall,
        token: Optional[CapabilityToken],
    ) -> bool:
        """Check if a valid declassification bridge exists."""
        return (
            token is not None
            and token.has_declassification
            and token.matches(call)
        )

    def _valid_user_intent_bridge(
        self,
        call: NormalizedToolCall,
        token: Optional[CapabilityToken],
    ) -> bool:
        """Check if a valid user-intent bridge exists."""
        return (
            token is not None
            and token.matches(call)
            and not token.expired
            and not token.used
        )

    @staticmethod
    def _integrity_name(label: ProvenanceLabel) -> str:
        from .labels import INTEGRITY_NAMES
        return INTEGRITY_NAMES.get(label.integrity, "Unknown")
