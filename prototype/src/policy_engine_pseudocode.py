"""
ProvShield policy engine pseudocode.
"""

from dataclasses import dataclass
from typing import Optional, Set


HIGH_RISK_EFFECTS = {
    "WriteExternal", "DeleteExternal", "SendNetwork", "ExecuteCode",
    "InstallPackage", "ModifyAuth", "CreateCredential", "FinancialAction",
}

LOW_INTEGRITY = {"ExternalContent", "ToolOutput", "ToolMetadata", "UntrustedSkill"}
EXTERNAL_SINKS = {"ExternalWriteSink", "NetworkSendSink"}


@dataclass
class PolicyDecision:
    kind: str
    reason: str


class PolicyEngine:
    def evaluate(self, call, provenance_graph, capability_token=None):
        labels = provenance_graph.labels()
        integrities: Set[str] = {label.integrity for label in labels}
        max_conf = provenance_graph.max_confidentiality()

        if call.sink in EXTERNAL_SINKS and max_conf in {"Secret", "CapabilityToken"}:
            if not self.valid_declassification(call, capability_token):
                return PolicyDecision("deny", "Secret cannot flow to external sink.")

        if call.effect in HIGH_RISK_EFFECTS and integrities.intersection(LOW_INTEGRITY):
            if self.valid_user_intent_bridge(call, capability_token):
                return PolicyDecision("allow", "High-risk effect authorized by bound bridge.")
            return PolicyDecision("require_bridge", "Low-integrity influence on high-risk effect.")

        if "ToolMetadata" in integrities and call.effect in {"ModifyAuth", "CreateCredential"}:
            return PolicyDecision("deny", "Tool metadata cannot authorize privileged effects.")

        if call.effect == "ExecuteCode" and not provenance_graph.has_direct_user_intent(call):
            return PolicyDecision("deny", "Code execution requires direct user intent.")

        return PolicyDecision("allow", "Policy permits call.")

    def valid_declassification(self, call, token) -> bool:
        return token is not None and token.matches(call) and token.has_declassification

    def valid_user_intent_bridge(self, call, token) -> bool:
        return token is not None and token.matches(call) and not token.expired and not token.used
