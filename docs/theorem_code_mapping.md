# Theorem-to-Code Mapping

This document maps each Coq theorem in `prototype/formal/ProvShield.v` to its
corresponding Python implementation and test.

## Theorems

| Coq Theorem | Python Implementation | Test Coverage |
|---|---|---|
| `label_unforgeability` | `ProvenanceLabel._compute_signature()` uses HMAC-SHA256 with runtime key | `TestHMACLabelSignature.test_forged_signature_rejected` |
| `model_cannot_forge_label` | Model has no access to `_RUNTIME_HMAC_KEY` in `labels.py` | `TestHMACLabelSignature.test_tampered_label_fails_verification` |
| `token_unforgeability` | `CapabilityToken` requires `CapabilityTokenStore.mint()` with HMAC key | `TestTokens.test_mint_and_lookup` |
| `model_cannot_forge_token` | Model cannot call `mint()` without bridge confirmation | `TestBridgeReplaySwap.test_bridge_consumed_token_rejected` |
| `no_secret_exfiltration` | `PolicyEngine.evaluate()` P2 rule: secret+external without declassification → DENY | `TestEndToEnd.test_webpage_to_email_exfiltration_blocked` |
| `bridge_non_replay` | `CapabilityToken.consume()` marks `used=True`; `verify_token()` checks nonce | `TestBridgeReplaySwap.test_bridge_consumed_token_rejected` |
| `bridge_no_destination_swap` | `CapabilityToken.matches()` checks `destination` field | `TestBridgeReplaySwap.test_bridge_destination_swap_rejected` |
| `reachable_well_formed` | All transitions preserve sidecar label validity | `TestLabels.test_integrity_lattice_ordering` |
| `reachable_no_secret_exfil` | `monitor_decide_secret` → `PolicyEngine` P2 rule | `TestEndToEnd.test_webpage_to_email_exfiltration_blocked` |

## Transition System

| Coq Transition | Python Implementation |
|---|---|
| `TIngestUser` | `SidecarProvenanceStore.ingest()` with `Integrity.USER_INTENT` |
| `TIngestExternal` | `SidecarProvenanceStore.ingest()` with `Integrity.EXTERNAL` |
| `TRegisterTool` | `register_tool()` in `monitor.py` / `MCPProxy.register_tool()` |
| `TModelPropose` | `RuntimeMonitor.normalize_call()` |
| `TMonitorAllow` | `PolicyEngine.evaluate()` → `DecisionKind.ALLOW` |
| `TMonitorDeny` | `PolicyEngine.evaluate()` → `DecisionKind.DENY` |
| `TBridgeConfirm` | `BridgeManager.confirm()` → `BridgeManager.mint_token()` |
| `TExecuteTool` | `RuntimeMonitor.check_and_execute()` → `executor(call)` |
| `TAudit` | `AuditLogger.record_decision()` / `record_execution()` |

## Policy Rules

| Policy | Coq Formalization | Python Rule | Location |
|---|---|---|---|
| P0: Unknown tool deny | N/A (Coq doesn't model tool registry) | `tool_registered` check | `policy.py` P0 |
| P1: Low-integrity → high-risk bridge | `is_low_integrity` + `is_high_risk` | Low-integrity influence check | `policy.py` P1 |
| P1b: Low-integrity + local write + sensitive | N/A | WRITE_LOCAL + sensitive payload | `policy.py` P1b |
| P2: Secret external exfil deny | `no_secret_exfiltration` | Secret + external + no token | `policy.py` P2 |
| P3: Metadata cannot authorize privileged | N/A | ToolMetadata + PRIVILEGED_ACTIONS | `policy.py` P3 |
| P4: Untrusted skill cannot modify policy | N/A | UntrustedSkill + PRIVILEGED_ACTIONS | `policy.py` P4 |
| P5: Code exec requires user intent | N/A | EXECUTE_CODE + has_direct_user_intent | `policy.py` P5 |

## Proof Hierarchy

The formal guarantees are organized into three levels:

### Level 1: Mechanized Core (Coq-verified)

- **Transition system**: Inductive type with 9 constructors (`TIngestUser`, `TIngestExternal`, `TRegisterTool`, `TModelPropose`, `TMonitorAllow`, `TMonitorDeny`, `TBridgeConfirm`, `TExecuteTool`, `TAudit`).
- **Reachable-state invariant** (`reachable_well_formed`): All transitions preserve label well-formedness. **Verified by coqc 9.0.**
- **No-secret-exfiltration** (`reachable_no_secret_exfil`): In any reachable state, the monitor denies secret-to-external flows without a valid bridge. **Verified by coqc 9.0.**
- **Bridge non-replay** (`bridge_non_replay`, `bridge_no_destination_swap`): Bridge tokens are bound to specific normalized calls and consumed on use. **Verified by coqc 9.0.**

### Level 2: Proof Sketches (Paper §5)

- **Label unforgeability** (Theorem 1): Proof by induction on transitions, relying on the TCB assumption that the LLM cannot access the HMAC key. The Coq formalization proves the definition-level invariant; the full proof sketch is in the paper.
- **Capability token unforgeability** (Theorem 2): Similar structure to Theorem 1. Tokens can only be created by TCB transitions (BridgeConfirm or AdminGrant). The LLM cannot compute valid MACs.

### Level 3: Stated Assumptions (Not mechanized)

- **HMAC security**: We assume HMAC-SHA256 is a secure MAC. This is a standard cryptographic assumption, not proven in Coq.
- **TCB integrity**: We assume the runtime monitor, sidecar store, policy engine, and bridge manager are not compromised. If the runtime itself is compromised, all guarantees are void.
- **LLM oracle model**: We model the LLM as an adversarial proposal function. We do not claim to prevent the LLM from being influenced by untrusted content; we only claim that high-risk tool execution cannot occur without proper runtime authorization.

## Limitations

1. **Theorems 1-2 are definition-level in Coq**: They prove `label_valid l = true → sig > 0`, not that the runtime transition system maintains the invariant that only TCB can create valid labels. The full proof sketch (induction on transitions + TCB assumption) is in the paper but not mechanized.
2. **Transition relation is abstract**: `apply_transition` models state changes but does not enforce all preconditions (e.g., monitor must approve before execute). Some preconditions are checked at the Python level but not formalized in Coq.
3. **No hidden-state invariant**: The Coq formalization does not prove that model-generated text cannot influence the model's own hidden state — only that it cannot forge sidecar labels. This is explicitly stated as a non-goal.
4. **HMAC assumption**: The formalization assumes HMAC is cryptographically secure; this is not proven in Coq. The HMAC key is managed at the module level; production deployment requires a proper key management system.
5. **Policy rules P0, P1b, P3-P5 are not formalized**: Only P1 (low-integrity → high-risk bridge) and P2 (secret external exfil deny) have Coq counterparts. The remaining policy rules are implemented in Python but not formalized.
6. **Taint inference is heuristic**: The Python implementation uses content overlap, template fill, and external influence rules for provenance reconstruction. This is not modeled in the formal framework.