# Theorem-to-Code Mapping

This document maps each Coq theorem in `prototype/formal/ProvShield.v` to its
corresponding Python implementation and test.

## Theorems

| Coq Theorem | Python Implementation | Test Coverage |
|---|---|---|
| `label_unforgeability` | `ProvenanceLabel._compute_signature()` uses HMAC-SHA256 with runtime key | `TestHMACLabelSignature.test_forged_signature_rejected` |
| `model_cannot_forge_label` | Model has no access to `_RUNTIME_HMAC_KEY` in `labels.py` | `TestHMACLabelSignature.test_tampered_label_fails_verification` |
| `token_unforgeability` | `CapabilityToken` requires `CapabilityTokenStore.mint()` with HMAC key | `TestTokens.test_mint_and_lookup` |
| `model_cannot_forge_token` | Model cannot call `mint()` without bridge confirmation | `TestBridgeReplaySwap` |
| `no_secret_exfiltration` | `PolicyEngine.evaluate()` P2 rule: secret+external without declassification → DENY | `TestEndToEnd.test_secret_exfiltration_blocked` |
| `bridge_non_replay` | `CapabilityToken.consume()` marks `used=True`; `verify_token()` checks nonce | `TestBridgeReplaySwap.test_bridge_replay_rejected` |
| `bridge_no_destination_swap` | `CapabilityToken.matches()` checks `destination` field | `TestBridgeReplaySwap.test_bridge_destination_swap_rejected` |
| `reachable_well_formed` | All transitions preserve sidecar label validity | `TestLabels.test_integrity_lattice_ordering` |
| `reachable_no_secret_exfil` | `monitor_decide_secret` → `PolicyEngine` P2 rule | `TestEndToEnd.test_secret_exfiltration_blocked` |

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

## Limitations

1. **Theorems 1-2 are definition-level**: They prove `label_valid l = true → sig > 0`, not that the runtime transition system maintains the invariant that only TCB can create valid labels.
2. **Transition relation is abstract**: `apply_transition` models state changes but does not enforce preconditions (e.g., monitor must approve before execute).
3. **No hidden-state invariant**: The Coq formalization does not prove that model-generated text cannot influence the model's own hidden state — only that it cannot forge sidecar labels.
4. **HMAC assumption**: The formalization assumes HMAC is cryptographically secure; this is not proven in Coq.
