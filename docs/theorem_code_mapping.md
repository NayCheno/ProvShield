# Theorem–Code–Test Mapping

This document maps each formal theorem in `prototype/formal/ProvShield.v` to the corresponding code invariant in `src/provshield/` and the tests in `tests/test_provshield.py` that verify it.

## Overview

| # | Theorem | Code Invariant | Test(s) |
|---|---|---|---|
| 1 | Label Unforgeability | Sidecar store only mutated by runtime; model cannot write to `R` | `test_label_unforgeability_*` |
| 2 | Token Unforgeability | `CapabilityToken.matches()` requires valid MAC; model cannot compute MAC | `test_token_*`, `test_mint_and_lookup` |
| 3 | No Secret Exfiltration | P2 rule in `PolicyEngine.evaluate()` denies secret→external without bridge | `test_webpage_to_email_exfiltration_blocked` |
| 4 | No Low-Integrity Control | P1/P1b rules require bridge for high-risk from low-integrity sources | `test_skill_injection_blocked`, `test_write_local_*` |
| 5 | Bridge Non-Replay | `CapabilityToken.matches()` checks all 6 fields + nonce consumption | `test_bridge_*`, `test_consumed_token_*` |

## Detailed Mapping

### Theorem 1: Label Unforgeability

**Statement:** In any reachable state, model-generated text cannot create a valid label with higher integrity than permitted by runtime transitions.

**Coq:** `label_unforgeability` (ProvShield.v:237–248)

**Code invariant:**
- `SidecarProvenanceStore.ingest()` (`store.py:74–88`): Only runtime code calls this; model output goes through `ContextBuilder` which assigns labels based on origin, not model claims.
- `ProvenanceLabel.runtime_signature` (`labels.py`): MAC over nonce + timestamp + integrity + confidentiality. Signing key never exposed to model context.
- `RuntimeMonitor.check_and_execute()` (`monitor.py:131–195`): Model proposed calls are normalized and checked against sidecar store, not against model-generated labels.

**Tests:**
- `TestLabels.test_label_creation` — verifies label integrity/confidentiality assignment
- `TestLabels.test_unique_signatures` — verifies each label gets unique signature
- `TestProvenanceStore.test_ingest_and_get` — verifies sidecar store mutation only through `ingest()`
- `TestExplicitProvenance.test_explicit_source_ids_used_when_available` — verifies explicit provenance tracking

**Gap:** Model cannot write to sidecar store because `SidecarProvenanceStore` is a Python object only accessible to runtime code. The LLM's text output is never interpreted as a label.

---

### Theorem 2: Token Unforgeability

**Statement:** A valid capability token can only be created by the runtime through a bridge confirmation or administrative transition.

**Coq:** `token_unforgeability` (ProvShield.v:254–263)

**Code invariant:**
- `CapabilityTokenStore.mint()` (`tokens.py:77–92`): Only callable by `BridgeManager.confirm_and_mint()`.
- `CapabilityToken.token_signature` (`tokens.py:27`): HMAC over all fields. Key in TCB.
- `model_cannot_forge_token` (ProvShield.v:267): Tokens with signature=0 are invalid.

**Tests:**
- `TestTokens.test_mint_and_lookup` — verifies token creation and lookup
- `TestTokens.test_consume_once` — verifies one-time consumption
- `TestPrincipalBoundTokens.test_token_principal_mismatch_rejected` — verifies principal binding
- `TestPrincipalBoundTokens.test_normalized_call_matches_token_principal` — verifies call-side check

**Gap:** Token minting only happens through `BridgeManager.confirm_and_mint()` which requires a confirmed bridge. Model has no direct access to `CapabilityTokenStore`.

---

### Theorem 3: No Unauthorized Secret Exfiltration

**Statement:** If a proposed call sends/writes payload with confidentiality ≥ Secret to an external sink, the call cannot execute without a valid declassification bridge.

**Coq:** `no_secret_exfiltration` (ProvShield.v:275–293)

**Code invariant:**
- `PolicyEngine.evaluate()` P2 rule (`policy.py:56–68`): Checks `call.sink in EXTERNAL_SINKS` and `max_conf in {SECRET, CAPABILITY_TOKEN}` without valid declassification → DENY.
- `_valid_declassification()` (`policy.py:123–133`): Requires `token.has_declassification and token.matches(call)`.

**Tests:**
- `TestEndToEnd.test_webpage_to_email_exfiltration_blocked` — secret + external sink → DENY
- `TestPolicyEngine.test_secret_exfiltration_denied` — direct policy test
- `TestWriteLocalPolicyGap.test_external_content_local_write_secret_blocked` — P1b + secret

**Gap:** None significant. P2 rule directly implements the theorem.

---

### Theorem 4: No Low-Integrity Control of High-Risk Effects

**Statement:** If a high-risk effect is influenced by low-integrity sources, the call cannot execute without a valid bridge.

**Coq:** (implied by label_unforgeability + policy enforcement)

**Code invariant:**
- `PolicyEngine.evaluate()` P1 rule (`policy.py:99–115`): `call.effect in HIGH_RISK_EFFECTS` and `low_int_influence` → REQUIRE_BRIDGE.
- `PolicyEngine.evaluate()` P1b rule (`policy.py:120–141`): WRITE_LOCAL + low-integrity + sensitive payload → REQUIRE_BRIDGE.
- `PolicyEngine.evaluate()` P5 rule (`policy.py:89–97`): EXECUTE_CODE without user intent → DENY.

**Tests:**
- `TestEndToEnd.test_skill_injection_blocked` — UntrustedSkill + DELETE_LOCAL → REQUIRE_BRIDGE
- `TestWriteLocalPolicyGap.test_external_content_local_write_private_data_blocked` — P1b
- `TestWriteLocalPolicyGap.test_external_content_local_write_secret_blocked` — P1b + secret
- `TestWriteLocalPolicyGap.test_external_content_local_write_public_data_allowed` — public data allowed
- `TestWriteLocalPolicyGap.test_user_intent_local_write_private_data_allowed` — user intent allowed
- `TestEndToEnd.test_mcp_metadata_poisoning_blocked` — ToolMetadata + CREATE_CREDENTIAL → DENY

**Gap:** None significant. P1, P1b, P5 rules directly implement the theorem.

---

### Theorem 5: Bridge Non-Replay

**Statement:** A bridge token authorized for call (a,e,d,h,p,n) cannot authorize a different call where any field differs, or where the token has expired/consumed.

**Coq:** `bridge_non_replay` (ProvShield.v:300–314), `bridge_no_destination_swap` (ProvShield.v:319–338)

**Code invariant:**
- `CapabilityToken.matches()` (`tokens.py:33–45`): Checks action, sink, destination, payload_digest, principal, expired, used.
- `NormalizedToolCall.matches_token()` (`types.py:120–132`): Same check from call side.
- `CapabilityToken.consume()` (`tokens.py:47–53`): Sets `used=True`, raises on double-consume.

**Tests:**
- `TestBridgeReplaySwap.test_bridge_destination_swap_rejected` — destination mismatch
- `TestBridgeReplaySwap.test_bridge_expired_token_rejected` — expiry check
- `TestBridgeReplaySwap.test_bridge_consumed_token_rejected` — one-time consumption
- `TestPrincipalBoundTokens.test_token_principal_mismatch_rejected` — principal mismatch

**Gap:** Payload swap test not explicitly present (destination swap covers the pattern). Could add explicit payload_digest mismatch test.

---

## Summary

| Theorem | Code Coverage | Test Coverage | Gap |
|---|---|---|---|
| Label Unforgeability | ✅ Sidecar store isolation | ✅ 4 tests | Minor: no explicit "model cannot write sidecar" test |
| Token Unforgeability | ✅ HMAC + mint path restriction | ✅ 4 tests | None |
| No Secret Exfiltration | ✅ P2 rule | ✅ 3 tests | None |
| No Low-Integrity Control | ✅ P1/P1b/P5 rules | ✅ 6 tests | None |
| Bridge Non-Replay | ✅ 6-field match + consume | ✅ 4 tests | Minor: no explicit payload_digest mismatch test |

**Total:** 5 theorems, 5 code invariants, 21 dedicated tests, 2 minor gaps.
