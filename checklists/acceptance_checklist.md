# Acceptance Checklist

**Legend:**
- `[x]` = **Verified** — current codebase evidence supports the claim
- `[~]` = **Partially verified** — evidence exists but has known issues (see notes)
- `[ ]` = **Not verified** — no current evidence or evidence is stale/inconsistent

> Updated 2026-05-27 after C1-C5 blocker fixes.
> Evaluation results from unified run (eval/results/results_manifest.json).

## Security

- [~] ASR reduced by at least 80% vs no-defense on main suites. → Unified eval: ProvShield 0.0% vs no_defense 12.5% (100% reduction). Small scale (16 attack scenarios); needs larger eval for CCF-A.
- [x] Secret exfiltration without declassification is zero in evaluated suite. → Policy P2 denies secret+external without valid token. Per-argument source slicing now active (C3 taint propagation).
- [~] Label spoofing attacks fail. → HMAC-SHA256 labels (PR-4); adaptive suite exists but small sample.
- [~] Capability token forgery attacks fail. → Token bound to action/sink/dest/payload/principal/nonce; small sample.
- [x] Bridge replay attacks fail. → C1: BridgeRequest stores full NormalizedToolCall; nonce consumed on use.
- [x] Destination swap attacks fail. → C1: complete_bridge uses original call with original destination.
- [x] Payload swap attacks fail. → C1: complete_bridge uses original call with original payload digest.
- [~] Untrusted MCP metadata cannot authorize privileged effects. → C2: UNKNOWN_HIGH_RISK default; MCP proxy skeleton, not full integration.
- [~] Untrusted skills cannot modify policy or authority. → HMAC verification exists; not real supply chain attestation.
- [~] Adaptive white-box ASR is at most 10%. → Unified eval shows 0% on small sample; needs larger eval.

## Utility

- [~] BTCR is at least 90% of no-defense baseline. → Unified eval: 100% (7 benign). C2 fixes unknown tool default.
- [~] False blocking rate is at most 8%. → 0% in unified eval (small scale). C3 taint propagation reduces false positives.
- [~] Confirmation burden is at most 15% of benign tasks. → 0% in unified eval. C1 fixes bridge end-to-end.
- [~] Read-only tasks do not trigger unnecessary confirmation. → Needs real read-only workload.
- [~] Trusted skills remain useful. → HMAC test exists; workload insufficient.

## Performance

- [~] Monitor p50 latency at most 100 ms. → Unified eval: 7,354 ms (includes LLM latency). Monitor-only: ~0.03 ms.
- [~] Monitor p95 latency at most 300 ms. → Same caveat.
- [~] Prompt token overhead at most 10%. → No rigorous token accounting.
- [x] Audit trace is replayable. → C4: tools/replay_audit.py implements deterministic replay verifier.

## Formal

- [x] Label lattice defined. → Integrity 8-level, Confidentiality 4-level in code and Coq.
- [x] Transition system complete. → C5: Coq file has Transition inductive (9 constructors), apply_transition, Reachable.
- [x] Label unforgeability theorem proved/sketched. → Definition-level + reachable_well_formed invariant (C5).
- [x] Token unforgeability theorem proved/sketched. → Definition-level proof (C5).
- [x] No-secret-exfiltration theorem proved/sketched. → monitor_decide_secret + reachable_no_secret_exfil (C5).
- [x] Bridge non-replay theorem proved/sketched. → bridge_non_replay + bridge_no_destination_swap (C5).
- [x] Limitations explicit. → Paper §7 with 7 paragraphs; Coq file lists limitations.

## Paper

- [~] Novelty over Fides / MCPSHIELD explicit. → Comparison table exists; claim discipline needs audit.
- [~] Strong baselines included. → 5 baselines in unified eval (no_defense, prompt_hardening, input_firewall, generic_confirmation, static_allowlist).
- [~] Adaptive attacks included. → 3 adaptive scenarios in unified eval; sample is small.
- [~] Results support claims. → Unified eval with manifest; small scale (23 scenarios).
- [x] Artifact appendix included. → Docker + Python 3.13 aligned (PR-5).

## Additional (Roadmap M5/M7)

- [~] Ablation study completed. → Not re-run with unified eval framework.
- [~] Failure analysis completed. → No failures in unified eval (0% ASR).
- [~] LLM-based evaluation completed. → Unified eval: 23 scenarios, mimo-v2.5-pro. Small scale.
- [~] Mechanized proofs. → C5: Coq has transition relation + reachable invariant. Not full coqc verification.
- [ ] User study. → Simulated only (not real users).
- [~] Stronger baselines (Fides/AttriGuard). → 5 baselines in unified eval; not real IFC/attribution implementations.
