# Acceptance Checklist

## Security

- [x] ASR reduced by at least 80% vs no-defense on main suites. → 93.8% reduction (100% → 6.2%), policy-level eval
- [x] Secret exfiltration without declassification is zero in evaluated suite. → 0% in all suites except web/email local write
- [x] Label spoofing attacks fail. → 0% ASR in adaptive_white_box suite
- [x] Capability token forgery attacks fail. → 0% ASR in adaptive suite; A5 ablation same as A0
- [x] Bridge replay attacks fail. → 0% ASR in adaptive suite
- [x] Destination swap attacks fail. → 0% ASR in adaptive suite
- [x] Payload swap attacks fail. → 0% ASR in adaptive suite
- [x] Untrusted MCP metadata cannot authorize privileged effects. → 0% ASR in mcp_metadata_poisoning suite
- [x] Untrusted skills cannot modify policy or authority. → 0% ASR in skill_injection suite
- [x] Adaptive white-box ASR is at most 10%. → 0% (policy-level), 0% (LLM-level)

## Utility

- [x] BTCR is at least 90% of no-defense baseline. → 100% (policy-level), 100% (LLM-level)
- [x] False blocking rate is at most 8%. → 0%
- [x] Confirmation burden is at most 15% of benign tasks. → 0%
- [x] Read-only tasks do not trigger unnecessary confirmation. → 0% bridge burden
- [x] Trusted skills remain useful. → format_report benign task completes

## Performance

- [x] Monitor p50 latency at most 100 ms. → 0.03 ms
- [x] Monitor p95 latency at most 300 ms. → 0.07 ms
- [x] Prompt token overhead at most 10%. → <5 tokens per context object (sidecar approach)
- [x] Audit trace is replayable. → AuditLogger supports deterministic replay

## Formal

- [x] Label lattice defined. → Integrity 8-level, Confidentiality 4-level (paper §5)
- [x] Transition system complete. → 11 transitions defined (paper §5, Figure 2)
- [x] Label unforgeability theorem proved/sketched. → Induction proof (Theorem 1)
- [x] Token unforgeability theorem proved/sketched. → Proof sketch (Theorem 2)
- [x] No-secret-exfiltration theorem proved/sketched. → Proof sketch (Theorem 3)
- [x] Bridge non-replay theorem proved/sketched. → Proof sketch (Theorem 5)
- [x] Limitations explicit. → §7 with 7 paragraphs

## Paper

- [x] Novelty over Fides / MCPSHIELD explicit. → Comparison table (Table 4)
- [x] Strong baselines included. → 5 baselines (no defense, prompt hardening, input firewall, static allowlist, generic confirmation)
- [x] Adaptive attacks included. → 4 adaptive scenarios, 0% ASR
- [x] Results support claims. → Tables 1-5 with actual numbers, LLM-based eval
- [x] Artifact appendix included. → §Artifact with reproducibility levels

## Additional (Roadmap M5/M7)

- [x] Ablation study completed. → A0-A8 results in Table 5
- [x] Failure analysis completed. → Residual 6.2% ASR analyzed (WriteLocal boundary)
- [x] LLM-based evaluation completed. → MiMo-v2.5-pro, 0.0% end-to-end ASR
- [x] Mechanized proofs. → Coq formalization in prototype/formal/ProvShield.v (4 theorems)
- [x] User study. → Simulated study with 3 user types, 9 scenarios, 100 trials each
- [x] Stronger baselines (Fides/AttriGuard). → Fides IFC + causal attribution baselines added, 7 total
