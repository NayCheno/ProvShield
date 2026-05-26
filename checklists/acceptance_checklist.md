# Acceptance Checklist

**Legend:**
- `[x]` = **Verified** — current codebase evidence supports the claim
- `[~]` = **Partially verified** — evidence exists but has known issues (see notes)
- `[ ]` = **Not verified** — no current evidence or evidence is stale/inconsistent

> Stale results moved to `eval/results/.stale/` on 2026-05-26 due to internal inconsistencies.
> All `[~]` items referencing ASR numbers must be re-verified after a clean evaluation run.

## Security

- [~] ASR reduced by at least 80% vs no-defense on main suites. → Stale: was 93.8% (100% → 6.2%), but ablation A0 showed 4.76% residual. Needs rerun with consistent pipeline.
- [~] Secret exfiltration without declassification is zero in evaluated suite. → Synthetic tests exist, but provenance is imprecise (all-label policy). Needs per-argument source slicing.
- [~] Label spoofing attacks fail. → Adaptive suite exists but small sample; label signature is SHA-256 not HMAC.
- [~] Capability token forgery attacks fail. → A5 ablation same as A0 suggests token-related attacks were not triggered.
- [~] Bridge replay attacks fail. → Bridge re-execution flow is not end-to-end complete (monitor.complete_bridge does not re-execute).
- [~] Destination swap attacks fail. → Same issue as bridge replay.
- [~] Payload swap attacks fail. → Same issue as bridge replay.
- [~] Untrusted MCP metadata cannot authorize privileged effects. → Policy rules exist; MCP proxy is JSON-RPC skeleton, not real MCP integration.
- [~] Untrusted skills cannot modify policy or authority. → HMAC verification exists; not real software supply chain attestation.
- [~] Adaptive white-box ASR is at most 10%. → Nominal (0% in stale results); evidence quality insufficient.

## Utility

- [~] BTCR is at least 90% of no-defense baseline. → Unknown tools default to READ_PUBLIC, inflating pass rate.
- [~] False blocking rate is at most 8%. → All-label provenance would cause false positives in real workloads.
- [~] Confirmation burden is at most 15% of benign tasks. → Bridge flow not end-to-end complete.
- [~] Read-only tasks do not trigger unnecessary confirmation. → Needs real read-only workload.
- [~] Trusted skills remain useful. → HMAC test exists; workload insufficient.

## Performance

- [~] Monitor p50 latency at most 100 ms. → Synthetic Python-only (0.03 ms); excludes real MCP, LLM, I/O, serialization.
- [~] Monitor p95 latency at most 300 ms. → Same caveat.
- [~] Prompt token overhead at most 10%. → No rigorous token accounting.
- [~] Audit trace is replayable. → AuditLogger exists but no deterministic replay verifier.

## Formal

- [x] Label lattice defined. → Integrity 8-level, Confidentiality 4-level in code and Coq.
- [~] Transition system complete. → Paper §5 defines 11 transitions; Coq file does not formalize transition relation.
- [~] Label unforgeability theorem proved/sketched. → Coq theorem is a definition tautology (label_valid → sig > 0), not a transition invariant.
- [~] Token unforgeability theorem proved/sketched. → Same: tautological proof.
- [~] No-secret-exfiltration theorem proved/sketched. → Proof sketch exists; Coq field mismatch (tok.token_id vs token_action).
- [~] Bridge non-replay theorem proved/sketched. → Proof sketch exists; bridge flow not complete in code.
- [x] Limitations explicit. → Paper §7 with 7 paragraphs.

## Paper

- [~] Novelty over Fides / MCPSHIELD explicit. → Comparison table exists; claim discipline needs audit.
- [ ] Strong baselines included. → Baselines are simulated functions (keyword matching, hash-based), not real comparable systems.
- [~] Adaptive attacks included. → 4 adaptive scenarios exist; sample is small.
- [ ] Results support claims. → Stale results are inconsistent (0% vs 4.76% ASR). Cannot support claims until rerun.
- [~] Artifact appendix included. → Exists but Python 3.13 vs Docker 3.12 conflict.

## Additional (Roadmap M5/M7)

- [~] Ablation study completed. → A0-A8 exist but stale; results inconsistent.
- [~] Failure analysis completed. → Residual analysis exists but based on stale results.
- [~] LLM-based evaluation completed. → 18 scenarios; manipulation rate only 18.18%; too small for strong claims.
- [ ] Mechanized proofs. → Coq file has field mismatch (tok.token_id etc.), likely cannot compile.
- [ ] User study. → Simulated only (not real users).
- [~] Stronger baselines (Fides/AttriGuard). → Simulated functions, not real implementations.
