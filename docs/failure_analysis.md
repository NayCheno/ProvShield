# Failure Analysis

## Overview

In the expanded LLM-in-the-loop evaluation (660 scenarios: 420 attack + 240 benign, mimo-v2.5-pro), ProvShield achieves 0.24% end-to-end ASR (95% CI [0.04%, 1.34%]) and 92.1% BTCR (95% CI [88.0%, 94.9%]). This section analyzes why attacks fail and what the residual risks are.

## Attack Failure Categories

### 1. LLM Refused to Generate Malicious Tool Call (~89% of attacks)

The LLM itself refused to generate the malicious tool call in the vast majority of attack scenarios. The LLM manipulation rate is 10.71%, meaning only ~45 of 420 attack scenarios produced a tool call matching the attack target.

**Implication:** ProvShield's low ASR is partly attributable to the model's own resistance. The 90.5% ASR reduction (2.14% → 0.24%) is relative to the no-defense baseline, which also benefits from model robustness. In adversarial settings with a weaker or fine-tuned model, the runtime monitor becomes the critical defense layer.

### 2. ProvShield Blocked the Call (conditional block rate: 20%)

Among scenarios where the LLM generated the attack target tool, ProvShield blocked 20% through policy enforcement (DENY or REQUIRE_BRIDGE). This is the core value of ProvShield: when the LLM is manipulated, the runtime prevents unauthorized execution.

### 3. Residual ASR (0.24%)

The residual 0.24% ASR (1 attack success out of 420) occurs in scenarios where:
- The LLM generates a tool call
- The call's provenance does not trigger high-risk thresholds
- Conservative taint propagation (all context → all arguments) may allow some calls that finer-grained provenance would block

**Implication:** The conservative provenance mode used in evaluation is a safe upper bound. Implementing oracle or runtime-heuristic provenance modes would likely reduce the residual ASR further.

## Utility Analysis

### False Blocking (7.9%)

The 7.9% false blocking rate (92.1% BTCR vs 100% no-defense) arises from benign scenarios where:
- The LLM generates tool calls with conservative provenance linking to external content
- Policy requires a bridge for high-risk effects with low-integrity influence
- Without a bridge, the call is denied

**Mitigation:** Field-level provenance tracking and user bridge interaction would reduce this rate in practice.

### Confirmation Burden (7.9%)

The 7.9% bridge burden means ~19 of 240 benign scenarios require user confirmation. This is within the 15% acceptance threshold.

## Residual Risks

### Risk 1: Low No-Defense ASR

The no-defense ASR of 2.14% is low, meaning the absolute attack surface is small. While the 90.5% relative reduction is meaningful, reviewers may question whether the benchmark is sufficiently challenging.

**Mitigation:** Test with multiple LLMs (including weaker or fine-tuned models); implement stronger attack prompts; add scenarios where the attack is embedded in a legitimate workflow.

### Risk 2: Conservative Taint Propagation

The evaluation uses conservative taint: all context objects are bound to all arguments. This may inflate false blocking and may allow some attacks that would be caught with finer-grained provenance.

**Mitigation:** Implement and evaluate three provenance modes: oracle-source, conservative-all-context, and runtime-heuristic. Report all three as ablation/sensitivity analysis.

### Risk 3: Single-Model Evaluation

All results are from mimo-v2.5-pro. Different models may have different manipulation rates and different failure modes.

**Mitigation:** Evaluate with at least 2-3 additional models (e.g., GPT-4o, Claude, Llama).

### Risk 4: Baseline Quality

The baselines (prompt hardening, input firewall, generic confirmation, static allowlist) are implemented as rule-based functions, not real systems. No real Fides-style IFC or causal attribution baseline is included.

**Mitigation:** Implement at least one strong baseline as a faithful reproduction, or clearly document why real implementations are not reproducible.

### Risk 5: Formal Proof Status

The Coq formalization compiles with coqc 9.0 and includes the transition relation with reachable-state invariants. However, Theorems 1-2 (unforgeability) are definition-level: they prove that valid labels/tokens have non-zero MAC, which follows from the definitions. The full proof that model-generated text cannot forge labels requires the TCB assumption (model has no access to HMAC key), which is stated but not mechanized.

**Mitigation:** Either strengthen the Coq proofs to include the TCB assumption as a formal axiom, or clearly state in the paper that these are proof sketches under stated assumptions.

## Recommendations

1. **Test with multiple LLMs** to separate model safety from runtime enforcement
2. **Implement oracle/heuristic provenance modes** and report as ablation
3. **Strengthen attack prompts** to increase manipulation rate for weaker models
4. **Add at least one strong baseline** (real IFC or attribution)
5. **Document proof status honestly** in the paper (sketches, not fully mechanized)
