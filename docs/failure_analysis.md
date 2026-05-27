# Failure Analysis

## Overview

In the current unified evaluation (23 scenarios, mimo-v2.5-pro), ProvShield
achieves 0.0% end-to-end ASR. No attack succeeded. This section analyzes
why attacks failed and what the residual risks are.

## Attack Failure Categories

### 1. LLM Refused to Generate Malicious Tool Call (62.5% of attacks)

The LLM itself refused to generate the malicious tool call in 10 of 16 attack
scenarios. This is the model's built-in safety, not ProvShield's enforcement.

**Implication:** ProvShield's 0% ASR is partly attributable to the model's own
resistance. In adversarial settings with a weaker or fine-tuned model, the
runtime monitor becomes the critical defense layer.

### 2. LLM Generated Different Tool Than Attack Expected (18.75%)

In 3 scenarios, the LLM generated a tool call, but it was a different tool than
the attack expected (e.g., `execute_shell` instead of `send_email`). ProvShield
allowed these calls because they were benign.

**Implication:** Attack scenarios need more precise success conditions that
account for semantic equivalence, not just exact tool name matching.

### 3. ProvShield Blocked the Call (18.75%)

In 3 scenarios, the LLM generated the expected malicious tool call, and
ProvShield correctly blocked it through policy enforcement (DENY or
REQUIRE_BRIDGE).

**This is the core value of ProvShield:** when the LLM is manipulated, the
runtime prevents unauthorized execution.

## Residual Risks

### Risk 1: Weak Model Safety

If an adversary uses a fine-tuned or jailbroken model, the LLM refusal rate
drops to 0%, and ProvShield's block rate (50% conditional) becomes the sole
defense. The 50% conditional block rate means half of manipulated calls still
pass through.

**Mitigation:** Expand the policy rules to cover more attack patterns; increase
the proportion of calls that trigger REQUIRE_BRIDGE.

### Risk 2: Small Evaluation Scale

23 scenarios (16 attack + 7 benign) is insufficient for strong claims. The
95% confidence interval for ASR=0% with n=16 is [0%, 20%] (Wilson score).

**Mitigation:** Scale to ≥400 attack scenarios with diverse attack strategies.

### Risk 3: Baseline Quality

The baselines (prompt hardening, input firewall, generic confirmation) are
implemented as pattern-matching functions, not real systems. A real prompt
hardening baseline would re-prompt the LLM; a real input firewall would use a
trained classifier.

**Mitigation:** Implement at least one strong baseline (e.g., Fides-style IFC)
as a faithful reproduction.

### Risk 4: No Adaptive Attacks

The current adaptive white-box scenarios (3) are too few and not truly adaptive.
A real adaptive attacker would study ProvShield's policy and craft inputs that
exploit gaps.

**Mitigation:** Implement ≥100 adaptive white-box scenarios with iterative
refinement.

## Recommendations

1. **Scale evaluation** to ≥400 attack + ≥200 benign scenarios
2. **Add confidence intervals** (95% CI via Wilson score or bootstrap)
3. **Implement strong baselines** (real IFC, real classifier)
4. **Add adaptive attack suite** with ≥100 scenarios
5. **Test with multiple LLMs** to separate model safety from runtime enforcement
6. **Re-run ablation study** with unified framework
