# Rebuttal Preparation

## Likely reviewer concern: novelty

Prepared response:

- Clarify that basic IFC is not claimed as new.
- Emphasize MCP metadata + skill loader + tool output + external content boundary.
- Emphasize bridge-bound declassification and capability issuance.
- Point to adaptive attacks and artifact.
- **Evidence:** Table 4 shows 10 design features across 6 approaches. ProvShield is the only one combining sidecar provenance, bound bridges, capability tokens, and MCP/skill-specific defense.

## Likely concern: causality

Prepared response:

- We do not claim full semantic causality.
- The LLM is modeled as an adversarial proposal oracle.
- Security property is about runtime execution under provenance policy.
- **Evidence:** Formal model §5 treats LLM output as untrusted. Theorem 1 proves label unforgeability regardless of model behavior. Limitations §7 explicitly states we don't prove model internals are unaffected.

## Likely concern: utility

Prepared response:

- Present BTCR and confirmation burden.
- Explain read-only fast path.
- Show benign high-risk tasks succeed with bridge.
- **Evidence:** 100% BTCR across all 5 benign categories (policy-level and LLM-level). 0% false blocking. 0% bridge burden for benign tasks. User-requested email send (benign_B2_email_03) completes without unnecessary bridge.

## Likely concern: confirmation fatigue

Prepared response:

- Bridge is only for high-risk effects.
- It is scoped and one-time.
- Generic confirmation baseline shows why binding matters.
- **Evidence:** Ablation A3 (no bridge binding) shows ASR rises from 6% to 50%, proving that bound bridges are essential. The benign suite shows 0 bridge requests for read-only tasks.

## Likely concern: benchmark realism

Prepared response:

- Include real MCP server metadata where possible.
- Include skill, web, email, and RAG channels.
- Include adaptive white-box attacks.
- **Evidence:** 27 scenarios across 6 attack suites + 5 benign categories. 4 adaptive white-box scenarios. LLM-based evaluation with mimo-v2.5-pro (18 scenarios). Scenarios based on published attack patterns (SkillInject, MCPTox, MCP Safety Audit, indirect prompt injection).

## Likely concern: overclaiming formal proof

Prepared response:

- The formal model intentionally abstracts model internals.
- The theorem covers enforced runtime transition to tool execution.
- The non-goals section states this limitation.
- **Evidence:** Theorem 1 proof sketch uses induction on transition steps. The model is explicitly treated as an adversarial proposal oracle (§5). Non-goals in §3 and Limitations in §7 state that we don't prove model activations are unaffected.

## Likely concern: evaluation scale

Prepared response:

- 27 policy-level scenarios + 18 LLM-level scenarios = 45 total.
- Ablation study (A0-A8) provides component-level evidence.
- Failure analysis identifies the exact boundary case.
- **Evidence:** LLM-based evaluation with mimo-v2.5-pro shows 0.0% end-to-end ASR. Ablation Table 5 shows each component's contribution. Failure analysis in §7.4.5 explains the residual 6.2% ASR (WriteLocal boundary).

## Likely concern: baseline strength

Prepared response:

- 5 baselines cover the main defense categories: no defense, prompt hardening (text-level), input firewall (classification), static allowlist (coarse), generic confirmation (interaction).
- Prompt hardening is the most relevant baseline per OpenAI's own guidance.
- **Evidence:** Prompt hardening reduces ASR to 66.7% for skill injection but fails against MCP metadata and adaptive attacks (100% ASR). Input firewall and generic confirmation provide no protection (100% ASR across all suites).
