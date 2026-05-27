# Evaluation Results

Generated from manifest: git_sha=80a732b3, policy_hash=sha256:8c1b517c2..., model=mimo-v2-pro, timestamp=2026-05-27T18:01:16Z

Scenarios: 780 (530 attack + 250 benign)

## Table 1: Attack Success Rate by Suite

| Defense | SkillInject | MCPTox | MCP Safety | Web/Email | RAG | Adaptive | Overall ASR | 95% CI |
|---|---|---|---|---|---|---|---|---|
| ProvShield | 0.0% | 0.0% | 0.0% | 1.7% | 0.0% | 0.7% | 0.6% | [0.2%, 1.7%] |
| no_defense | 7.1% | 7.0% | 0.0% | 2.5% | 3.9% | 5.9% | 5.1% | [3.5%, 7.3%] |
| prompt_hardening | 3.6% | 3.5% | 0.0% | 1.7% | 1.0% | 0.7% | 1.9% | [1.0%, 3.4%] |
| input_firewall | 4.8% | 4.7% | 0.0% | 1.7% | 2.9% | 3.7% | 3.4% | [2.2%, 5.3%] |
| generic_confirmation | 7.1% | 7.0% | 0.0% | 2.5% | 3.9% | 5.9% | 5.1% | [3.5%, 7.3%] |
| static_allowlist | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | [0.0%, 0.7%] |

## Table 2: Utility and Performance

| Defense | BTCR | BTCR 95% CI | False Block | Bridge Burden |
|---|---|---|---|---|
| ProvShield | 92.4% | [88.4%, 95.1%] | 7.6% | 0.0% |
| no_defense | 100.0% | [98.5%, 100.0%] | 0.0% | 0.0% |
| prompt_hardening | 100.0% | [98.5%, 100.0%] | 0.0% | 0.0% |
| input_firewall | 100.0% | [98.5%, 100.0%] | 0.0% | 0.0% |
| generic_confirmation | 100.0% | [98.5%, 100.0%] | 0.0% | 0.0% |
| static_allowlist | 79.2% | [73.8%, 83.8%] | 20.8% | 0.0% |

## Table 3: Conditional Metrics (ProvShield)

- LLM manipulation rate: 14.9%
- PS block rate conditional: 44.3%
- Attack-tool conditional block: 100.0% (all attack tools blocked)
- No-defense ASR: 5.1%

## Table 4: Multi-Model Evaluation

Models evaluated: 3 (mimo-v2-pro / mimo-v2.5-pro / mimo-v2.5)
Scenarios per model: 10

| Model | ASR (e2e) | No-defense ASR | Manipulation Rate | Block Rate | BTCR |
|---|---|---|---|---|---|
| mimo-v2-pro_standard | 0.0% | 0.0% | 60.0% | 100.0% | 100.0% |
| mimo-v2.5-pro_standard | 0.0% | 0.0% | 60.0% | 100.0% | 100.0% |
| mimo-v2.5_standard | 0.0% | 0.0% | 80.0% | 100.0% | 100.0% |

## Table 5: Adversarial Evaluation

Direct-call adversary ASR: 0.0%
Adversarial LLM ASR: N/A

## Table 6: Per-Suite Attack Details (ProvShield)

| Suite | N | Attacks Succeeded | ASR | 95% CI |
|---|---|---|---|---|
| adaptive_white_box | 136 | 1 | 0.7% | [0.1%, 4.0%] |
| browser | 0 | 0 | 0.0% | [N/A] |
| email | 0 | 0 | 0.0% | [N/A] |
| mcp | 0 | 0 | 0.0% | [N/A] |
| mcp_metadata_poisoning | 86 | 0 | 0.0% | [0.0%, 4.3%] |
| mixed | 0 | 0 | 0.0% | [N/A] |
| rag_injection | 103 | 0 | 0.0% | [0.0%, 3.6%] |
| skill_injection | 84 | 0 | 0.0% | [0.0%, 4.4%] |
| skills | 0 | 0 | 0.0% | [N/A] |
| web_email_injection | 121 | 2 | 1.7% | [0.5%, 5.8%] |

## Table 7: Workflow-Embedded Attack Evaluation

72 workflow-embedded attack scenarios across 9 workflow types.
Direct-call adversary: 0.0% ASR (all 72 scenarios blocked by ProvShield).

| Workflow Suite | N | Blocked | Direct-call ASR |
|---|---|---|---|
| workflow_comms | 8 | 8 | 0.0% |
| workflow_devops | 8 | 8 | 0.0% |
| workflow_docs | 8 | 8 | 0.0% |
| workflow_finance | 8 | 8 | 0.0% |
| workflow_hr | 8 | 8 | 0.0% |
| workflow_marketing | 8 | 8 | 0.0% |
| workflow_research2 | 8 | 8 | 0.0% |
| workflow_security | 8 | 8 | 0.0% |
| workflow_support | 8 | 8 | 0.0% |
| **Total** | **72** | **72** | **0.0%** |
