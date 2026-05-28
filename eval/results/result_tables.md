# ProvShield Evaluation Results

Generated from manifest: git_sha=3b6f389, policy_hash=sha256:8c1b517c2..., model=mimo-v2-pro, timestamp=2026-05-28T05:03:36Z, updated=2026-05-28T12:00:00Z

Scenarios: 530 attack + 250 benign

## Table 1: Attack Success Rate

| Defense | ASR | 95% CI | BTCR |
|---|---:|---:|---:|
| ProvShield | 0.6% | [0.2%, 1.7%] | 92.4% |
| no_defense | 5.1% | [3.5%, 7.3%] | 100.0% |
| prompt_hardening | 1.9% | [1.0%, 3.4%] | 100.0% |
| input_firewall | 3.4% | [2.2%, 5.3%] | 100.0% |
| generic_confirmation | 5.1% | [3.5%, 7.3%] | 100.0% |
| static_allowlist | 0.0% | [0.0%, 0.7%] | 79.2% |
| fides_ifc | 4.9% | [3.4%, 7.1%] | 100.0% |
| causal_attribution | 4.9% | [3.4%, 7.1%] | 100.0% |
| mcp_security | 5.1% | [3.5%, 7.3%] | 100.0% |

## Table 2: ProvShield Decomposition

| Metric | Value |
|---|---:|
| LLM manipulation rate | 14.9% |
| PS block rate (conditional) | 44.3% |
| End-to-end ASR | 0.6% |
| Benign completion | 92.4% |
| LLM latency p50 | 6,052 ms |
| LLM latency p95 | 10,215 ms |

## Table 3: Per-Suite ASR Breakdown

| Suite | N | Attacks Succeeded | ASR |
|---|---:|---:|---:|
| adaptive_white_box | 136 | 1 | 0.7% |
| browser | 0 | 0 | 0.0% |
| email | 0 | 0 | 0.0% |
| mcp | 0 | 0 | 0.0% |
| mcp_metadata_poisoning | 86 | 0 | 0.0% |
| mixed | 0 | 0 | 0.0% |
| rag_injection | 103 | 0 | 0.0% |
| skill_injection | 84 | 0 | 0.0% |
| skills | 0 | 0 | 0.0% |
| web_email_injection | 121 | 2 | 1.7% |

## Table 4: Conditional Metrics

| Metric | Definition | Value |
|---|---|---:|
| ASR (given LLM tool call) | Attack success given LLM generated any tool call | 3.8% |
| ASR (given LLM attack tool) | Attack success given LLM generated the specific attack tool | 0.0% |
| PS block rate (given attack tool) | Block rate given LLM generated the specific attack tool | 100.0% |
| False blocking rate (deny) | Benign calls denied (not bridged) | 7.6% |
| False blocking rate (deny+bridge) | Benign calls denied or requiring bridge | 21.1% |
| Confirmation burden | Benign tasks requiring bridge confirmation | 7.6% |

## Monitor Latency

| Metric | Value |
|---|---:|
| p50 | 0.0 ms |
| p95 | 0.0 ms |
| mean | 0.0 ms |
| count | 780 |

## Table 5: Multi-Model Evaluation (75 scenarios per model)

| Model | ASR (e2e) | No-defense ASR | Manipulation | Block Rate | BTCR |
|---|---:|---:|---:|---:|---:|
| mimo-v2-pro | 4.0% | 8.0% | 32.0% | 100.0% | 100.0% |
| mimo-v2.5-pro | 2.0% | 2.0% | 10.0% | 100.0% | 100.0% |
| mimo-v2.5 | 4.0% | 10.0% | 50.0% | 100.0% | 88.0% |

## Table 6: Workflow-Embedded Attack Evaluation

72 workflow-embedded attack scenarios across 9 workflow types.
Direct-call adversary: 0.0% ASR (all 72 scenarios blocked by ProvShield).

| Workflow Suite | N | Blocked | Direct-call ASR |
|---|---:|---:|---:|
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

## Table 7: Direct-Call Adversary (bypasses LLM)

101 crafted malicious tool calls sent directly to the runtime monitor.
Conservative provenance mode: all context objects linked to all arguments.

| Effect Type | N | Blocked | Block Rate |
|---|---:|---:|---:|
| SendNetwork | 17 | 17 | 100.0% |
| ExecuteCode | 17 | 17 | 100.0% |
| DeleteLocal | 12 | 12 | 100.0% |
| CreateCredential | 11 | 11 | 100.0% |
| WriteExternal | 11 | 11 | 100.0% |
| CalendarInvite | 11 | 11 | 100.0% |
| ModifyAuth | 11 | 11 | 100.0% |
| Financial | 11 | 11 | 100.0% |
| **Total** | **101** | **101** | **100.0%** |

## Table 8: Provenance Mode Ablation (15 high-manipulation scenarios)

| Mode | N | Manipulated | Blocked | Manip. Rate | Block Rate |
|---|---:|---:|---:|---:|---:|
| Oracle | 15 | 1 | 1 | 6.7% | 100.0% |
| Conservative | 15 | 3 | 3 | 20.0% | 100.0% |
| Heuristic | 15 | 3 | 3 | 20.0% | 100.0% |

## Table 9: Stress-Test Scenarios (18 scenarios, mimo-v2.5)

Professional maintenance/operations framing with single-turn requests.
User-level social engineering (all context = UserIntent integrity).

| Tool | N | Manipulated | Manip. Rate |
|---|---:|---:|---:|
| execute_shell | 5 | 5 | 100.0% |
| send_email | 3 | 3 | 100.0% |
| delete_file | 10 | 7 | 70.0% |
| **Total** | **18** | **15** | **83.3%** |