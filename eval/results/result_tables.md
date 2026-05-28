# ProvShield Evaluation Results

Generated: 2026-05-28T05:03:36Z  
Model: `mimo-v2.5-pro`  
Git: `df198dd124b5`  
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

| Metric | Value |
|---|---:|
| ASR (given LLM tool call) | 3.8% |
| ASR (given LLM attack tool) | 0.0% |
| PS block rate (given attack tool) | 100.0% |
| False blocking rate | 21.1% |
| Confirmation burden | 0.0% |

## Monitor Latency

| Metric | Value |
|---|---:|
| p50 | 0.0 ms |
| p95 | 0.0 ms |
| mean | 0.0 ms |
| count | 780 |
