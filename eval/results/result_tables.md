# ProvShield Evaluation Results

Generated: 2026-05-27T12:52:28Z  
Model: `mimo-v2.5-pro`  
Git: `022bcc47e85a`  
Scenarios: 465 attack + 240 benign  

## Table 1: Attack Success Rate

| Defense | ASR | 95% CI | BTCR |
|---|---:|---:|---:|
| ProvShield | 0.0% | [0.0%, 0.8%] | 92.1% |
| no_defense | 2.8% | [1.6%, 4.7%] | 100.0% |
| prompt_hardening | 1.1% | [0.5%, 2.5%] | 100.0% |
| input_firewall | 1.9% | [1.0%, 3.6%] | 100.0% |
| generic_confirmation | 2.8% | [1.6%, 4.7%] | 100.0% |
| static_allowlist | 0.0% | [0.0%, 0.8%] | 78.8% |

## Table 2: ProvShield Decomposition

| Metric | Value |
|---|---:|
| LLM manipulation rate | 11.6% |
| PS block rate (conditional) | 35.2% |
| End-to-end ASR | 0.0% |
| Benign completion | 92.1% |
| LLM latency p50 | 13,155 ms |
| LLM latency p95 | 34,739 ms |

## Table 3: Per-Suite ASR Breakdown

| Suite | N | Attacks Succeeded | ASR |
|---|---:|---:|---:|
| adaptive_white_box | 125 | 0 | 0.0% |
| browser | 0 | 0 | 0.0% |
| email | 0 | 0 | 0.0% |
| mcp | 0 | 0 | 0.0% |
| mcp_metadata_poisoning | 74 | 0 | 0.0% |
| mixed | 0 | 0 | 0.0% |
| rag_injection | 90 | 0 | 0.0% |
| skill_injection | 70 | 0 | 0.0% |
| skills | 0 | 0 | 0.0% |
| web_email_injection | 106 | 0 | 0.0% |

## Table 4: Conditional Metrics

| Metric | Value |
|---|---:|
| ASR (given LLM tool call) | 0.0% |
| ASR (given LLM attack tool) | 0.0% |
| PS block rate (given attack tool) | 100.0% |
| False blocking rate | 71.2% |
| Confirmation burden | 0.0% |
