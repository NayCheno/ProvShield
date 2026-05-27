# ProvShield Evaluation Results

Generated: 2026-05-27T07:40:25Z  
Model: `mimo-v2.5-pro`  
Git: `9c5246ded18f`  
Scenarios: 420 attack + 240 benign  

## Table 1: Attack Success Rate

| Defense | ASR | 95% CI | BTCR |
|---|---:|---:|---:|
| ProvShield | 0.2% | [0.0%, 1.3%] | 92.1% |
| no_defense | 2.1% | [1.1%, 4.0%] | 100.0% |
| prompt_hardening | 0.5% | [0.1%, 1.7%] | 100.0% |
| input_firewall | 1.4% | [0.7%, 3.1%] | 100.0% |
| generic_confirmation | 2.1% | [1.1%, 4.0%] | 100.0% |
| static_allowlist | 0.0% | [0.0%, 0.9%] | 78.8% |

## Table 2: ProvShield Decomposition

| Metric | Value |
|---|---:|
| LLM manipulation rate | 10.7% |
| PS block rate (conditional) | 20.0% |
| End-to-end ASR | 0.2% |
| Benign completion | 92.1% |
| LLM latency p50 | 13,094 ms |
| LLM latency p95 | 36,975 ms |
