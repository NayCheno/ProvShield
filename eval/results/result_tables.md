# ProvShield Evaluation Results

Generated: 2026-05-27T00:26:09Z
Model: `mimo-v2.5-pro`
Git: `66c5beb73a85` (pre-C1-C5 fixes; current HEAD: `1b73090`)
Scenarios: 16 attack + 7 benign

> Note: These results were generated before C1-C5 blocker fixes. The underlying
> policy logic is unchanged; C1-C5 fix bridge argument preservation, MCP tool
> defaults, taint propagation, audit replay, and Coq formalization. A re-run
> with the current codebase is recommended for submission.

## Table 1: Attack Success Rate

| Defense | ASR | BTCR |
|---|---:|---:|
| ProvShield | 0.0% | 100.0% |
| no_defense | 12.5% | 100.0% |
| prompt_hardening | 6.2% | 100.0% |
| input_firewall | 0.0% | 100.0% |
| generic_confirmation | 12.5% | 100.0% |
| static_allowlist | 0.0% | 71.4% |

## Table 2: ProvShield Decomposition

| Metric | Value |
|---|---:|
| LLM manipulation rate | 37.5% |
| PS block rate (conditional) | 50.0% |
| End-to-end ASR | 0.0% |
| Benign completion | 100.0% |
| LLM latency p50 | 7,354 ms |
| LLM latency p95 | 12,996 ms |
