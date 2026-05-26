# Reproducibility Plan

## Goals

A reviewer should be able to reproduce:

1. sample attack traces;
2. monitor allow/deny/bridge decisions;
3. main benchmark subset;
4. ablation subset;
5. latency measurements;
6. theorem/proof artifacts if mechanized.

## Artifact layout proposal

```text
artifact/
├── docker/
├── configs/
├── data/
│   ├── attacks/
│   └── benign/
├── scripts/
│   ├── run_attack_suite.sh
│   ├── run_benign_suite.sh
│   ├── run_ablation.sh
│   └── analyze_results.py
├── results/
└── README.md
```

## Reproducibility levels

### Level 1: Smoke test

- Run 5 attacks and 5 benign tasks.
- Expected time: short.
- Goal: verify monitor behavior.

### Level 2: Paper subset

- Run representative tasks from each suite.
- Goal: reproduce main trends.

### Level 3: Full evaluation

- Run all tasks and baselines.
- Goal: reproduce paper tables.

## Determinism

- Fix seeds.
- Store prompts.
- Store model version.
- Store policy version.
- Store normalized tool call traces.
- Store audit replay inputs.

## Sensitive data

Use synthetic secrets and canary tokens only. Do not include real credentials, emails, or private documents.
