# Submission Readiness Checklist

## Before submission

- [ ] Re-run related work search and update citations.
- [ ] Verify all arXiv IDs and author names.
- [x] Freeze threat model. → docs/02_threat_model.md, paper §3
- [x] Freeze benchmark definitions. → eval/data/scenarios.json (27 scenarios)
- [x] Freeze policy version used for experiments. → artifact/configs/default_policy.yaml
- [x] Run all baselines. → 5 baselines in eval harness
- [x] Run all ablations. → A0-A8 in eval/results/ablation_results.json
- [x] Run adaptive attacks. → 4 adaptive scenarios, 0% ASR
- [x] Validate audit replay. → AuditLogger supports deterministic replay
- [x] Clean artifact. → artifact/ with Makefile, Dockerfile, README
- [x] Remove real secrets or private data. → All synthetic (canary tokens)
- [ ] Have at least two internal reviewers read the paper.

## Claim audit

For every strong claim in the abstract/introduction:

- [x] Is there a theorem, experiment, or explicit assumption supporting it? → 5 theorems + 27 scenarios + LLM eval
- [x] Is the claim limited to runtime-observable tool execution? → Yes, formal model treats LLM as adversarial oracle
- [x] Does it avoid implying the model cannot be influenced? → Yes, Limitations §7 states this explicitly
- [x] Does it avoid overstating user confirmation guarantees? → Yes, social engineering limitation stated

## Figures and tables

- [x] Architecture figure. → Figure 1 (TikZ)
- [ ] Attack examples figure. → Not a separate figure; attacks described in §2
- [x] Label/effect table. → Table 1 (effect types)
- [x] Main ASR table. → Table 2 (ASR by suite and defense)
- [x] Utility table. → Table 3 (utility and overhead)
- [x] Ablation table. → Table 5 (A0-A8)
- [x] Performance table. → Embedded in Table 3 (latency columns)
- [x] Related work table. → Table 4 (design comparison)
