# Submission Readiness Checklist

## Paper Completeness

- [x] Abstract — complete, consistent with body numbers
- [x] Introduction — motivation, instruction/data boundary failure, contributions
- [x] Motivating Attacks — 4 attack scenarios (web exfil, MCP metadata, skill injection, bridge laundering)
- [x] Threat Model — adversary capabilities, TCB definition, non-goals
- [x] Design — provenance labels, effect-typed tools, runtime monitor, bridge, capability tokens
- [x] Formal Model — state definition, transitions, 5 theorems with proof sketches
- [x] Implementation — 6 components described
- [x] Evaluation — 780 scenarios, 6 defenses, per-suite breakdown, ablation, failure analysis
- [x] Related Work — prompt injection, IFC, capability security, taint tracking, MCP security, skill security, attribution
- [x] Discussion — conservative policy, social engineering, model influence, deployment
- [x] Limitations — model influence, social engineering, conservative policy, residual attacks, TCB assumptions, evaluation scope, formal proofs
- [x] Ethics — dual-use, user autonomy, audit log privacy, false sense of security
- [x] Artifact appendix — prototype, eval harness, policy, formal model, Docker, CI

## Number Consistency

All numbers verified against `eval/results/result_tables.md`:

| Metric | Paper Value | Source |
|---|---|---|
| Total scenarios | 780 | result_tables.md |
| Attack scenarios | 530 | result_tables.md |
| Benign scenarios | 250 | result_tables.md |
| ProvShield ASR | 0.6% | result_tables.md |
| ProvShield ASR 95% CI | [0.2%, 1.7%] | result_tables.md |
| No-defense ASR | 5.1% | result_tables.md |
| BTCR | 92.4% | result_tables.md |
| ASR reduction | 88% | computed |
| False blocking | 7.6% | computed (100%-92.4%) |
| Bridge burden | 7.6% | result_tables.md |
| LLM manipulation rate | 14.9% | result_tables.md |
| Conditional block rate (attack tool) | 100% | result_tables.md |

## Artifact

- [x] Smoke test runs (122 tests pass)
- [x] Docker support (Dockerfile present)
- [x] CI workflow (.github/workflows/ci.yml)
- [x] Audit log schema (JSON Schema)
- [x] Policy configuration (YAML)
- [x] Coq formalization (prototype/formal/ProvShield.v)
- [x] Table generation scripts (eval/scripts/analyze_results.py)

## Documentation

- [x] README.md — updated to v0.3 with current numbers
- [x] PROJECT_INDEX.md — file index
- [x] artifact/README.md — reproducibility levels, current numbers
- [x] docs/metrics_definitions.md — canonical metric definitions
- [x] docs/theorem_code_mapping.md — proof hierarchy and limitations
- [x] docs/failure_analysis.md — residual risks and recommendations
- [x] checklists/acceptance_checklist.md — verified items
- [x] checklists/rebuttal_preparation.md — 10 anticipated questions

## Remaining Gaps (documented, not blocking submission)

1. **Single-model evaluation**: All results from mimo-v2-pro. Multi-model evaluation planned for camera-ready.
2. **Baseline quality**: Baselines are rule-based implementations. Discussion of stronger baselines in paper limitations.
3. **No-defense ASR**: 5.1% is relatively low. Workflow-embedded attacks increase manipulation rate.
4. **Real MCP integration**: MCP proxy is functional but not integrated with production MCP client/server.
5. **User study**: Simulated only. Real user study would strengthen bridge evaluation.
6. **Ablation study**: Policy-level (21 predefined scenarios). Expanded LLM-in-the-loop ablation planned.
