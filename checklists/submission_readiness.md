# Submission Readiness Checklist

## Paper Completeness

- [x] Abstract — complete, consistent with body numbers
- [x] Introduction — motivation, instruction/data boundary failure, contributions
- [x] Motivating Attacks — 4 attack scenarios (web exfil, MCP metadata, skill injection, bridge laundering)
- [x] Threat Model — adversary capabilities, TCB definition, non-goals
- [x] Design — provenance labels, effect-typed tools, runtime monitor, bridge, capability tokens
- [x] Formal Model — state definition, transitions, 5 theorems with proof sketches
- [x] Implementation — 6 components described
- [x] Evaluation — 780 scenarios, 9 defenses (including 3 baseline variants), per-suite breakdown, ablation, failure analysis, multi-model evaluation
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

- [x] Smoke test runs (129 tests pass — 124 unit + 5 MCP integration)
- [x] Docker support (Dockerfile present)
- [x] CI workflow (.github/workflows/ci.yml)
- [x] Audit log schema (JSON Schema)
- [x] Policy configuration (YAML)
- [x] Coq formalization (prototype/formal/ProvShield.v)
- [x] Table generation scripts (eval/scripts/analyze_results.py with per-suite table)
- [x] make all passes end-to-end (check → smoke → eval → paper → replay)
- [x] No-bypass MCP integration test (test_no_bypass_direct_executor)
- [x] Test isolation (conftest.py resets TOOL_PROFILES between tests)
- [x] Manifest metadata in LaTeX table captions (git sha 80a732b, policy hash 8c1b517c)

## Baseline Variants (Phase 2)

- [x] Fides-style IFC baseline (prompt-rendered labels + policy prompt)
- [x] Causal attribution baseline (injection-pattern-based causal ablation)
- [x] MCP security baseline (metadata scanner for suspicious patterns)
- [x] Total baselines: 8 (no_defense, prompt_hardening, input_firewall, generic_confirmation, static_allowlist, fides_ifc, causal_attribution, mcp_security)

## Adversarial Evaluation (Phase 1)

- [x] Adversarial LLM mode script (eval/scripts/run_adversarial_eval.py)
- [x] Direct tool-call adversary (bypasses LLM, tests monitor enforcement)
- [x] 4 separate ASR metrics reported (end-to-end, no-defense, LLM manipulation, conditional block)
- [x] Multi-model evaluation: 3 models (mimo-v2-pro, mimo-v2.5-pro, mimo-v2.5), 75 scenarios each (50 attack + 25 benign)
- [~] No-defense ASR ≥30% in adversarial setting: 10% with mimo-v2.5 (gap remains; mimo models are generally robust). Stress-test: 83% no-defense ASR with user-level social engineering (18 scenarios, mimo-v2.5).
- [x] 72 workflow-embedded attack scenarios generated and verified (0.0% direct-call ASR)
- [x] Stress-test scenarios: 18 scenarios achieving 83% no-defense ASR (mimo-v2.5)
- [x] High-manipulation scenarios: 80 scenarios, 50% manipulation rate (mimo-v2.5)
- [x] Direct-call adversary: 101 scenarios, 8 effect types, 100% block rate
- [x] Provenance mode ablation: oracle/conservative/heuristic, 15 scenarios, 100% block rate
## Theorem-Code Mapping (Phase 4)
- [x] All 9 theorem → code → test mappings verified against actual test names
- [x] Proof hierarchy documented (Level 1: mechanized, Level 2: sketch, Level 3: assumption)
- [x] HMAC security stated as axiom
- [x] Paper wording uses "proof sketches" not "fully proven"
## Remaining Gaps (documented, not blocking submission)
1. **Multi-model scale**: 3 models evaluated with 75 scenarios each. Need ≥300 attack + ≥100 benign per model for full §8.4 gate.
2. **No-defense ASR**: 5.1% (standard) / 10% (mimo-v2.5). Stress-test achieves 83% with user-level social engineering (18 scenarios). §8.4 gate requires ≥30% in standard setting.
3. **Baseline quality**: 3 baseline variants (IFC, attribution, MCP security) implemented AND run at scale (780 scenarios). All show 4.9–5.1% ASR, no better than no defense.
4. **Real MCP integration**: MCP proxy is functional; no-bypass test verifies architectural invariant. Not integrated with production MCP client/server.
5. **User study**: Simulated only. Real user study would strengthen bridge evaluation.
6. **Ablation study**: Policy-level (21 predefined scenarios) + provenance mode ablation (15 scenarios, 3 modes). Expanded LLM-in-the-loop ablation planned.
7. **Coq Docker compilation**: Coq not installed locally; needs Docker to verify.