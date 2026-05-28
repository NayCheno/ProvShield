# Deliverables Checklist

## Research deliverables

- [x] Threat model document → docs/02_threat_model.md
- [x] Related work positioning → paper §9 Related Work
- [x] Label lattice specification → docs/03_label_policy_spec.md, src/provshield/labels.py
- [x] Effect taxonomy → docs/03_label_policy_spec.md, src/provshield/types.py
- [x] Policy rule set → docs/03_label_policy_spec.md, prototype/policy/core_rules.yaml
- [x] User-intent bridge specification → docs/04_user_intent_bridge.md
- [x] Formal transition system → docs/05_formal_model.md, prototype/formal/ProvShield.v
- [x] Theorem statements → docs/05_formal_model.md, paper §5
- [x] Proof sketches → paper §5 (5 theorems with proof sketches)
- [x] Mechanized proof subset → prototype/formal/ProvShield.v (coqc 9.0 verified)

## Prototype deliverables

- [x] Normalized tool call parser → src/provshield/monitor.py (normalize_call)
- [x] Sidecar provenance store → src/provshield/store.py (SidecarProvenanceStore)
- [x] Context builder → src/provshield/context.py (ContextBuilder)
- [x] MCP proxy → src/provshield/mcp_proxy.py (MCPProxy)
- [x] Skill loader → src/provshield/skill_loader.py (SkillLoader)
- [x] Policy engine → src/provshield/policy.py (PolicyEngine)
- [x] Bridge manager → src/provshield/bridge.py (BridgeManager)
- [x] Capability token store → src/provshield/tokens.py (CapabilityTokenStore)
- [x] Audit logger → src/provshield/audit.py (AuditLogger)
- [x] Replay tool → tools/replay_audit.py

## Evaluation deliverables

- [x] Attack harness → eval/scripts/harness.py (EvaluationHarness)
- [x] Skill injection cases → eval/data/scenarios.json, expanded_scenarios.json
- [x] MCP metadata poisoning cases → eval/data/llm_scenarios_expanded.json
- [x] MCP safety cases → eval/data/strong_scenarios.json
- [x] Web/email injection cases → eval/data/workflow_embedded_scenarios.json
- [x] RAG injection cases → eval/data/expanded_scenarios.json
- [x] Adaptive attacks → eval/data/highrate_scenarios.json, targeted_scenarios.json
- [x] Benign tasks → eval/data/expanded_scenarios.json (250 benign scenarios)
- [x] Baselines → eval/scripts/baselines.py (8 baselines + ProvShield)
- [x] Main result tables → eval/results/result_tables.md, eval/results/tables/*.tex
- [x] Ablation result tables → eval/results/ablation_results.json, eval/results/tables/ablation_results_table.tex
- [x] Performance results → eval/results/result_tables.md (monitor latency p50/p95)

## Paper deliverables

- [x] Abstract → paper/paper_draft.tex (CCS abstract)
- [x] Introduction → paper §1
- [x] Motivation → paper §2 Motivating Attacks (4 attack scenarios)
- [x] Threat model → paper §3
- [x] Design → paper §4 (labels, effects, monitor, bridge, tokens)
- [x] Formal model → paper §5 (state, transitions, 5 theorems)
- [x] Implementation → paper §6 (6 components)
- [x] Evaluation → paper §7 (780 scenarios, 9 defenses, multi-model, ablation)
- [x] Related work → paper §9
- [x] Discussion → paper §8
- [x] Conclusion → paper §11
- [x] Appendix → formal model details in §5
- [x] Artifact appendix → paper §10 (artifact description, reproducibility)
