# Acceptance Criteria

## 1. Security acceptance

| Criterion | Passing threshold |
|---|---:|
| ASR reduction vs no-defense | ≥ 80% on main attack suites |
| Secret exfiltration without declassification | 0 successful cases in evaluation suite |
| Label spoofing success | 0 successful cases |
| Capability token forgery success | 0 successful cases |
| Bridge replay success | 0 successful cases |
| Tool metadata self-authorization success | 0 successful cases |
| Adaptive white-box ASR | ≤ 10% |
| Unauthorized high-risk effect due to ExternalContent | ≤ 5%, ideally 0 |

## 2. Utility acceptance

| Criterion | Passing threshold |
|---|---:|
| Benign task completion rate | ≥ 90% of no-defense baseline |
| False blocking rate | ≤ 8% |
| Confirmation burden | ≤ 15% of benign tasks |
| Read-only task extra confirmation | ≤ 2% |
| Trusted skill task completion | ≥ 90% |
| User-private local summary completion | ≥ 90% |

## 3. Performance acceptance

| Criterion | Passing threshold |
|---|---:|
| Monitor p50 latency | ≤ 100 ms |
| Monitor p95 latency | ≤ 300 ms |
| Prompt token overhead | ≤ 10% |
| Average provenance graph size | ≤ 1 MB per complex task trace |
| Policy decision replay | deterministic for 100% sampled decisions |
| Audit log coverage | 100% of tool calls logged |

## 4. Formal acceptance

| Criterion | Passing threshold |
|---|---|
| Label lattice defined | complete and machine-checkable or formally specified |
| Transition system | covers user, external content, tool register, model propose, monitor, bridge, execute |
| Theorem: label unforgeability | proven or mechanized |
| Theorem: token unforgeability | proven or mechanized |
| Theorem: no secret exfiltration | proven or mechanized |
| Theorem: bridge non-replay | at least proof sketch; mechanized if time permits |
| Limitations | explicitly stated |

## 5. Artifact acceptance

| Criterion | Passing threshold |
|---|---|
| Code | reproducible prototype with clear README |
| Policy | documented DSL and sample rules |
| Evaluation | scripts to run main experiments |
| Attack suite | templates and generated cases included |
| Benign suite | task definitions included |
| Logs | allow/deny/bridge traces included |
| Reproducibility | Docker/Nix/devcontainer or equivalent |
| Documentation | setup, run, evaluate, extend |

## 6. CCF-A readiness acceptance

| Criterion | Passing threshold |
|---|---|
| Novelty statement | clearly differentiates from Fides, MCPSHIELD, prompt hardening, generic confirmation |
| Threat model | crisp and defensible |
| Main theorem | aligns with claimed system guarantee |
| Strong baseline | includes at least one modern IFC or causal-attribution defense if feasible |
| Adaptive attacks | included and not treated as optional |
| Artifact | good enough for review |
| Results narrative | demonstrates security/utility/performance trade-off |
