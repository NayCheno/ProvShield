# Risk Register

| Risk | Probability | Impact | Mitigation | Owner |
|---|---:|---:|---|---|
| Novelty overlap with Fides / MCPSHIELD | High | High | Narrow claim to MCP + Skills + bridge-bound capability enforcement. | PI |
| Formal proof too broad | Medium | High | Model LLM as adversarial proposal oracle; prove sink enforcement only. | Formal lead |
| Provenance reconstruction imprecise | High | Medium | Conservative join; deny/bridge on uncertainty. | Systems lead |
| Utility loss from overblocking | Medium | High | Tune policies; separate read-only from write/send/delete/exec. | Eval lead |
| User confirmation fatigue | Medium | Medium | Bridge only for high-risk effects; make UI concise. | UX lead |
| Benchmark incompleteness | Medium | High | Use multiple suites + adaptive attacks + realistic benign tasks. | Eval lead |
| Tool bypass | Low | High | Route all tool calls through proxy; test bypass attempts. | Systems lead |
| Audit logs leak sensitive info | Medium | Medium | Redaction, hashing, synthetic artifacts. | Security lead |
| Latency too high | Medium | Medium | Cache policy decisions; optimize provenance graph. | Systems lead |
| Artifact too hard to run | Medium | High | Docker/Nix, small benchmark subset, deterministic scripts. | Artifact lead |
