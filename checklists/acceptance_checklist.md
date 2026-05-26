# Acceptance Checklist

## Security

- [ ] ASR reduced by at least 80% vs no-defense on main suites.
- [ ] Secret exfiltration without declassification is zero in evaluated suite.
- [ ] Label spoofing attacks fail.
- [ ] Capability token forgery attacks fail.
- [ ] Bridge replay attacks fail.
- [ ] Destination swap attacks fail.
- [ ] Payload swap attacks fail.
- [ ] Untrusted MCP metadata cannot authorize privileged effects.
- [ ] Untrusted skills cannot modify policy or authority.
- [ ] Adaptive white-box ASR is at most 10%.

## Utility

- [ ] BTCR is at least 90% of no-defense baseline.
- [ ] False blocking rate is at most 8%.
- [ ] Confirmation burden is at most 15% of benign tasks.
- [ ] Read-only tasks do not trigger unnecessary confirmation.
- [ ] Trusted skills remain useful.

## Performance

- [ ] Monitor p50 latency at most 100 ms.
- [ ] Monitor p95 latency at most 300 ms.
- [ ] Prompt token overhead at most 10%.
- [ ] Audit trace is replayable.

## Formal

- [ ] Label lattice defined.
- [ ] Transition system complete.
- [ ] Label unforgeability theorem proved/sketched.
- [ ] Token unforgeability theorem proved/sketched.
- [ ] No-secret-exfiltration theorem proved/sketched.
- [ ] Bridge non-replay theorem proved/sketched.
- [ ] Limitations explicit.

## Paper

- [ ] Novelty over Fides / MCPSHIELD explicit.
- [ ] Strong baselines included.
- [ ] Adaptive attacks included.
- [ ] Results support claims.
- [ ] Artifact appendix included.
