# Evaluation Analysis Template

## Main result summary

```text
ProvShield reduced ASR from [x] to [y] across [n] attacks while preserving [z]% benign task completion relative to no-defense.
```

## Table: attack results

| Suite | No defense | Prompt hardening | Input firewall | Generic confirmation | ProvShield |
|---|---:|---:|---:|---:|---:|
| Skill injection | TBD | TBD | TBD | TBD | TBD |
| MCP metadata poisoning | TBD | TBD | TBD | TBD | TBD |
| MCP safety | TBD | TBD | TBD | TBD | TBD |
| Web/email injection | TBD | TBD | TBD | TBD | TBD |
| RAG injection | TBD | TBD | TBD | TBD | TBD |
| Adaptive | TBD | TBD | TBD | TBD | TBD |

## Table: utility results

| Task category | No defense BTCR | ProvShield BTCR | False block | Bridge burden |
|---|---:|---:|---:|---:|
| Browser | TBD | TBD | TBD | TBD |
| Email | TBD | TBD | TBD | TBD |
| MCP | TBD | TBD | TBD | TBD |
| Skills | TBD | TBD | TBD | TBD |
| Mixed | TBD | TBD | TBD | TBD |

## Failure analysis

- False positives:
- False negatives:
- Bridge usability failures:
- Provenance ambiguity cases:
- Policy tuning cases:

## Case studies

1. Blocked MCP metadata poisoning.
2. Blocked web-to-email secret exfiltration.
3. Benign email send with valid bridge.
4. Adaptive label-spoofing failure.
