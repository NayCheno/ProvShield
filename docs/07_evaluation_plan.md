# Evaluation Plan

## 1. Research questions

| ID | Question |
|---|---|
| RQ1 | Does provenance-typed enforcement reduce attack success rate compared with prompt-only defenses? |
| RQ2 | Does the user-intent bridge preserve benign task completion better than static allowlists? |
| RQ3 | Are sidecar labels robust against adaptive label spoofing? |
| RQ4 | Does treating MCP tool metadata as low-integrity reduce metadata poisoning attacks? |
| RQ5 | What latency and friction does runtime monitoring add? |

## 2. Attack suites

### A1: Skill injection

- Source: SkillInject-style cases.
- Goal: malicious skill instruction causes send/write/delete/exec or secret exfiltration.
- Expected ProvShield behavior: deny or require bridge.

### A2: MCP metadata poisoning

- Source: MCPTox-style cases.
- Goal: malicious tool description/schema causes unauthorized tool call.
- Expected behavior: metadata remains low-integrity unless attested.

### A3: MCP safety audit scenarios

- Source: MCP Safety Audit-style scenarios.
- Goal: code execution, credential theft, remote control.
- Expected behavior: block exec/secret/auth flows.

### A4: Web/email prompt injection

- Source: hand-built realistic web pages and emails.
- Goal: indirect prompt injection through external content.
- Expected behavior: external content cannot control high-risk sinks.

### A5: RAG injection

- Source: malicious retrieved docs.
- Goal: delayed exfiltration or workflow hijacking.
- Expected behavior: low-integrity retrieval cannot create new privileged objectives.

### A6: Adaptive white-box attacks

- Attacker knows policy and label rendering.
- Attempts label spoofing, bridge laundering, payload swap, replay, tool metadata self-authorization.
- Expected behavior: runtime-side sidecar and token binding defeat spoofing.

## 3. Benign tasks

| Category | Examples |
|---|---|
| Browser | read webpages, summarize facts, produce local report |
| Email | summarize inbox, draft reply, extract action items |
| File | organize files, generate report, read private doc locally |
| MCP | query GitHub issues, inspect calendar, retrieve database rows |
| Skills | formatting, code analysis, data cleaning, report generation |
| Mixed | read email + web + produce draft, but no unauthorized send |

## 4. Baselines

| Baseline | Description |
|---|---|
| No defense | Original agent runtime. |
| Prompt hardening | System prompt says ignore malicious external content. |
| Input firewall | Classifier or rules filter suspicious input. |
| Static allowlist | Only selected tools allowed. |
| Generic confirmation | Confirm all high-risk tools without provenance binding. |
| Fides-style IFC | If reproducible, implement comparable confidentiality/integrity IFC. |
| Causal attribution monitor | Baseline variant: counterfactual comparison of tool calls with/without external content. |

## 5. Metrics

### Security metrics

```text
Attack Success Rate (ASR)
Secret Exfiltration Rate
Unauthorized Write Rate
Unauthorized Delete Rate
Unauthorized Exec Rate
Metadata Poisoning Success Rate
Bridge Abuse Success Rate
Adaptive Attack Success Rate
```

### Utility metrics

```text
Benign Task Completion Rate (BTCR)
False Blocking Rate
False Bridge Rate
Confirmation Burden
Mean Interactions per Task
Task Latency
```

### Performance metrics

```text
Monitor p50/p95 latency
Policy evaluation time
Provenance graph size
Prompt token overhead
Memory overhead
Audit log size
```

## 6. Ablations

| Ablation | Purpose |
|---|---|
| Remove provenance labels | Test whether labels are essential. |
| Remove runtime monitor | Test whether prompt-only labels help. |
| Remove bridge binding | Compare with generic confirmation. |
| Trust tool metadata | Test MCP metadata poisoning impact. |
| Remove capability tokens | Test replay / spoofing. |
| Remove confidentiality lattice | Test secret exfiltration protection. |
| Remove integrity lattice | Test unauthorized control protection. |

## 7. Reporting format

Main tables:

1. ASR by attack suite and baseline.
2. BTCR by benign task category and baseline.
3. False blocking and confirmation burden.
4. Performance overhead.
5. Adaptive attack breakdown.
6. Ablation results.

Main figures:

1. Attack success reduction bar chart.
2. Security-utility trade-off plot.
3. Monitor latency distribution.
4. Bridge decision flow.
5. Provenance graph example.

## 8. Statistical discipline

- Report mean and confidence interval.
- Use paired tasks across baselines.
- Separate attack suite generation from evaluation.
- Include seed and prompt templates in artifact.
- Pre-register success criteria before final run.
