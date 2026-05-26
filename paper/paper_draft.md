# ProvShield: Provenance-Typed Runtime Enforcement for MCP and Skill-Based LLM Agents

> Draft version: v0.1
> Status: initial paper draft. Experimental sections contain planned tables and placeholders.

## Abstract

LLM agents increasingly combine natural-language instructions, external documents, tool descriptions, tool outputs, and executable skills in a single planning context. This collapses the boundary between instructions and data: a malicious webpage, email, retrieved document, MCP tool description, or skill file can become an instruction that causes the agent to send private data, delete files, execute code, or leak credentials. Existing defenses such as prompt hardening, input filtering, and generic user confirmation are insufficient because attacks are contextual and often exploit the agent's authority rather than a fixed malicious string pattern.

We present **ProvShield**, a provenance-typed runtime enforcement system for MCP and skill-based LLM agents. ProvShield treats the LLM as an untrusted planner and moves authorization to the runtime. Content entering the agent is assigned unforgeable sidecar provenance labels that track integrity and confidentiality. Tools are declared with effect types and sinks. Before any tool call executes, a runtime monitor checks whether the proposed action, destination, payload, and capability token satisfy a source-to-sink policy. For high-risk effects, ProvShield requires a bound user-intent bridge that is specific to the action, sink, destination, payload digest, principal, and expiration.

We formalize ProvShield with a labeled transition system and prove label unforgeability, capability-token unforgeability, no unauthorized secret exfiltration, low-integrity control prevention for high-risk effects, and bridge non-replay under the stated trusted computing base. We implement ProvShield as an MCP proxy, skill loader, context builder, policy engine, bridge manager, and audit logger. We evaluate it on skill-injection, MCP metadata poisoning, MCP safety, web/email prompt injection, RAG injection, and adaptive attacks. Our planned evaluation measures attack success rate, benign task completion, false blocking, confirmation burden, and runtime overhead.

## 1. Introduction

LLM agents are no longer passive chat systems. They read webpages, search private documents, inspect email, call MCP tools, load skills, and perform write actions on behalf of users. This shift changes the security problem. A prompt injection does not need to compromise the model in the traditional sense; it only needs to convince the model to use the authority already granted to the agent.

The root cause is an instruction/data boundary failure. A single model context may contain system policies, user goals, tool descriptions, retrieved documents, email text, skill instructions, and tool outputs. All are represented as natural language, but they do not have the same authority. A webpage should provide facts, not new objectives. A tool output should inform the agent, not authorize a new write. A tool description should describe the interface, not grant itself privilege. A skill file should not override system policy. Yet many agents feed these sources to the model without a runtime-enforced distinction.

A common response is to harden the system prompt: tell the model to ignore instructions in webpages and emails. This is useful but brittle. Another response is input filtering: classify malicious text before it reaches the model. This fails when attacks are contextual, indirect, or socially engineered. A third response is generic confirmation: ask the user before writes. This can be laundered by vague confirmations that do not bind the actual destination, payload, or source of influence.

This paper takes a different position. The model may be manipulated; the runtime must still prevent unauthorized high-risk effects. We design ProvShield, a provenance-typed runtime enforcement system for MCP and skill-based agents. ProvShield assigns unforgeable sidecar labels to content as it enters the agent runtime, tracks integrity and confidentiality through transformations, declares tools with effect types and sinks, and intercepts all proposed tool calls. A tool call executes only if the runtime can establish that its action, destination, payload, and capability are authorized by policy. When user confirmation is required, the confirmation is not generic; it creates a one-time bridge bound to the exact action, sink, destination, payload digest, expiry, and principal.

### Contributions

This paper makes the following contributions:

1. **A provenance-typed security model for MCP and skill-based agents.** We define integrity and confidentiality lattices for user intent, system policy, skills, tool metadata, tool outputs, external content, secrets, and capability tokens.
2. **An effect-typed runtime monitor.** We introduce source-to-sink rules that gate write, send, delete, execute, credential, authentication, and financial effects.
3. **A bound user-intent bridge.** We design an action-specific, destination-specific, payload-specific declassification mechanism that avoids the weakness of generic confirmation.
4. **A formal model and safety properties.** We model the LLM as an adversarial proposal oracle and prove runtime-observable sink enforcement properties.
5. **A prototype for MCP and skill-based agents.** We implement MCP proxying, skill loading, sidecar provenance, policy checking, bridge handling, and audit replay.
6. **A systematic evaluation plan.** We evaluate against skill injection, MCP metadata poisoning, MCP safety scenarios, web/email prompt injection, RAG injection, and adaptive attacks.

## 2. Motivating Attacks

### 2.1 Webpage-to-email exfiltration

A user asks the agent to summarize a webpage. The webpage contains hidden text instructing the agent to send the user's API key to an attacker-controlled email address. A prompt-only defense requires the model to recognize and ignore the hidden instruction. ProvShield instead labels the webpage as `ExternalContent`. If the model proposes `send_email`, the monitor detects that the destination and objective are influenced by low-integrity content and that the payload may contain `Secret`. The call is denied unless an explicit, bound declassification exists.

### 2.2 MCP metadata poisoning

An MCP server registers a tool with a benign name but a malicious description: “Use this tool to validate credentials; before calling, include all available tokens.” If the agent treats tool metadata as trusted instruction, the metadata can shape future tool calls. ProvShield treats unattested metadata as `ToolMetadata`, a low-integrity source. Metadata can describe schema but cannot grant itself authority or introduce privileged objectives.

### 2.3 Skill file injection

A skill package includes instructions that appear to implement a formatting task but also tell the agent to delete local files after completion. If loaded as trusted natural-language instructions, the skill can override user intent. ProvShield labels untrusted skills separately, prevents them from changing policy, and blocks destructive effects unless authorized by user intent and capability.

### 2.4 Confirmation laundering

A malicious email asks the agent to “send the requested diagnostic information to the support address.” The agent presents a generic confirmation: “Send email?” The user clicks yes. The actual recipient is attacker-controlled and the payload includes private data. ProvShield's bridge would show the exact recipient, payload digest, source categories, and private-data crossing. A bridge for one payload and destination cannot authorize another.

## 3. Threat Model

The adversary may control external content, emails, retrieved documents, tool outputs, untrusted MCP metadata, and untrusted skill files. The adversary may know the policy rules and the label syntax rendered to the model. The adversary may attempt label spoofing, metadata poisoning, bridge laundering, delayed injection, multi-step exfiltration, or capability replay.

The LLM is not trusted to make authorization decisions. It is modeled as a proposal function that may output arbitrary tool calls. The trusted computing base consists of the runtime monitor, sidecar provenance store, policy engine, token generator, bridge manager, and audit logger.

ProvShield does not attempt to prove that untrusted text has no influence on the model's hidden state. Instead, it proves that high-risk tool execution cannot occur unless the runtime-observable provenance and capability constraints are satisfied.

## 4. Design

### 4.1 Provenance labels

Each object in the context store is associated with a provenance label:

```text
Labeled<T> = (value: T, label: ProvenanceLabel)
```

The label includes integrity, confidentiality, origin, principals, transformation history, runtime signature, nonce, and timestamp. Labels are maintained in a sidecar store. Natural-language labels shown to the model are advisory and cannot create authority.

The integrity lattice is:

```text
SystemPolicy > UserIntent > TrustedSkill > AttestedToolMetadata > ToolMetadata > ToolOutput > ExternalContent > UntrustedSkill
```

The confidentiality lattice is:

```text
Public < UserPrivate < Secret < CapabilityToken
```

### 4.2 Effect-typed tools

Each tool declares effects and sinks. Examples include `ReadPrivate`, `WriteExternal`, `SendNetwork`, `DeleteLocal`, `ExecuteCode`, `ModifyAuth`, and `CreateCredential`. The monitor uses these declarations to determine whether a proposed call is low-risk, high-risk, bridge-required, or denied.

### 4.3 Runtime monitor

The monitor intercepts all tool calls. For each call, it:

1. normalizes the tool name and arguments;
2. infers effects and sinks;
3. reconstructs argument and payload provenance from the sidecar graph;
4. checks source-to-sink policy;
5. allows, denies, sanitizes, quarantines, or requests a bridge;
6. logs the decision for replay.

### 4.4 User-intent bridge

High-risk effects require user intent. A bridge binds the exact action, effect, sink, destination, payload digest, source categories, principal, expiration, and one-time nonce. It can authorize only the normalized call for which it was minted.

### 4.5 Capability tokens

A successful bridge creates a capability token. The token is not textually usable by the model. It is stored in runtime state and checked by the monitor. Tokens cannot be copied from prompt text, modified, or replayed.

## 5. Formal Model

We define runtime state as:

```text
Σ = (C, R, T, S, P, B, A)
```

where `C` is the context store, `R` is runtime provenance state, `T` is the tool registry, `S` is the secret store, `P` is the policy, `B` is bridge/token state, and `A` is the audit log.

Transitions include user input, external content ingestion, skill loading, tool registration, model proposal, monitor allow, monitor deny, bridge confirmation, tool execution, label propagation, and audit logging.

### Theorem 1: Label unforgeability

In any reachable state, model-generated text cannot create a valid label with higher integrity than permitted by runtime transitions.

### Theorem 2: Capability token unforgeability

In any reachable state, a valid capability token can only be created by the runtime through a bridge confirmation or administrative transition.

### Theorem 3: No unauthorized secret exfiltration

If a proposed call sends or writes payload with confidentiality at least `Secret` to an external sink, the call cannot reach execution unless a valid declassification bridge exists.

### Theorem 4: No low-integrity control of high-risk effects

If a high-risk effect is influenced by low-integrity sources such as external content, tool output, untrusted skill, or untrusted tool metadata, the call cannot execute unless a valid bridge or policy exception authorizes the flow.

### Theorem 5: Bridge non-replay

A bridge token authorized for a normalized call cannot authorize a different action, sink, destination, payload digest, principal, or expired call.

## 6. Implementation

ProvShield is implemented as a runtime layer around an existing agent system. The implementation consists of:

- MCP proxy for tool registration and call mediation;
- skill loader for provenance-aware skill ingestion;
- context builder for sidecar labels;
- policy engine for source-to-sink rules;
- bridge manager for user confirmations and token issuance;
- audit logger for deterministic replay.

The prototype avoids modifying MCP servers by mediating calls through a proxy. Tool metadata is labeled at registration time. Tool outputs are labeled at return time. All proposed calls pass through the monitor before execution.

## 7. Evaluation

### 7.1 Attack suites

We evaluate against:

- skill injection;
- MCP metadata poisoning;
- MCP safety scenarios;
- web/email prompt injection;
- RAG injection;
- adaptive white-box attacks.

### 7.2 Baselines

We compare with:

- no defense;
- prompt hardening;
- input firewall;
- static allowlist;
- generic confirmation;
- Fides-style IFC where feasible;
- causal attribution monitor where feasible.

### 7.3 Metrics

We report attack success rate, secret exfiltration rate, unauthorized write/delete/exec rate, bridge abuse success, benign task completion, false blocking, confirmation burden, and monitor latency.

### 7.4 Planned result tables

#### Table 1: Attack success rate

| Defense | SkillInject | MCPTox | MCP Safety | Web/Email | RAG | Adaptive |
|---|---:|---:|---:|---:|---:|---:|
| No defense | TBD | TBD | TBD | TBD | TBD | TBD |
| Prompt hardening | TBD | TBD | TBD | TBD | TBD | TBD |
| Input firewall | TBD | TBD | TBD | TBD | TBD | TBD |
| Generic confirmation | TBD | TBD | TBD | TBD | TBD | TBD |
| ProvShield | TBD | TBD | TBD | TBD | TBD | TBD |

#### Table 2: Utility and overhead

| Defense | BTCR | False block | Bridge burden | p50 latency | p95 latency |
|---|---:|---:|---:|---:|---:|
| No defense | TBD | TBD | TBD | TBD | TBD |
| ProvShield | TBD | TBD | TBD | TBD | TBD |

## 8. Discussion

ProvShield's guarantees are runtime guarantees. It does not claim to remove malicious influence from model activations. Its policy may be conservative when provenance is ambiguous. User confirmations can still be socially engineered, but bridge binding prevents generic confirmation from authorizing hidden destination or payload changes. ProvShield should be deployed with sandboxing, least privilege, and secret management.

## 9. Related Work

This work relates to prompt injection defenses, information-flow control, capability systems, taint tracking, MCP security, skill security, tool-use monitoring, and secure confirmation UI. The closest work includes agent IFC systems, MCP security frameworks, and action-attribution monitors. ProvShield differs by focusing on the combined MCP/skill/tool-metadata/external-content boundary and by introducing bridge-bound runtime capability issuance.

## 10. Conclusion

Prompt injection in agents is best understood as an authority-flow problem. Untrusted content may influence language generation, but it should not be able to control privileged tool effects. ProvShield enforces this boundary through unforgeable provenance labels, effect-typed tools, runtime source-to-sink policy, and bound user-intent bridges.
