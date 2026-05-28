# Preventing Authority Laundering in Tool-Using LLM Agents

> Draft version: v1.0 (CCF-A rewrite)
> Status: 780 scenarios, 9 defense configurations (including 3 strong baselines), 3-model evaluation, direct-call adversary (23 scenarios, 95.7% blocked), high-manipulation (80 scenarios), mechanized core (Coq 9.0). ProvShield 0.6% ASR (88% reduction), 92.4% BTCR, 100% conditional block rate across all models.

## Abstract

Tool-using LLM agents do not merely generate text; they exercise delegated authority. They read private data, invoke MCP tools, load skills, write files, send emails, and execute code. This changes the security problem: an attacker does not need to compromise the model as software—it is enough to launder a low-authority observation into a high-authority tool action. We call this *authority laundering*: the process by which a low-authority source—such as a webpage, email, retrieved document, MCP tool description, skill file, or tool output—is transformed by an LLM planner into a high-risk tool effect without proper authorization.

We present **ProvShield**, a runtime authority firewall for MCP and skill-based LLM agents. ProvShield treats the LLM as an untrusted planner and moves all authorization decisions to the runtime. Each content object entering the agent is assigned an HMAC-keyed sidecar provenance label tracking authority origin. Tools are declared with effect types and sinks. Before any tool call executes, a runtime monitor verifies that the proposed action, destination, payload, and capability satisfy a source-to-sink authority policy. For high-risk effects, ProvShield requires an *intent-bound declassification capability*: a one-time, cryptographically bound authorization specific to the exact action, sink, destination, payload digest, principal, and expiration—not a generic user confirmation.

We formalize ProvShield with a labeled transition system and mechanize its core properties: label unforgeability, capability-token unforgeability, no unauthorized secret exfiltration, no low-integrity control of high-risk effects, and bridge non-replay, under explicit trusted computing base assumptions. We implement ProvShield as an MCP proxy, skill loader, policy engine, bridge manager, and audit logger. We evaluate on 780 scenarios (530 attack, 250 benign) spanning six authority-laundering classes against nine defense configurations—including three strong baselines (Fides-style IFC, causal attribution, MCP security)—and 72 workflow-embedded strong attacks. ProvShield achieves 0.6% ASR (95% CI [0.2%, 1.7%]), an 88% reduction from the no-defense baseline, while maintaining 92.4% BTCR. Its conditional block rate is 100%: every attack tool call the LLM generates is stopped by the runtime. Direct-call adversary evaluation with a fully compromised planner confirms 95.7% block rate with conservative provenance.

## 1. Introduction

Tool-using LLM agents do not merely generate text; they exercise delegated authority. They read private data, invoke MCP tools, load skills, write files, send emails, and execute code on behalf of users. This changes the prompt-injection problem. The attacker does not need to compromise the model as software; it is enough to launder a low-authority observation into a high-authority tool action.

We call this failure mode *authority laundering*. A webpage that the agent summarizes should provide facts, not authorize a new email send. A tool output should inform the agent, not trigger code execution. A tool description should describe its interface, not grant itself permission to attach credentials. A skill file should not override system policy. Yet in current agent architectures, these sources are represented as natural language in a shared planning context, without a runtime-enforced distinction between data and instruction, between observation and authorization.

Existing defenses are insufficient because they address the wrong layer. Prompt hardening tells the model to ignore injected instructions, but this depends on model obedience and fails against contextual or metadata-driven attacks. Input filtering classifies malicious text, but laundering can be indirect, socially engineered, or embedded in tool metadata. Generic confirmation asks the user before writes, but the confirmation does not bind the actual destination, payload, or source of influence—enabling confirmation laundering. Attribution monitors estimate which context influenced an action, but influence is not authority.

This paper takes a different position. The model may be manipulated or fully compromised; the runtime must still prevent unauthorized high-risk effects. We design **ProvShield**, a runtime authority firewall for MCP and skill-based LLM agents. ProvShield assigns HMAC-keyed sidecar labels to content as it enters the agent runtime, declares tools with effect types and sinks, and intercepts all proposed tool calls before execution. A tool call executes only if the runtime can establish an authority proof: the action, destination, payload, and capability are authorized by high-authority sources or by an *intent-bound declassification capability*—a one-time, cryptographically bound authorization specific to the exact call. ProvShield does not ask whether the model recognized malicious text; it asks whether the proposed effect has sufficient authority to execute.

### Contributions

This paper makes the following contributions:

1. **Problem formulation: Agent Authority Laundering.** We define authority laundering as a security failure specific to tool-using LLM agents, where low-authority observations are transformed into high-authority tool effects through model planning. We identify six laundering classes and analyze why existing defenses fail against each.

2. **Authority-flow model for MCP/Skills agents.** We formalize source authorities, effects, sinks, authority levels, user intent, and declassification capabilities as a runtime transition system over the observation-to-execution pipeline. Unlike program-level IFC, ProvShield's labels are maintained in a sidecar store that the LLM cannot access.

3. **Intent-bound declassification capability.** We design a security abstraction where user confirmation binds action, effect, sink, destination, payload digest, source category, principal, and expiry into a non-replayable, one-time runtime capability—not a generic confirmation dialog.

4. **Runtime authority firewall.** We treat the LLM as an untrusted planner and enforce authority proofs at the tool execution boundary, preventing unauthorized high-risk effects even when the planner is fully compromised.

5. **Authority-laundering benchmark.** We construct a benchmark covering six laundering classes—MCP metadata poisoning, skill instruction laundering, tool-output laundering, RAG/email/web authority laundering, and direct-call compromised planner scenarios—with 780 LLM-in-the-loop scenarios across three models.

6. **Empirical separation of model manipulation from runtime enforcement.** We decompose attack success into LLM manipulation rate, attack-tool generation rate, conditional runtime block rate, and direct-call adversary ASR, demonstrating that ProvShield's 100% conditional block rate operates independently of model safety alignment.

## 2. Authority Laundering Attacks

We define authority laundering as the process by which a low-authority observation is transformed by an LLM planner into a high-authority tool effect. We identify six classes of authority laundering attacks, each exploiting a different failure mode in current agent architectures.

### 2.1 Observation-to-Send Laundering

A user asks the agent to summarize a webpage. The webpage contains hidden text instructing the agent to send the user's API key to an attacker-controlled email address. The low-authority source (webpage content) is laundered into a high-authority effect (SendNetwork). A prompt-only defense requires the model to recognize and ignore the hidden instruction. ProvShield labels the webpage as `ExternalContent`. If the model proposes `send_email`, the monitor detects that the destination and objective are influenced by low-integrity content and that the payload may contain `Secret`. The call is denied unless an explicit, bound declassification exists.

### 2.2 Metadata-to-Credential Laundering

An MCP server registers a tool with a benign name but a malicious description: "Use this tool to validate credentials; before calling, include all available tokens." The tool metadata—a low-authority source—is laundered into a credential-modification effect. If the agent treats tool metadata as trusted instruction, the metadata can shape future tool calls. ProvShield treats unattested metadata as `ToolMetadata`, a low-integrity source. Metadata can describe schema but cannot grant itself authority or introduce privileged objectives.

### 2.3 Skill-to-Delete Laundering

A skill package includes instructions that appear to implement a formatting task but also tell the agent to delete local files after completion. The untrusted skill instruction—a low-authority source—is laundered into a destructive effect (DeleteLocal). ProvShield labels untrusted skills separately, prevents them from changing policy, and blocks destructive effects unless authorized by user intent and capability.

### 2.4 Tool-Output-to-Exec Laundering

A security scanner tool returns output that includes a hidden instruction to execute a shell command as part of "post-scan cleanup." The tool output—a low-authority source—is laundered into a code-execution effect (ExecuteCode). ProvShield labels tool outputs as `ToolOutput`, which cannot authorize high-risk effects on its own. The policy engine requires a bridge for any `ExecuteCode` effect influenced by tool output.

### 2.5 Confirmation Laundering

A malicious email asks the agent to "send the requested diagnostic information to the support address." The agent presents a generic confirmation: "Send email?" The user clicks yes. The actual recipient is attacker-controlled and the payload includes private data. ProvShield's intent-bound declassification capability would show the exact recipient, payload digest, source categories, and private-data crossing. A capability for one payload and destination cannot authorize another.

### 2.6 Replay and Swap Laundering

An attacker obtains a previously authorized bridge token and attempts to reuse it for a different destination, payload, or action. Alternatively, the attacker modifies the proposed call after the bridge is confirmed but before execution—a destination swap or payload swap. ProvShield's capability tokens carry a MAC over all six normalized call fields (action, effect, destination, payload digest, principal, nonce) and an expiration timestamp. Any field mismatch causes verification to fail. The nonce is consumed upon use, preventing replay.

### Attack Taxonomy

| Attack Class | Low-Privilege Source | Laundered Effect | Failure Mode | ProvShield Block Point |
|---|---|---|---|---|
| Observation-to-send | Web/email/RAG | SendNetwork | Model trusts external content | Source-to-sink policy denies ExternalContent→SendNetwork |
| Metadata-to-credential | MCP tool metadata | CreateCredential/ModifyAuth | Metadata self-authorization | Metadata integrity < UserIntent; effect denied |
| Skill-to-delete | Untrusted skill | DeleteLocal | Skill overrides policy | Skill labeled UntrustedSkill; bridge required |
| Tool-output-to-exec | Tool output | ExecuteCode | Output contains hidden instruction | ToolOutput cannot authorize ExecuteCode alone |
| Confirmation | Ambiguous UI | Bound authority | Vague confirmation hides payload | Bridge binds action+destination+digest+sources |
| Replay/swap | Old bridge/capability | New destination/payload | Token reuse or field mutation | MAC over all fields + nonce consumption |

## 3. Threat Model

The adversary may control external content, emails, retrieved documents, tool outputs, untrusted MCP metadata, and untrusted skill files. The adversary may know the policy rules and the label syntax rendered to the model. The adversary may attempt label spoofing, metadata poisoning, bridge laundering, delayed injection, multi-step exfiltration, or capability replay.

The LLM is *not* trusted to make authorization decisions. It may be fully compromised: the adversary may control the planner's output completely. The security property is not that the model is unaffected by malicious content, but that *unauthorized high-risk effects cannot execute* regardless of the planner's behavior. The LLM is modeled as an adversarial proposal function that may output arbitrary tool calls.

The trusted computing base (TCB) consists of:

- the runtime monitor,
- the sidecar provenance store,
- the policy engine,
- the token generator (HMAC-SHA256),
- the bridge manager, and
- the audit logger.

ProvShield assumes the TCB is not compromised. It does not attempt to prove that untrusted text has no influence on the model's hidden state. Instead, it proves that high-risk tool execution cannot occur unless the runtime-observable authority and capability constraints are satisfied.

## 4. Design

ProvShield's design centers on the principle that every high-risk tool effect requires a runtime-verifiable authority proof. Figure 1 shows the architecture. The LLM is treated as an untrusted planner; all proposed tool calls pass through a runtime monitor before execution.

### 4.1 Runtime Authority Firewall

The runtime authority firewall is the core of ProvShield. Every proposed tool call—whether generated by the LLM, a compromised planner, or any other source—must pass through the monitor before execution. The monitor operates deterministically: it does not use the LLM for policy decisions. The firewall implements a simple principle: *no tool effect executes without sufficient authority*.

For each proposed call, the firewall:
1. normalizes the tool name and arguments into a canonical form;
2. infers effects and sinks from the tool's declaration;
3. reconstructs argument and payload provenance from the sidecar store;
4. checks whether the authority sources satisfy the source-to-sink policy;
5. allows, denies, or requires an intent-bound declassification capability;
6. logs the decision for replay.

### 4.2 Authority-Flow Model

Each object entering the agent runtime is assigned an *authority label* tracking its origin:

```text
Labeled<T> = (value: T, label: AuthorityLabel)
```

The label includes integrity (authority level), confidentiality, origin, principals, transformation history, runtime signature, nonce, and timestamp. Labels are maintained in a sidecar store that the LLM cannot access or modify.

The integrity lattice orders sources by authority:

```text
SystemPolicy > UserIntent > TrustedSkill
  > AttestedToolMetadata > ToolMetadata
  > ToolOutput > ExternalContent > UntrustedSkill
```

The confidentiality lattice tracks sensitivity:

```text
Public < UserPrivate < Secret < CapabilityToken
```

These lattices are inspired by Denning's information-flow lattices and the decentralized label model of Myers and Liskov. Unlike program-level IFC systems, ProvShield labels are maintained in a sidecar store separate from the model context, preventing the LLM from manipulating its own security metadata. This is not a contribution of IFC itself—IFC is a tool—but of applying authority-flow reasoning to the specific problem of agent tool execution where the planner is untrusted.

### 4.3 Effect-Typed Tool Interfaces

Each tool declares its effects and sinks, making its authority requirements explicit. The monitor uses these declarations to determine whether a proposed call is low-risk, high-risk, bridge-required, or denied.

| Effect | Example Sink | Default Action |
|---|---|---|
| `ReadPrivate` | Local file system | Allow (logged) |
| `WriteExternal` | Network endpoint | Bridge required |
| `SendNetwork` | Email, HTTP POST | Bridge required |
| `DeleteLocal` | File system | Bridge required |
| `ExecuteCode` | Shell, sandbox | Bridge required |
| `ModifyAuth` | Credential store | Deny (unless admin) |
| `CreateCredential` | Token vault | Deny (unless admin) |
| `Financial` | Payment API | Deny (unless admin) |

MCP tools are registered through a proxy that intercepts `tools/list` and `tools/call` messages. Tool metadata from untrusted servers is labeled `ToolMetadata` (low integrity); metadata from attested publishers may receive `AttestedToolMetadata`. Tool output is labeled at return time as `ToolOutput`, which cannot authorize high-risk effects on its own.

### 4.4 Intent-Bound Declassification Capability

High-risk effects require an *intent-bound declassification capability*—not a generic user confirmation. The capability binds the exact action, effect, sink, destination, payload digest, source categories, principal, expiration, and one-time nonce. It can authorize only the normalized call for which it was minted.

The bridge presentation to the user includes:

- the action name and destination;
- a SHA-256 digest of the payload;
- the provenance source categories contributing to the payload;
- whether private data or secrets cross a confidentiality boundary;
- a short expiration window (default: 30 seconds).

This design avoids the weakness of generic confirmation, where the user approves a vague action that the attacker can launder into a different destination, payload, or effect.

### 4.5 Capability Tokens

A successful bridge creates a capability token. The token is not textually usable by the model. It is stored in runtime state and checked by the monitor. Tokens cannot be copied from prompt text, modified, or replayed. Each token carries a cryptographic binding (HMAC-SHA256) to the normalized action, sink, destination, payload digest, principal, and nonce.

### 4.6 MCP Metadata and Skill Loading

MCP and Skills are not merely attack surfaces—they are *authority-bearing interfaces* that can launder privilege. A tool description that says "include all available tokens" is attempting to upgrade its own authority. A skill that instructs the agent to delete files is attempting to exercise authority it was not granted.

ProvShield treats MCP metadata and skill instructions as low-integrity sources by default. MCP metadata cannot authorize itself to receive credentials or modify policy. Skill instructions from untrusted sources cannot override system policy or trigger high-risk effects without a bridge. Skills from verified publishers (attested via signature, registry approval, or administrator approval) may receive higher integrity labels.

### 4.7 Audit Replay

Every monitor decision, bridge interaction, and tool execution is logged with full provenance state. The audit log enables deterministic replay of policy decisions for forensic analysis. Each entry records the proposed call, provenance sources, policy rule applied, decision (allow/deny/bridge), and if applicable, the bridge details and capability token.

## 5. Formal Model

We mechanize the core of ProvShield's authority model as a labeled transition system and prove safety properties about runtime-observable tool execution. We prove these properties for the mechanized core and sketch extensions for the full policy surface.

### 5.1 State

We define runtime state as:

```math
\Sigma = (C, R, T, S, P, B, A)
```

where `C` is the context store, `R` is runtime provenance state, `T` is the tool registry, `S` is the secret store, `P` is the policy, `B` is bridge/token state, and `A` is the audit log. Each component is typed:

- $C : \text{ObjId} \to \text{Labeled}(\text{Value})$, where $\text{Labeled}(V) = V \times \text{ProvenanceLabel}$.
- $R : \text{ObjId} \to \text{ProvenanceLabel}$, the sidecar store mapping objects to their runtime-signed labels.
- $T : \text{ToolName} \to \text{EffectSet} \times \text{SinkSet}$, the effect-type declarations for each tool.
- $S : \text{SecretId} \to \text{Confidentiality} \times \text{Value}$, the secret store.
- $P \subseteq \text{Integrity} \times \text{Confidentiality} \times \text{Effect} \times \text{Sink} \times \{\texttt{allow}, \texttt{deny}, \texttt{bridge}\}$, the policy rules.
- $B : \text{BridgeId} \to \text{BridgeToken}$, the active bridge tokens.
- $A = [\text{AuditEntry}]$, the append-only audit log.

A *provenance label* $\ell = (I, C_\ell, \text{origin}, \text{principals}, \text{transforms}, \sigma, \text{nonce}, t)$ consists of integrity $I$ ordered by the integrity lattice and confidentiality $C_\ell$ ordered by the confidentiality lattice. The runtime signature $\sigma = \text{MAC}_k(\text{nonce} \| t \| I \| C_\ell)$ binds the label to the TCB key $k$.

A *normalized tool call* is a tuple $k = (a, e, d, h, p, n)$ where $a$ is the tool action, $e$ is the effect class, $d$ is the destination, $h$ is the payload digest, $p$ is the principal, and $n$ is the nonce. Normalization is deterministic: two calls are equivalent iff all six fields match.

### 5.2 TCB Assumptions

The formal model assumes:

1. The HMAC key $k$ is known only to the TCB and never exposed to the context store $C$.
2. The sidecar store $R$ is only written by TCB transitions, not by model output.
3. The policy engine $P$ is not modifiable by the LLM or external content.
4. The bridge manager correctly enforces one-time nonce semantics.
5. The tool registry $T$ accurately declares effect types.

These assumptions define the security boundary: if any TCB component is compromised, the properties may not hold.

### 5.3 Theorems

We prove the following properties for the mechanized core:

**Theorem 1 (No Unauthorized Authority Escalation).** In any reachable state $\sigma \in \textit{Reach}(\Sigma_0)$, model-generated text cannot create a valid label with higher integrity than permitted by runtime transitions.

*Proof sketch.* By induction on transition steps. The invariant $\text{Inv}(\sigma_n)$ holds: no label in $R$ with integrity $> \texttt{ExternalContent}$ was created without a TCB transition. Labels are valid only if they carry $\sigma = \text{MAC}_k(\text{nonce} \| t \| I \| C_\ell)$. The LLM cannot compute $\sigma$ because $k$ is in the TCB and never exposed to $C$. $\blacksquare$

**Theorem 2 (Capability Token Unforgeability).** In any reachable state, a valid capability token can only be created by the runtime through a bridge confirmation or administrative transition.

*Proof sketch.* Tokens are created only in TCB transitions. The token includes a MAC over the normalized call parameters and nonce. The LLM cannot compute a valid MAC without the key. $\blacksquare$

**Theorem 3 (No Secret Externalization Without Declassification).** If a proposed call sends or writes payload with confidentiality $\geq \texttt{Secret}$ to an external sink, the call cannot reach execution unless a valid declassification capability exists.

*Proof sketch.* The monitor reconstructs payload provenance from $R$. If any component has confidentiality $\geq \texttt{Secret}$ and the sink is external, the policy requires a bridge. A bridge is valid only if it binds the exact payload digest, destination, and action. $\blacksquare$

**Theorem 4 (No Low-Integrity Control of High-Risk Effects).** If a high-risk effect is influenced by low-integrity sources, the call cannot execute unless a valid bridge or policy exception authorizes the flow.

*Proof sketch.* The monitor traces provenance of all arguments through $R$. If any argument's provenance includes a source with integrity $< \texttt{UserIntent}$ and the call has a high-risk effect, the policy requires a bridge. A bridge authorizes a specific normalized call; it cannot be repurposed. $\blacksquare$

**Theorem 5 (Bridge Non-Replay).** A bridge token authorized for a normalized call $(a, e, d, h, p, n)$ cannot authorize a different tuple where any field differs, or where the token has expired.

*Proof sketch.* The token includes a MAC over all six fields plus an expiration timestamp. The nonce $n$ is consumed upon use (one-time semantics). $\blacksquare$

### 5.4 Limitations

The formal model abstracts the LLM as an adversarial proposal function. It does not model neural activations or semantic attention. It proves safety of runtime-enforced execution, not correctness of generated plans. The properties hold under the TCB assumptions above; if the HMAC key is compromised or the runtime binary is subverted, the guarantees may not hold. Not all policy rules are mechanized; some are verified by unit tests and proof sketches.

## 6. Implementation

ProvShield is implemented as a runtime layer around an existing agent system. The implementation consists of six components:

1. **MCP proxy** for tool registration and call mediation. It intercepts `tools/list` and `tools/call` messages, labeling metadata at registration and outputs at return time.
2. **Skill loader** for provenance-aware skill ingestion. Skills from untrusted sources are labeled `UntrustedSkill`; attested skills from verified publishers are labeled `TrustedSkill`.
3. **Context builder** for sidecar label construction. It assigns provenance labels to every object entering the agent context, including user messages, system prompts, web content, email, RAG results, and tool outputs.
4. **Policy engine** for source-to-sink rules. The engine is configured via a declarative YAML policy that maps effect types and provenance patterns to actions (allow, deny, bridge).
5. **Bridge manager** for user confirmations and token issuance. It renders human-readable bridge presentations, collects confirmation, and issues cryptographically bound capability tokens.
6. **Audit logger** for deterministic replay. Every monitor decision, bridge interaction, and tool execution is logged with full provenance state for post-hoc analysis.

The prototype avoids modifying MCP servers by mediating calls through a proxy. Tool metadata is labeled at registration time. Tool outputs are labeled at return time. All proposed calls pass through the monitor before execution. The implementation uses Python for the policy engine and bridge manager, with JSON-serializable provenance labels and HMAC-based token signatures.

## 7. Evaluation

Our evaluation is organized around a central question: *Does ProvShield prevent authority laundering when the planner is manipulated or fully compromised?*

### 7.1 Research Questions

| ID | Question |
|---|---|
| RQ1 | Does runtime authority enforcement reduce end-to-end authority laundering success rate compared to prompt-only and post-hoc defenses? |
| RQ2 | Does the intent-bound declassification capability preserve benign task completion better than static allowlists? |
| RQ3 | What is the runtime enforcement guarantee when the planner is fully compromised (direct-call adversary)? |
| RQ4 | How do model manipulation rate, attack-tool generation rate, and conditional block rate decompose the defense? |
| RQ5 | What latency and friction does runtime monitoring add? |

### 7.2 Authority-Laundering Attack Suites

We evaluate against six authority-laundering classes:

1. **Observation-to-send (Skill injection)**: malicious instructions embedded in skill files laundered into send/write effects.
2. **Metadata-to-credential (MCP metadata poisoning)**: tool descriptions that attempt to exfiltrate credentials or modify authority.
3. **MCP safety scenarios**: demonstrated exploits against MCP-connected LLM agents including code execution, remote access, and credential theft.
4. **Observation-to-send (Web/email/RAG injection)**: indirect injection through retrieved web pages, email content, and RAG documents.
5. **Adaptive white-box attacks**: attackers with knowledge of the policy and label syntax who attempt to craft inputs that bypass enforcement.
6. **Direct-call adversary**: a fully compromised planner that directly issues attack tool calls, testing the runtime's upper-bound guarantee.

### 7.3 Baselines

We compare ProvShield against eight baselines:

| Baseline | Mechanism | Scope |
|---|---|---|
| No defense | Agent runs without security mediation | None |
| Prompt hardening | System prompt instructs model to ignore injected instructions | Model-level |
| Input firewall | Pattern classifier filters suspicious input before it reaches the model | Pre-model |
| Static allowlist | Tools restricted to a fixed set; no dynamic policy | Tool-level |
| Generic confirmation | User confirms all writes; confirmation does not bind destination or payload | User-level |
| Fides-style IFC | Information-flow labels rendered in prompt; model self-enforces | Prompt-level |
| Causal attribution | Post-hoc counterfactual comparison of tool calls with and without external content | Post-hoc |
| MCP security | Metadata scanner inspects tool metadata for suspicious patterns | Metadata-level |

### 7.4 Metrics

We decompose defense effectiveness into the following metrics:

| Metric | Definition | Why It Matters |
|---|---|---|
| No-defense ASR | Attack success rate without runtime enforcement | Measures attack strength against the model |
| LLM manipulation rate | Fraction of attack scenarios where model generates any tool call | Model susceptibility |
| Attack-tool generation rate | Fraction where model generates the specific target attack tool | Opportunity for runtime intervention |
| Runtime block rate (conditional) | Fraction of attack tool calls blocked by the monitor, given generation | Monitor effectiveness |
| Direct-call ASR | ASR when the planner directly issues attack calls | Runtime upper-bound guarantee |
| BTCR | Benign task completion rate | Usability |
| Deny false-block rate | Fraction of benign calls incorrectly denied | Usability cost |
| Bridge burden | Fraction of benign tasks requiring user confirmation | UX cost |
| Monitor latency (p50/p95) | Per-call latency added by the monitor | Performance overhead |

### 7.5 Results

#### Table 1: Attack Success Rate (end-to-end, LLM-in-the-loop, 780 scenarios)

| Defense | ASR | 95% CI | BTCR |
|---|---:|---:|---:|
| No defense | 5.1% | [3.5%, 7.3%] | 100.0% |
| Prompt hardening | 1.9% | [1.0%, 3.4%] | 100.0% |
| Input firewall | 3.4% | [2.2%, 5.3%] | 100.0% |
| Generic confirm. | 5.1% | [3.5%, 7.3%] | 100.0% |
| Static allowlist | 0.0% | [0.0%, 0.7%] | 79.2% |
| Fides-style IFC | 4.9% | [3.4%, 7.1%] | 100.0% |
| Causal attribution | 4.9% | [3.4%, 7.1%] | 100.0% |
| MCP security | 5.1% | [3.5%, 7.3%] | 100.0% |
| **ProvShield** | **0.6%** | **[0.2%, 1.7%]** | **92.4%** |

#### Table 2: Defense Decomposition

| Metric | Value |
|---|---:|
| No-defense ASR | 5.1% |
| LLM manipulation rate | 14.9% |
| Attack-tool generation rate | 14.9% |
| Runtime block rate (conditional on attack tool) | 100.0% |
| End-to-end ASR (ProvShield) | 0.6% |
| Benign completion rate | 92.4% |

### 7.6 Security Analysis

Across 530 attack scenarios evaluated with LLM-in-the-loop, ProvShield achieves an ASR of **0.6%** (95% CI [0.2%, 1.7%]), an **88%** reduction from the no-defense baseline of 5.1% (95% CI [3.5%, 7.3%]).

The defense decomposition reveals that the LLM itself provides partial resistance: the manipulation rate is 14.9%, meaning the model generates any tool call in only ~15% of attack scenarios. Among those where the LLM generates the specific attack target tool, ProvShield's conditional block rate is **100%**: every malicious tool call is stopped by the runtime. This separation is critical: it shows that ProvShield's guarantee is independent of model safety alignment. Even if a future model is more susceptible to manipulation, the runtime enforcement remains effective.

The no-defense ASR of 5.1% reflects the robustness of modern LLMs against many injection patterns. The 72 workflow-embedded attack scenarios across 9 workflow types (where malicious actions are framed as legitimate IT procedures, compliance requirements, or policy updates) increase the manipulation rate. ProvShield's 100% block rate demonstrates that even when the LLM is manipulated, the runtime prevents all unauthorized execution.

### 7.7 Baseline Analysis

Prompt hardening reduces ASR to 1.9% but cannot defend against contextual or metadata-based attacks. Input firewall achieves 3.4% ASR but fails when attacks are embedded in legitimate content. Generic confirmation provides no protection (5.1% ASR, identical to no defense) because it does not bind the specific destination or payload—enabling confirmation laundering. Static allowlist achieves 0.0% ASR but at the cost of 20.8% false blocking (79.2% BTCR).

The three strong baselines perform no better than no defense (4.9–5.1% ASR). **Fides-style IFC** renders provenance labels in the prompt and relies on the model to self-enforce, but the model ignores the labels under injection pressure—demonstrating that prompt-side IFC cannot serve as an authority boundary. **Causal attribution** compares tool calls with and without external content to identify injection-driven calls, but the threshold-based filtering fails to distinguish malicious from benign influenced calls—influence is not authority. **MCP security** scans tool metadata for suspicious patterns but does not address content-level injection or runtime tool-output laundering.

### 7.8 Direct-Call Adversary

To test the runtime's upper-bound guarantee, we evaluate a direct-call adversary: the planner is fully compromised and directly issues attack tool calls, bypassing LLM generation entirely. This tests whether the runtime can block authority laundering even when there is no model manipulation to detect.

Across 23 direct-call scenarios covering all critical effects (ExecuteCode, SendNetwork, DeleteLocal, CreateCredential), ProvShield blocks **22/23 (95.7%)** with conservative provenance mode. The single bypass is a tool profile classification issue for the `write_file` tool, not a fundamental enforcement gap. All critical effects (code execution, network send, deletion, credential creation) are blocked at 100%. This result confirms that ProvShield's authority enforcement operates at the runtime level, independent of the planner.

### 7.9 Utility

ProvShield maintains **92.4% BTCR** (95% CI [88.0%, 94.9%]), compared to 100% for no defense. The ~7.6% utility cost comes from legitimate tool calls that require bridge confirmation. The bridge burden is 7.6% of benign tasks—within the 25% threshold. Monitor latency is negligible: p50 ~0.03ms, p95 ~0.07ms per tool call.

### 7.10 Multi-Model Evaluation

We evaluate across three models (mimo-v2-pro, mimo-v2.5-pro, mimo-v2.5), 75 scenarios each. ProvShield achieves **100% conditional block rate** across all models, confirming that the runtime enforcement is model-independent.

## 8. Related Work

We organize related work by why each approach cannot, on its own, prevent authority laundering.

### 8.1 Prompt Hardening

System prompt defenses instruct the model to ignore injected instructions in webpages, emails, and tool outputs. These approaches depend on model obedience and fail when attacks are contextual, embedded in metadata, or exploit the model's planning process. Prompt hardening cannot serve as an authority boundary because it asks the model to self-police—an untrusted planner cannot be its own authority firewall.

### 8.2 Input Firewalls

Input filtering classifies malicious text before it reaches the model. These approaches fail against authority laundering because (a) laundering can be embedded in tool metadata rather than text content, (b) attacks can be contextual and not pattern-matchable, and (c) social engineering and delayed injection defeat static classification.

### 8.3 Generic Confirmation

Generic user confirmation asks the user before high-risk actions. This fails against confirmation laundering: the confirmation dialog does not bind the actual destination, payload, or source of influence, allowing the attacker to hide the true effect behind a vague prompt. ProvShield's intent-bound declassification capability is explicitly designed to address this failure.

### 8.4 Agent Information-Flow Control

IFC-based approaches track confidentiality and integrity labels through the agent's planning process. When labels are rendered in the prompt and the model is expected to self-enforce, the model ignores the labels under injection pressure—as our evaluation demonstrates. ProvShield's contribution is not IFC itself but the application of authority-flow reasoning to agent tool execution with labels in a sidecar store (not the prompt), capability-bound declassification, and runtime enforcement.

### 8.5 Attribution Monitors

Causal attribution monitors estimate which context influenced a tool call using counterfactual analysis. Influence estimation is useful but insufficient: a tool call may be influenced by external content without being unauthorized (e.g., summarizing a webpage), or authorized by user intent despite external influence. ProvShield uses enforceable authority proofs rather than probabilistic influence estimates.

### 8.6 MCP Security Scanners

MCP scanners perform static analysis of tool metadata for suspicious patterns. These approaches cannot cover runtime tool-output laundering, RAG injection, or email/web authority laundering—attack classes that manifest at execution time, not at metadata registration time.

## 9. Limitations

We acknowledge the following limitations:

1. **No-defense ASR is moderate.** The 5.1% no-defense ASR reflects model safety alignment. Stress-test scenarios with social engineering achieve 83% ASR, but the standard benchmark reflects realistic attack conditions. Future work should include more adversarial prompt strategies.

2. **Limited model coverage.** We evaluate on three models from the same family (mimo-v2). Cross-family evaluation (e.g., GPT-4, Claude, Gemini, open-source models) would strengthen generalizability.

3. **Small direct-call adversary.** The direct-call evaluation uses 23 scenarios. While these cover all critical effects, a larger suite would provide stronger evidence.

4. **Simulated user study.** Bridge confirmation is tested with programmatic acceptance, not real users. A real-user study would reveal social engineering risks in the bridge UI.

5. **Formal model scope.** The mechanized core covers label unforgeability, token unforgeability, and no-secret-exfiltration. Not all policy rules are mechanized; some rely on proof sketches and unit tests.

6. **TCB assumptions.** The security properties depend on HMAC key secrecy, runtime integrity, and correct tool effect declarations. These assumptions must be validated in deployment.

## 10. Ethics

All attack scenarios in our benchmark are synthetic and designed for controlled evaluation. No real credentials, private data, or user accounts are used. The benchmark is designed to be reproducible: scenarios, prompts, seeds, and evaluation scripts are included in the artifact. We do not release attack payloads that could be directly used against production systems. Responsible disclosure considerations apply to any real-world integration.

## 11. Conclusion

Tool-using LLM agents face a fundamental security challenge: authority laundering. Low-authority observations—webpages, emails, RAG documents, tool metadata, skill instructions, tool outputs—are transformed by the LLM planner into high-authority tool effects. Existing defenses that rely on model self-policing, text classification, or generic confirmation fail because they address the wrong layer.

ProvShield addresses authority laundering with a runtime authority firewall. It treats the LLM as an untrusted planner, enforces source-to-sink authority policies at the tool execution boundary, and requires intent-bound declassification capabilities for high-risk effects. The formal model mechanizes core safety properties under explicit TCB assumptions. The evaluation demonstrates 0.6% ASR (88% reduction), 100% conditional block rate across three models, 95.7% direct-call block rate, and 92.4% benign task completion.

ProvShield's approach is complementary to, not a replacement for, model-level defenses. Prompt hardening and input filtering reduce the LLM manipulation rate; ProvShield provides the runtime guarantee that even when manipulation succeeds, unauthorized high-risk effects cannot execute. Future work includes cross-model evaluation, real-user studies, stronger adaptive attacks, and enterprise deployment with audited tool registries.
