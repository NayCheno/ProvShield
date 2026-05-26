# Formal Model Plan

## 1. Scope

The formal model proves properties about runtime-observable information flow and tool execution. It does not prove that the model's hidden state is unaffected by untrusted text.

## 2. State

```text
Σ = (C, R, T, S, P, B, A)
```

Where:

| Symbol | Meaning |
|---|---|
| `C` | context store containing labeled messages and objects |
| `R` | runtime state and sidecar provenance graph |
| `T` | tool registry and effect declarations |
| `S` | secret store |
| `P` | policy set |
| `B` | active user-intent bridges and capability tokens |
| `A` | audit log |

## 3. Events

```text
UserInput(u)
LoadSkill(s)
RegisterTool(t)
ReceiveExternalContent(x)
ToolOutput(o)
ModelStep(c)
ProposeToolCall(k)
MonitorAllow(k)
MonitorDeny(k)
RequireBridge(k)
BridgeConfirm(b)
BridgeReject(b)
ExecuteTool(k)
PropagateLabel(o)
Audit(e)
```

## 4. Transition relation

```text
Σ --e--> Σ'
```

Important transitions:

### T-UserInput

User-provided goal enters context with `UserIntent` integrity.

### T-ExternalContent

External content enters context with `ExternalContent` integrity.

### T-ToolRegister

Unattested tool metadata enters as `ToolMetadata`; attested metadata enters as `AttestedToolMetadata`.

### T-ModelStep

The model may read rendered context and produce proposed actions. Its output is not trusted to carry labels.

### T-ProposeToolCall

The proposed call is normalized. Argument labels are reconstructed by the runtime from the argument construction graph and context slice.

### T-MonitorAllow

A call may execute only if policy permits its source-to-sink flows and required capabilities exist.

### T-MonitorDeny

If policy denies, no tool execution occurs and audit log records the reason.

### T-BridgeConfirm

A user confirmation mints a bridge-bound capability token.

### T-ExecuteTool

Tool execution is possible only after MonitorAllow.

## 5. Theorems

### Theorem 1: Label unforgeability

For any reachable state, no model-generated text can create a valid provenance label with higher integrity than permitted by runtime transitions.

### Theorem 2: Capability token unforgeability

For any reachable state, a valid capability token can only appear if minted by a runtime transition `BridgeConfirm` or an approved administrative policy transition.

### Theorem 3: No secret exfiltration

If a proposed tool call has sink `ExternalWriteSink` or `NetworkSendSink` and payload label confidentiality is at least `Secret`, then the call cannot reach `ExecuteTool` unless a valid declassification bridge exists.

### Theorem 4: No low-integrity control of high-risk effects

If a high-risk tool call is influenced by `ExternalContent`, `ToolOutput`, `ToolMetadata`, or `UntrustedSkill`, then the call cannot reach `ExecuteTool` unless permitted by a valid user-intent bridge or policy exception.

### Theorem 5: Bridge non-replay

A bridge token authorized for call `k` cannot authorize a normalized call `k'` if action, sink, destination, payload digest, expiry, principal, or nonce differ.

### Theorem 6: Policy preservation

Every transition preserves label well-formedness, token validity, and audit completeness.

## 6. Proof strategy

Use induction on transition steps.

For each theorem:

1. Prove initial state satisfies invariant.
2. For each transition, show invariant preserved.
3. For monitor transitions, prove policy check is complete for high-risk sinks.
4. For bridge transitions, prove binding constraints.
5. For model transitions, rely on unforgeability because model output cannot write sidecar metadata.

## 7. Mechanization plan

Minimum mechanization target:

- label lattice definitions;
- join operation;
- tool effect classes;
- normalized call equality;
- token validity predicate;
- transition relation;
- 3 core theorems:
  - label preservation;
  - token unforgeability;
  - no secret exfiltration.

Optional:

- bridge non-replay theorem;
- audit completeness theorem;
- deterministic policy decision theorem.

## 8. Limitations section for paper

State explicitly:

- The formal model abstracts LLM behavior as an adversarial proposal function.
- It does not model neural activations or semantic attention.
- It proves safety of runtime-enforced execution, not correctness of generated plans.
- It assumes runtime monitor and cryptographic primitives are not compromised.
