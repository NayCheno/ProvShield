# Runtime Architecture

## 1. Overview

```text
                  ┌─────────────────────────┐
                  │        User UI          │
                  └───────────┬─────────────┘
                              │
                              ▼
┌──────────────┐    ┌───────────────────────┐    ┌──────────────┐
│ Skill Loader │───▶│  Labeled Context      │◀───│ Browser/RAG  │
└──────────────┘    │  + Sidecar Store       │    │ Email/Files  │
                    └───────────┬───────────┘    └──────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │      LLM Planner      │
                    └───────────┬───────────┘
                                │ proposed tool call
                                ▼
                    ┌───────────────────────┐
                    │  ProvShield Monitor   │
                    └───────┬───────┬───────┘
                            │       │
                      allow │       │ deny / bridge
                            ▼       ▼
                    ┌────────────┐  ┌────────────────┐
                    │ MCP Proxy  │  │ User Bridge UI │
                    └─────┬──────┘  └────────────────┘
                          ▼
                    ┌────────────┐
                    │ MCP Tools  │
                    └────────────┘
```

## 2. Modules

### 2.1 Context Builder

Responsibilities:

- ingest content;
- assign labels;
- store sidecar metadata;
- render prompt with human-readable boundaries;
- maintain context slice IDs;
- record transformations.

### 2.2 Skill Loader

Responsibilities:

- classify skill as trusted or untrusted;
- verify signatures if available;
- label skill instructions;
- sandbox skill execution if needed;
- prevent skill from modifying policy.

### 2.3 MCP Proxy

Responsibilities:

- intercept tool registration;
- classify tool metadata provenance;
- require attestation for trusted metadata;
- mediate tool calls;
- label tool outputs;
- apply network and filesystem guardrails.

### 2.4 Tool Invocation Monitor

Responsibilities:

- normalize call;
- infer effect;
- compute source provenance;
- check policy;
- request bridge or deny;
- issue capability token;
- write audit log.

### 2.5 Policy Engine

Responsibilities:

- evaluate source-to-sink rules;
- enforce confidentiality rules;
- enforce integrity rules;
- decide allow / deny / bridge;
- provide explanations for audit.

### 2.6 Bridge Manager

Responsibilities:

- construct confirmation UI payload;
- compute payload digest;
- verify user action;
- mint one-time capability token;
- reject replay or mismatch.

### 2.7 Audit Logger

Responsibilities:

- log context provenance;
- log proposed tool calls;
- log policy decisions;
- log bridge confirmation details;
- support deterministic replay.

## 3. Implementation plan

### Phase 1: Proxy-first prototype

Implement as a proxy around an existing agent runtime. This avoids modifying every MCP server.

### Phase 2: Skill loader integration

Intercept skill loading and label instructions/files.

### Phase 3: Browser/email/RAG adapters

Label external content and private data consistently.

### Phase 4: Full audit replay

Enable replay of allow/deny decisions from trace files.

## 4. API sketch

```python
monitor.check(
    normalized_call=call,
    provenance_graph=graph,
    tool_effects=effects,
    policy=policy,
    active_bridges=bridges,
) -> Decision
```

Decision types:

```text
Allow
Deny(reason)
RequireBridge(bridge_request)
Sanitize(transform)
Quarantine(reason)
```

## 5. Deployment model

Recommended deployment:

```text
Agent runtime -> local ProvShield proxy -> external MCP/tool servers
```

For high-risk enterprise deployment:

```text
Agent runtime -> enterprise ProvShield gateway -> approved tool registry -> audited tools
```
