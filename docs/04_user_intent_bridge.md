# User-Intent Bridge Design

## 1. Problem

Generic confirmation is weak:

```text
Agent: I want to send an email. Confirm?
User: Yes.
```

This can be abused by malicious content that socially engineers the user or hides the true sink/payload/destination.

ProvShield uses a **bound user-intent bridge** instead.

## 2. Bridge object

```json
{
  "bridge_id": "uuid",
  "user_id": "user-123",
  "original_user_goal": "Send the draft report to Alice",
  "proposed_action": "send_email",
  "effect": "SendNetwork",
  "sink": "email.outbound",
  "destination": "alice@example.com",
  "payload_digest": "sha256:...",
  "visible_diff_digest": "sha256:...",
  "sources_used": ["UserIntent", "UserPrivate"],
  "blocked_or_untrusted_sources": ["ExternalContent:webpage"],
  "declassification": ["UserPrivate -> ExternalWriteSink"],
  "expires_at": "2026-06-01T00:00:00Z",
  "nonce": "random-128-bit",
  "one_time": true,
  "runtime_signature": "..."
}
```

## 3. UI requirements

The confirmation UI must display:

- tool name;
- effect class;
- destination;
- complete payload preview or diff;
- whether payload includes private or secret data;
- source categories that influenced action and payload;
- untrusted sources that are blocked or ignored;
- exact scope of the confirmation;
- expiration and one-time status.

## 4. Bridge rules

### B1: No vague bridge

A confirmation such as “allow email sending” is invalid. The bridge must bind action, destination, and payload digest.

### B2: No destination swap

A bridge for `alice@example.com` cannot authorize `mallory@example.com`.

### B3: No payload swap

If payload digest changes, the bridge is invalid.

### B4: No effect broadening

A bridge for `send_email` cannot authorize `delete_file` or `execute_code`.

### B5: No replay

Bridge nonce is one-time. Reuse is denied.

### B6: No expired bridge

Expired bridge tokens are denied.

### B7: Explicit declassification

If private or secret content crosses into an external sink, the bridge must state the declassification.

## 5. Bridge decision flow

```text
Proposed tool call
  ↓
Monitor detects high-risk effect
  ↓
Monitor computes source and payload provenance
  ↓
If policy denies absolutely -> deny
  ↓
If policy allows with bridge -> show bound confirmation
  ↓
User confirms exact action
  ↓
Runtime mints one-time capability token
  ↓
Tool executes if token still matches normalized call
```

## 6. When to deny instead of bridge

Do not offer confirmation when:

- payload contains raw credential material;
- action modifies auth policy;
- destination is generated solely by ExternalContent;
- tool metadata requests privilege escalation;
- model cannot produce a stable payload preview;
- policy explicitly denies this sink;
- user has not expressed a related objective.

## 7. Bridge metrics

Measure:

- bridge request rate per benign task;
- bridge abuse success rate;
- incorrect confirmation rate in user study or simulated study;
- false-positive bridge requests;
- tasks blocked due to no valid bridge;
- average confirmation detail length.
