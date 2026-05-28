# Baseline Fidelity Documentation

This document describes the implementation fidelity of each baseline defense
evaluated in the ProvShield paper. For each baseline, we state: (1) what the
original system does, (2) how we implement it, (3) what assumptions we make,
and (4) what limitations our implementation has compared to the original.

## Baselines Evaluated

### 1. No Defense

**Original:** Agent executes all tool calls without any security mediation.

**Implementation:** Direct tool execution through the runtime monitor with no
policy checks. The monitor normalizes the call and immediately executes via
the executor callback.

**Fidelity:** Exact — no approximation needed.

### 2. Prompt Hardening

**Original approach:** System prompt instructs the model to ignore injected
instructions in external content (OpenAI, 2025).

**Implementation:** `PromptHardeningBaseline` in `baselines.py`. Adds a
hardened system prompt and checks context messages against known injection
patterns (regex matching). If patterns are found in context text, the call
is denied.

**Assumptions:**
- The model follows the hardened prompt perfectly
- Injection patterns can be captured by regex

**Limitations:**
- Real prompt hardening modifies the system prompt; we simulate its effect
  by pattern matching since we use the same LLM call for all baselines
- Cannot capture contextual or semantically subtle injections

**Fidelity:** Moderate — captures the concept but not the exact mechanism.

### 3. Input Firewall

**Original approach:** Classifier-based input filter that detects malicious
text before it reaches the model.

**Implementation:** `InputFirewallBaseline` in `baselines.py`. Uses keyword
and pattern matching to detect malicious content in context messages. If
detected, the tool call is denied.

**Assumptions:**
- Malicious content can be detected by keyword/pattern matching
- The firewall sees all context before the model

**Limitations:**
- Real firewalls use ML classifiers; we use regex patterns
- May miss novel attack patterns
- Does not adapt to new attack strategies

**Fidelity:** Low-moderate — rule-based approximation of ML-based filtering.

### 4. Static Allowlist

**Original approach:** Only allow a fixed set of read-only tools; block all
write/send/execute operations.

**Implementation:** `StaticAllowlistBaseline` in `baselines.py`. Maintains
a hardcoded set of allowed tools (read_webpage, read_email, query_database).
All other tools are denied.

**Assumptions:**
- Read-only tools are safe
- Write/send/execute tools are dangerous

**Limitations:**
- Very coarse-grained — blocks legitimate write operations
- Does not consider context or provenance

**Fidelity:** High — this is a simple policy that can be implemented exactly.

### 5. Generic Confirmation

**Original approach:** Ask the user to confirm all write/send operations,
but the confirmation does not bind specific destination or payload.

**Implementation:** `GenericConfirmationBaseline` in `baselines.py`. For
high-risk tools (send_email, write_file, delete_file, execute_shell), the
call is marked as "confirm" (simulated user always confirms). The key
difference from ProvShield's bridge is that the confirmation is not
cryptographically bound to the specific call parameters.

**Assumptions:**
- User always confirms (worst case for the baseline)
- Confirmation is generic, not bound to action/destination/payload

**Limitations:**
- Real confirmation UIs vary; we assume the worst case (user always says yes)
- Does not model user rejection

**Fidelity:** High — captures the essential weakness of generic confirmation.

### 6. Fides-style IFC

**Original approach:** Microsoft Research's Fides framework applies
information-flow control to LLM agents, tracking labels within the model
context. Labels are rendered in the prompt and the model is expected to
self-enforce flow restrictions.

**Implementation:** `FidesIFCBaseline` in `baselines.py`. Adds provenance
labels as text markers in the context (e.g., `[ExternalContent]`,
`[SystemPolicy]`). The model sees these labels and is expected to refuse
calls that would violate IFC rules. We check if the model generates a tool
call despite seeing low-integrity labels in context.

**Assumptions:**
- Labels rendered in the prompt are advisory — the model decides whether
  to honor them
- The model can see and process label text

**Limitations:**
- Fides may have additional runtime enforcement not captured here
- We model only the prompt-side label rendering, not any backend enforcement
- The model's self-enforcement is the weak point (demonstrated by our results:
  4.9% ASR, no better than no defense)

**Fidelity:** Moderate — captures the prompt-side label rendering approach.
If Fides includes runtime enforcement, our implementation underestimates
its effectiveness. However, our results show that prompt-side labels alone
are insufficient, which is the key finding.

### 7. Causal Attribution (AttriGuard)

**Original approach:** AttriGuard proposes causal attribution of tool
invocations to distinguish user-intent-driven calls from injection-driven
calls through counterfactual testing (He et al., 2026).

**Implementation:** `CausalAttributionBaseline` in `baselines.py`. Compares
tool calls made with and without external content in context. If the call
changes when external content is removed, it is flagged as potentially
injection-driven and denied.

**Assumptions:**
- Injection-driven calls will differ from user-intent-driven calls when
  external content is removed
- A single counterfactual comparison is sufficient

**Limitations:**
- Real AttriGuard uses multiple counterfactual tests and statistical analysis
- Our implementation is a simplified single-comparison version
- May miss subtle injections that don't change the tool call

**Fidelity:** Low-moderate — captures the counterfactual testing concept
but not the full statistical analysis.

### 8. MCP Security Scanner

**Original approach:** MCPSafetyScanner inspects MCP tool metadata for
suspicious patterns that might indicate poisoning or exfiltration attempts
(Radosevich & Halloran, 2025).

**Implementation:** `MCPSecurityBaseline` in `baselines.py`. Scans tool
descriptions for suspicious patterns (e.g., "include all tokens", "send
credentials", "forward API keys"). If suspicious patterns are found in
tool metadata, calls to that tool are denied.

**Assumptions:**
- Suspicious patterns in tool metadata can be detected by keyword matching
- Tool metadata is the primary attack vector

**Limitations:**
- Real MCPSafetyScanner uses more sophisticated analysis
- Does not address content-level injection (only metadata)
- May miss novel metadata poisoning patterns

**Fidelity:** Moderate — captures the metadata scanning concept but uses
simpler detection than the original.

## Summary

| Baseline | Fidelity | Key Limitation |
|---|---|---|
| No defense | Exact | N/A |
| Prompt hardening | Moderate | Simulates effect via pattern matching |
| Input firewall | Low-moderate | Rule-based vs ML-based |
| Static allowlist | High | Exact implementation |
| Generic confirmation | High | Assumes worst-case (always confirms) |
| Fides-style IFC | Moderate | Prompt-side only; may underestimate |
| Causal attribution | Low-moderate | Single comparison vs full analysis |
| MCP security | Moderate | Keyword matching vs sophisticated analysis |

## Implications for Paper Claims

The paper states that baselines are "evaluated against the same scenarios
using the same harness." This is accurate — all baselines use the same
LLM API, same scenarios, and same success definitions.

The paper does **not** claim that our baselines are exact reproductions of
the original systems. The comparison table (Table 7) compares **design
features**, not implementation fidelity. The key finding — that prompt-side
and post-hoc defenses are insufficient against the attack patterns in our
benchmark — holds regardless of baseline fidelity, because:

1. The baselines represent the **approach** (prompt-side, filtering, confirmation),
   not specific implementations
2. Even perfect implementations of these approaches have fundamental limitations:
   - Prompt-side labels can be ignored by the model
   - Input filtering cannot catch all contextual attacks
   - Generic confirmation does not bind specific parameters
3. ProvShield's runtime enforcement is fundamentally different: it operates
   **outside** the model's decision-making, making it resistant to the same
   attacks that bypass prompt-side defenses
