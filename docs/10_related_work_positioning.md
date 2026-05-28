# Related Work Positioning

## 1. Positioning thesis

ProvShield addresses *authority laundering*: the process by which a low-authority observation is transformed by an LLM planner into a high-authority tool effect. It is not another prompt-injection detector. It is a runtime authority firewall that treats LLM output as an untrusted proposal and checks whether the proposed tool call has sufficient authority to execute.

## 2. Comparison table

| Work category | Typical mechanism | Limitation | ProvShield difference |
|---|---|---|---|
| Prompt hardening | System prompt tells model to ignore malicious content | Depends on model obedience | Enforces at runtime before tools execute |
| Input firewall | Classifies malicious text | Contextual/social attacks bypass filters | Does not require detecting maliciousness |
| Generic confirmation | Ask user before high-risk tool | Vague confirmation can be laundered | Confirmation bound to action/destination/payload/source |
| Static allowlist | Restrict allowed tools | Poor utility; coarse granularity | Per-call source-to-sink policy |
| Agent IFC | Track confidentiality/integrity | May not address MCP metadata and skill-specific bridges | Focus on MCP + Skills + ToolMetadata + bridge binding |
| MCP scanner | Pre-deployment scan | Cannot stop runtime tool-output attacks | Runtime per-call enforcement |
| Causal attribution | Estimate which context caused action | Can be expensive or uncertain | Uses enforceable provenance and capability binding |

## 3. Differentiation from Fides-style IFC

ProvShield should claim differentiation only where defensible:

1. Explicit treatment of MCP tool metadata as a low-integrity input unless attested.
2. Explicit skill loader integration.
3. Action/destination/payload/source-bound user-intent bridge.
4. Capability token binding for high-risk effects.
5. Evaluation on MCP metadata poisoning and skill-injection attacks.
6. Audit replay for per-call policy decisions.

Avoid claiming that basic confidentiality/integrity IFC is new.

## 4. Differentiation from MCPSHIELD-like frameworks

If MCPSHIELD or similar work already includes LTS, capability, attestation, IFC, and runtime policy enforcement, ProvShield must sharpen its contribution:

- tighter formalization of bridge-bound declassification;
- actual prototype integrated with common open-source runtime;
- systematic skill + MCP + web/email/RAG combined attack evaluation;
- evidence that generic MCP security mechanisms are insufficient for tool-output and metadata poisoning;
- public artifact and replayable traces.

## 5. Differentiation from AttriGuard / AgentWatcher-like monitors

Causal attribution monitors attempt to identify whether an action is grounded in user intent or untrusted observations.

ProvShield should position itself as:

- complementary, not necessarily competing;
- less dependent on model self-explanation;
- focused on enforceable sink policies;
- capable of using causal attribution as an optional provenance signal, not as the root of trust.

## 6. Related-work writing rule

Use the following sentence pattern:

> Prior work has shown that agent security benefits from information-flow control and action attribution. ProvShield builds on this insight but targets the under-specified boundary between MCP metadata, skill instructions, tool outputs, and external content, and introduces a bound user-intent bridge that converts low-integrity influence into explicitly scoped runtime capabilities.

## 7. Citation hygiene

Before submission:

- verify all arXiv IDs and publication dates;
- distinguish peer-reviewed papers from preprints;
- check for newer versions after the initial package date;
- add official MCP specification citations;
- add OpenAI agent prompt injection defense article only as motivation, not as technical prior art.
