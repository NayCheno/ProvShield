# Positioning Memo: Authority Laundering

## Core Thesis

**Old positioning:** ProvShield uses provenance-typed runtime enforcement to block prompt injection in MCP and skill-based agents.

**New positioning:** Prompt injection in tool-using agents is an *authority laundering* attack: low-authority observations are converted by the model into high-authority tool actions. ProvShield prevents this by requiring every high-risk effect to carry an unforgeable, intent-bound authority proof before execution.

## Why This Reframe

The old framing risks CCF-A reviewers reading the paper as "IFC + taint tracking + capability token + runtime monitor applied to LLM agents." This suppresses novelty because provenance, IFC, capability, and declassification are all existing concepts.

The new framing makes the paper's contribution a *problem definition* (authority laundering) rather than a *tool application* (IFC to agents). This is structurally stronger for CCF-A because:

1. Problem papers with clear taxonomies and benchmarks are valued.
2. The authority laundering concept is agent-specific and not reducible to classical IFC.
3. Intent-bound declassification is a novel security abstraction for agent runtimes.

## Authority Laundering Definition

> Authority laundering is the process by which a low-authority observation—such as a webpage, email, RAG document, MCP tool description, skill file, or tool output—is transformed by an LLM planner into a high-authority tool action, such as sending private data, deleting files, executing code, or modifying credentials.

The attacker does not need to compromise the model as software. It is enough to launder a low-authority observation into a high-authority tool action.

## Six Laundering Attack Classes

| Class | Low-Authority Source | Laundered Effect | Example |
|---|---|---|---|
| Observation-to-send | Web/email/RAG | SendNetwork | Webpage triggers secret email |
| Metadata-to-credential | MCP tool metadata | CreateCredential/ModifyAuth | Tool description requests token attachment |
| Skill-to-delete | Untrusted skill | DeleteLocal | Formatter skill deletes files |
| Tool-output-to-exec | Tool output | ExecuteCode | Scanner output triggers shell command |
| Confirmation laundering | Ambiguous UI prompt | Bound authority | Vague confirmation hides payload/destination |
| Replay/swap | Old bridge/capability | New destination/payload | Destination swap / payload swap |

## New Title

**Primary:** Preventing Authority Laundering in Tool-Using LLM Agents

**Backup:** ProvShield: Intent-Bound Runtime Authority Control for MCP and Skill-Based Agents

## New Contribution List

1. **Problem formulation: Agent Authority Laundering.** We define authority laundering as a security failure specific to tool-using LLM agents, where low-authority observations are transformed into high-authority tool effects through model planning.

2. **Authority-flow model for MCP/Skills agents.** We formalize source authorities, effects, sinks, authority levels, user intent, and declassification capabilities as a runtime transition system over the observation-to-execution pipeline.

3. **Intent-bound declassification capability.** We design a security abstraction where user confirmation binds action, effect, sink, destination, payload digest, source category, principal, and expiry into a non-replayable, one-time runtime capability.

4. **Runtime authority firewall.** We treat the LLM as an untrusted planner and enforce authority proofs at the tool execution boundary, preventing unauthorized high-risk effects even when the planner is fully compromised.

5. **Authority-laundering benchmark.** We construct a benchmark covering six laundering classes—MCP metadata poisoning, skill instruction laundering, tool-output laundering, RAG/email/web authority laundering, and direct-call compromised planner scenarios—with 780 LLM-in-the-loop scenarios.

6. **Empirical separation of model manipulation from runtime enforcement.** We decompose attack success into LLM manipulation rate, attack-tool generation rate, conditional runtime block rate, and direct-call adversary ASR, showing that ProvShield's 100% conditional block rate operates independently of model safety alignment.

## Key Terminology Changes

| Old Term | New Term |
|---|---|
| Prompt injection defense | Authority laundering prevention |
| Provenance labels (core contribution) | Intent-bound authority proof (core contribution) |
| User confirmation bridge | Intent-bound declassification capability |
| LLM is untrusted planner | Planner compromise assumed; runtime enforces authority boundary |
| MCP metadata / skill files (attack sources) | MCP/Skills are authority-bearing interfaces that can launder privilege |
| Coq verified | Mechanized core + proof sketches under explicit TCB assumptions |
