# Prototype Starter

This folder contains schemas, policy templates, pseudocode, and examples for implementing ProvShield.

## Suggested implementation order

1. Implement `NormalizedToolCall` and effect declarations.
2. Implement sidecar provenance store.
3. Implement policy evaluation for deny/allow/bridge.
4. Implement bridge token binding.
5. Add MCP proxy interception.
6. Add skill loader labeling.
7. Add audit replay.

## Key invariant

The LLM never directly executes tools. It only proposes calls. All calls pass through the monitor.
