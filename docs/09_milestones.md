# Milestones

## M0: Positioning and threat model

**Duration:** 2-3 weeks

Deliverables:

- threat model;
- related work table;
- label taxonomy;
- effect taxonomy;
- initial CCF-A scoring;
- paper abstract v0.

Exit criteria:

- reviewers can understand what the paper does not claim;
- difference from Fides / MCPSHIELD is explicit;
- high-risk sinks are enumerated.

## M1: Formal core

**Duration:** 4-6 weeks

Deliverables:

- small-step semantics;
- label lattice;
- transition rules;
- 3-5 theorem statements;
- proof sketches or mechanized core.

Exit criteria:

- no-secret-exfiltration theorem is internally consistent;
- bridge non-replay property is stated precisely;
- model is treated as adversarial proposal oracle.

## M2: Runtime prototype

**Duration:** 6-8 weeks

Deliverables:

- MCP proxy;
- sidecar provenance store;
- policy engine;
- bridge manager;
- audit logger;
- normalized tool call representation.

Exit criteria:

- tool calls cannot bypass monitor;
- policy engine can allow/deny/bridge;
- audit replay works for sampled decisions.

## M3: Attack reproduction

**Duration:** 4-6 weeks

Deliverables:

- Skill injection cases;
- MCP metadata poisoning cases;
- web/email/RAG injection cases;
- adaptive attacks;
- attack harness.

Exit criteria:

- no-defense baseline has measurable attack success;
- ProvShield blocks representative examples;
- attack definitions are reproducible.

## M4: Full evaluation

**Duration:** 4-6 weeks

Deliverables:

- main security table;
- benign utility table;
- performance table;
- ablation study;
- case studies;
- failure analysis.

Exit criteria:

- ASR reduction ≥ 80%;
- BTCR ≥ 90% of no-defense;
- p95 monitor latency ≤ 300 ms;
- adaptive attack results included.

## M5: Paper and artifact

**Duration:** 4 weeks

Deliverables:

- paper draft;
- artifact appendix;
- Docker/Nix/devcontainer;
- open-source repo cleanup;
- rebuttal prep notes.

Exit criteria:

- all claims backed by results or theorem;
- limitations section is honest;
- artifact can be run by a new user.
