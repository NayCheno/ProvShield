# Simulated Reviewer Reviews

## Review 1: IFC / Information-Flow Reviewer

**Overall Assessment:** Weak Accept

**Strengths:**
- Clear problem formulation (authority laundering) that goes beyond standard prompt injection
- Intent-bound declassification capability is a well-designed security abstraction
- Mechanized core provides formal assurance for key properties

**Strongest Objection:**
The information-flow model used (integrity/confidentiality lattices, sidecar labels, taint tracking) is essentially a standard IFC system applied to LLM agents. The paper claims "authority laundering" as a new problem, but the technical solution is classical information-flow control with capability tokens. The novelty is in the application domain, not the mechanism.

**Response in Paper:**
Section 4.2 explicitly acknowledges that the lattices are "inspired by Denning and Myers/Liskov" and that "IFC is a tool, not the contribution." The contribution is the authority-flow model for agent runtimes where the planner is untrusted, the intent-bound declassification capability, and the runtime authority firewall that operates independently of model behavior. Unlike program-level IFC, ProvShield's labels are in a sidecar store the LLM cannot access.

**Secondary Concern:**
The formal model abstracts the LLM as an adversarial proposal function. Real LLMs are neither fully adversarial nor fully compliant. How does the model account for partial manipulation?

**Response:**
The adversarial proposal model provides the strongest possible guarantee: even if the planner is fully compromised, unauthorized effects cannot execute. Our evaluation decomposes model manipulation rate (14.9%) from runtime block rate (100%), showing the guarantee holds at both extremes.

---

## Review 2: LLM Security / Prompt Injection Reviewer

**Overall Assessment:** Weak Accept

**Strengths:**
- 780 LLM-in-the-loop scenarios with three models
- Defense decomposition (manipulation rate vs. block rate) is methodologically sound
- Direct-call adversary evaluation shows runtime upper-bound guarantee

**Strongest Objection:**
The no-defense ASR of 5.1% is surprisingly low. This suggests the model itself is already resistant to most attacks, making ProvShield's contribution less impactful. The paper should acknowledge that modern LLMs have significant built-in resistance.

**Response in Paper:**
Section 7.6 explicitly addresses this: "The no-defense ASR of 5.1% reflects the robustness of modern LLMs against many injection patterns." We include stress-test scenarios (83% ASR with social engineering) and high-manipulation scenarios (17.5% ASR with mimo-v2.5). The defense decomposition (Table 2) separates model resistance from runtime enforcement, showing ProvShield's 100% conditional block rate is independent of model safety alignment.

**Secondary Concern:**
101 direct-call scenarios across 8 effect types is solid evidence. Can the authors expand this to cover additional real-world MCP workflows?

**Response:**
Acknowledged in Limitations. The 101 scenarios cover all eight critical effect types (ExecuteCode, SendNetwork, DeleteLocal, CreateCredential, WriteExternal, CalendarInvite, ModifyAuth, Financial) with 100% block rate across all effects.

---

## Review 3: Systems / Artifact Reviewer

**Overall Assessment:** Accept

**Strengths:**
- Complete artifact with Docker reproducibility (122 tests pass in container)
- 146 unit tests, 12 MCP integration tests
- Audit replay with deterministic traces
- Coq file compiles with coqc 9.0
- Makefile with check, replay, and smoke targets

**Strongest Objection:**
The prototype is Python-based with JSON-serializable labels. Real MCP servers use JSON-RPC over stdio. How does the proxy overhead scale in production? The latency numbers (0.03ms p50) are for policy evaluation only, not including network round-trips.

**Response in Paper:**
Section 7.9 reports monitor-only latency. The proxy overhead includes JSON-RPC interception but not network latency, which is deployment-dependent. We report policy evaluation time as the controllable overhead.

**Secondary Concern:**
The tool effect manifest (artifact/configs/tool_effect_manifest.yaml) requires manual annotation. How does this scale to large tool ecosystems?

**Response:**
Tool effect annotation is a one-time cost per tool declaration. MCP tools already declare schemas; adding effect types is a schema extension. We provide a default manifest and documentation for extending it.
