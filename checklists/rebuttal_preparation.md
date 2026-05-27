# Rebuttal Preparation

Anticipated reviewer questions and prepared responses for the ProvShield paper.

## Q1: No-defense ASR is only 5.1% — is the benchmark strong enough?

**Reviewer concern:** The no-defense ASR of 5.1% means the LLM itself resists most attacks. Is ProvShield solving a problem that doesn't exist?

**Response:**
- The 5.1% no-defense ASR reflects modern LLM robustness against naive injection, which is itself a positive finding.
- The 88 workflow-embedded strong attack scenarios (45 strong + 22 targeted + 21 high-rate) specifically target this concern by embedding attacks in legitimate workflows, increasing manipulation rate.
- ProvShield's value is defense-in-depth: even a 5.1% ASR is unacceptable for high-risk operations (credential theft, data exfiltration). ProvShield reduces this to 0.6%.
- The 14.9% LLM manipulation rate means the model IS manipulated in ~79/530 attack scenarios. Among those where the specific attack tool is generated, ProvShield blocks 100%.
- We report per-suite breakdowns showing that MCP metadata (7.0% no-defense ASR) and skill injection (7.1%) have meaningful attack surfaces.

**Evidence:** Table 1 (overall ASR), Table 3 (per-suite ASR), Section 7.4 security analysis.

## Q2: How is ProvShield better than prompt hardening?

**Reviewer concern:** Prompt hardening achieves 1.9% ASR with 100% BTCR. ProvShield achieves 0.6% ASR but only 92.4% BTCR. Is the trade-off worth it?

**Response:**
- Prompt hardening fails against contextual, metadata-based, and skill injection attacks that do not contain recognizable malicious strings.
- The 1.9% ASR for prompt hardening assumes the system prompt can enumerate all attack patterns; this is fundamentally brittle.
- ProvShield provides a principled guarantee: even if the model is fully manipulated, the runtime prevents unauthorized execution. This is a categorically different security property.
- The 92.4% BTCR with 7.6% bridge burden means most false blocks can be resolved through user bridge interaction in a real deployment.
- ProvShield's ablation study (Table 4) demonstrates that removing provenance labels raises ASR to 81%, confirming the value of runtime enforcement beyond prompt-level defenses.

**Evidence:** Table 1, Table 4 (ablation), Section 7.4 comparison.

## Q3: The baselines are rule-based implementations, not real systems

**Reviewer concern:** The baselines (prompt hardening, input firewall, generic confirmation, static allowlist) are implemented as simple functions, not faithful reproductions of real systems.

**Response:**
- We implement baselines that capture the core mechanism of each defense category: prompt-level instruction, input classification, blanket confirmation, and tool restriction.
- These are fair comparisons because we evaluate each defense at its intended level of abstraction. A "real" input firewall would still be a classifier; our pattern-based filter represents the lower bound of classifier performance.
- Static allowlist represents a realistic conservative defense (0.0% ASR, 79.2% BTCR) and demonstrates that ProvShield achieves better security-utility trade-off.
- We acknowledge this limitation explicitly and discuss Fides-style IFC and causal attribution as stronger baselines that would strengthen the comparison.

**Evidence:** Section 7.2, Section 10 (Limitations), Table 1.

## Q4: Single-model evaluation (mimo-v2-pro only)

**Reviewer concern:** All results are from one model. How generalizable are the findings?

**Response:**
- We acknowledge this as a key limitation (Section 10).
- The core contribution (runtime enforcement) is model-agnostic: it operates on tool calls, not model internals. The monitor's behavior is deterministic and does not depend on the LLM.
- The LLM manipulation rate (14.9%) varies by model; a weaker model would have higher manipulation, making ProvShield's runtime enforcement more critical.
- We are actively evaluating with additional models and plan to include multi-model results in the camera-ready version.

**Evidence:** Section 10 (Limitations), Section 7.4.

## Q5: The formal proofs are proof sketches, not fully mechanized

**Reviewer concern:** The Coq formalization compiles, but Theorems 1-2 are definition-level. The paper claims formal guarantees but relies on TCB assumptions.

**Response:**
- We are explicit about proof status: Theorems 1-5 are presented as proof sketches with the Coq mechanization covering the transition relation and reachable-state invariants.
- The unforgeability theorems rely on the TCB assumption (LLM has no access to HMAC key), which is stated as an axiom, not proven in Coq.
- The proof hierarchy (mechanized core → proof sketch → TCB assumption) is documented in docs/theorem_code_mapping.md.
- This is standard practice for systems security papers: the formal model provides rigor for the core invariants, while implementation-level assumptions (HMAC security, TCB integrity) are stated explicitly.

**Evidence:** Section 5, Section 10 (Limitations), docs/theorem_code_mapping.md.

## Q6: Conservative provenance may inflate false blocking

**Reviewer concern:** The evaluation uses conservative taint (all context → all arguments), which may not reflect real-world provenance precision.

**Response:**
- We acknowledge this (Section 10): 7.6% false blocking partly reflects conservative taint propagation.
- The ablation study (Table 4, A1) demonstrates that removing provenance labels entirely raises ASR to 81%, showing that even conservative provenance provides significant security benefit.
- Field-level provenance tracking is a natural extension that would reduce false blocking while maintaining security guarantees.
- The 7.6% false blocking is within the 15% acceptance threshold and represents worst-case behavior; real deployments with user bridge interaction would have lower effective blocking.

**Evidence:** Section 10, Table 4 (ablation), Section 7.4 utility analysis.

## Q7: Bridge/capability mechanism relies on user attention

**Reviewer concern:** Users may blindly confirm bridge prompts, defeating the purpose.

**Response:**
- Bridge binding is designed to resist this: the presentation includes payload digest, destination, provenance source categories, and confidentiality boundary crossings. This is not a generic "are you sure?" prompt.
- A bridge authorized for one (action, destination, payload) cannot authorize a different tuple. This prevents confirmation laundering.
- We acknowledge social engineering as a residual risk (Section 10).
- The 7.6% bridge burden means the average user sees ~1 bridge prompt per 13 benign tasks, reducing habituation risk.

**Evidence:** Section 4.4 (Bridge), Section 10 (Limitations), Theorem 5.

## Q8: How does this compare to Fides (Microsoft Research)?

**Reviewer concern:** Fides also applies IFC to LLM agents. What is the novelty?

**Response:**
- Fides tracks information-flow labels within the model context (prompt-visible). ProvShield maintains provenance in a sidecar store outside the model context, preventing the LLM from manipulating its own security metadata.
- ProvShield adds bound user-intent bridges with cryptographic capability tokens, which Fides does not have.
- ProvShield explicitly handles MCP tool metadata and skill files as distinct provenance categories with specific policy rules.
- The comparison table (Table 5) provides a detailed feature-by-feature comparison.

**Evidence:** Section 9 (Related Work), Table 5 (comparison), Section 4.1.

## Q9: MCP proxy is not integrated with a real agent runtime

**Reviewer concern:** The prototype uses a local JSON-RPC proxy, not a real MCP client/server integration.

**Response:**
- The MCP proxy intercepts tools/list and tools/call messages, which are the standard MCP protocol messages. The proxy architecture is designed to be transparent to both client and server.
- The evaluation harness exercises the full monitor path: normalization, provenance reconstruction, policy evaluation, bridge management, and audit logging.
- We acknowledge that integration with a production MCP client/server would strengthen the systems contribution (Section 10).

**Evidence:** Section 6 (Implementation), Section 10 (Limitations).

## Q10: 780 scenarios is relatively small for a benchmark

**Reviewer concern:** The benchmark has only 780 scenarios. Is this sufficient for statistical significance?

**Response:**
- We report 95% Wilson confidence intervals for all metrics, demonstrating statistical rigor.
- The 530 attack scenarios span 6 attack categories with 88 workflow-embedded strong attacks.
- Each scenario is evaluated with LLM-in-the-loop, making each evaluation expensive but realistic.
- The benchmark is designed for coverage (attack categories, defense configurations, benign task types) rather than raw volume.

**Evidence:** Section 7, Tables 1-3, artifact/scenarios.
