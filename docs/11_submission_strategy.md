# CCF-A Submission Strategy

## 1. Target venues

Primary target style:

- USENIX Security;
- NDSS;
- IEEE S&P;
- ACM CCS.

The paper should be framed as a systems security paper with formal foundations, not as a pure ML paper.

## 2. Reviewer expectations

Reviewers will ask:

1. Is this more than prompt engineering?
2. Is the threat model realistic?
3. Is the formal property actually meaningful?
4. Is the system implemented, or only conceptual?
5. Are baselines strong?
6. Does the evaluation include adaptive attacks?
7. Does security destroy utility?
8. Is this different from existing agent IFC / MCP security frameworks?

## 3. Paper positioning

Bad framing:

> We add labels to prompts so the model knows which text is instruction and which is data.

Good framing:

> We externalize instruction/data authority into a runtime-side provenance and effect system, and treat the model as an untrusted planner whose tool calls require policy proof before execution.

## 4. Claim discipline

Do not claim:

- model cannot be influenced by prompt injection;
- all prompt injection is solved;
- confirmation eliminates social engineering;
- provenance perfectly captures semantic causality.

Claim instead:

- high-risk sinks are protected by runtime-observable provenance constraints;
- low-integrity content cannot directly execute high-risk effects;
- secret exfiltration is prevented under the stated TCB;
- bridge-bound declassification is non-replayable and action-specific.

## 5. Required figures

1. Attack path without ProvShield.
2. Runtime architecture.
3. Label lattice and effect sinks.
4. User-intent bridge flow.
5. Evaluation results: ASR vs BTCR.

## 6. Required tables

1. Comparison with related work.
2. Threat model matrix.
3. Policy rule examples.
4. Main attack results.
5. Benign utility results.
6. Ablation results.
7. Performance overhead.

## 7. Strong rebuttal preparation

Prepare responses to:

### Objection: “This is just IFC.”

Response: Basic IFC is not the novelty. The contribution is applying a provenance-typed effect system to the MCP/Skill/tool-output boundary, combined with bridge-bound declassification and runtime enforcement across realistic agent channels.

### Objection: “You cannot know what influenced the model.”

Response: We do not claim to know hidden causal influence. We enforce that any runtime-observable high-risk call must carry an authorized provenance proof and capability. The model is an adversarial proposal generator in the formal model.

### Objection: “Users can still approve bad actions.”

Response: Correct. ProvShield reduces unauthorized execution and vague-confirmation laundering, but cannot prevent intentional user approval. The bridge design minimizes ambiguity by binding destination and payload.

### Objection: “Too much false blocking.”

Response: Show benign utility results and bridge burden. Read-only tasks should remain almost unaffected.

## 8. Minimum results for submission

A submission should not go out until it has:

- a running prototype;
- attack results on at least three suites;
- benign task results;
- ablation;
- performance overhead;
- formal proof sketch or mechanized core;
- artifact plan.
