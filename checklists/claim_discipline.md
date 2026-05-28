# Claim Discipline Checklist

## Terminology Rules

- [ ] NEVER write "fully verified" or "fully proven" — use "mechanized core" or "mechanized core + proof sketches"
- [ ] NEVER claim the model is unaffected by prompt injection — only claim runtime-observable effects are blocked
- [ ] NEVER claim ProvShield prevents all prompt injection — claim it prevents unauthorized high-risk tool effects
- [ ] ALWAYS use "authority laundering" not "prompt injection defense" when referring to the paper's contribution
- [ ] ALWAYS qualify formal claims with "under stated TCB assumptions"

## Section-by-Section Checks

### Abstract
- [ ] Defines authority laundering explicitly
- [ ] Uses "mechanized core" not "Coq verified"
- [ ] Includes decomposed metrics (manipulation rate, conditional block, direct-call)
- [ ] Does not claim model is unaffected

### Introduction
- [ ] First paragraph defines authority laundering
- [ ] Does not claim to "solve prompt injection"
- [ ] Contribution 1 is problem formulation, not provenance labels
- [ ] Mentions "intent-bound declassification capability" not just "bridge"
- [ ] States planner may be "fully compromised"

### Threat Model
- [ ] States LLM may be fully compromised
- [ ] Security property is "unauthorized high-risk effects cannot execute"
- [ ] Does NOT claim "model is unaffected"
- [ ] TCB assumptions are explicit

### Formal Model
- [ ] Uses "mechanized core" throughout
- [ ] TCB assumptions listed explicitly
- [ ] Limitations paragraph present
- [ ] Does NOT claim "fully verified system"
- [ ] Proof sketches clearly labeled as sketches, not proofs

### Evaluation
- [ ] RQ framing: "Does ProvShield prevent authority laundering?"
- [ ] Decomposed metrics table present
- [ ] Direct-call adversary results included
- [ ] Security analysis uses authority laundering language
- [ ] Baseline analysis explains WHY each fails (not just THAT it fails)
- [ ] Does not cherry-pick favorable metrics

### Related Work
- [ ] Each category explains why it cannot prevent authority laundering
- [ ] IFC is acknowledged as a tool, not dismissed
- [ ] Does not strawman baselines

### Limitations
- [ ] No-defense ASR acknowledged as moderate
- [ ] Model coverage limitations stated
- [ ] Direct-call scale acknowledged as small
- [ ] User study acknowledged as simulated
- [ ] TCB assumptions acknowledged

## Global Checks

- [ ] No claim of "solving prompt injection" anywhere in the paper
- [ ] No claim of "fully verified" or "fully proven" anywhere
- [ ] All ASR numbers use 95% Wilson confidence intervals
- [ ] All numbers match between abstract, intro, evaluation, and conclusion
- [ ] Authority laundering defined consistently across sections
- [ ] "Intent-bound declassification capability" used consistently (not mixed with "generic bridge")
