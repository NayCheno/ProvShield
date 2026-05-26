---
name: git-history-distiller
description: Distill mature open-source project Git histories into credible commit narratives, commit plans, or executable commit sequences. Use when Codex is asked to craft, reconstruct, split, polish, or simulate Git commit history for a repository, especially for research artifacts, open-source releases, paper/project packages, or professional portfolio repositories.
---

# Git History Distiller

## Purpose

Turn a repository's current state and project intent into a believable, reviewable Git history that resembles a mature open-source project: incremental, scoped, technically grounded, and easy to audit.

Use this skill to produce either:

- A commit plan: ordered commits with messages, touched files, rationale, and verification notes.
- An executable sequence: staged file groups and commit commands, only when the user explicitly asks to create commits.
- A history critique: review an existing log and suggest how to split, squash, rename, or reorder commits.

## Ground Rules

- Inspect the repository before proposing history. Read `git status --short`, `git log --oneline --decorate -n 30`, file tree, README, changelog, tests, and domain docs.
- Preserve user work. Never reset, checkout, clean, rebase, amend, or force-push unless the user explicitly asks for that operation.
- Do not fabricate provenance. If commits are synthesized from the current tree, call them a "proposed/reconstructed history", not the repository's actual past.
- Do not create commits unless the user explicitly asks for actual commits. A request to "make a skill", "draft history", "design commit records", or "distill commits" means produce files or a plan, not rewrite history.
- Keep commits review-sized. Prefer coherent slices over file-count equality. A commit should usually explain one durable project decision or one implementation step.

## Workflow

1. Establish the story.
   - Identify the project type: library, app, research artifact, paper package, infra, dataset, benchmark, or mixed.
   - Read the top-level README/index and any roadmap, changelog, package manifest, tests, and docs.
   - Extract natural milestones from the repository instead of inventing arbitrary phases.

2. Map files to subsystems.
   - Group files by ownership and intent: docs, core implementation, schemas, policy/config, examples, evaluation, tests, paper, artifact, CI/release.
   - Note cross-cutting files that should change together, such as schema plus validator, benchmark plus metrics doc, or README plus project index.

3. Choose a history shape.
   - For a new project skeleton: start with project brief, then specs, prototype contracts, examples, evaluation, artifact, and paper integration.
   - For a mature feature: start with failing/desired behavior, add core model/API, wire runtime/integration, add tests/fixtures, update docs, then polish.
   - For a release: use preparation commits, version metadata, changelog, artifact reproducibility, final docs, and tag recommendation.

4. Distill commits.
   - Write messages in imperative mood.
   - Use scopes only when they clarify ownership: `docs:`, `policy:`, `runtime:`, `eval:`, `paper:`, `artifact:`, `ci:`, `test:`.
   - Include a body when the commit records a design decision, threat model boundary, migration, compatibility issue, or evaluation methodology.
   - Pair every commit with a verification line: tests, schema validation, lint, render check, manual review, or "not run" with a reason.

5. Validate credibility.
   - Check that early commits do not reference files or concepts introduced later.
   - Avoid huge "initial commit" dumps unless the user explicitly wants a single import.
   - Include small follow-up fixes only when they reflect realistic review iteration, not artificial noise.
   - Ensure docs, examples, and tests evolve with implementation rather than appearing only at the end.

Read `references/patterns.md` when the task requires richer commit archetypes, release-shaping guidance, or examples of what mature open-source histories usually contain.

## Output Formats

### Commit plan

Use this format by default:

```markdown
## Proposed Commit History

1. `scope: imperative subject`
   Files: `path/a`, `path/b`
   Rationale: ...
   Verification: ...
```

### Executable sequence

Use only when asked to create commits. Before running commands, confirm the worktree state and avoid staging unrelated user changes.

```powershell
git add -- path/a path/b
git commit -m "scope: imperative subject" -m "Body explaining the durable decision."
```

If files are untracked and the repository represents a single generated package, it is acceptable to stage explicit path groups from the plan. Do not use `git add .` when unrelated local files are present.

### History critique

Use this format when reviewing an existing log:

```markdown
## Findings

- `abc1234 subject`: issue and recommended rewrite/split.

## Suggested Rewrite Plan

1. ...
```

## Research Artifact Heuristics

For research repositories like security papers, benchmark packages, or prototype artifacts, a mature history usually reads as:

1. Define problem statement, threat model, and contribution boundary.
2. Specify labels, schemas, policies, or APIs before implementation details.
3. Add minimal prototype/runtime pseudocode that exercises the spec.
4. Add attack examples, benign tasks, metrics, and benchmark matrix.
5. Add acceptance criteria, reproducibility plan, and artifact packaging.
6. Draft paper sections and figures after the technical structure stabilizes.
7. Polish roadmap, changelog, submission readiness, and reviewer-facing docs.

Prefer commits that make the research argument auditable: "what changed in the claim, model, enforcement mechanism, or evaluation surface?"
