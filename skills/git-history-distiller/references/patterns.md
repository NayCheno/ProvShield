# Mature Open-Source Git History Patterns

Load this reference when a task needs more than a short commit list: release shaping, realistic sequencing, commit taxonomy, or review of an existing log.

## Common Commit Archetypes

- **Project frame**: README, scope, license, contribution model, roadmap, architecture sketch.
- **Domain model**: schemas, types, policy DSLs, interfaces, invariants, migration notes.
- **Core behavior**: runtime logic, adapters, service boundaries, parsers, validators, execution paths.
- **Fixtures and examples**: sample configs, attack traces, golden inputs, reproducible demonstrations.
- **Tests and evaluation**: unit tests, integration tests, benchmark matrix, metrics, expected outputs.
- **Docs as contracts**: threat model, API reference, acceptance criteria, operator guide, limitations.
- **Hardening**: error handling, boundary checks, compatibility, resource limits, security review fixes.
- **Release work**: changelog, version bump, packaging, artifact instructions, CI/reproducibility.

## Realistic Sequencing

- Start with the smallest artifact that explains why the repo exists.
- Introduce contracts before consumers when possible.
- Add examples near the feature they validate, not all at the end.
- Add tests when behavior becomes concrete enough to test.
- Update documentation in the same commit as user-visible behavior, unless the docs are a standalone design document.
- Reserve final commits for cleanup, consistency, release notes, and reproducibility checks.

## Message Style

Good subjects:

- `docs: define MCP provenance threat model`
- `policy: add source-to-sink enforcement rules`
- `eval: map attacks to benchmark scenarios`
- `artifact: document reproducible runtime layout`
- `paper: outline enforcement theorem structure`

Weak subjects:

- `update files`
- `final changes`
- `add docs`
- `fix`
- `misc`

Use a body when the "why" is not obvious:

```text
policy: bind write effects to user intent tokens

The monitor now treats Write, Send, Delete, Exec, and Auth as high-risk
sinks that require action-specific confirmation. This records the policy
boundary needed for later non-replay and non-interference arguments.
```

## Credibility Checks

- A commit should be understandable from its diff and message without relying on future commits.
- A mature history can include review fixes, but should not add fake churn.
- Large generated assets should have a preceding commit explaining the generator or source.
- Evaluation commits should state what is measured, not just that files were added.
- Paper commits should track argument structure: threat model, formal model, system, evaluation, limitations.

## Useful Local Commands

```powershell
git status --short
git log --oneline --decorate -n 30
git diff --stat
git diff --name-only
rg --files
```

For commit planning without changing history:

```powershell
git diff --name-status
git ls-files --others --exclude-standard
```

For actual commit creation, stage exact paths from the plan and inspect staged diff:

```powershell
git add -- path/a path/b
git diff --cached --stat
git diff --cached --check
git commit -m "scope: imperative subject"
```
