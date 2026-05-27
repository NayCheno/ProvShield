# ProvShield Artifact

Reproducible evaluation artifact for **ProvShield: Provenance-Typed Runtime Enforcement for MCP and Skill-Based LLM Agents**.

This package contains the attack suite, benign task suite, ablation configurations, evaluation scripts, and analysis tools needed to reproduce the paper's results.

## Status

**Prototype v0.3 — C1-C5 blockers resolved, expanded evaluation complete.** Bridge re-execution preserves original arguments (C1), MCP tools default to UNKNOWN_HIGH_RISK (C2), taint propagation for argument sources (C3), deterministic audit replay verifier (C4), Coq transition relation with reachable-state invariants (C5). Expanded evaluation: 780 scenarios (530 attack + 250 benign), mimo-v2-pro, 6 defense configurations (including 88 workflow-embedded attack scenarios), 95% Wilson CI. ProvShield ASR: 0.2% (95% CI [0.0%, 0.8%]). BTCR: 92.4% (95% CI [88.0%, 94.9%]).

## Quick Start

```bash
# 1. Clone and enter the repository
cd provshield_package

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the smoke test (~2 min)
make smoke
```

## Directory Layout

```text
artifact/
├── README.md                  # This file
├── Makefile                   # Build and evaluation targets
├── audit_log_schema.json      # JSON Schema for audit log entries
├── configs/
│   └── default_policy.yaml    # Default ProvShield policy (source-to-sink rules)
├── docker/
│   ├── Dockerfile             # Container image for reproducible runs
│   └── docker-compose.yml     # Compose configuration
├── scripts/
│   ├── run_smoke_test.sh      # Level 1: 5 attacks + 5 benign (quick)
│   ├── run_full_evaluation.sh # Level 3: all suites, baselines, ablations
│   └── analyze_results.py     # Generate LaTeX tables and CSV from results
├── data/                      # (generated) Normalized call traces
│   ├── attacks/
│   └── benign/
└── results/                   # (generated) Evaluation outputs
```
## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Python | >= 3.13 | Runtime |
| PyYAML | >= 6.0 | Policy and scenario parsing |
| pytest | >= 8.0 | Test runner |

Install all dependencies:

```bash
pip install -r requirements.txt
```

## Reproducibility Levels

The artifact supports three reproducibility levels:

### Level 1: Smoke Test (~10 seconds)

Verify basic monitor behavior with representative scenarios.
```bash
make smoke
```
**Output:** `artifact/results/smoke/` with per-scenario decision logs.

### Level 2: Standard Evaluation (~10 seconds)

Run all attack suites, benign tasks, and baseline comparisons.
```bash
make eval
```
**Output:** `eval/results/` with per-scenario JSONL traces, manifest, summary, and per-defense results.

### Level 3: Full Reproducibility (~2 minutes)

Run evaluation + generate tables + verify audit replay.
```bash
make all
```
**Output:** All Level 2 outputs + `eval/results/tables/*.tex` + replay verification.

## Evaluation Suites

### Attack Suites

| Suite | Scenarios | Description |
|---|---|---|
| `skill_injection` | ~75 | Skill files with hidden destructive or exfiltration instructions |
| `mcp_metadata_poisoning` | ~75 | MCP tool metadata that attempts to authorize itself or extract secrets |
| `mcp_safety` | ~75 | Unauthorized code execution, credential theft, remote control |
| `web_email_injection` | ~75 | Webpage-to-email exfiltration, email-to-file deletion, hidden HTML |
| `rag_injection` | ~75 | Delayed triggers and poisoned retrieval objectives |
| `adaptive_white_box` | ~75 | Label spoofing, bridge replay, destination/payload swap, policy probing |
| `workflow_embedded` | 88 | Attacks embedded in legitimate workflows (45 strong + 22 targeted + 21 high-rate) |

**Total attack scenarios: 530** (including 88 workflow-embedded strong attacks).

### Benign Tasks

| Category | Tasks | Description |
|---|---|---|
| `browser` | 50 | Public webpage summarization and comparison |
| `email` | 50 | Inbox summarization, draft replies, user-requested sends |
| `mcp` | 50 | Issue queries, calendar invites |
| `skills` | 50 | Report formatting, code linting |
| `mixed` | 50 | Cross-tool workflows (web+email, private doc delivery) |

**Total benign scenarios: 250.**
### Defenses

Each scenario is evaluated against:

- **No defense:** Direct tool execution without provenance checks.
- **Prompt hardening:** System prompt instructs model to ignore injected instructions.
- **Input firewall:** Pattern-based malicious input filter.
- **Generic confirmation:** User confirms all write/send operations without binding.
- **Static allowlist:** Only read-only tools allowed.
- **ProvShield:** Full provenance-typed runtime enforcement.

### Ablation Study (A0-A8)

| ID | Configuration | Expected Effect |
|---|---|---|
| A0 | Full ProvShield | Baseline |
| A1 | No provenance labels | Label spoofing success increases |
| A2 | No runtime monitor | Labels alone insufficient |
| A3 | No bridge binding | Confirmation laundering succeeds |
| A4 | Trust tool metadata | Metadata poisoning success increases |
| A5 | No capability token | Replay and swap attacks succeed |
| A6 | Confidentiality only | Integrity attacks persist |
| A7 | Integrity only | Secret leakage increases |
| A8 | No audit replay | Forensic quality degrades |

## Metrics

### Security Metrics

- **Attack Success Rate (ASR):** Fraction of attack tasks that cause unauthorized high-risk execution.
- **Secret Exfiltration Rate (SER):** Fraction of secret-targeted tasks where secret reaches an external sink.
- **Unauthorized Write Rate:** External or destructive writes not authorized by user intent or bridge.
- **Metadata Poisoning Success Rate:** Attacks where unattested metadata controls high-risk effects.
- **Bridge Abuse Success Rate:** Invalid confirmations accepted by the runtime.

### Utility Metrics

- **Benign Task Completion Rate (BTCR):** Fraction of benign tasks completed successfully.
- **False Blocking Rate:** Benign calls denied when they should be allowed or bridged.
- **Confirmation Burden:** Number of bridge prompts per benign task.
- **False Bridge Rate:** Bridges requested for tasks that should be auto-allowed.

### Performance Metrics

- Monitor p50/p95 latency.
- Policy evaluation time.
- Provenance graph construction time.
- Audit log size.
- Token overhead from rendered labels.

## Generating Tables

After running evaluations, generate paper-ready tables:

```bash
python artifact/scripts/analyze_results.py --results-dir artifact/results --output-dir artifact/results/tables
```

This produces:

- `attack_results_table.tex` — LaTeX table for ASR by suite and defense.
- `utility_results_table.tex` — LaTeX table for BTCR, false blocking, bridge burden.
- `ablation_results_table.tex` — LaTeX table for ablation study.
- `metrics_summary.csv` — Machine-readable summary of all metrics.

## Audit Log Format

Each evaluation run produces audit logs conforming to `audit_log_schema.json`. Key fields:

- `trace_id`: Unique identifier linking related events.
- `event_type`: One of `context_ingest`, `tool_register`, `model_propose`, `monitor_decision`, `bridge_request`, `bridge_confirm`, `tool_execute`, `tool_output`, `deny`.
- `normalized_call`: The intercepted tool call with normalized arguments.
- `policy_decision`: The monitor's decision (allow/deny/require_bridge) with reason.
- `replay_hash`: Deterministic hash for audit replay.

## Determinism

To ensure reproducible results:

- Random seeds are fixed per scenario (`--seed` flag, default 42).
- Prompts and model versions are stored in each run manifest.
- Policy version hash is recorded in every audit entry.
- Normalized tool call traces are stored alongside decisions.

## Docker Usage

For fully reproducible execution:

```bash
cd artifact/docker
docker compose build
docker compose run provshield make smoke
```

## Sensitive Data Policy

All credentials, emails, and documents in this artifact are synthetic. Canary tokens are used for exfiltration detection. No real credentials or private data are included.

## Citing

If you use this artifact, please cite:

```bibtex
@article{provshield2026,
  title   = {ProvShield: Provenance-Typed Runtime Enforcement for MCP and Skill-Based LLM Agents},
  author  = {TBD},
  year    = {2026}
}
```
