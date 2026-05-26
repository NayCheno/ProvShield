# 项目文件索引

## 1. 立项与计划

| 文件 | 用途 |
|---|---|
| `docs/00_project_brief.md` | 一页版研究简介，适合给导师/合作者快速阅读。 |
| `docs/01_initial_research_plan.md` | 完整研究计划。 |
| `docs/09_milestones.md` | 里程碑拆解。 |
| `milestones/roadmap.md` | 5-7 个月路线图。 |
| `milestones/weekly_execution_plan.md` | 周级执行计划。 |

## 2. 技术规格

| 文件 | 用途 |
|---|---|
| `docs/02_threat_model.md` | 威胁模型、攻击者能力、非目标。 |
| `docs/03_label_policy_spec.md` | provenance label、confidentiality/integrity lattice、policy 规范。 |
| `docs/04_user_intent_bridge.md` | user-confirmed intent bridge 设计。 |
| `docs/05_formal_model.md` | small-step semantics / LTS 证明计划。 |
| `docs/06_runtime_architecture.md` | MCP proxy、skill loader、monitor 架构。 |
| `prototype/schemas/*.json` | 工程 schema 起点。 |
| `prototype/policy/*.yaml` | policy DSL 起点。 |

## 3. 评测与验收

| 文件 | 用途 |
|---|---|
| `docs/07_evaluation_plan.md` | 主评测方案。 |
| `docs/08_acceptance_criteria.md` | 验收标准。 |
| `eval/benchmark_matrix.csv` | benchmark x baseline x metric 矩阵。 |
| `eval/attack_suite_plan.yaml` | 攻击集设计。 |
| `eval/benign_tasks.yaml` | benign workload。 |
| `eval/ablation_plan.md` | 消融实验。 |
| `checklists/acceptance_checklist.md` | 逐项验收。 |

## 4. 论文材料

| 文件 | 用途 |
|---|---|
| `paper/paper_draft.md` | 英文论文草稿。 |
| `paper/paper_outline_cn.md` | 中文论文提纲。 |
| `paper/paper_draft.tex` | LaTeX 骨架。 |
| `paper/references.bib` | 参考文献初稿。 |
| `paper/figures/*.mmd` | Mermaid 图。 |
| `docs/10_related_work_positioning.md` | 与 Fides、MCPSHIELD、AttriGuard 等的差异定位。 |
| `docs/11_submission_strategy.md` | CCF-A 投稿策略。 |

## 5. Artifact 与复现

| 文件 | 用途 |
|---|---|
| `artifact/reproducibility_plan.md` | artifact 复现计划。 |
| `artifact/audit_log_schema.json` | audit log schema。 |
| `artifact/docker/Dockerfile.template` | Docker 模板。 |
| `artifact/Makefile.template` | Makefile 模板。 |
| `checklists/submission_readiness.md` | 投稿前检查。 |
| `checklists/rebuttal_preparation.md` | rebuttal 准备。 |

## 6. Codex Skills

| 文件 | 用途 |
|---|---|
| `skills/git-history-distiller/SKILL.md` | 将仓库当前状态蒸馏为成熟开源项目风格的提交计划、提交序列或历史评审。 |
| `skills/git-history-distiller/references/patterns.md` | 成熟开源项目提交类型、节奏、消息风格和可信度检查参考。 |
