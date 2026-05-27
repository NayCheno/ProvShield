# ProvShield / Provenance-Typed Agent Runtime 研究包

本压缩包是一个可直接启动的研究项目骨架，目标是把“面向 MCP 与 Skills 的不可伪造 provenance-typed runtime enforcement”推进到 CCF-A 安全会议可投稿级别。

## 核心主张

LLM agent 的 prompt injection 失败不是单纯的文本过滤失败，而是 **低完整性来源对高风险工具 sink 的非法影响**。ProvShield 将模型视为不可信 planner，在 runtime 外部维护不可伪造 provenance label、capability token、effect-typed tool call 和 user-intent bridge，从而在执行工具前强制阻断未授权的数据流与控制流。

## 包结构

```text
provshield_package/
├── README.md
├── PROJECT_INDEX.md
├── docs/                 # 研究计划、威胁模型、架构、验收、投稿策略
├── paper/                # 论文草稿、中文提纲、LaTeX 骨架、参考文献、图示
├── prototype/            # 原型 schema、policy、伪代码、样例攻击 trace
├── eval/                 # 评测矩阵、攻击集、benign tasks、指标和消融
├── milestones/           # 路线图、周计划、交付清单、tracker
├── artifact/             # 可复现计划、Docker/Makefile 模板、audit log schema
├── skills/               # Codex skills，用于项目工作流复用
└── checklists/           # 验收、投稿、rebuttal 检查表
```

## 推荐使用方式

1. 先读 `docs/00_project_brief.md` 和 `docs/01_initial_research_plan.md`。
2. 用 `docs/02_threat_model.md` 固定论文边界，避免 scope 膨胀。
3. 用 `prototype/policy/core_rules.yaml` 和 `prototype/schemas/*.json` 启动工程实现。
4. 用 `eval/benchmark_matrix.csv` 和 `eval/attack_suite_plan.yaml` 搭建实验。
5. 用 `paper/paper_draft.md` 作为第一版论文主文。
6. 如需把当前树整理成成熟开源项目风格的提交历史，用 `skills/git-history-distiller/` 生成提交计划。
7. 每个里程碑结束时按 `checklists/acceptance_checklist.md` 做 gate review。

## 当前状态

这是 **ProvShield research package v0.3**（research prototype）。代码主线已完成关键阻塞修复（C1–C5），包含 780 场景 LLM-in-the-loop 评测（530 attack + 250 benign，mimo-v2-pro），ProvShield ASR 0.6%（95% CI [0.2%, 1.7%]），BTCR 92.4%（95% CI [88.0%, 94.9%]）。Coq 形式化可编译（coqc 9.0），Docker 可复现。

**投稿成熟度：** 当前为强 workshop / CCF-B 级别。主要待补强项：multi-model evaluation、stronger baselines、benchmark attack strength、proof claim discipline。详见审查报告与 roadmap。
