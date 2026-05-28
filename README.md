# ProvShield: Preventing Authority Laundering in Tool-Using LLM Agents

本仓库是 ProvShield 研究包，目标是把"面向 MCP 与 Skills 的 authority laundering 防御"推进到 CCF-A 安全会议可投稿级别。

## 核心主张


工具型 LLM agent 的 prompt injection 本质上不是文本过滤失败，而是 **权限洗白（authority laundering）**：低权限来源（网页、邮件、RAG 文档、MCP metadata、skill 文件、tool output）通过模型规划过程被转换成高权限工具行为。ProvShield 将模型视为不可信 planner，在 runtime 外部维护不可伪造 provenance label、capability token、effect-typed tool call 和 intent-bound declassification capability，从而在执行工具前强制阻断未授权的 authority laundering。


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

这是 **ProvShield research package v1.0**（CCF-A rewrite）。论文已重构为 authority laundering 框架，包含 780 场景 LLM-in-the-loop 评测（530 attack + 250 benign），101 场景 direct-call adversary（100% block rate），3 模型评测，mechanized core（Coq 9.0）。ProvShield ASR 0.6%（95% CI [0.2%, 1.7%]），BTCR 92.4%，conditional block rate 100%。

**投稿成熟度：** CCF-A rewrite v1.0。论文已完成 authority laundering 重写，实验数据满足最低投稿阈值。详见 `checklists/acceptance_checklist.md` 和 `docs/simulated_reviews.md`。
