# 中文论文提纲

## 标题

ProvShield: 面向 MCP 与 Skill-Based LLM Agents 的 Provenance-Typed Runtime Enforcement

## 摘要要点

- 问题：LLM agent 把自然语言同时作为指令、数据、工具描述和执行计划，导致 prompt injection 可以通过网页、邮件、tool output、MCP metadata、skill 文件进入系统。
- 洞见：攻击成功的关键不是模型“看到”恶意文本，而是低完整性来源控制了高风险工具 sink。
- 方法：runtime-side provenance labels + effect-typed tools + user-intent bridge + capability tokens。
- 证明：label/token unforgeability、no-secret-exfiltration、bridge non-replay、sink-level non-interference。
- 实现：MCP proxy、skill loader、browser/email/RAG adapters、policy engine、audit replay。
- 评测：SkillInject、MCPTox、MCP Safety Audit、web/email/RAG injection、adaptive attacks。

## 章节结构

### 1. Introduction

- Agent prompt injection 已经从字符串级攻击发展为上下文化社会工程。
- MCP 与 skill 增加了 tool metadata 和 skill instruction 这两个新边界。
- 现有 prompt hardening / input filtering / generic confirmation 不够。
- 贡献列表。

### 2. Motivating Examples

- Webpage injection: webpage asks agent to send secret。
- MCP metadata poisoning: tool description embeds malicious instruction。
- Skill injection: skill file contains hidden instruction。
- Generic confirmation laundering: user confirms vague email action。

### 3. Threat Model

- 攻击者控制 external content、tool output、untrusted skill、untrusted MCP metadata。
- 模型视为 untrusted planner。
- runtime monitor 是 TCB。
- 非目标：证明模型内部不受影响。

### 4. ProvShield Design

- label lattice；
- sidecar provenance；
- effect-typed tool semantics；
- runtime monitor；
- user-intent bridge；
- audit log。

### 5. Formal Semantics

- state；
- transitions；
- monitor rule；
- bridge rule；
- theorem statements。

### 6. Implementation

- MCP proxy；
- skill loader；
- context builder；
- policy engine；
- bridge UI；
- audit replay。

### 7. Evaluation

- attack suites；
- benign tasks；
- baselines；
- metrics；
- main results；
- ablation；
- performance；
- case studies。

### 8. Discussion

- 证明范围；
- provenance imprecision；
- user confirmation limitations；
- deployment；
- policy tuning。

### 9. Related Work

- prompt injection defenses；
- agent IFC；
- MCP security；
- capability-based systems；
- taint tracking / IFC；
- secure UI confirmation。

### 10. Conclusion

- 重点回到 source-sink enforcement，而不是文本过滤。
