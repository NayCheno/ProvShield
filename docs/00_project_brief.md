# ProvShield: Provenance-Typed Runtime Enforcement for MCP and Skill-Based Agents

## 一句话

为 agent runtime 设计一个强制的 instruction/data boundary：来自 skill、MCP tool metadata、tool output、网页、邮件、RAG 的内容携带 runtime 维护的不可伪造 provenance label，并在模型调用工具前进行 source-to-sink 信息流检查。

## 研究问题

现代 LLM agent 同时处理自然语言指令、工具描述、网页内容、邮件、RAG 文档、skill 文件和工具输出。攻击者可以把恶意指令藏在低信任数据源中，使模型错误地调用高风险工具，例如发送邮件、删除文件、执行代码、泄露 secret 或修改权限。

关键问题是：

> 即使模型被低信任内容操纵，runtime 能否保证这些内容不能未经授权地影响高风险 tool invocation？

## 核心方案

ProvShield 将模型视为不可信 planner，把安全决策移到 runtime：

1. **不可伪造 provenance label**：标签存储在 runtime sidecar 中，而不是由模型在 prompt 文本中声明。
2. **双格标签体系**：同时跟踪 integrity 与 confidentiality。
3. **effect-typed tool call**：每个工具声明 Read、Write、Send、Delete、Exec、Auth 等 effect。
4. **runtime monitor**：拦截所有 tool call，检查参数、payload、destination、capability、source provenance。
5. **user-intent bridge**：对 write/send/delete/exec 等高风险动作，要求 action-specific、destination-specific、payload-specific 的用户确认。
6. **formal proof**：证明 label unforgeability、no-secret-exfiltration、bridge non-replay、sink-level non-interference。
7. **系统原型**：适配 MCP client、skill loader、browser/email/RAG adapters。

## 预期贡献

- 面向 MCP + Skills + tool metadata + external content 的 provenance-typed runtime enforcement 设计。
- 可形式化的 source-sink policy 与 small-step semantics。
- 可落地的 MCP proxy / skill loader / runtime monitor 原型。
- 覆盖 SkillInject、MCPTox、MCP Safety Audit、web/email/RAG prompt injection 的系统评测。
- 对比 prompt hardening、input firewall、static allowlist、generic confirmation、Fides-style IFC 等 baseline。

## 初始 CCF-A 判断

| 版本 | 严格评分 | 判断 |
|---|---:|---|
| 原始 idea | 7.0/10 | Borderline / Weak Reject |
| 当前优化版 | 8.0/10 | Weak Accept potential |
| 强实现 + 强评测 + formal proof | 8.3/10 | Accept potential |

## 最大风险

1. 与现有 agent IFC / MCP security 工作撞车。
2. “调用依据”不可完全观测。
3. 用户确认可能被社会工程诱导。
4. 过度阻断降低 benign task completion。

## 关键化解

- 不声称证明模型内部不受影响，只证明 runtime-observable sink enforcement。
- 标签和 token 在 runtime sidecar 中维护，模型不能伪造。
- user-intent bridge 绑定 action、destination、payload digest、expiry、nonce。
- 加入 adaptive white-box attacks，而不是只测静态 prompt injection。
