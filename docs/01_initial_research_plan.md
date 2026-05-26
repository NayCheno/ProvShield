# 初始研究计划

## 1. 项目名称

**ProvShield: Provenance-Typed Runtime Enforcement for MCP and Skill-Based LLM Agents**

## 2. 研究目标

构建一个 agent runtime 安全框架，使来自低完整性来源的内容不能未经授权地影响高风险工具调用。框架覆盖：

- MCP tool metadata；
- MCP tool output；
- skill instructions / skill files；
- web pages；
- email；
- RAG documents；
- private files；
- secrets and capability tokens。

## 3. 技术路线

### 3.1 Label taxonomy

定义：

```text
UserIntent
SystemPolicy
TrustedSkill
UntrustedSkill
AttestedToolMetadata
ToolMetadata
ToolOutput
ExternalContent
Secret
CapabilityToken
```

完整设计见 `docs/03_label_policy_spec.md`。

### 3.2 Policy enforcement

核心策略：

```text
ExternalContent 不得直接影响 Write/Send/Delete/Exec/Auth 类工具调用，
除非存在 action-specific user-intent bridge。

Secret 不得流向 ExternalSink，
除非存在 explicit declassification。

ToolMetadata 不得为自身授予权限。

CapabilityToken 不得由模型生成、复制或修改。
```

### 3.3 Runtime monitor

monitor 拦截 tool call，并执行：

1. 解析 tool effect；
2. 计算参数和 payload 的 provenance；
3. 检查 source-to-sink policy；
4. allow / deny / require bridge；
5. 写 audit log；
6. 对 tool output 继续传播标签。

### 3.4 Formal model

建立 small-step semantics / labeled transition system。目标定理：

- label unforgeability；
- token unforgeability；
- no-secret-exfiltration；
- no-write-down / no-control-up；
- bridge soundness；
- audit completeness。

### 3.5 Prototype

实现一个 runtime proxy：

```text
MCP Client -> ProvShield MCP Proxy -> MCP Servers
Agent Runtime -> ProvShield Monitor -> Tools
Skill Loader -> Provenance Sidecar -> Context Builder
```

## 4. Evaluation plan

详见 `docs/07_evaluation_plan.md`。主评测包括：

- SkillInject；
- MCPTox；
- MCP Safety Audit；
- real web/email prompt injection；
- RAG injection；
- adaptive attacks。

## 5. Expected outcome

论文主张：

> ProvShield 在不依赖模型识别恶意文本的情况下，通过 provenance-typed runtime enforcement 显著降低 prompt injection 对 high-risk tool sinks 的攻击成功率，同时保持较高 benign task completion。

## 6. 研究边界

### In scope

- Runtime-observable tool invocation。
- Source-to-sink policy。
- Capability token / bridge / declassification。
- MCP + skills + external content。

### Out of scope

- 证明模型内部思考不受 external content 影响。
- 解决所有社工式用户误确认。
- 完全阻止被授权用户主动泄露 secret。
- 代替 sandbox / OS-level isolation。

## 7. 最小可发表版本

最低可发表版本需要同时满足：

1. 一个真实 agent runtime 上的原型；
2. 至少 MCP + web/email + skill loader 三类入口；
3. 至少三个 benchmark 或 attack suite；
4. 与 4 个以上 baseline 的系统对比；
5. 至少 3 个形式化定理；
6. 完整 artifact。
