# 契约、证据与裁决

`AuditLead` 记录调查问题，`CaseInvariantV2` 定义要核查的义务，
`InvariantAssessment` 记录该义务在当前源码版本上的结果。三者不能互相替代。
运行主线见 [HARNESS.md](HARNESS.md)，实现类型见 `internal/artifacts/contracts.go`，
JSON Schema 位于 `schemas/`。

## Lead → CaseInvariantV2

Lead 从 `open` 进入 `expanded`、`formalized` 或 `closed`，持久化当前问题、下一步动作、
源码和工具引用。关闭 Lead 只是结束调查，不证明安全。
`formalize_contract` 校验通过后，契约才进入案例；旧式自由文本候选不会绕过契约门控。
`done` 中的契约草稿也须先完成同样的绑定。只有所有当前 sample 的 Lead 均已形式化或
关闭时才正常完成；预算耗尽仍有未决 Lead 的运行保留不完整覆盖状态。已接受契约与模型
新草稿分开保存，后续失败不会删除已接受项。最终调查包只消费机器接受过的契约，不能
凭模型提供的 grounding、ID 或 hash 声明跳过校验。

契约的主要字段：

| 字段 | 约束 |
| --- | --- |
| `invariant_id`, `definition_hash` | 标识逻辑义务及其定义；不能拿另一个义务的 assessment 拼接 |
| `scope`, `lead_ref`, `origin` | 固定扫描范围、调查来源和产生通道 |
| `subjects` | 当前版本真实的 path / symbol / 行范围 / 内容哈希 |
| `preconditions` | 属性适用所需的前提；跨函数消费点应作为 subject 一并提供 |
| `required_property`, `security_effect` | 待核查属性及不满足时的安全影响 |
| `evidence_refs` | 已观察源码、观测记录或已落盘 ToolFact |
| `verification_queries` | 已注册查询及其有类型参数；可以为空 |
| `related_twes`, `grounding` | 弱点关联与证据来源说明 |

`verification_queries: []` 表示没有对应的注册查询，不表示契约无效。
`definition_hash` 绑定逻辑内容；重新核查其他版本时重新绑定 subject 坐标、内容哈希和 scope，
不把旧源码证据当作新版本的事实。

## ToolFact 与查询能力

工具输出保留操作名、参数、scope、状态、来源和 coverage gaps；引用必须属于本次运行，
内容哈希一致。`cpp.taint.trace` 和显式开启预扫得到的 `cpp.taint.prescan` 事实可以附到
Lead 和契约，并交给独立复核者阅读。
查询事实不能被 Planner 文本改成更强的结论。

当前注册的契约查询 `cpp.contract.direct_struct_field_assignment` 核查指定函数内的直接
结构体字段赋值。它证明的是局部 AST 事实，不覆盖所有别名、值关系或所有执行路径。
多个 subject 时须明确查询所指的 `path::symbol`。

污点查询、字段赋值和调用关系具有不同证明范围。没有污点路径、barrier 命中、代码片段
未出现某调用，都不能单独证明全局不可达或属性满足。证据窗口不足应记录缺口。

## 独立复核与 InvariantAssessment

Expert 和 Challenger 各自读取绑定源码与相同不可变工具事实；Verifier 汇总查询和源码
核查，产生 `satisfied`、`violated` 或 `unresolved`。Assessment 仍需绑定相同的
`invariant_id`、`definition_hash` 和 scope，并记录 witness、前提、反证和缺失证据。

注册查询的适用范围与源码复核结果分别保留：

- 查询证明属性满足时，修复导致旧触发前提消失不应把该结果抹成“未证前提”。
- 查询证明局部违反、但跨函数前提未观察到时，保留局部事实并显式记录缺口，不能宣称
  完整安全影响链已证实。
- 只有源码反证而没有注册查询时，`source_contradicted` 区别于一般证据不足；它不是自动
  得到的确定性安全证明。

## Arbiter 门控

Arbiter 校验契约、唯一 assessment、源码和工具引用，并要求独立复核之间一致。
typed contract 主线不需要额外一次模型投票。

| 条件 | 允许的结果 |
| --- | --- |
| 没有绑定契约、无唯一有效 assessment、引用失效或证据冲突 | `needs_review` |
| 有效 `satisfied` 且没有反证 | `no_issue_observed` |
| 注册查询局部违反且独立复核一致 | `likely_issue` |
| 上述违反且前提、witness 和完整影响链都得到支持 | `confirmed_candidate` |
| 无注册查询，三方源码复核一致、前提成立且无缺口或反证 | `likely_issue`，依据为 `source_corroborated_no_query` |

`confirmed_candidate` 仍是可供人工复核的候选；`no_issue_observed` 只针对该版本、该范围和
该契约，不是全项目安全证书。每份 findings 应保留 `verification_basis` 与剩余覆盖缺口。

## 离线完整性与评测

`validate-run` 校验 bundle 文件、哈希、事件和契约/assessment/finding 的连接。
benchmark 只接受当前 attempt 的成功且有效 bundle；失败、陈旧产物和范围冲突记为
`ERROR`。有效但侦察覆盖不完整的零结果记为 `INCOMPLETE_COVERAGE`，不能混入 TN。
