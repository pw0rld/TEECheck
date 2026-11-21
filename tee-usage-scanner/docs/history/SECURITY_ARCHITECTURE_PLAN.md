# 待实现：后置 SecurityArchitecture（原 M5）

状态：设计规划，尚未接入默认扫描主线。当前事实、Lead、契约、独立 assessment 和 Arbiter
已经分层，但这不等于下述安全架构产物已经存在。完整旧设计保留在
[ARCHITECTURE-before-phase3.md](ARCHITECTURE-before-phase3.md)。

## 目标

在 Planner 已取证的路径上归纳最小安全模型，分开维护：

- `StructuralArchitecture`：模块、符号、类型、调用和构建条件，主要来自确定性索引。
- `SecurityArchitecture`：主体、资产、信任区域、边界、流、权限、状态生命周期和假设，
  来自已验证工具路径、源码、文档和显式标注的推断。

`ProjectMapV0` 继续位于 Planner 之前；安全模型只能在证据之后产生，不能重新引入由
稀疏提示预先生成、又被下游当作已证事实的全局架构。

## 验证约束

1. 安全节点引用真实 structural node、文档事实，或显式标为 unknown。
2. observed flow / lifecycle 引用工具路径或多段源码证据；单行关键词不能建立跨函数关系。
3. inferred 关系的依赖链最终落到 observed / documented 证据。
4. unknown 用来提出下一步问题，不能充当负面结论。
5. Planner 或 Verifier 的反证能够撤销关系，并使其依赖项失效。
6. 只建模已经调查的 source、boundary、transformer、guard、authority、state 和部署假设。

候选产物是 `architecture.v2.json` 与 append-only `architecture_updates.jsonl`；接口、
存放位置、schema 和失效传播规则仍需单独设计、实现与测试。不要在当前 bundle 校验器中
把这些规划文件设为必需。

## 接入前需要验证

- 与已有 `CaseInvariantV2` / `InvariantAssessment` 分工明确，避免重复存储 verdict。
- 更新事件可追溯，旧假设不会在被否定后继续进入 Arbiter。
- 旧 `architecture.v1` / `project_invariants.v1` 的兼容路径可以退役而不破坏历史 bundle 读取。
- 通过独立评测证明辅助调查效果；不能仅凭生成架构更完整就宣称召回提高。
