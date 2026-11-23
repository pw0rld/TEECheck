# TEECheck：当前架构

本文描述已实现的主线；运行方式见 [HARNESS.md](HARNESS.md)，证据和裁决规则见
[CONTRACTS.md](CONTRACTS.md)，模型配置见 [ROLE_MODELS.md](ROLE_MODELS.md)。
评测协议、数据集范围及限制见 [benchmark README](../../teecheck-benchmark/README.md)。

## 主数据流

```text
固定源码与 ScannedScope
  → 预处理与确定性程序索引（RepoFacts）
  → 中性 ProjectMapV0 / EntrySurfaces / 3 跳入口闭包与字段访问桥
  → 可选 L2 批量入口污点预扫（--enable-taint-prescan）：中性路径 ToolFact / Top-10 浏览线索
  → Planner Pass A：项目侦察、边界入口、按需取证、AuditLead
  → Planner Pass B：TWE 补覆盖、扩展 Lead、CaseInvariantV2
  → CasePack + 独立 Expert / Challenger 源码复核
  → Verifier：InvariantAssessment
  → Arbiter：机械校验与分级裁决
  → findings.json / 报告 / 可离线校验的 run bundle
```

确定性规则通道与 Planner 通道可以分别产生案例，合并后保留来源标记。
批量污点预扫本身不产生案例或 Finding；它只把可引用的路径线索交给 Planner 做源码调查。
`architecture.v1` / `project_invariants.v1` 是默认关闭的兼容阶段；只有显式启用
`--enable-legacy-prior` 才运行，不是上述主线的必要前置条件。

## 各层职责

| 层 | 负责 | 不据此推断 |
| --- | --- | --- |
| Source / scope | 固定仓库、版本、实际扫描路径和源码内容 | 本地裁剪 fixture 等同完整上游仓库 |
| RepoFacts / ProjectMap | 符号、模块、调用关系、入口特征及覆盖缺口 | 一个导出函数一定能被外部调用，或一定存在漏洞 |
| Entry taint prescan | 就绪数据库上的批量 may-flow 路径与浏览排序 | 路径可达即存在漏洞，或没有路径即安全 |
| Planner | 浏览证据、维护 Lead、提出绑定源码的契约 | 自由文本怀疑已得到证实 |
| ToolFact | 保存工具参数、来源、结果、摘要哈希和覆盖限制 | 没有路径等同安全 |
| CaseInvariantV2 | 定义要核查的前提和属性 | 属性在当前版本已满足或违反 |
| InvariantAssessment | 记录当前版本的核查结果和依据 | 局部违例自动构成完整漏洞链 |
| Arbiter | 校验契约、复核与 assessment 的一致性并给出等级 | 用额外模型投票补足缺失证据 |

所有阶段共用同一源码和 scope。程序索引失败、局部扫描、未解决的 Lead、预算终止
等情况必须保留为覆盖缺口；评测不能把失败或不完整的零结果计为真阴性。

## 已落地的扩展点

- `internal/planner/actions`：有类型参数的只读工具；`trace_taint` 使用固定 QL 模板，
  与索引工具共用 CodeQL 数据库，不接收模型生成的 QL。
- `internal/contracts` / `internal/contractreview`：源码锚点、证据引用、契约和独立复核校验。
- `internal/verifier` / `internal/arbiter`：查询结果与源码复核分离、机械裁决。
- `internal/runbundle` 及公开 `runbundle` 包：离线完整性校验，供 CLI 和 benchmark 复用。
- `internal/llm` / `ROLE_MODELS.md`：兼容 API 的传输适配和启动时确定的角色模型路由。

## 规划与历史

后置、可修订的 `SecurityArchitecture` / `architecture.v2` 尚未接入主流程；
设计约束单列在 [SecurityArchitecture 规划](history/SECURITY_ARCHITECTURE_PLAN.md)。
旧版目标架构和路线图保留在 [history/](history/README.md)，其中的目录编号、阶段状态和
接口名称不代表当前实现。当前运行产物以 HARNESS 及实际 bundle 为准。
