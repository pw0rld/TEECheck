# TEECheck × tee-audit 融合架构快照

> 快照日期：2026-07-31（前一版 2026-07-23）
> 分支：`merge/tee-audit-integration`（领先 main 193 提交，41 个包全绿）
> 用途：汇报当前架构与进度。数据取自代码库实测，进度如实标注。

---

## 1. 一句话

把两个各做一半的系统合成一条流程：**tee-audit** 贡献 TEE 领域经验与结构化事实层，**TEECheck** 贡献多 Agent 调查与人工复核闭环。经验型漏洞知识（TWE）作前置，先理解项目、再以 CodeQL 事实为证据、由多个独立 Agent 交叉复核，最后落到人工裁决。

只有**一条统一流程**，不做 deterministic / exploratory / hybrid 三套模式。

---

## 2. 主流程数据流

```
目标仓库 (TEE 项目源码)
   │
   ▼  确定性扫描（← tee-audit 信号库）
Fingerprint ─────────── 平台 / 信任 artifact / manifest 信号，可引用
   │
   ▼  LLM，一次（← tee-audit dossier 方法）
Architecture + Invariant ─ 项目理解层；每条陈述带证据状态，引用经校验
   │
   ▼  调查
Planner + 事实层 ─────── 按 TWE 场景调查，调 CodeQL 事实层取 ToolFact
   │
   ▼  多 Agent 交叉复核
Expert → Challenger → Verifier → Arbiter ─ Challenger 两阶段独立判断
   │
   ▼
Finding + 人工复核 ───── SARIF / Review / Benchmark 门禁
```

贯穿全流程的两条：
- **全部 19 个 TWE** 编译成前置知识，注入各 Agent——不用 RAG / embedding。
- **ToolFact** 绑定真实代码位置，写入后不可改写。

**状态**：前四段（Fingerprint / Architecture / Invariant / Planner+事实层）已接入主编排并跑通；多 Agent 复核层已实现；输出层（Finding/SARIF）未接，端到端真跑待建库阶段。

### 2.1 单次审计运行流程

```text
TWE taxonomy / 经验 playbook                 目标 TEE 仓库
        │                                         │
        ▼                                         ▼
编译为本次运行的前置知识                 Fingerprint 确定性扫描
        │                                平台 / manifest / trust artifact
        │                                         │
        └──────────────────┬──────────────────────┘
                           ▼
                ProjectProfile（项目画像）
                           │
                           ▼
                Architecture（参与方、组件、
                  数据流与信任边界）
                           │
                           ▼
                ProjectInvariant（结合 TWE
                   生成项目安全不变量）
                           │
                           ▼
                  Planner 拆分调查任务
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       源码探索与路径追踪         TrustIR / CodeQL 事实查询
                                        │
                                        ▼
                              ToolFact（位置、路径、状态）
              └────────────┬────────────┘
                           ▼
                       Case Pack
                           │
                           ▼
       Expert → Challenger Phase 1 → Challenger Phase 2
                           │
                           ▼
                       Verifier
                           │
                           ▼
                        Arbiter
                           │
                           ▼
                 当前：Findings v2
                           │
                           ▼
          待 PR-08：Finding v3 → SARIF → 人工复核
                           │
                           ▼
          待 PR-09：vulnerable / fixed Benchmark 门禁
```

这条流程中，TWE 提供“应该检查什么以及如何检查”的前置经验，ProjectProfile、Architecture
和 ProjectInvariant 将经验落到当前项目；ToolFact 只提供可复现的代码事实，最终安全语义由
多 Agent 复核并交给人工裁决。

### 2.2 每个阶段负责什么

| 阶段 | 输入 | 主要职责 | 输出 |
|---|---|---|---|
| **TWE 前置知识** | TEE 漏洞经验、taxonomy 与 playbook | 描述漏洞场景、攻击者能力、调查步骤、必要证据、常见防御和误报；告诉系统“应该检查什么”，但不直接产生漏洞结论 | 本次运行共享的 TWE 上下文 |
| **Fingerprint / ProjectProfile** | 目标仓库源码与配置文件 | 确定性扫描 TEE 平台、语言、framework、manifest、trust artifact 和边界信号，为后续推理提供可引用的项目画像 | `ProjectProfile` |
| **Architecture** | ProjectProfile、TWE 上下文、目标源码 | 识别参与方、组件、角色、资产、入口点、数据流、状态生命周期和信任边界；无法被源码支持的陈述降级为假设或 unknown | `ArchitectureModel`、Architecture Dossier |
| **ProjectInvariant** | ProjectProfile、Architecture、TWE 上下文 | 把通用漏洞经验实例化为当前项目应满足的安全条件，例如“恢复后的安全版本必须由不可回滚的可信来源约束” | `ProjectInvariant[]` |
| **Planner** | TWE、Architecture、ProjectInvariant、项目画像 | 选择需要深入的代码路径，把宽泛的安全问题拆成可执行调查，并确定需要源码探索还是事实层查询 | `TWEInvestigation`、候选项与 Evidence Bundle |
| **源码探索** | Planner 调查任务、目标源码 | 定位入口、调用者、状态读写、持久化与恢复路径，补充工具查询暂时无法表达的业务上下文 | 带源码引用的调查证据 |
| **TrustIR / CodeQL 事实层** | 事实查询请求、CodeQL DB、事实表 | 提取实体、数据传播、guard、调用路径及代码位置；工具失败、覆盖不完整和 unsupported 均显式保留，不能解释成“没有漏洞” | 不可改写的 `ToolFact` |
| **Case Pack** | 调查结果、相关架构切片、不变量与 ToolFact 引用 | 把一个候选问题收敛成有边界的复核单元，避免后续 Agent 重新读取无关的全仓库上下文 | `CasePack` |
| **Expert** | Case Pack、TWE、Architecture、Invariant、ToolFact | 根据现有证据提出漏洞假设，说明攻击前提、攻击步骤、安全影响与缺失证据 | `Hypothesis` |
| **Challenger Phase 1** | 与 Expert 相同的基础上下文，但不读取 Expert 结论 | 先独立分析当前 Case，形成自己的判断，降低直接被 Expert 结论锚定的风险 | Independent View |
| **Challenger Phase 2** | Independent View 与 Expert Hypothesis | 对比双方判断，寻找反例、已有防御、不可达路径、错误假设和证据缺口 | `Challenge` |
| **Verifier** | Hypothesis、Challenge、源码与 ToolFact | 把争议转换成具体工具问题，重新校验引用、路径、guard 和攻击链，并区分“未找到”与“能够证明不存在” | `VerificationMemo`、追加式 Invariant 状态更新 |
| **Arbiter** | Expert、Challenger、Verifier 结果及原始证据 | 综合各方结果，但不改写 ToolFact；只有证据完整、路径可达且安全影响成立时才能输出 confirmed | 当前为 `Findings v2` |
| **Finding / 人工复核** | Arbiter 输出、代码证据与复核记录 | 由人决定最终真伪、严重度、披露和修复状态；人工结论追加记录，不覆盖原始工具事实和 Agent 判断 | 待 PR-08 接入的 `Finding v3`、SARIF、`HumanVerdict` |
| **Benchmark 门禁** | vulnerable/fixed 样本、对照组与最终 Finding | 检查漏洞版本能否命中、修复版本是否干净，并统计对照组误报，防止系统只会套用 TWE 模板 | 待 PR-09 接入的 differential 与 FP 门禁结果 |

上述阶段遵守同一条证据边界：**TWE 提供检查方法，ToolFact 提供代码事实，Agent 负责安全语义判断，HumanVerdict 才是最终人工结论。**

---

## 3. 目录结构与流程对照

以 `tee-usage-scanner/` 为主控制面。下图把 `cmd/teecheck run` 的实际编排顺序（取自
`internal/pipeline/run.go`）映射到承载它的 Go 包：

```text
cmd/teecheck run
      │
      ▼   internal/pipeline   ── 总编排；internal/events 记录事件 / blob / replay
┌──────────────────────────────────────────────────────────────────────┐
│ ① 预处理·画像   preprocessor · repofetch · repomap · repomix · mapper    │ → ProjectProfile
│ ② 项目理解      architecture · invariants · citations                    │ → ArchitectureModel · ProjectInvariant
│ ③ TWE 前置知识  twe · twecontext · twepipeline · twexpert                │ → 本次运行的 TWE 上下文
│ ④ 调查·事实层   planner (+planner/actions) · trustirfacts · codeql        │ → TWEInvestigation · ToolFact
│                 investigations · cases                                   │ → CasePack
│ ⑤ 多 Agent 复核 expert → challenger → verifier → arbiter                  │ → Findings v2
│                 agentbus · agentutil · collabrun（Agent 间通信/协作）      │
│ ⑥ 输出·闭环     report · review · stats · feedback                        │ → 报告；HumanVerdict/SARIF 待 PR-08
└──────────────────────────────────────────────────────────────────────┘
贯穿全程   artifacts（契约类型）· schema（运行时校验）· runfs（路径/JSON）· llm（GLM）· config
旧旁路     solver · twepipeline · twexpert · cmd/twescan  ── 仅 twescan 可达，PR-10 待退役
```

> 注：语言限制已解除——`planner/actions/langtext.go` 接受 `.rs .c .h .cc .cpp`，
> `knowledge/sinks/` 已随旧路径移除。

### 3.1 目录树

```text
tee-usage-scanner/
├── cmd/
│   ├── teecheck/          主 CLI：run 一把梭，也可单跑各阶段子命令
│   └── twescan/           旧扫描旁路（PR-10 待退役）
│
├── internal/             业务逻辑（39 个包）
│   │                     ——编排——
│   ├── pipeline/         run 总编排，串起下列所有阶段
│   ├── runinit/ runfs/   运行目录初始化、路径与 JSON 读写（ReadProjectInvariants 在此）
│   ├── config/ events/   配置；事件 / content-addressed blob / replay
│   │                     ——① 预处理·画像——
│   ├── preprocessor/     拉仓库、产 ProjectProfile
│   ├── repofetch/ repomap/ repomix/ mapper/   仓库获取与代码地图
│   ├── solver/                                旧旁路（仅 twescan 可达）
│   │                     ——② 项目理解——
│   ├── architecture/     ArchitectureModel + Dossier
│   ├── invariants/       ProjectInvariant
│   ├── citations/        引用/证据校验（SHA256 绑定源码）
│   │                     ——③ TWE 前置知识——
│   ├── twe/ twecontext/  19 个 TWE 定义、编译成 agent 上下文
│   ├── twepipeline/ twexpert/                 TWE 相关流水线/专家
│   │                     ——④ 调查·事实层——
│   ├── planner/          L3 Planner（含 actions/ 动作）；硬编码 rust.json / .rs
│   ├── trustirfacts/     TrustIR-C 事实层，产 ToolFact（最大包）
│   ├── codeql/           CodeQL DB 交互
│   ├── investigations/   TWEInvestigation 构建
│   ├── cases/            CasePack 收敛
│   ├── executor/ tools/ staticcheck/          工具执行支撑
│   │                     ——⑤ 多 Agent 复核——
│   ├── expert/ challenger/ verifier/ arbiter/ 假设 → 挑战(两阶段) → 校验 → 裁决
│   ├── agentbus/ agentutil/ collabrun/        Agent 间通信 / 协作运行
│   │                     ——⑥ 输出·闭环——
│   ├── report/ review/ stats/ feedback/       报告、人工复核、统计、反馈学习
│   │                     ——贯穿——
│   ├── artifacts/        全部契约类型（ProjectInvariants / ToolFact / CasePack / Findings…）
│   ├── schema/           运行时 JSON schema 校验
│   ├── llm/              LLM 客户端（GLM）
│   └── knowledge/        知识加载
│
├── knowledge/            知识库（数据，非代码）
│   ├── twe/
│   │   ├── definitions/  taxonomy / catalog / exclusion / enum_registry（19 个 TWE）
│   │   └── playbooks/    rollback.yml · flow.yml（2 个，其余 17 待补）
│   ├── wiki/             obligations / patterns / apis / projects（领域文档）
│   ├── learned/          true-positive / false-positive / review-memory（反馈闭环）
│   └── raw/              cve / papers / sdk / prior-reviews（原始素材）
│
├── codeql/               CodeQL 查询与库文件
├── testdata/  examples/  docs/  README.md
├── runs/                 运行产物输出
└── go.mod  go.sum
```

**分工对应**：tee-audit 贡献前半段的领域知识与事实层（②③④ + `knowledge/`），TEECheck 贡献
后半段的调查、复核与闭环（⑤⑥）；`artifacts/` 是两边共享的契约边界。

---

## 4. 实现进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| PR-00 | 仓库导入 · 资产三分 · Apache-2.0 许可 | ✅ 完成 |
| PR-01 | 8 份契约 schema 绑定 Go + 校验 | ✅ 完成 |
| PR-02 | 19 个 TWE 定义 + 事实词表搬迁 · token 预算硬上限 | ✅ 完成 |
| PR-03 | ProjectProfile v2 · 加 OP-TEE / TF-M 指纹 | ✅ 完成 |
| PR-04 | Architecture + Invariant Agent · citation 校验器 | ✅ 完成 |
| spike | §23.7 C 事实表架构可行性 · CVE-2026-44362 differential | ✅ 通过 |
| PR-05 | TrustIR-C 事实层 · 骨架 + LLM 标注端 | ✅ 完成 |
| PR-06 | Planner 集成 · Rollback Investigation | ✅ 完成 |
| wiring | 主流程接通 · 四个新包串进 `teecheck run` | ✅ 完成 |
| PR-07 | 多 Agent 独立复核 · Challenger 两阶段隔离 | ✅ 完成 |
| PR-08 | Finding v3 · SARIF · Review · Stats | ⬜ 未开始 |
| PR-09 | Benchmark 门禁 · 需建 CodeQL DB · 首次真端到端 | ⬜ 未开始 |
| PR-10 | 扩展其余 TWE + 退役旧旁路 | 🟡 进行中：collab-run 与 legacy 分支已退役（2026-07-31），剩 `cmd/twescan` 一支 |

**11 段里 8 段完成。** 地基与项目理解层完整，事实层与调查/复核层已实现并接入主流程。

---

## 5. 关键设计决策

融合前定死、不在各阶段反复讨论的前提：

1. **v1 主攻 C / TEE OS** —— benchmark 45 个案例里 43 个是 C（OP-TEE ×27、TF-M ×9…）。事实层从零建 C 后端，tee-audit 的 rust/go/js 查询作图纸。
2. **TWE 是经验剧本，不是 RAG** —— 全部 TWE 编译成前置上下文一次注入，不用 embedding / 向量检索。不因画像没选中就让 Agent 看不到某个漏洞族。
3. **事实表架构 · O(1) 扩展语言** —— 薄壳查询消费 `GeneratedTrustFacts.qll`，语言耦合压进事实表。已在 CVE-2026-44362 上验证 vuln/fixed differential 成立。
4. **证据不可变 · 双向红线** —— 工具失败 = `unresolved` 不 = 安全；工具无产出也不得合成 finding。

---

## 6. 当前边界：未做与未验（诚实呈现）

主线骨架接通了，但离「一条完整可评测闭环」还有明确差距：

- **只有 rollback 一个 TWE 切片贯通。** 七族里只有 STATE 有 CodeQL 查询，其余六族（Flow/Guard/Binding/Config/Design/Leakage）返回 unsupported；19 个 TWE 只有 2 个有 playbook。
- **已建真 CodeQL DB，LLM 全路径已端到端跑过。** 2026-07-29 装好 CodeQL，事实层实测 108 秒完成 clone→建库→查询→ToolFact；CVE-2026-44362 上漏洞版命中 1 条、修复版 0 条，差分成立。但 benchmark 门禁（PR-09）仍未建。
- **LLM 标注质量未验。** 标注端代码写了、逻辑用 fake 测过，但「能不能在真代码上标对」要真模型 + 真代码树才知道。
- **输出层未接。** Finding v3 / SARIF / Review / Stats（PR-08）还没接到用户可见输出。
- **旧旁路只剩 `twescan`。** `collab-run`、legacy pipeline 分支与 `internal/{scanner,mapper,hotspots,repomap}` 已于 2026-07-31 退役；`cmd/twescan` 及其独占的 solver/twepipeline/twexpert 仍在。

---

## 7. 一句话总结

**融合（把 tee-audit 搬进来）基本到位；主线骨架接通、能跑 heuristic。** 剩下三块：输出层（PR-08，不建库）、真端到端跑（PR-09，需建库）、覆盖面从 rollback 一个切片铺开到全部七族（PR-10）。
