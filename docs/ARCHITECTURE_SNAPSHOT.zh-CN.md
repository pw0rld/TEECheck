# TEECheck × tee-audit 融合架构快照

> 快照日期：2026-07-23
> 分支：`merge/tee-audit-integration`（领先 main 84 提交，596 测试 / 57 包全绿）
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
- **全部 16 个 TWE** 编译成前置知识，注入各 Agent——不用 RAG / embedding。
- **ToolFact** 绑定真实代码位置，写入后不可改写。

**状态**：前四段（Fingerprint / Architecture / Invariant / Planner+事实层）已接入主编排并跑通；多 Agent 复核层已实现；输出层（Finding/SARIF）未接，端到端真跑待建库阶段。

---

## 3. 三层结论必须分离（核心纪律）

工具事实、Agent 判断、人工结论互不覆盖。

| 层 | 载体 | 能决定 | 不能决定 |
|---|---|---|---|
| 工具事实 | `ToolFact`（不可变） | 实体、位置、路径、查询命中、检测到的 guard | 业务影响、最终漏洞 |
| Agent 判断 | `AgentAssessment`（可挑战） | 安全语义、攻击假设、缺失证据 | 修改工具事实、取代人工 |
| 人工结论 | `HumanVerdict`（追加） | 最终漏洞、严重度、披露/修复 | 覆盖原始记录（只追加） |

**两道红线**：工具失败不得解释为「没有漏洞」；工具无产出也不得合成漏洞。tee-audit 那条「无产出就从 invariant 造 finding」的行为**明令禁止移植**。

---

## 4. 融合从何而来：T 型互补

两边不是对等的两半。tee-audit 强在前半段（领域知识 + 事实），TEECheck 强在后半段（调查 + 复核 + 闭环）。

**tee-audit 贡献前半段**（导入 17.7k 行 Python，资产三分处置）：
- 16 个 TWE 漏洞族定义 + 事实词表
- TEE 平台 / manifest 指纹信号库
- Architecture / Invariant 生成方法
- 事实表架构 + CodeQL 查询图纸

**TEECheck 贡献后半段**（Go 控制面 / runtime）：
- Planner + 多 Agent 协作
- 事件 / content-addressed blob / replay
- 带 SHA256 校验的源码引用
- 人工 review + 统计 + benchmark

**中间的 CodeQL 事实层**——`标注 → 事实表 → 薄壳查询`——用 tee-audit 架构在 C 上重建：语言逻辑压进事实表，新增一门语言的成本从 O(查询数) 降到 **O(1)**。

---

## 5. 实现进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| PR-00 | 仓库导入 · 资产三分 · Apache-2.0 许可 | ✅ 完成 |
| PR-01 | 8 份契约 schema 绑定 Go + 校验 | ✅ 完成 |
| PR-02 | 16 个 TWE 定义 + 事实词表搬迁 · token 预算硬上限 | ✅ 完成 |
| PR-03 | ProjectProfile v2 · 加 OP-TEE / TF-M 指纹 | ✅ 完成 |
| PR-04 | Architecture + Invariant Agent · citation 校验器 | ✅ 完成 |
| spike | §23.7 C 事实表架构可行性 · CVE-2026-44362 differential | ✅ 通过 |
| PR-05 | TrustIR-C 事实层 · 骨架 + LLM 标注端 | ✅ 完成 |
| PR-06 | Planner 集成 · Rollback Investigation | ✅ 完成 |
| wiring | 主流程接通 · 四个新包串进 `teecheck run` | ✅ 完成 |
| PR-07 | 多 Agent 独立复核 · Challenger 两阶段隔离 | ✅ 完成 |
| PR-08 | Finding v3 · SARIF · Review · Stats | ⬜ 未开始 |
| PR-09 | Benchmark 门禁 · 需建 CodeQL DB · 首次真端到端 | ⬜ 未开始 |
| PR-10 | 扩展其余 15 个 TWE + 退役旧旁路 | ⬜ 未开始 |

**11 段里 8 段完成。** 地基与项目理解层完整，事实层与调查/复核层已实现并接入主流程。

---

## 6. 关键设计决策

融合前定死、不在各阶段反复讨论的前提：

1. **v1 主攻 C / TEE OS** —— benchmark 45 个案例里 43 个是 C（OP-TEE ×27、TF-M ×9…）。事实层从零建 C 后端，tee-audit 的 rust/go/js 查询作图纸。
2. **TWE 是经验剧本，不是 RAG** —— 全部 TWE 编译成前置上下文一次注入，不用 embedding / 向量检索。不因画像没选中就让 Agent 看不到某个漏洞族。
3. **事实表架构 · O(1) 扩展语言** —— 薄壳查询消费 `GeneratedTrustFacts.qll`，语言耦合压进事实表。已在 CVE-2026-44362 上验证 vuln/fixed differential 成立。
4. **证据不可变 · 双向红线** —— 工具失败 = `unresolved` 不 = 安全；工具无产出也不得合成 finding。

---

## 7. 当前边界：未做与未验（诚实呈现）

主线骨架接通了，但离「一条完整可评测闭环」还有明确差距：

- **只有 rollback 一个 TWE 切片贯通。** 七族里只有 STATE 有 CodeQL 查询，其余六族（Flow/Guard/Binding/Config/Design/Leakage）返回 unsupported；16 个 TWE 只有 1 个有 playbook。
- **没建真 CodeQL DB、没端到端真跑过。** Heuristic 路径证明了主编排接通、理解层产出正常；LLM 全路径 + benchmark 门禁待 PR-09 建库才验。
- **LLM 标注质量未验。** 标注端代码写了、逻辑用 fake 测过，但「能不能在真代码上标对」要真模型 + 真代码树才知道。
- **输出层未接。** Finding v3 / SARIF / Review / Stats（PR-08）还没接到用户可见输出。
- **旧旁路仍在。** `twescan` / `querygen` 是「两套语义」里的旧那套，退役排在 PR-10。

---

## 8. 一句话总结

**融合（把 tee-audit 搬进来）基本到位；主线骨架接通、能跑 heuristic。** 剩下三块：输出层（PR-08，不建库）、真端到端跑（PR-09，需建库）、覆盖面从 rollback 一个切片铺开到全部七族（PR-10）。
