# 删除 heuristic 模式(产品只走 LLM)— 设计文档

> 日期：2026-07-24
> 分支：`merge/tee-audit-integration`
> 状态：设计待确认
> 关联：延续 [[project_v1_scope_glm_only]]（v1 只跑 GLM，OpenAI/Claude 代码在但不验证）。

---

## 1. 背景与目标

当前每个 agent 都有 `heuristic`（不调 LLM 的退化路径）与 `llm` 双模式，由 config 的 `Mode` + 五个子模式字段驱动，并暴露为 CLI 的 `-mode heuristic|llm`。问题：

- heuristic 是**生产代码里的一整条假分支**（部分产出空/退化结果，如 `invariants.BuildHeuristic` 返回空集），维护负担且让测试"假通过"——测试走 heuristic 时并没有走真正的 llm 代码路径。
- 决策：**产品只走 LLM，heuristic 模式整个从设计里删除。**

目标：删掉所有 agent 的 heuristic 分支、`Mode`/子模式 config、`-mode` CLI；生产代码只留一条 llm 路径；测试改用**注入的假 client**（test-only，不进生产二进制）。

---

## 2. 核心决策

| 轴 | 决策 |
|---|---|
| heuristic 分支 | **全部删除**（真删，不留 flag）——每个 agent 的 `if mode==llm {} else {heuristic}` 只保留 llm 分支。 |
| client 获取 | **显式依赖注入**：每个 agent 的入口接收一个 `llm.Client` 参数；生产端造真 client 传入，测试端传假 client。不再在 agent 内部 `llm.NewClient(cfg)`。 |
| 多 provider | **不额外做**——`llm.Client` 是接口，`llm.NewClient(cfg)` 已按 `cfg.LLMProvider` 选 GLM/OpenAI。注入接口天然兼容；v1 仍 GLM-only（[[project_v1_scope_glm_only]]）。 |
| 测试 | 8 个用 heuristic 的测试改为**注入假 client**（返回写死的 LLM 回答），走真 llm 代码路径。 |
| config/CLI | 删除 `Mode` 概念里的 heuristic 语义、五个 `*Mode` 子字段、`-mode` flag（详见 §4.4）。 |

假 client 只存在于 `*_test.go`，不是产品的运行模式，不进发布二进制。

---

## 3. 现状分类（删除面）

### 3.1 已半注入型（Build 已收 client，只需删 mode 分支）
- `architecture/build.go`：`Build(ctx, client, mode, in, temp)` → 删 `mode` 参数与 `BuildHeuristic`，恒走 `BuildLLM`。调用方 `architecture/run.go:47-49`（条件构造 client）改为无条件注入。
- `invariants/build.go`：同上，`Build(...)` + `BuildHeuristic`（返回空集）删除，`invariants/run.go` 改注入。

### 3.2 内部造 client 型（需改成注入）
- `expert/run.go`：`RunWithEvents` 内 `if ExpertMode==llm { client=NewClient }` + heuristic 分支 → 改为入口收 `client llm.Client`，删 heuristic。
- `challenger/run.go` + `phase1.go`：`ChallengeMode` 分支 → 注入 + 删 heuristic。
- `verifier/run.go`：`RunWithBusAndEvents` 已恒造 client（225），但 `func Run`(非 bus)可能有 heuristic 分支/`VerifierMode` —— 统一为注入，删任何 heuristic 分支。
- `report/run.go`：`Mode==llm || VerifierMode==llm` 决定 synthesized vs concatenated —— 删 heuristic(concatenated) 分支，恒走 synthesized，注入 client。
- `feedback/run.go`（curator）：`CuratorMode` → 注入 + 删 heuristic。

### 3.3 待实现阶段核实
- `arbiter/chain.go`、`preprocessor/run.go`、`twecontext/context.go`、`repomap/run.go`、`stats/*`：grep 命中 "heuristic" 但可能只是注释/字符串/无关分支。实现时逐个确认：真有 heuristic 逻辑分支才删，纯注释/字符串按需清理，不硬改。

---

## 4. 设计

### 4.1 注入形态
每个 agent 入口签名新增 `client llm.Client` 参数（放在现有参数之后，保持其余不变）。例：
- `expert.RunWithEvents(cfg, rec, blobs)` → `expert.RunWithEvents(cfg, client, rec, blobs)`
- `architecture.Run(cfg)` → `architecture.Run(cfg, client)`（内部调 `BuildLLM(ctx, client, in, temp)`）
- `invariants.Run(cfg)` → `invariants.Run(cfg, client)`

`llm.NewClient(cfg)` 的调用点从各 agent 内部**上移到编排层**（`pipeline` 与各 `cmd/teecheck` 子命令）。

### 4.2 编排层构造一次、传给各阶段
`pipeline/run.go` 的 `Run(cfg)`：在进入 agent 阶段前 `client := llm.NewClient(cfg)`，传给 `architecture.Run`、`invariants.Run`、`expert.RunWithEvents`、`challenger.Run`、`verifier.RunWith*`、`arbiter.Run`、`report`/`feedback`（凡需 LLM 的阶段）。

`cmd/teecheck` 的单阶段子命令（`expert`、`challenge`、`verifier`、`arbiter`、`report`、`curator` 等）各自 `llm.NewClient(cfg)` 后传入对应 `Run`。

### 4.3 测试迁移（8 个文件）
`expert/context_test.go`、`invariants/build_test.go`、`invariants/run_test.go`、`architecture/run_test.go`、`architecture/build_test.go`、`challenger/phase1_test.go`、`scanner/scan_test.go`、`pipeline/run_test.go`：
- 定义/复用一个 `fakeClient`（实现 `llm.Client.Generate`，返回该测试所需的写死 JSON 回答）——仓库已有此模式（如 `invariants/build_test.go`、`architecture/build_test.go`）。
- 把 `Mode: "heuristic"` 的构造改为注入 `fakeClient`，断言不变或收紧到"给定该 LLM 回答，产出正确 artifact"。
- 断言**不得被弱化为只测管道接通**——每个迁移后的测试要验证真实解析/产出行为。

### 4.4 config / CLI 清理
- 删除 `config.Config` 的 `ExpertMode` / `ChallengeMode` / `VerifierMode` / `ArbiterMode` / `CuratorMode` 字段及其默认赋值（`config.go:107-111, 301, 336, 371, 408, 445`）与 `Mode==llm` 翻转块（`config.go:616-621`）。
- `Mode` 字段：report 的 `-mode llm|heuristic`（synthesized|concatenated）删除 heuristic 语义。运行/扫描的 `-mode`（`config.go:492, 562`）删除或恒为 llm。实现时确认 `Mode` 是否还有非-heuristic 用途（如 pipeline 的 llm-vs-legacy-scanner 分支 `run.go:119` 用 `Mode==llm`）——**注意**：pipeline 的 `Mode` 还用于选 L3 planner vs legacy scanner，这与 heuristic 无关，**保留**；只删 heuristic 这一取值语义。

### 4.5 TestPipelineHeuristic → 注入假 client 的端到端 smoke（已定：甲）
`pipeline/run_test.go` 的 `TestPipelineHeuristic` 是"不带 LLM 跑整条流水线"的 smoke 测试，靠 heuristic 模式实现。**结论：保留，改为注入假 client。**

- `pipeline.Run` 增加可注入 client 的接缝：新增 `pipeline.RunWithClient(cfg, client llm.Client)`（或等价形态），`Run(cfg)` 内部 `RunWithClient(cfg, llm.NewClient(cfg))`——生产不变，测试走可注入入口。
- 测试传一个对各阶段返回"够用的"写死回答的 `fakeClient`，改名 `TestPipelineEndToEnd_FakeClient`（不再叫 heuristic）。
- **该测试用 `Mode="llm"`**——跑真实生产路径（L3 Planner + bus agents），只是 client 是假的。不测 legacy scanner 分支（PR-10 待退役）。
- 保住端到端"管道接通"覆盖。假 client 需为多个阶段准备写死回答（fixture 较重）——接受此成本。

### 4.6 heuristic 与 legacy-scanner 分支的解耦
现状：`TestPipelineHeuristic` 靠 `Mode="heuristic"` 走 else 分支（legacy scanner）+ 各 agent 的 heuristic 子模式。删 heuristic 后：
- agent 阶段（architecture/invariants/expert/challenger/verifier/arbiter）在**两个分支下都接收注入的 client**、恒走 llm——不管 pipeline 走 L3 还是 legacy scanner。
- `Mode=="llm"` 这个门仅作 **L3-Planner vs legacy-scanner** 选择器**保留**（与 heuristic 无关）。legacy 分支保留、能编译（其 agent 也接注入 client），但不为它单独写测试。

---

## 5. 非目标（本期不做）
- 新增/验证 GLM 以外的 provider（v1 GLM-only 决定不变）。
- 面向开发者的"喂固定回答离线跑整个流程"的运行时 debug 模式（那是另一个功能，默认不做）。
- 改动 pipeline 的 `Mode==llm` 选 L3-planner-vs-legacy-scanner 逻辑（与 heuristic 无关，保留）。
- 触碰 `llm.NewClient` 的 provider 选择逻辑。

---

## 6. 验收标准
1. 生产代码中不再存在任何 agent 的 heuristic 分支、`BuildHeuristic`、`*Mode` 子字段、`-mode heuristic` 语义。
2. 每个需 LLM 的 agent 入口接收注入的 `llm.Client`；`llm.NewClient` 只在 `pipeline` 与 `cmd/teecheck` 构造。
3. 8 个原 heuristic 测试改为注入假 client，全部通过且断言仍验证真实行为。
4. `TestPipelineHeuristic` 按 §4.5 结论处理（保留=注入假 client / 删除）。
5. `go build ./...`、`go vet ./...`、`go test ./...` 全绿；teecheck-benchmark 不受影响。
6. `grep -rn "heuristic" internal/ cmd/`（非注释）无生产逻辑残留。

---

## 7. 待实现阶段决定的细节
- §3.3 各文件是否真有 heuristic 逻辑分支（vs 纯注释/字符串）。
- 假 client 的放置：每包各自定义，还是抽一个共享的 `internal/llm/llmtest` 测试辅助包（若多包需要相似 fake，共享更 DRY）。
- `Mode` 字段最终形态（report 的 synthesized-only；run/scan 的 `-mode` 是否保留为 llm-vs-legacy 语义）。
