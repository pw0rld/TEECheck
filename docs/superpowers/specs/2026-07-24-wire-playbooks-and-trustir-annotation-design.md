# 接入 TWEPlaybooks + TrustIR annotation — 设计文档

> 日期：2026-07-24
> 分支：`merge/tee-audit-integration`
> 状态：设计待确认
> 关联：审计 #5「一些组件已写好但没进生产流水线」。两块独立 wiring，都落在 `pipeline.runL3Planner`。

---

## 1. 背景与目标

两处"写好但没接进生产"的逻辑：

- **TWEPlaybooks**：planner 已会消费 playbook（`planner.go:501-506` 读 `cfg.TWEPlaybooks[twe].CommonDefenses/CommonFalsePositives`），但 `runL3Planner` 构造 `planner.RunConfig` 时（`run.go:338`）从不设 `TWEPlaybooks` 字段 → 永远空 → 常见防御/误报等 playbook 上下文进不了生产 CasePack。
- **TrustIR LLM 标注**：`trustirfacts.AnnotateFactTable` + `SetFactTable` 逻辑齐全，但生产代码零调用 → 生产只吃写死的 `knownFactTables` fixture；LLM 标注只在测试用。

目标：把这两块接进 `runL3Planner`，让 playbook 上下文进 CasePack、让未知仓库能用 LLM 标注的事实表——同时不改动 planner 循环、事实层查询语义或标注 prompt。

---

## 2. 核心决策

| 轴 | 决策 |
|---|---|
| TWEPlaybooks 转换层放哪 | pipeline 包（planner 刻意不依赖 twecontext，故在 pipeline 层做 `twecontext.Playbook → planner.TWEPlaybookSummary` 适配）。 |
| TrustIR 事实表优先级 | **known fixture 优先**。只有当该仓库**没有** known fixture 时才调 `AnnotateFactTable` + `SetFactTable`。已知 OP-TEE 仓库继续用可靠的确定性 fixture，行为不变。 |
| 标注失败/空表 | 记日志、回落到现状（known/StatusUnsupported），不硬失败。 |

---

## 3. 现状（已核实）

- `planner.RunConfig` 有字段 `TWEPlaybooks map[string]TWEPlaybookSummary`（`planner.go:95`）；`runL3Planner` 的 `planner.Run(ctx, RunConfig{...})`（`run.go:338`）**未设**它。
- `twecontext.Catalog` 有 `All() []Playbook`（`context.go:227`）——playbook 数据源。
- `runL3Planner(cfg, client, ...)` 现已接收注入的 `client`（可传给 `AnnotateFactTable`）。
- 事实层在 `runL3Planner` 构造：`eng := codeql.New()` → `NewDefaultRegistryWithFacts(eng, queryPackDir)`（`run.go:~300`）。
- `trustirfacts` 的 `factTableFor` / `knownFactTables` / `isLLMFactTable` / `normalizeRepo` **均未导出** → pipeline 无法直接判断"是否有 known fixture"。需新增一个导出谓词。
- `AnnotateFactTable(ctx, client, registry twe.EnumRegistry, sourceRoot string) (FactTable, AnnotationReport, error)` 与 `SetFactTable(repository string, table FactTable)` 已导出。
- enum 词表经 `twe.LoadEnumRegistry(path)` 加载；默认路径 `trustirfacts.DefaultEnumRegistryPath = "knowledge/twe/definitions/enum_registry.yml"`。

---

## 4. 设计

### 4A. TWEPlaybooks → CasePack

1. **新增 pipeline 适配函数**（pipeline 包内，例如 `run.go` 或新 `playbooks.go`）：
   ```go
   func playbookSummariesFrom(cat twecontext.Catalog) map[string]planner.TWEPlaybookSummary
   ```
   遍历 `cat.All()`，按每个 Playbook 的 TWE ID 建 map，把 `twecontext.Playbook` 的对应字段拷进 `planner.TWEPlaybookSummary`（字段以 `planner.TWEPlaybookSummary` 定义为准：至少 `CommonDefenses`、`CommonFalsePositives`；实现时按结构体逐字段映射，不多不少）。
2. **加载 catalog**：`runL3Planner` 用 twecontext 加载 playbook catalog（与 preprocessor 编译 TWE 上下文相同的数据源/路径 `knowledge/twe/playbooks/` 下的 YAML）。若加载失败，记日志、`TWEPlaybooks` 留空（planner 现有的 `cfg.TWEPlaybooks[...]` 查询本就容忍空 → 降级不崩）。
3. **设进 RunConfig**：`planner.RunConfig{ ..., TWEPlaybooks: playbookSummariesFrom(cat) }`。

效果：planner 现成的 playbook 查询返回真实内容 → CommonDefenses/CommonFalsePositives 流入 CasePack。

### 4B. TrustIR annotation → 生产（known 优先）

1. **trustirfacts 新增导出谓词**：
   ```go
   // HasKnownFactTable reports whether repository has a hand-authored
   // deterministic fixture (independent of any LLM-annotated table).
   func HasKnownFactTable(repository string) bool {
       _, ok := knownFactTables[normalizeRepo(repository)]
       return ok
   }
   ```
2. **runL3Planner 决策**（在构造事实层 registry 前，已有 `client`、`repository`（`manifest.RepoURL`）、`sourceRoot`（`fetch.LocalPath`/`manifest.LocalPath`））：
   ```go
   if !trustirfacts.HasKnownFactTable(repository) {
       reg, err := twe.LoadEnumRegistry(filepath.Join(cfg.KnowledgeRoot, "twe", "definitions", "enum_registry.yml"))
       if err != nil {
           // log: cannot load enum registry — skip annotation, fall back
       } else {
           table, report, aerr := trustirfacts.AnnotateFactTable(ctx, client, reg, sourceRoot)
           if aerr == nil && !table.Empty() {
               trustirfacts.SetFactTable(repository, table)
           } else {
               // log: annotation failed/empty — fall back to deterministic/unsupported
           }
       }
   }
   ```
3. 已有 known fixture 的仓库：跳过整段 → 行为与现状完全一致。

效果：已知 OP-TEE 仓库用可靠 fixture；未知仓库靠 LLM 标注补；两条都在失败时安全回落。

---

## 5. 测试

- **4A**：单元测 `playbookSummariesFrom`——给一个含某 TWE playbook 的 catalog，断言输出 map 在该 TWE 键下带正确的 CommonDefenses/CommonFalsePositives。
- **4B-谓词**：`HasKnownFactTable` 对一个已知 fixture 仓库返回 true、对随机仓库返回 false。
- **4B-决策**：用 fake `llm.Client` 驱动决策逻辑——
  - known 仓库 → `AnnotateFactTable` **不**被调用（fake client 的 `Calls` 为空）、`SetFactTable` 未设。
  - 未知仓库 → annotate 被调、成功非空 → `SetFactTable` 生效（后续 `factTableFor` 命中 LLM 表）。
  - 未知仓库 + fake 返回空/错 → 不 `SetFactTable`，安全回落。
  决策逻辑宜抽成一个可测的纯函数/小 helper（如 `maybeAnnotateFactTable(ctx, client, repo, sourceRoot, enumPath) (annotated bool, err error)`），避免只能通过整条 pipeline 才能测。

---

## 6. 非目标
- 不改 planner 探索循环、事实层查询（薄壳 `.ql`）语义、标注 prompt 本身。
- 不改 factsource 的 LLM-优先合并逻辑（只是通过"有 known 就不标注"从调用侧实现 known 优先）。
- 不扩展 `AnnotateFactTable` 的覆盖面或新增 operation（那是 #6/后续）。
- 不动 CasePack schema（playbook 字段已存在于 planner 的 investigation/CasePack 产出路径）。

---

## 7. 验收标准
1. `runL3Planner` 设置 `RunConfig.TWEPlaybooks`；带 playbook 的 TWE 对应的 case 携带 CommonDefenses/CommonFalsePositives。
2. `trustirfacts.HasKnownFactTable` 导出且正确。
3. 已知 fixture 仓库：`AnnotateFactTable` 不被调用（行为不回归）；未知仓库：被调用且成功时 `SetFactTable` 生效。
4. 标注失败/空 → 安全回落，pipeline 不崩。
5. `go build ./...`、`go vet ./...`、`go test ./...` 全绿（除既有 collabrun live-endpoint 失败）；benchmark 不受影响。

---

## 8. 待实现阶段确认的细节
- `planner.TWEPlaybookSummary` 的确切字段集（逐字段映射，以结构体定义为准）。
- twecontext catalog 在 `runL3Planner` 的确切加载入口（复用 preprocessor 用的 loader / 路径）。
- `repository` 与 `sourceRoot` 在 runL3Planner 里的确切变量（`manifest.RepoURL` vs `cfg.RepoURL`；`fetch.LocalPath` vs `manifest.LocalPath`）。
