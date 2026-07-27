# llm 路径的 Case Pack 生成 — 设计文档

> 日期：2026-07-27
> 分支：`merge/tee-audit-integration`
> 状态：设计待确认
> 起因：对 `runs/CVE-2016-6129-baseline` 的单 run 审计

---

## 0. 给不熟悉本项目的读者

TEECheck 用一串 LLM Agent 审计 TEE 代码。流水线的中段是这样交接的：

```
planner(L3 侦查) → 03_cases/*.json → expert → challenger → verifier → arbiter
```

`03_cases/` 里的每个文件是一个 **Case Pack**（`artifacts.CasePack`）——把一处可疑点收敛成有边界的复核单元，交给后面四个 Agent。它是 planner 与下游之间**唯一**的数据通道。

本设计修复的是：这条通道上，携带知识最多的那一份 Case Pack **从来没有被任何下游读到过**。

---

## 1. 问题

### 1.1 两个生产者，一个消费不到

`03_cases/` 有两个写入方：

| 写入方 | 执行顺序 | 文件名 | 来源 |
|---|---|---|---|
| `planner/planner.go:518-525` | 第 4 步 | `<investigation_id>.json`，例如 `inv-flow-001-3a998d336f97.json` | planner `done` 负载里的 `investigations[]`，经 `investigations.BuildCasePack` |
| `cases/run.go:41-46` | 第 5 步 | `case-%03d.json` | `02_hotspots/hotspot_index.json`，而后者是 planner 自己写的**兼容垫片**（`planner/shim.go` 的 `WriteHotspotShim`，把 `candidates[]` 伪装成旧格式） |

下游 6 个包、7 处调用点,全部以 `case-*.json` 做 glob：

```
internal/expert/run.go:33
internal/challenger/run.go:33
internal/verifier/run.go:54
internal/arbiter/run.go:149
internal/pipeline/run.go:496
internal/stats/collector.go:224
internal/stats/review.go:48
```

`inv-` 不匹配 `case-*` ⇒ **planner 写的那份落盘即死。**

### 1.2 死掉的是携带 playbook 经验的那一份

两个生产者填的是同一个 `artifacts.CasePack` 类型的**互补**字段子集（`artifacts/types.go:173` 的注释写着 "The fields below are additive (PR-06)"）：

| 字段 | planner（investigation 派生） | cases（垫片派生） |
|---|---|---|
| `related_twes` / `related_invariants` / `architecture_refs` / `tool_fact_refs` | ✅ | ❌ |
| `required_evidence` / `coverage_gaps` / `missing_links` | ✅ | ❌ |
| **`common_defenses` / `common_false_positives`** | ✅ | ❌ |
| `snippets`（代码片段） / `knowledge_hints` | ❌ | ✅ |
| `hotspot_id` / `why_selected` / `expected_obligations` / `graph_facts` | ❌ | ✅ |

`planner.go:517-523` 显示，`playbook.CommonDefenses` / `CommonFalsePositives` 的**唯一下游投递通道就是这份 pack**。

**因此：playbook 的经验内容从未到达过 expert / challenger / verifier / arbiter。** 它只到达过 planner——通过 `BuildSystemPrompt` 的 prompt 注入。

### 1.3 为什么没被发现

引入这条路径的是 `bf9ead6`（PR-06，**2026-07-23**）。它把投递管道的两端都建好了：写盘（`planner.go:525`）、也挂到了 `RunResult.CasePacks`（`planner.go:461`）。然后**两端都没接**：

- 文件名不匹配下游 glob
- `RunResult.CasePacks` 的唯一读者是 `planner/rollback_investigation_test.go:123`，一个断言 `len(result.CasePacks) == 1` 的测试

那个测试证明了"pack 被造出来了"，没人测"pack 被读到了"。这是本次事故的直接教训，见 §6 验收标准 3。

缺陷只存在了 4 天，但**这 4 天覆盖了本项目至今全部的 playbook 对照测量**（`flow.yml` 于 07-26、`guard.yml` 于 07-27），因此影响面与存在时长无关。在 PR-06 之前不存在孤儿 pack——因为那时根本没有 investigation 路径。

### 1.4 影响面（实测）

对 `runs/` 下全部 29 个 L3 run 逐个统计：

| run 类型 | candidates | investigations | 现状实际产出的 case |
|---|---|---|---|
| 18 个 benchmark run（当前 pipeline） | 0–2 | **1–3，18/18 全非空** | 只有 candidate 那条 |
| 10 个真实项目扫描（`scan-20260520-*`） | 1–4 | 0 | 只有 candidate 那条 |

**注意**：那 10 个项目扫描没有 `01_context/` 目录——它们早于 TWE / architecture / invariant 接线，是旧 pipeline 的产物。**它们不能作为"大仓库上 investigation 是否可靠"的证据**，那个问题目前无数据（见 §8 风险 1）。

两个直接后果：

1. **5 个 run 现在记录为"0 候选"，实际各有 1–3 个 investigation 被丢弃**：`CVE-2019-0876-baseline`、`CVE-2019-1010293-baseline`、`CVE-2021-43619-baseline`、`CVE-2016-6129-withguard`、`probe-vuln`。

   但被丢弃的内容**多数是空的**——逐个查 `filled_roles` 后：

   | run | filled_roles | missing_roles |
   |---|---|---|
   | `CVE-2019-0876-baseline` | 0 | 3 |
   | `CVE-2021-43619-baseline` | 0 | 5 |
   | `probe-vuln` | 0 | 5 |
   | `CVE-2016-6129-withguard` | 1 / 1 / 0 | 0 / 0 / 2 |

   前三个的 investigation 记录的是"我找了这个 TWE，全部角色都没定位到"——它们**没有可交给下游的目标**。这五个 run 里真正有实质内容被丢弃的只有 `CVE-2016-6129-withguard`。这直接决定了 §4 组件 1 的空目标规则。

2. **`flow.yml` 与 `guard.yml` 两次对照测量的结论均不成立。** 两份测量记（`notes/2026-07-26-flow-playbook-measurement.md`、`notes/2026-07-27-guard-playbook-measurement.md`）比较的是 candidate 路径的产出，而 playbook 经验字段走的是被丢弃的那条通道。修复后必须重跑，在此之前不得引用这两份结论。

---

## 2. 已确认的机械事实

在设计前逐条核实过，作为下面各项决定的依据：

| 事实 | 位置 | 对设计的影响 |
|---|---|---|
| `candidates` 与 `investigations` 是 `done` 负载里两个独立列表，无 ID 关联，`investigations` 标注为 `(optional)` | `planner/prompt.go:70` | 两者不能互相推导，必须各自处理（§3 决定 2） |
| `CasePack.CaseID` 的格式在全仓**没有任何代码解析** | 全仓 grep 无 split/parse/prefix 命中 | 可以让两个生产者各自保留自己的 ID 形态，无需统一格式，也无需新增字段 |
| `cases.Run` 被 llm 路径与 legacy 路径共用 | `pipeline/run.go:159` 与 `:184` | 改动必须以不触碰 legacy 分支的方式进行（§4 组件 3） |
| `planner/actions/legacy_keyword_scan.go:62` 这个 planner **动作**自身会跑 `mapper.Run` 写 `01_repo_map`/`02_hotspots`，而后 `WriteHotspotShim` 再覆盖它们 | 同左 | 这是清单里的 "`twescan` legacy bypass"，与垫片是两件事，**本期不动**（§7） |

### 2.1 去重规则在真实数据上的分布（29 个 L3 run 全量统计）

把每个 run 的 candidate 路径集合与 investigation 的 `filled_roles` 路径集合逐一比对：

| 情形 | 出现次数 |
|---|---|
| 两侧集合**完全相等** | 14 |
| **部分重叠但不相等** | **0** |
| 完全不相交 | **0** |
| 至少一侧为空 | 15 |

**"部分重叠"这个分支在真实数据上一次都没有出现过。** 这不意味着它不会发生（29 个样本、其中 18 个是 1–4 个文件的 fixture），但它说明：去重规则的复杂度主要是防御性的，而"两侧指向同一个文件"才是主导形态。规则仍按 §4 组件 1 的写法实现并全分支单测，但设计上不应为"部分重叠"付出额外代价。

---

## 3. 两个已定的决定

### 决定 1：llm 路径改由 investigation 主导，垫片在该路径下退休

备选与取舍：

- **只接通管道**（改文件名或放宽 glob）——最小改动，但两条 pack 路径继续并存，下游会同时看到同一批候选的富、贫两份 case，必须另定合并规则，垫片和字段质量问题全部保留。**否决**：只是把问题从"看不见"变成"看得见"。
- **全面重构 L3 的 case 生成**——连硬编码 `expected_obligations` 表、幻觉 `why_selected` 一并重做。**否决**：范围过大，且 `why_selected` 的可信度问题属另一议题。
- **采纳**：llm 路径下 planner 直接产出 Case Pack，`cases` 阶段退化为 enrich；垫片 `WriteHotspotShim` 删除；legacy 路径原样不动。

### 决定 2：candidates 与 investigations 都转成 Case Pack，按 target_files 去重

备选与取舍：

- **只认 investigations，无回退**——最干净，但 `investigations` 在 schema 里是 optional，且大仓库上的可靠性无数据（§1.4）。**否决**：可能把真实项目扫描静默打成全空。
- **investigation 优先，为空时回退垫片**——最保守，但垫片必须保留（与决定 1 冲突），且回退是**静默**的：运行看上去正常，下游却沙了 playbook 知识，日志上区分不出。**否决**：静默降级正是本次事故的形态。
- **采纳**：两者都转 pack。investigation 派生的字段富，candidate 派生的字段瘦但不丢。垫片可删，也不会因模型未吐 investigation 而归零。

代价：同一处漏洞可能出两份 case。去重规则见 §4 组件 1。

---

## 4. 组件设计

### 组件 1：`internal/planner/casepacks.go`（新建）

接管 `shim.go` 在 llm 路径的职责。三个导出函数：

```go
// BuildFromCandidate 把一个 planner candidate 转成瘦 Case Pack。
func BuildFromCandidate(cand artifacts.Candidate, manifest artifacts.Manifest) artifacts.CasePack

// Merge 按 target_files 集合去重，返回最终要落盘的 pack 列表。
func Merge(rich, thin []artifacts.CasePack) []artifacts.CasePack

// Write 把 packs 统一写成 03_cases/case-%03d.json。
func Write(runDir string, packs []artifacts.CasePack) error
```

**去重规则（本设计的主要风险点，必须写死并单独测）：**

- key = `TargetFiles` 排序去重后的**集合**
- **只有集合完全相等才合并。** 交集非空但不相等 ⇒ **不合并**，各自成为独立 case。
- 合并时以富 pack 为底，并入瘦 pack 的 `WhySelected`；`Priority` 取两者中较高者（high > medium > low）。
- 富 pack 排在瘦 pack 之前编号（`case-001` 起），使编号顺序稳定可复现。

**规则的理由**：宁可多出一个 case（expert 多跑一次，成本可见、可测量），不可合并掉两个不同漏洞（损失静默、且正是本次事故的形态）。§2.1 的实测显示"部分重叠"分支在现有数据上从未触发，因此这条规则的代价目前是零，但仍需实现与单测。

**空目标规则：`TargetFiles` 为空的 pack 不落盘。**

一个 `filled_roles` 全空的 investigation（所有角色都在 `missing_roles` 里）转成的 Case Pack 没有任何文件可供下游查看——把它交给 expert 等于要求 expert 对着空气做假设。§1.4 的实测显示这种形态占被丢弃 investigation 的多数（5 个 run 中的 3 个）。

该 investigation 的记录**不会丢失**：它仍完整保存在 `03_investigations/`，并按 planner 系统提示（`prompt.go:88`）的定性，是"下一步侦查任务"，不是漏洞结论、也不是安全证据。它只是不构成一个 case。

### 组件 2：`internal/planner/shim.go`

删除 `WriteHotspotShim` 及其调用点。llm 路径下不再写 `01_repo_map/` 与 `02_hotspots/`。

（`legacy_keyword_scan` 动作若被 LLM 调用，仍可能写这两个目录——那是该动作的既有行为，不在本期范围。）

### 组件 3：`internal/cases` 拆两个入口

- `Run(cfg)` — **签名与行为完全不变**，legacy 路径继续使用。
- `Enrich(cfg)` — 新增。读 `03_cases/case-*.json`，为每份补两个字段后回写：
  - `Snippets` ← 复用现有 `collectSnippets(manifest.LocalPath, pack.TargetFiles, pack.TargetSymbols)`
  - `KnowledgeHints` ← 复用现有 `knowledge.LookupForCase(knowledgeRoot, pack, 4)`

两个入口共用现有 helper，**不复制实现**。

### 组件 4：`internal/pipeline/run.go:159`

llm 分支的 `cases.Run(stageCfg)` 改为 `cases.Enrich(stageCfg)`。`:184` 的 legacy 分支一个字符都不改。

### 组件 5：`internal/planner/planner.go:524-529`

`processInvestigations` 不再自行写盘，只返回 packs。写盘统一由 `casepacks.Write` 承担，使编号与去重在同一处发生。

### 组件 6：`internal/symbolcheck`（新建）+ `internal/investigations/validate.go`

**为什么在本期做**：接通管道会把 `filled_roles` 里的幻觉符号一并送到下游。审计在 `runs/CVE-2016-6129-baseline` 的 `inv-flow-001-3a998d336f97.json` 中发现 `filled_roles` 有一项 `{line: 141, symbol: "der_decode_sequence_flexi"}`，而该符号在整个 fixture 中**不存在**（141 行是 `LTC_SET_ASN1`，143 行是 `der_decode_sequence`）。它通过了校验，因为 `validate.go:183` 的 `validateRoleLocations` **只 `os.Stat` 文件是否存在，不检查符号**。

在管道接通之前，这个幻觉止步于一个没人读的孤儿文件；接通之后它会直达 expert。**修复放大缺陷，因此缺陷必须同期修。**

**新建 `internal/symbolcheck`**，暴露一个函数：

```go
// FileContainsSymbol 报告 symbol 是否作为大小写不敏感的子串出现在
// repoRoot/path 的文件内容中。
func FileContainsSymbol(repoRoot, path, symbol string) (bool, error)
```

**为什么是新包而不是放进 `internal/citations`**：`architecture/validate.go:280-287` 有一条明确的既有设计决定——citations 包的职责止于"证明字节区间存在且哈希一致"，"这段内容是否包含 X"属于项目理解层，刻意不放进去。本设计遵守该决定。

**为什么是共享包而不是就地写 5 行**：这个概念已经有三个消费者——`architecture`（已实现）、`investigations`（本期）、`verifier` 的 citation 校验（§7 点名的下一份 spec）。本项目刚刚被"两处本该一致却不一致"咬过一次。

**`internal/architecture` 的改动范围（精确）**：只把 `validate.go:248-254` 那段"无行号分支的整文件包含性检查"替换为调用 `symbolcheck.FileContainsSymbol`，行为逐字保持一致（同样大小写不敏感、同样的失败文案）。**`citedRegionContains`（`validate.go:288`，按字节区间检查）不动、不搬**——它读的是 `citations.Resolve` 后的字节区间，与整文件检查是两个不同的问题，合并它们需要先想清楚 verifier 那份 spec 要哪一个，本期不预判。

**`validateRoleLocations` 的改动**：在现有 `os.Stat` 检查之后追加一步——若 `loc.Symbol` 非空且未出现在该文件中，同样降级进 `MissingRoles`，`Adjustment.Kind` 用新值 `unresolved_role_symbol`（与既有的 `unresolved_role_location` 并列）。`loc.Symbol` 为空时跳过该步，不改变现有行为。

**刻意不做的**：不检查符号是否出现在 `loc.StartLine` **附近**。整文件包含性能证明地捕获已观察到的缺陷形态，且不引入"附近是多少行"这个任意常数。代价是"符号确实在文件里、但 `start_line` 指错了地方"这一形态仍会漏过——记入 §8 风险 5。这与 `architecture/validate.go:252` 无行号分支的既有做法一致。

### 数据流（改后）

```
planner done 负载
  ├─ investigations[] → investigations.BuildCasePack → 富 pack
  └─ candidates[]     → casepacks.BuildFromCandidate → 瘦 pack
                             ↓
                    casepacks.Merge（target_files 集合相等才合并）
                             ↓
                    casepacks.Write → 03_cases/case-%03d.json
                             ↓
                    cases.Enrich（补 snippets + knowledge_hints）
                             ↓
              expert → challenger → verifier → arbiter
```

---

## 5. 连带后果（明确记录，非疏漏）

垫片删除后，`expected_obligations` 在 llm 路径下**会消失**——它唯一的来源是 `cases/run.go:277` 的 `caseTemplate(hotspot.Kind)` 硬编码表。

- 富 pack 以 `required_evidence`（来自 playbook 与 investigation）承担同一角色。
- 瘦 pack 则没有该字段。

这是删除垫片的自然结果，不是额外重构。审计恰好证明了那张表的产出质量：在 `CVE-2016-6129-baseline` 中，category `boundary` 一律产出"授权与调用方绑定 / 信任边界重校验 / 安全失败行为"三条，与该案（RSA 签名校验）毫无关系，而 challenger 花了约一半篇幅去反驳这组无关义务。

**该后果已向决策者说明并获确认。**

### 5.1 一个本节最初漏掉的字段：`Category`（已修正）

本节最初只点了 `expected_obligations`。实施期间的复审发现 `Category` 也走同一条垫片链，而它**不是**可以一并作废的：

`internal/cases` 的 `caseTemplate(kind)` 对 `attestation` / `authorization` / `state_machine` / `key_management` / `fallback` 五个 kind 是恒等映射，其余归 `boundary`；`internal/arbiter` 的 `severityForCategory` 再把 `attestation` / `authorization` / `key_management` 判为 **high**，其余 medium。

若瘦 pack 的 `Category` 留空，一个模型标注为 `attestation` 的候选会从 severity `high` 静默降为 `medium`——出现在最终 findings 里，日志上看不出。

**处置**：`BuildFromCandidate` 用 `categoryForKind` 复现同一映射（仅 category，不复制 obligations 与 open-questions 列表）。这是**保持现状**，不是新增行为。

**另记**：富 pack 的 `Category` 取自 `inv.Classification`，值域是 `standard` / `variant`，落进 `severityForCategory` 的 default 分支恒为 medium。这是 PR-06 以来的既有行为，本期不改，记入 §8 风险 7。

---

## 6. 验收标准

全部验收以单测形式表达，输入手写构造。**不依赖 `runs/` 下的任何历史运行**——那些运行是坏 pipeline 的产物，它们的价值已经在 §1.4 与 §2.1 的统计中被提取完毕，随后即被删除。

| # | 标准 |
|---|---|
| 1 | **消费者侧读回测试**：由 planner 路径落盘一批 pack，再用 expert 所用的同一 glob（`case-*.json`）读回，断言富 pack 的 `common_defenses` / `common_false_positives` / `required_evidence` 非空。PR-06 缺的正是这个测试，它是本次事故的直接防线 |
| 2 | **去重规则单测**，覆盖四种输入：集合相等（合并，且 `WhySelected` 并入、`Priority` 取高）、交集非空但不等（不合并）、无交集（不合并）、一侧为空（各自保留） |
| 3 | **空目标规则单测**：`filled_roles` 全空的 investigation 不产生落盘文件；对应的 `03_investigations/` 记录仍然存在 |
| 4 | **编号稳定性单测**：同一批输入两次运行，`case-%03d.json` 的编号与内容一致（富 pack 在前） |
| 5 | `cases.Enrich` 单测：读一份已落盘的 pack，补上 `Snippets` 与 `KnowledgeHints` 后回写，其余字段逐字段不变 |
| 6 | **符号校验单测**：`filled_roles` 中 symbol 不存在于文件 → 降级进 `MissingRoles` 且产生 `unresolved_role_symbol` 调整记录；symbol 存在 → 保留；symbol 为空 → 保留（行为不变）。用审计中实际观察到的 `der_decode_sequence_flexi` 形态作为其中一个用例 |
| 7 | `internal/symbolcheck` 有独立单测；`internal/architecture` 改为调用它后，其既有测试全部仍然通过 |
| 8 | legacy 路径（`--mode` 非 `llm`）的产物逐字节不变 |
| 9 | `go build ./...` 与 `go test ./...` 两模块全绿（既有的 `internal/collabrun` live-endpoint 失败除外） |

---

## 7. 非目标

- **不修 verifier 的 citation 校验**（`internal/citations/validation.go` 只查 sha256 不查内容包含性）——同次审计发现的另一个严重问题，属"证据链诚实性"主题，单独一份 spec。本期新建的 `internal/symbolcheck` 是那份工作的现成材料。
- **不做符号的行号邻近性检查**——只做整文件包含性，理由见组件 6。
- **不改硬编码 `expected_obligations` 表本身**（只是让它在 llm 路径下失去消费者）。
- **不动 legacy 路径**的任何代码。
- **不动 `legacy_keyword_scan` 动作**与它写垫片目录的行为。
- **不动 planner 的上下文窗口**（`prompt.go:333` 的 `LastRoundsForPrompt(2)`）——归入 web 观察窗议题。
- **不在本期重跑 flow / guard 对照测量**——修复合入后单独进行。

---

## 8. 已知风险

1. **大仓库上 investigation 的产出率无数据。** 18/18 benchmark run 都产出了 investigation，但它们全是 1–4 个文件的 fixture。真实项目扫描的 10 个样本早于该功能，不构成证据。决定 2 采纳"两者都转 pack"正是为了让这个未知不致命：即便大仓库上 investigation 为空，candidate 路径仍会产出 case。

2. **去重规则的保守方向目前无代价，但也未被验证。** "集合完全相等才合并"理论上会让部分重叠的候选各自成 case、增加 expert 调用次数；而 §2.1 的实测显示该分支在 29 个 run 上从未触发，所以当前代价为零。反过来说，这也意味着**该分支的正确性只由单测保证，没有任何真实数据背书**。若将来在大仓库上观察到 case 数膨胀，再考虑放宽——放宽前需要一个衡量"被合并掉的两份是否确实同一处"的方法。

3. ~~富 pack 的 `filled_roles` 可能含幻觉符号~~ — **已纳入本期范围**，见组件 6。原风险为："接通管道会放大该缺陷，两份工作的先后顺序需要留意"；解决方式是不留时间窗，同期修。

4. **本次事故的形态是"造了但没接"，而修复引入的新代码同样有这个风险。** 验收标准 1 就是针对它设的：任何新增的产出通道都必须有一个从消费者一侧读回来的测试，而不是只断言产出存在。

5. **符号校验只做整文件包含性，"符号在文件里但 `start_line` 指错位置"仍会漏过。** 这是组件 6 刻意的取舍（不引入任意的邻近窗口常数）。若将来发现该形态在真实数据上频繁出现，再考虑加窗口——加之前需要先量出一个有依据的窗口大小，而不是拍一个数字。

7. **富 pack 的 `Category` 恒为 `standard` 或 `variant`，因而 `severityForCategory` 恒判 medium。** 这是 `investigations.BuildCasePack` 自 PR-06 起的既有行为（`Category: inv.Classification`），本期不改。后果：investigation 派生的 case 无法被评为 high，无论它涉及的是 attestation 还是 key management。修它需要先决定 investigation 的 classification 与 case 的 category 是不是同一个概念——它们看起来不是。属证据链诚实性那份 spec 或其后续。

6. **整文件子串匹配会有假阴性放行以外的另一面：短符号可能假阳性通过。** 例如符号 `i` 或 `ok` 几乎必然出现在任何 C 文件中，于是校验形同虚设。本期不加最小长度限制——`architecture/validate.go:252` 的既有实现同样没有，而统一两处行为的价值高于各自打补丁。若要加，应两处一起加，属 §7 点名的那份 spec。
