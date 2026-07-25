# TWE Playbook 分层注入 — 设计文档

> 日期：2026-07-24
> 分支：`merge/tee-audit-integration`
> 状态：设计待确认
> 关联：架构文档决策 #2（TWE 是经验剧本、全量注入、不做 RAG）；`internal/twecontext` 的 `maxPlaybookContextTokens = 900`。

---

## 1. 背景

当前 playbook 走**全量、无条件、注入所有 agent**（决策 #2），因此每份被硬限在 **900 token**（`context.go:46`；实测 rollback.yml 已占 720，余量仅 180）。后果是经验被压成标识符式的短语：

```yaml
look_for:
  - version_or_epoch_fields_that_are_declared_but_never_assigned_before_a_guard_reads_them
common_false_positives:
  - a_non_replayable_anchor_is_checked_before_any_security_effect
```

真正有用的经验（具体 API 名、代码模式、"为什么这是防御而那不是"的因果）写不进去。这形成一个三难：**丰富的经验 / 16 族全覆盖 / 全量注入**，三者只能取二。当前实现牺牲了「丰富」。

**目标**：解开这个三难——保住决策 #2 的核心（不因未选中就看不见某个漏洞族），同时让被关注的族能拿到真正详细的经验。

---

## 2. 核心决策

**分层注入**：同一份 playbook 渲染成两档。

| 档 | 内容 | 到达方式 | 预算 |
|---|---|---|---|
| **brief（简版）** | id / name / family / scenario / look_for | **全量注入所有 agent**（沿用现有 `twe_agent_context.txt` 通路） | **250 token/份**（16 份 ≈ 4K） |
| **detail（详版）** | 全部 13 个字段 + 允许自然语言展开 | **planner 通过新 action `twe_playbook_detail(twe_id)` 按需拉取** | **3000 token/份** |

- **单一真相源**：detail 不是新文件、不加 schema 字段——就是现有 YAML 的完整渲染。brief 是它的字段子集。`schemas/twe-playbook.v1.json` **不变**（13 个必填字段已够）。
- **成本**：全量部分从 14.4K(16×900) 降到 **4K**；详版只在 agent 主动索取时付费。

### 明确的范围取舍（已确认）
详版**只有 planner 能拉**——action 机制只存在于 planner 循环。expert / challenger / verifier / arbiter 仍只看到 brief。代价是复核链拿不到详版经验；接受此限制，理由是 planner 是决定"调查什么"的环节，收益最大，且不引入新的推送机制。后续若复核链也需要，再单独设计（见 §6 非目标）。

---

## 3. 设计

### 3.1 两个渲染函数（`internal/twecontext`）

现有 `compilePlaybookBlock`（:302）渲染全部字段。拆成：

- `compileBriefBlock(p Playbook) string` — 只渲染 `[ID] Name | family=`、`Scenario`、`Look for`。
- `compileDetailBlock(p Playbook) string` — 现有 `compilePlaybookBlock` 的行为（全部字段），改名保留。

`Compile()` 改用 brief，并把上限常量拆成两个：
```go
const maxBriefContextTokens  = 250   // 每份 brief 的编译期硬上限
const maxDetailContextTokens = 3000  // 每份 detail 的硬上限
```
两者都**fail closed**（超限即编译失败，不截断）——保持现有 `Compile` 的语义，理由不变：宁可不跑，也不给 agent 一份被砍半的知识。

detail 的上限在 `Load()`/`Validate()` 时检查（因为 detail 不参与 Compile，但必须在运行前就保证可用），这样一份写超的 playbook 在 preprocess 阶段就失败，而不是等 agent 拉取时才炸。

### 3.2 新增 API

```go
// Detail 返回单份 playbook 的完整渲染；ok=false 表示该 TWE ID 没有 playbook。
func (c *Catalog) Detail(tweID string) (text string, ok bool)
```

### 3.3 新 planner action：`twe_playbook_detail`

`internal/planner/actions/twe_playbook_detail.go`，与现有 action 同构（`Handler` 接口：`Name()` + `Run(ctx, ActionRequest) ActionResult`）：

- args：`{"twe_id": string}`
- 行为：查 catalog → 命中返回 detail 文本；未命中返回 `OK=false` + 错误说明（沿用其它 action 的失败约定：不返回 Go error，通过 `ActionResult.Error` 让 LLM 观察并改正）。
- handler 持有 catalog（构造时注入），与 `FactLayerQueryHandler` 持引擎的模式一致；注册在 `NewDefaultRegistryWithNav`/`WithFacts` 一侧（catalog 由 `runL3Planner` 加载后传入）。
- prompt：在 `actionArgSchemas` 加一行；APPROACH 里提示"当某个 TWE 与本次调查相关时，用 `twe_playbook_detail` 取该族的完整调查方法"。

### 3.4 复现性（重要）

现有 `TWEKnowledgeManifest` 用 `ContextSHA256` 钉住"agent 看见了什么"。分层后，**详版是运行时动态拉取的，不在这个哈希里**——复现性会出现缺口。

处理：detail 的每次拉取由 planner 现有的 action 事件机制记录（action 名 + `twe_id` + 结果哈希进 events/blobs，与其它 action 一致）。**Manifest 保持不变**（它钉的是全量注入的那一层，语义仍然准确）；"本次运行还额外看了哪些详版"从 events 可完整重建。这样不改 manifest schema，也不丢可追溯性。

---

## 4. 迁移现有 playbook

`rollback.yml` 当前 720 token（全字段）。分层后：
- 它的 brief（scenario + look_for）需 ≤250 token —— scenario 现为一段长句，**大概率超限**，需要压缩成 1–2 句。
- 它的 detail 保持现状即可（720 < 3000），且未来可自由扩写到 3000。

实现阶段必须实测 brief 渲染的 token 数并按需改写 `rollback.yml` 的 `scenario`（只压缩 scenario，不动其它字段——其它字段属 detail 层，正是要让它们能变丰富的地方）。

---

## 5. 测试

- `compileBriefBlock` 只含 scenario/look_for，不含 investigation_steps/defenses/false_positives。
- `compileDetailBlock` 含全部 13 字段。
- `Compile()` 对超 250 token 的 brief **fail closed**（构造一份超限 playbook 断言报错，且错误信息点名是哪一份）。
- `Load()`/`Validate()` 对超 3000 token 的 detail fail closed。
- `Catalog.Detail("TWE-STATE-001")` 命中返回全字段文本；`Detail("TWE-NOPE-999")` 返回 ok=false。
- action：命中返回 OK=true 且输出含 detail 特有字段（如 "False positives:"）；未命中返回 OK=false 且 Error 非空；args 非法（缺 twe_id）返回 OK=false。
- 迁移回归：现有 `rollback.yml` 能通过 Load + Compile（brief 不超限）。

---

## 6. 非目标
- 不给 expert/challenger/verifier/arbiter 增加拉取详版的机制（§2 已说明的范围取舍）。
- 不引入 RAG / embedding / 向量检索（决策 #2 不变：brief 仍是全量注入，不做相关性筛选）。
- 不新增 playbook YAML 字段，不改 `schemas/twe-playbook.v1.json`。
- 不改 `TWEKnowledgeManifest` schema。
- 不在本期编写新的 playbook 内容（覆盖面是独立议题；本期只解开预算枷锁）。

---

## 7. 验收标准
1. brief 全量注入，每份 ≤250 token，超限编译失败并点名。
2. detail 每份 ≤3000 token，超限在 Load/Validate 阶段失败。
3. planner 可用 `twe_playbook_detail(twe_id)` 取到全字段文本；未知 ID 得到明确错误而非空结果。
4. 拉取行为进 events，可从 events 重建"本次额外看了哪些详版"。
5. 现有 `rollback.yml` 迁移后可正常编译运行（必要时压缩其 scenario）。
6. `go build ./...`、`go vet ./...`、`go test ./...` 全绿（既有 collabrun live-endpoint 失败除外）。

---

## 8. 待实现阶段确认
- `rollback.yml` 的 scenario 压缩到 ≤250 token 后的具体措辞。
- catalog 传入 action handler 的确切装配点（`runL3Planner` 里已需加载 catalog——与 #5 spec 的 playbook 适配器共用同一次 `twecontext.Load`，避免重复加载）。
