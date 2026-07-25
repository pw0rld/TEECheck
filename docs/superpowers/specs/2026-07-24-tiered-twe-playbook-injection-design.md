# TWE Playbook 分层注入 — 设计文档

> 日期：2026-07-24
> 分支：`merge/tee-audit-integration`
> 状态：设计待确认
> 代码：`internal/twecontext/`、`internal/preprocessor/twe_context.go`、`internal/planner/`
> 相关：架构文档《TEECheck × tee-audit 融合架构快照》§5 决策 #2

---

## 0. 给不熟悉本项目的读者

TEECheck 是一个用多个 LLM Agent 审计 TEE（可信执行环境，如 OP-TEE）代码的系统。它的一条核心设计是：**在 Agent 开始工作前，先把 TEE 领域的漏洞经验注入它们的 prompt**，让 Agent 知道"该找什么、什么算证据、什么是常见误报"，而不是让一个通用模型盲看代码。

这份经验的载体叫 **TWE Playbook**。

- **TWE**（TEE Weakness Entry）= TEE 漏洞族分类，共 **16 条**，如 `TWE-STATE-001 状态回滚`、`TWE-FLOW-001 宿主机数据到达 enclave 安全决策`。这层只是**锚点**（id/name/family），来自上游项目 tee-audit，不进 prompt。
- **Playbook** = 针对某一族的**调查方法论**，是本项目自己新增的一层（tee-audit 没有此概念）。它进 prompt，是真正驱动 Agent 行为的东西。

一份 playbook 是一个 YAML，13 个必填字段。以现存唯一一份 `knowledge/twe/playbooks/rollback.yml` 为例（节选）：

```yaml
id: TWE-STATE-001
name: Trusted State Rollback
family: State
scenario: >
  攻击者控制不可信持久化存储，恢复旧版本的 TEE 受保护状态……完整性/签名校验
  仍然通过，但可信计算接受了陈旧的安全状态，因为新鲜性没有锚定在可重放状态之外。
look_for:                      # 去哪找
  - version_or_epoch_fields_that_are_declared_but_never_assigned_before_a_guard_reads_them
investigation_steps:           # 按什么步骤查
  - trace_version_epoch_or_counter_fields_to_the_runtime_object
required_evidence:             # 什么才算证据成立
  - freshness_anchor_is_itself_replayable_alongside_the_state
common_defenses:               # 见到这些说明有正确防御，别误报
  - hardware_monotonic_counter
common_false_positives:        # 典型误报模式
  - restored_state_is_only_a_non_security_cache
```

---

## 1. 现状：这套机制现在怎么运转

### 1.1 一次运行的完整链路

```
knowledge/twe/playbooks/*.yml
        │  preprocess 阶段（preprocessor/run.go:50 调 compileTWEKnowledge）
        ▼
   twecontext.Load(dir)      加载 + 逐份 Validate
        │
        ▼
   Catalog.Compile()         把【全部】playbook 拼成一段纯文本
        │                    （不做检索、不做筛选、不用 embedding）
        ▼
runs/<id>/01_context/twe_agent_context.txt      ← 实测 2872 字节
        │
        └─→ 注入 7 个 Agent 的 prompt：
              architecture / invariants / planner /
              expert / challenger / verifier / arbiter
```

同时产出 `twe_knowledge_manifest.v1.json`，用 `CatalogSHA256` / `ContextSHA256` / `TWEIDs` 钉住"本次运行 Agent 到底看见了哪些知识"，用于复现。

### 1.2 全量注入是刻意的设计决策

架构文档 §5 决策 #2 原文：

> **TWE 是经验剧本，不是 RAG** —— 全部 TWE 编译成前置上下文一次注入，不用 embedding / 向量检索。**不因画像没选中就让 Agent 看不到某个漏洞族。**

这个决策有充分理由：漏检（miss）是安全审计里最严重的失败模式。如果靠相关性检索决定"给 Agent 看哪几族"，检索错了就等于让 Agent 对某类漏洞天生失明，而且这种失明是静默的。

### 1.3 由此产生的预算枷锁

因为**每份 playbook 都要进 7 个 Agent 的每次 LLM 调用**，单份变胖的成本被放大。所以代码里设了一个编译期硬上限（`internal/twecontext/context.go:46`）：

```go
const maxPlaybookContextTokens = 900
```

超限**直接编译失败**，不截断（原注释：`must fail closed here, not truncate`）——宁可不跑，也不给 Agent 一份被砍掉一半的知识。这个 fail-closed 语义本身是对的，应保留。

---

## 2. 问题

### 2.1 现象：经验被预算压成了标识符

`rollback.yml` 实测已占 **720 token**（上限 900，余量仅 180 token ≈ 720 字符）。为了塞进去，内容被写成了这样：

```yaml
- version_or_epoch_fields_that_are_declared_but_never_assigned_before_a_guard_reads_them
- a_non_replayable_anchor_is_checked_before_any_security_effect
- the_guards_input_is_confirmed_written_from_a_live_source_on_every_call_path_to_it
```

**这是被压缩成 snake_case 标识符的自然语言。**真正有用的审计经验需要的是：具体 API 名（`TEE_GetPersistentObject`、RPMB 计数器）、代码模式示例、"为什么这算防御而那不算"的因果解释、真实 CVE 的引用。这些一写进去就爆 900。

换句话说：**900 这个数字不是"留了 25% 余量"，而是把知识锁死在了当前这种压缩形态。**

### 2.2 各字段实测占用

| 字段 | token | 分层归属 |
|---|---:|---|
| scenario | 98 | brief |
| look_for | 102 | brief |
| investigation_steps | 158 | detail |
| common_false_positives | 98 | detail |
| required_evidence | 75 | detail |
| common_defenses | 61 | detail |
| trustir_hints | 56 | detail |
| attacker_capabilities | 32 | detail |
| related_twes | 14 | detail |
| **合计（含标题行）** | **~720** | |

### 2.3 根因：一个三难困境

| 想要 | 现状 |
|---|---|
| ① 经验足够**丰富**（能写具体 API、代码模式、因果） | ❌ 被 900 挡住 |
| ② **16 族全覆盖**（现在只有 1 份） | 待补 |
| ③ **全量注入**（决策 #2，不做检索、不漏检） | ✅ 保住了 |

**三者只能取二。**当前实现牺牲了①。而如果为了①把上限提到 3000，在保持②③的前提下成本会失控：

| 上限 | 16 份合计 | planner 8 轮 | + 8 个 case × 5 个复核 Agent | 单次运行量级 |
|---|---:|---:|---:|---:|
| 900（现状） | 14.4K | 115K | +576K | **~700K token** |
| 3000（够写真经验） | 48K | 384K | +1.9M | **~2.3M token** |

（对照：本次实测探针整次运行仅 6488 token，因为**只有 1 份 playbook**。）

### 2.4 实测证据：这不是纸面问题

2026-07-24 对 `CVE-2019-1010292`（OP-TEE 注册内存越界，CWE-20 输入校验类）做了一次真实端到端探针：

- planner 跑满 8 轮，自述 `"Investigation into TWE-STATE-001 (Trusted State Rollback)"`
- 产出 candidates=0，最终 **0 findings**
- 原因链：知识库只有回滚 playbook → invariants Agent 依指令"把上面的 TWE 场景实例化到本项目架构上"（`invariants/prompt.go:82`）→ 只产出唯一一条 `INV-STATE-001`（状态连续性）→ planner 拿着这条唯一线索去找回滚代码 → 在一个输入校验漏洞上必然扑空

**结论**：覆盖面（②）必须补，而补覆盖面会立刻撞上预算枷锁（①）。所以预算问题必须先解开，否则补出来的 16 份仍然只能是标识符。

---

## 3. 候选方案

| 方案 | 做法 | 取舍 | 结论 |
|---|---|---|---|
| **A. 直接放宽上限 + 依赖 prompt caching** | 900 → 3000，靠 system prompt 缓存吸收重复成本 | 最简单。但依赖 GLM 侧是否支持 prompt caching；不支持则 2.3M token 成本真实发生 | 未采纳（外部依赖不可控） |
| **B. 选择性注入** | 按 ProjectProfile / case 类型只注入相关族 | 成本最低。但**推翻决策 #2**，重新引入"没选中就看不见"的静默漏检 | 未采纳（违背核心安全属性） |
| **C. 分层注入** ✅ | 简版全量注入 + 详版按需拉取 | 保住决策 #2 的核心（每一族 Agent 都能看见），同时让被关注的族拿到真经验 | **采纳** |

---

## 4. 设计：分层注入

### 4.1 核心

**同一份 YAML 渲染成两档。**不新增文件、不新增字段、不改 schema。

| 档 | 字段 | 到达方式 | 预算 | 实测 |
|---|---|---|---|---|
| **brief（简版）** | id / name / family / **scenario** / **look_for** | **全量注入 7 个 Agent**（沿用现有 `twe_agent_context.txt` 通路） | **250 token/份** | rollback 实测 **213**，余量 15% |
| **detail（详版）** | **全部 13 个字段**，允许自然语言展开 | **planner 通过新 action `twe_playbook_detail(twe_id)` 按需拉取** | **3000 token/份** | rollback 现 720，可扩 4 倍 |

**成本对比**：全量注入部分从 14.4K（16×900）降到 **4K**（16×250）——比现状**更省**；详版只在 Agent 主动索取时才付费。

**为什么 brief 选 scenario + look_for**：Agent 需要据此判断"这一族与我眼前的代码是否相关，值不值得拉详版"。scenario 说明这是什么漏洞，look_for 说明它长什么样——这两者足以做相关性判断，而 investigation_steps / evidence / defenses 等只有在决定深入后才有用。

### 4.2 代码改动

**`internal/twecontext/context.go`**

现有 `compilePlaybookBlock`（:302）渲染全部字段。拆为两个：

```go
// 只渲染 [ID] Name | family=、Scenario、Look for
func compileBriefBlock(p Playbook) string

// 渲染全部 13 字段（= 现有 compilePlaybookBlock 的行为）
func compileDetailBlock(p Playbook) string
```

上限常量拆为两个，均保持 **fail closed**：

```go
const maxBriefContextTokens  = 250   // Compile() 时检查，超限编译失败并点名是哪一份
const maxDetailContextTokens = 3000  // Load()/Validate() 时检查
```

detail 的检查放在 `Load()`/`Validate()`（而非 Compile），因为 detail 不参与 Compile；这样一份写超的 playbook 在 **preprocess 阶段就失败**，而不是等 Agent 拉取时才炸。

新增查询 API：

```go
// Detail 返回单份 playbook 的完整渲染；ok=false 表示该 TWE ID 没有 playbook。
func (c *Catalog) Detail(tweID string) (text string, ok bool)
```

`Compile()` 改用 `compileBriefBlock`，其余逻辑（manifest、SHA256、token 统计）不变。

**新 planner action：`internal/planner/actions/twe_playbook_detail.go`**

与现有 action 同构（实现 `Handler` 接口：`Name() string` + `Run(ctx, ActionRequest) ActionResult`）：

- args：`{"twe_id": string}`
- 命中 → `OK=true`，`Output` 为 detail 全文
- 未命中 → `OK=false` + `Error` 说明（沿用现有约定：失败不返回 Go error，而是通过 `ActionResult.Error` 让 LLM 观察并自行改正）
- handler 构造时注入 catalog（与 `FactLayerQueryHandler` 持有引擎的模式一致），在 registry 装配处注册
- prompt：`actionArgSchemas` 加一行；APPROACH 提示"当某个 TWE 与本次调查相关时，用 `twe_playbook_detail` 取该族的完整调查方法"

### 4.3 复现性处理（重要）

现有 `TWEKnowledgeManifest` 用 `ContextSHA256` 钉住"Agent 看见了什么"。分层后**详版是运行时动态拉取的，不在这个哈希里** —— 复现性出现缺口。

**处理方式**：detail 的每次拉取由 planner 现有的 action 事件机制记录（action 名 + `twe_id` + 结果，进 events.jsonl / blobs，与其它 action 一致）。**Manifest 保持不变**——它钉的是"全量注入的那一层"，这个语义仍然准确；"本次运行还额外看了哪些详版"可从 events 完整重建。

好处：不改 manifest schema，不丢可追溯性。

### 4.4 范围取舍（已确认的决策）

**详版只有 planner 能拉。**action 机制只存在于 planner 循环；expert / challenger / verifier / arbiter 仍只看到 brief。

- **代价**：复核链拿不到详版经验（例如 verifier 判断误报时看不到 `common_false_positives` 的完整列表）
- **理由**：planner 是决定"调查什么"的环节，收益最大；不引入新的推送机制，改动面可控
- **后续**：若复核链也需要，另行设计（见 §7 非目标）

---

## 5. 迁移

**实测结论：现有 `rollback.yml` 无需修改。**

- brief（标题 + scenario 98 + look_for 102）= **213 token** < 250 ✅
- detail（全字段）= **720 token** < 3000 ✅

（本节曾假设 scenario 需压缩，实测后否定——数据见 §2.2。）

---

## 6. 测试

| 测试 | 断言 |
|---|---|
| `compileBriefBlock` | 含 scenario / look_for；**不含** investigation_steps / defenses / false_positives |
| `compileDetailBlock` | 含全部 13 字段 |
| `Compile()` fail closed | 构造一份 brief 超 250 token 的 playbook → 编译失败，且错误信息**点名是哪一份** |
| `Load()` fail closed | 构造一份 detail 超 3000 token 的 playbook → 加载失败 |
| `Catalog.Detail` | `"TWE-STATE-001"` 返回全字段文本；`"TWE-NOPE-999"` 返回 ok=false |
| action 命中 | `OK=true`，Output 含 detail 特有字段（如 `"False positives:"`） |
| action 未命中 | `OK=false` 且 `Error` 非空（不是空结果） |
| action 非法参数 | 缺 `twe_id` → `OK=false` |
| 迁移回归 | 现有 `rollback.yml` 能通过 Load + Compile |

---

## 7. 非目标（本期不做）

- **不给 expert/challenger/verifier/arbiter 增加拉取详版的机制**（§4.4 的范围取舍）
- **不引入 RAG / embedding / 向量检索**——brief 仍是全量注入，不做相关性筛选（决策 #2 不变）
- **不新增 playbook YAML 字段**，不改 `schemas/twe-playbook.v1.json`
- **不改 `TWEKnowledgeManifest` schema**
- **不编写新的 playbook 内容**——覆盖面（16 族）是独立议题；本期只解开预算枷锁，为后续补覆盖面做准备

---

## 8. 验收标准

1. brief 全量注入，每份 ≤250 token，超限编译失败并点名是哪一份
2. detail 每份 ≤3000 token，超限在 Load/Validate 阶段失败（不是运行时才炸）
3. planner 可用 `twe_playbook_detail(twe_id)` 取到全字段文本；未知 ID 得到明确错误而非空结果
4. 拉取行为进 events，可从 events 重建"本次额外看了哪些详版"
5. 现有 `rollback.yml` 不改动即可通过 Load + Compile
6. `go build ./...`、`go vet ./...`、`go test ./...` 全绿（既有 `internal/collabrun` live-endpoint 失败除外）

---

## 9. 待实现阶段确认

- catalog 传入 action handler 的确切装配点：`runL3Planner` 里已需加载 catalog（见 2026-07-24 "wire-playbooks-and-trustir-annotation" spec 的 playbook 适配器），**两处应共用同一次 `twecontext.Load`**，避免重复加载。

---

## 10. 本设计解决与未解决的

**解决**：预算枷锁。详版从 900 放宽到 3000（4 倍），同时全量注入部分反而从 14.4K 降到 4K。后续补 16 族 playbook 时不会一撞就爆。

**未解决（明确遗留）**：
1. **覆盖面本身** —— 仍只有 1 份 playbook。这是下一个议题，且需要先解决"经验从哪来"（LLM 编造 vs 从真实 CVE patch 提炼）以及评测的 holdout 划分问题。
2. **复核链拿不到详版** —— §4.4 的已知取舍。
3. **单一 playbook 造成的隧道视野** —— §2.4 探针暴露的问题，本设计不解决它（那需要覆盖面），但为解决它扫清了障碍。
