# Planner 语言无关化(支持 C/OP-TEE)— 设计文档

> 日期：2026-07-24
> 分支：`merge/tee-audit-integration`
> 状态：设计已确认，待落实现计划
> 关联：架构快照 §6 决策 #1「v1 主攻 C/TEE OS」；审计 #2「主 Planner 仍是 Rust 专用」。这是合并能端到端跑 C 差分的**硬阻断**。

---

## 1. 背景与目标

benchmark 全部 44 个案例都是 `OP-TEE/optee_os`（C 代码），但当前主 Planner 结构上只能处理 Rust：硬编码 `sinks/rust.json`、prompt 只看 `.rs`、`tree_sitter_outline`/`reverse_trace` 对非 `.rs` 直接 fail。因此“vulnerable OP-TEE → confirmed finding”的差分检测，主探索 Agent 连目标文件都打不开。

**目标**：让 Planner **语言无关**，能探索 C/OP-TEE 源码，同时保住架构设计里的「源码探索 + 路径追踪」左腿——但**不引入任何语法/语言注册表**，也不为 C 攒 sink 清单。

---

## 2. 核心决策（B′）

在三个方案里选 B′：

| 方案 | 做法 | 路径追踪 | grammar | 选否 |
|---|---|---|---|---|
| A | 保留 tree-sitter，加 C grammar 注册表 | 精确 | 每语言维护 | ✗ |
| B | 删掉 `reverse_trace`/`tree_sitter_outline` 两个 action | 削弱 | 无 | ✗ |
| **B′** | **保留这两个能力，去掉 grammar 依赖，改文本+启发式实现** | 保留（精度略降） | 无 | ✓ |

**理由**：
- Planner 核心循环本就语言无关（见 §3），“只能 Rust”只是三个外围焊点造成的。
- `reverse_trace` 的找调用点（`findCallSites`）**本来就是文本遍历**，只有“调用点落在哪个函数”用了 tree-sitter——这步文本启发式可近似。
- 「源码探索 + 路径追踪」是设计里的头等能力（架构快照 §2.1 左腿），是**能力**不是“tree-sitter 这个实现”，可换实现保留。
- sink catalog 是旧 usage-scanner 的符号清单机制、会锚定 AI，语义引导改由语言无关的 **TWE + invariant + architecture** 承担（先验知识已注入 planner）。

**取舍（明说）**：路径追踪/大纲用文本近似，遇宏、函数指针、嵌套定义不如 tree-sitter 准；对 OP-TEE 以普通 C 函数为主的代码够用。

---

## 3. 现状：Planner 逻辑与三个语言焊点

**核心循环 `internal/planner/planner.go`**（语言无关，不动）：建 systemPrompt（TWE/架构/不变量 + action 列表）→ 多轮：LLM 选 action（每轮 ≤3）→ 执行 → 结果喂回 state → observedPaths 防路径幻觉 → LLM `done` → candidates → CasePack。

**三个把它焊死在 `.rs` 的地方**：

| # | 焊点 | 位置 |
|---|---|---|
| 1 | prompt 写死“只看 .rs、先查 rust sink catalog、忽略 Cargo、6 轮内收 1-2 候选” | `planner/prompt.go` |
| 2 | `tree_sitter_outline`/`reverse_trace` 硬拒非 `.rs` + 写死 `rust.GetLanguage()` + Rust 节点集 | `planner/actions/*.go` |
| 3 | 硬编码加载 `sinks/rust.json`，找不到即 fail | `pipeline/run.go:298` |

#2 = 拆掉这三个焊点。

---

## 4. 设计：改 / 删 / 不动

### 改

**`actions/reverse_trace.go`**
- 去掉 `github.com/smacker/go-tree-sitter/rust` 依赖与 `.rs` 走查过滤。
- `findCallSites`：保持文本遍历找调用点，走查范围从“仅 `.rs`”改为“按活跃语言的扩展名集”（或所有文本源码文件）。
- “调用点落在哪个函数”：由 tree-sitter 改为**文本启发式**——从调用行往上找最近的函数签名（跨 C/Rust 花括号语言通用的签名正则）。
- 输出格式（嵌套调用树）、BFS 深度上限（3）、每层 caller 上限（30）、输出字节上限（30000）全部保留。

**`actions/tree_sitter_outline.go`**
- 去掉 grammar 与 `.rs` 硬拒，改**轻量文本大纲**：正则匹配“像定义的行”（函数/结构体签名），输出 `<kind> line <n> <snippet>`。
- 可改名 `code_outline`（去掉误导性的 tree_sitter 前缀）——命名是实现细节，不阻塞设计。

**`planner/prompt.go`（去锚定）**
- 删除：`sink_catalog_lookup` 作为第一步、`globs=["*.rs"]`、忽略 Cargo、“6 轮内收敛 1-2 候选”等 Rust/sink 措辞。
- 改为：从 architecture + invariant + TWE 出发（“这个组件该守什么不变量”）→ ripgrep（按语言 glob）/ outline 定位 → reverse_trace 追信任决策点 → 对照 TWE 判断 → done。
- glob 按 `profile.Languages` 参数化（C → `*.c,*.h`；Rust → `*.rs`）。

**`pipeline/run.go`（runL3Planner）**
- 删除 `catalogPath := .../rust.json`、`os.Stat` fail 分支、`NewDefaultRegistryWithFacts(catalogPath, …)` 里的 catalogPath。
- registry 改用不带 sinks 的组装（保留 `fact_layer_query`）。
- 活跃语言取自 `profile.Languages`（primary = 首个或按文件计数最多者），传入 planner 供 prompt glob 使用。

### 删（真删，不留开关）
- `actions/sink_catalog_lookup.go`
- `actions/registry_with_sinks.go`
- `knowledge/sinks/rust.json` 及其加载路径
- prompt 中所有 sink catalog 引用

### 不动
- planner 核心循环、防幻觉、CasePack 生成、复核链对接。
- 右腿 `fact_layer_query` → `trustirfacts` 事实层（其 operation 覆盖面是 #5/#6 的范围）。

---

## 5. 语言选择机制

- `internal/artifacts` 的 `ProjectProfile.Languages []string` 已由 preprocessor 探测，且已通过 `promptProfile.Languages` 传入 planner——复用，不新增探测。
- **primary 语言** = `Languages[0]`（或按文件计数最多者，实现时定），仅用于 prompt 的 glob 提示。
- **action 层按扩展名 per-file dispatch**：`reverse_trace`/`outline` 看文件扩展名决定走查/解析范围，因此**混合语言仓库天然支持**，无需“单一语言”假设。

---

## 6. 爆炸半径（实现时必须核）

删除 sink catalog 会波及 legacy 旁路与测试：
- `cmd/twescan`、`actions/registry_with_sinks.go`、依赖 sink 的测试。
- 该旁路本就排 PR-10 退役；实现时**确认删除不波及主线 `teecheck run` 与 teecheck-benchmark**，受影响的 legacy 测试相应删除或调整。
- `go-tree-sitter` 依赖：若去 grammar 后 planner 不再 import rust/c 子包，检查 `go.mod` 是否还有其他使用者，无则可清理（非必需）。

---

## 7. 非目标（本期不做）
- 语言注册表 / 多语言插件框架（B′ 明确不做；未来若要精确导航再谈 A）。
- 扩展 `fact_layer_query` 的 operation 覆盖面（rollback 以外的 TWE 查询）——#5/#6。
- 建真 CodeQL DB、端到端差分——#6。
- 精确的 tree-sitter 级导航（本期接受文本近似）。

---

## 8. 验收标准
1. Planner 能在一个 C/OP-TEE 仓库上跑完探索循环并产出 candidates（不再因 `.rs` 或缺 rust.json 而 fail）。
2. `reverse_trace` 对 `.c/.h` 文件返回合理的调用树；`outline`/`code_outline` 对 C 文件返回函数/结构体大纲。
3. prompt 不再出现 sink catalog / `.rs`-only / 强制回合收敛措辞；glob 随 `profile.Languages` 变化。
4. sink catalog 相关文件与 action 已删除，主线 `teecheck run` 不引用它。
5. Rust 仓库上的行为不回归（`reverse_trace`/`outline` 对 `.rs` 仍可用）。
6. `go test ./...` 全绿；teecheck-benchmark 不受影响。

---

## 9. 待实现阶段决定的细节
- 文本大纲/签名匹配的正则集合（C/Rust 至少两套签名模式）。
- “最近函数签名”启发式对 C 的边界（宏展开、K&R 老式声明、多行签名）。
- `tree_sitter_outline` 是否改名 `code_outline`。
- primary 语言选择规则（首个 vs 文件计数最多）。
- 去锚定后 prompt 的 APPROACH 具体措辞。
