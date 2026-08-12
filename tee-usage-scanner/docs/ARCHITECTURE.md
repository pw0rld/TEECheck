# TEECheck Scanner 架构

> 状态：**Planner-Driven 目标架构 / 迁移中**
> 更新日期：2026-08-02
> 适用范围：`tee-usage-scanner/`
> 设计依据：01 阶段不得在代码事实之前判定危险所在
>
> 当前代码仍主要按 `preprocess → architecture → invariants → planner` 运行；本文定义重构后的
> 唯一目标架构，并在 §11 记录当前实现差异。旧顺序只用于解释迁移，不再指导新增实现。

---

## 1. 系统目标

输入一个固定 commit 的完整 TEE 代码仓库，在有限 token 和工具预算下，让 Planner 自主选择值得深入的代码关系，用 CodeQL、AST 和源码证据验证，最后输出可供多 Agent 与人工复核的漏洞候选。

核心原则：

1. **全仓广度由确定性程序索引提供。** 不要求 LLM 一次读完全部源码。
2. **审计目标由 Planner 运行时决定。** 01 阶段不通过固定漏洞规则预计算安全锚点。
3. **CodeQL/AST 是程序地图与证据查询引擎。** 通用索引不直接把代码形状映射为 finding。
4. **安全架构后置形成。** 初始只有中性的 `ProjectMapV0`；安全关系必须来自 Planner 已取得的项目证据。
5. **Invariant 是可验证契约，不是前置搜索提示。** Planner 先发现问题，再将其形式化为 `CaseInvariant`。
6. **项目优先、TWE 补充。** 第一轮 reconnaissance 不由 TWE 决定目标；之后再用 TWE 检查已知漏洞族覆盖。
7. **事实、判断、裁决分层。** ToolFact 不可被 Agent 改写；AgentAssessment 可被挑战；HumanVerdict 只追加。
8. **负面结论必须带范围。** `not found in slice` 不能升级为 `not present in repository`。

这不是“用 LLM 包一层规则扫描器”。确定性工具回答“代码在哪里、关系是否存在”，LLM 回答“项目中什么关系值得怀疑、为什么可能影响安全”。

---

## 2. 主数据流

```text
Pinned full repository
        │
        ▼
00 Scope Contract
   repository + commit + root + build target + scope hash
        │
        ▼
01A Program Index
   CodeQL DB + AST + symbols + calls + fields + build/config
        │
        ▼
01B ProjectMapV0
   Repository Card + Module Cards + pageable Function Capsules
        │
        ▼
02 Planner Reconnaissance（project-first）
   浏览项目地图，运行时选择 Audit Leads
        │
        ▼
03 Evidence Retrieval
   源码 + callers/callees + def-use + paths + build conditions
        │
        ▼
04 Hypothesis Formalization
   AuditLead → CaseInvariant + verification queries
        │
        ▼
05 Case Construction
   EvidenceSlice + ToolFacts + CaseInvariant + coverage gaps
        │
        ▼
06 Evidence-grounded SecurityArchitecture
   从已观察路径归纳最小充分安全架构
        │
        ▼
07 Expert → Challenger → Verifier → Arbiter
   Verifier 产出 InvariantAssessment；Arbiter 产出 Finding
        │
        ▼
08 Human Review + vulnerable/fixed Benchmark
```

逻辑编号表达职责与依赖顺序。迁移期间可以保留现有运行目录编号，但 artifact 依赖必须符合此图。

---

## 3. 统一扫描范围

所有阶段共享同一个 `ScannedScope`：

```json
{
  "repository": "https://github.com/OP-TEE/optee_os",
  "commit": "a9386bf...",
  "root": "/path/to/pinned/checkout",
  "build_target": "...",
  "files_indexed": 1234,
  "scope_hash": "sha256:..."
}
```

约束：

- Project Map、Planner 源码动作、CodeQL DB、Verifier 和引用校验使用同一 commit/root；
- 工具结果记录查询范围、构建模式和 unresolved edges；
- benchmark fixture 不能与事实层完整 checkout 并存为两个都叫“当前代码库”的范围；
- 某个动作只能看到子目录时，结果必须标记 `scope=partial`；
- scope 不一致的 ToolFact 不能作为当前 Case 的正面或负面证据。

这条约束同时吸收「一次运行只读一棵树」的修复结论。

---

## 4. 01A：Program Index

### 4.1 职责

Program Index 对全仓做确定性、无漏洞结论的结构化建模：

```text
文件、语言、构建目标
模块与依赖
函数、方法、类型、字段
直接调用边与未解析调用边
字段读写和返回值使用
全局状态与副作用
编译条件、feature、manifest、配置
CodeQL/CPG 数据库位置与能力
```

建议产物：

```text
01_context/scanned_scope.v1.json
01_context/repo_facts.v1.json
01_context/program_index_manifest.v1.json
```

`RepoFacts` 最低结构：

```json
{
  "scope": {},
  "modules": [],
  "symbols": [],
  "direct_call_edges": [],
  "unresolved_call_edges": [],
  "types_and_fields": [],
  "build_guards": [],
  "config_and_manifest_facts": [],
  "tool_databases": []
}
```

### 4.2 明确非职责

Program Index 不输出：

- `dangerous function`；
- `rollback candidate`；
- `security authority`；
- vulnerability score；
- finding。

关键词或 API 名称可以作为搜索字段保存，但不能直接提升为安全语义。注释中的 `version` 不能成为字段、状态或数据流。

### 4.3 CodeQL/AST 的两种职责

#### 通用程序查询

供 Planner 浏览和取证，不包含固定漏洞结论：

```text
list_modules
list_functions(module, page)
get_function_card(symbol)
get_callers / get_callees
get_field_readers / get_field_writers
get_return_consumers
get_dataflow
get_paths_between
get_build_conditions
get_related_functions
```

#### Case-specific verification

Planner 形成 CaseInvariant 后，可以生成或选择更具体的查询，验证字段传播、guard 支配、source-to-sink 和状态更新等性质。查询结果仍是 ToolFact，不直接成为最终安全结论。

现有手写 TrustIR fact table/薄壳查询可以作为迁移期验证后端，但不能继续承担 Planner 前目标选择的唯一入口。

---

## 5. 01B：ProjectMapV0

`ProjectMapV0` 是 Planner 的中性导航视图，不是 SecurityArchitecture，也不回答“哪里有漏洞”。

建议产物：

```text
01_context/project_map.v1.json
```

信息分三层，避免把全仓源码或全部函数卡一次塞入 prompt。

### 5.1 Repository Card

```json
{
  "documented_purpose": "...",
  "languages": ["c"],
  "build_targets": ["..."],
  "top_level_modules": [],
  "module_dependency_summary": [],
  "index_coverage": {}
}
```

### 5.2 Module Card

```json
{
  "module": "core/crypto",
  "function_count": 312,
  "exports": [],
  "major_types": [],
  "global_state": [],
  "calls_modules": [],
  "called_by_modules": [],
  "build_guards": []
}
```

### 5.3 Function Capsule

Function Capsule 是短小的程序事实摘要，由 Planner 分页或按条件查询：

```json
{
  "symbol": "shdr_load_pub_key",
  "module": "core/crypto",
  "signature": "...",
  "called_by": ["ree_fs_ta.c:..."],
  "calls": ["..."],
  "reads_fields": ["subkey.subkey_version"],
  "writes_fields": ["key.uuid", "key.e", "key.n"],
  "downstream_field_reads": ["key.version"],
  "side_effects": [],
  "build_guards": []
}
```

模块、symbol、call edge 等是 deterministic facts；“模块可能承担什么业务职责”可以由 LLM 总结，但必须标记 `documented`/`inferred`，不能伪装为 observed。

---

## 6. Planner-Driven Reconnaissance

### 6.1 Planner 是目标选择者

01 阶段不产生 Security Anchors。所谓“锚点”只是 Planner 当前选择调查的 symbol 或关系，是运行时状态。正式产物称为 `AuditLead`，避免把它误解为已确认安全事实。

Planner 至少经过以下状态：

```text
ORIENT
  阅读 Repository Card
        ↓
MAP
  覆盖主要 Module Cards，分页浏览 Function Capsules
        ↓
LEAD
  选择函数或跨函数关系，提出 Audit Question
        ↓
EXPAND
  请求源码、调用、字段传播、构建条件和路径
        ↓
FORMALIZE
  形成、修正或否定 CaseInvariant
        ↓
CASE / CLOSE
  建立有证据的 Case，或带原因关闭 Lead
```

Planner 在完成最低限度的 ORIENT/MAP coverage 前不能直接 `done`。

### 6.2 AuditLead

```json
{
  "lead_id": "lead-017",
  "target_symbols": [
    "shdr_load_pub_key",
    "check_update_version"
  ],
  "security_question": "subkey_version 是否传播到 pub_key.version？",
  "reason": [
    "producer reads subkey.subkey_version",
    "producer output does not show a write to key.version",
    "downstream consumer reads key.version"
  ],
  "requested_context": [
    "body:shdr_load_pub_key",
    "callers:shdr_load_pub_key",
    "def-use:subkey.subkey_version->pub_key.version"
  ],
  "uncertainty": "high",
  "state": "open|expanded|formalized|closed"
}
```

Lead 是问题，不是 finding；`reason` 必须引用 Planner 已看过的 Project Map facts。

### 6.3 开放式审计目标

Planner 不按固定漏洞签名选择函数，而是寻找：

- producer/consumer 对同一字段的契约不一致；
- 验证对象和最终使用对象不一致；
- 检查与安全效果相隔很远；
- 默认值、错误路径、恢复路径改变语义；
- 跨模块调用依赖隐含假设；
- 同类实现之间存在异常差异；
- 单个函数正常、组合后产生风险的生命周期；
- 无法由 Project Map 解释但影响较大的状态或调用关系。

这些是 Planner 的思考维度，不是匹配即报告的代码规则。

### 6.4 Project-first 与 TWE-guided 两遍

#### Pass A：Project-first

- 输入 Project Map 和程序事实；
- 不用特定 TWE 预选函数；
- 目标是发现项目特有的语义断裂和隐含契约。

#### Pass B：TWE-guided coverage

- Planner 可以调用 `twe_playbook_detail`；
- 检查已知 TWE 是否有第一遍未覆盖的必要角色或生命周期；
- TWE 只生成新的 Audit Question，不直接生成 Case/finding。

`related_twes` 允许为空；没有 catalog 映射的新问题必须能够继续调查。

### 6.5 覆盖与预算

为防止 LLM 只选择名称包含 `verify/auth/crypto` 的函数，Planner 持久化 Coverage Ledger：

```json
{
  "modules_total": 42,
  "modules_reviewed": 18,
  "function_capsules_total": 5400,
  "function_capsules_reviewed": 960,
  "unreviewed_clusters": [],
  "leads_open": 7,
  "budget_remaining": {}
}
```

选择预算同时覆盖高影响、跨模块、高不确定性、实现差异和少量多样性抽样。未选择只能记为 coverage gap，不能解释为无风险。

Planner 继续保留轮次、token、墙钟和单动作超时预算；连续重复动作由 loop detector 拒绝。最终路径必须来自本次实际观察过的 ToolFact/EvidenceSlice。

---

## 7. EvidenceSlice 与负面证据

Planner 对 Audit Lead 按需展开：

```text
source 向前：source → decode → transform → guard → authority
authority 向后：authority ← guard ← producer ← boundary/source
```

状态类问题额外展开：

```text
load → authenticate → freshness check → use → update → persist
```

建议产物：

```text
03_planner/evidence_slices/
```

每个 EvidenceSlice 包含：

- 目标函数源码和精确引用；
- callers/callees 及查询来源；
- 相关字段定义和 def-use；
- 结构体、全局状态和副作用；
- 编译条件和 build target；
- 已解析路径、unresolved edge 和查询 scope；
- 文档声明与代码事实的状态区分。

负面证据分级：

```text
not_found_in_snippet
not_found_in_file
not_found_in_partial_scope
not_found_in_indexed_repository
proved_unreachable_under_build_target
```

只有最后一级才能作为强不可达反证；每一级都保留工具、参数、scope 和 coverage gap。

---

## 8. SecurityArchitecture：后置、最小、可修订

### 8.1 两层架构

```text
StructuralArchitecture
  modules / symbols / types / calls / build guards
  来源：RepoFacts，确定性为主

SecurityArchitecture
  actors / assets / trust zones / boundaries / flows /
  authorities / state lifecycles / assumptions
  来源：Planner EvidenceSlice + docs + 经验证的语义归纳
```

`ProjectMapV0` 在 Planner 前产生；`SecurityArchitecture` 在 Planner 取得证据后产生。两者不能合并成一份一开始就声称完整的模型。

### 8.2 Grounding 约束

1. 每个安全节点引用 structural node、文档事实或明确 unknown；
2. 每条 observed flow/lifecycle 引用 ToolPath 或多段代码证据；
3. 单行关键词不能建立跨函数关系；
4. inferred 的依赖链最终落到 observed/documented fact；
5. unknown 是下一步问题，不是负面结论；
6. Planner/Verifier 的反证可以使架构关系失效。

### 8.3 最小充分架构

只建模已调查安全路径上的 source、boundary、transformer、guard、authority、state 和部署假设。不要要求 LLM 在有限上下文中复述完整软件架构。

建议使用：

```text
architecture.v2.json
architecture_updates.jsonl
```

`architecture_updates.jsonl` append-only 记录确认、降级、否定和依赖失效，避免旧假设继续进入 Arbiter。

---

## 9. Invariant：从前置猜测改为 Case 契约

### 9.1 四层模型

```text
L0 Security Principle   TWE 通用原则，不属于项目事实
L1 Audit Question       Planner AuditLead
L2 CaseInvariant        绑定具体 symbol/path 的可验证契约
L3 InvariantAssessment  satisfied / violated / unresolved
```

Invariant 不负责告诉 Planner 去哪里找漏洞。Planner 先取得证据，Invariant 再把问题形式化。

### 9.2 CaseInvariantV2

```json
{
  "invariant_id": "case-inv-017",
  "lead_ref": "lead-017",
  "scope": {
    "commit": "a9386bf...",
    "build_target": "..."
  },
  "subject_symbols": [
    "shdr_load_pub_key",
    "check_update_version"
  ],
  "preconditions": [
    "shdr->img_type == SHDR_SUBKEY",
    "shdr_load_pub_key returns TEE_SUCCESS"
  ],
  "required_property": {
    "kind": "field_propagation",
    "source": "subkey->subkey_version",
    "destination": "key->version",
    "before": "check_update_version(..., key.version)"
  },
  "security_effect": {
    "symbol": "check_update_version",
    "description": "decides whether the signed subkey version is accepted"
  },
  "evidence_refs": [],
  "verification_queries": [],
  "grounding": "path_bound",
  "related_twes": ["TWE-STATE-001"]
}
```

机械 gate：

- 必须绑定真实 symbol，不能只绑定 Architecture 文本或行号；
- 必须有 precondition、required property 和 security effect/consumer；
- 必须引用 EvidenceSlice/ToolFact；
- 必须给出可执行 verification query；
- 仅依赖 unknown/inferred 时退回 AuditLead；
- `related_twes` 允许为空，新问题不因 catalog gap 被丢弃。

### 9.3 InvariantAssessment

Invariant 表达“应该满足什么”，Assessment 表达“当前 commit 实际如何”。两者分开存储：

```json
{
  "invariant_id": "case-inv-017",
  "assessment": "satisfied|violated|unresolved",
  "evidence_refs": [],
  "witness": {
    "producer": "shdr_load_pub_key",
    "missing_or_present_edge": "subkey_version -> key.version",
    "authority": "check_update_version"
  }
}
```

只有 Verifier 或等价的确定性验证阶段可以产出 Assessment；Planner/Invariant Builder 不能自行把 proposed 义务标成 violated。

### 9.4 局部优先

```text
Local invariant          producer 正确填充字段
       ↓
Interprocedural          字段完整传播到 guard
       ↓
System invariant         guard 依赖的可信状态不能被回滚
```

先验证便宜、可证伪的局部契约，再根据证据决定是否追踪完整系统生命周期。

---

## 10. Case、证据与多 Agent 复核

### 10.1 三层证据分离

| 层 | 谁产出 | 可否被推翻 | 载体 |
|---|---|---|---|
| ToolFact | CodeQL/AST/确定性工具 | 不可由 Agent 改写 | `ToolFact` |
| AgentAssessment | Planner/Expert/Challenger/Verifier | 可以被后续证据挑战 | Lead、Hypothesis、Challenge、Assessment |
| HumanVerdict | 人 | 只追加，不覆盖原始记录 | `HumanVerdict` |

工具 `error`、`unsupported`、`unresolved` 和空结果语义不同，都不能解释为安全。

### 10.2 Case Pack

Case Pack 包含：

```text
AuditLead
CaseInvariant
EvidenceSlices
ToolFact refs
相关 SecurityArchitecture slice
coverage gaps / unresolved edges
required evidence
```

下游职责：

| Agent | 职责 |
|---|---|
| Expert | 基于 Case 证据解释攻击条件与影响，不扩大查询范围 |
| Challenger | 独立寻找保护机制、不可达条件、错误契约和反例 |
| Verifier | 将争议转换为工具问题，产出 InvariantAssessment |
| Arbiter | 综合证据与 Assessment；不改写 ToolFact |

Challenger 保留两阶段隔离：第一阶段不读 Expert 结论，第二阶段再对比双方判断。

---

## 11. 当前实现与目标差异

| 当前实现 | 目标架构 |
|---|---|
| `preprocess → architecture → invariants → planner` | `index/map → planner → case invariant/security architecture` |
| Architecture prompt 只见仓库身份或稀疏 profile | Planner 分页浏览全仓结构并按需取证 |
| Architecture 一次性生成安全关系 | SecurityArchitecture 从 EvidenceSlice 后置归纳并可修订 |
| ProjectInvariant 在 Planner 前批量生成 | CaseInvariant 由 Planner Lead + 证据按需生成 |
| TWE 先实例化项目义务 | project-first 发现，TWE-guided 补覆盖 |
| CodeQL 主要通过预定义 operation 使用 | 同时提供通用程序查询和 case-specific verification |
| `architecture_refs` 是 invariant 的主要 grounding | symbol + path + precondition + executable query 才能 grounding |
| invariant `status` 混合义务与验证结果 | CaseInvariant 与 InvariantAssessment 分离 |

兼容策略：

- `architecture.v1.json` 迁移期保留，但不再作为 Planner 前的安全事实源；
- `project_invariants.v1.json` 可以在 Planner 后由 CaseInvariant 汇总派生，只供旧下游读取；
- 现有 `twe_playbook_detail`、Planner action registry、ToolFact、CasePack、多 Agent 复核和事件/blob 设施继续复用；
- 先增加新 artifacts/actions，再删除旧的前置 Architecture/Invariant stage。

### 11.1 迁移顺序

1. **M0 Scope**：确保 Planner、CodeQL、引用校验和所有 Agent 使用同一完整 checkout。
2. **M1 Index/Map**：新增 RepoFacts、Repository/Module/Function Cards 和分页读取动作。
3. **M2 Planner Reconnaissance**：增加 ORIENT/MAP/LEAD 状态、Coverage Ledger 和 AuditLead artifact。
4. **M3 通用查询**：增加 callers/callees、field readers/writers、dataflow、paths、build conditions actions。
5. **M4 CaseInvariant**：将 `invariants.Run` 从 Planner 前移除，增加 `formalize_invariant`，允许 `related_twes` 为空。
6. **M5 SecurityArchitecture**：从 EvidenceSlices 生成 architecture.v2，支持 append-only updates。
7. **M6 下游迁移**：各 Agent 改读 case-scoped invariant/architecture，稳定后退役前置 v1 流程。

---

## 12. 目标运行产物

```text
runs/<run-id>/
├── 00_manifest.json
├── 01_context/
│   ├── scanned_scope.v1.json
│   ├── repo_facts.v1.json
│   ├── program_index_manifest.v1.json
│   ├── project_map.v1.json
│   ├── twe_knowledge_manifest.v1.json
│   └── twe_agent_context.txt
├── 02_tool_facts/
│   ├── generic/
│   └── case_verification/
├── 03_planner/
│   ├── rounds.jsonl
│   ├── coverage_ledger.json
│   ├── audit_leads.jsonl
│   └── evidence_slices/
├── 04_investigations/
│   ├── case_invariants/
│   └── invariant_assessments/
├── 05_architecture/
│   ├── architecture.v2.json
│   └── architecture_updates.jsonl
├── 06_cases/
├── 07_expert/
├── 08_challenger/
├── 09_verifier/
├── 10_arbiter/
├── blobs/
└── events.jsonl
```

上述是目标编号：目录名唯一且按主要产物依赖顺序排列。迁移期间的旧 run 目录仍可按旧路径读取，但新代码和新文档不应再引入重复序号。

运行目录仍是一切的单位：每个阶段通过文件契约交接；prompt/response 进入内容寻址 blob；`events.jsonl` append-only；任一阶段能够基于落盘输入单独重跑。

---

## 13. 契约与扩展点

目标新增契约：

```text
ScannedScope
RepoFacts / ProgramIndexManifest
ProjectMap / RepositoryCard / ModuleCard / FunctionCapsule
CoverageLedger
AuditLead
EvidenceSlice
CaseInvariantV2
InvariantAssessment
ArchitectureModelV2 / ArchitectureUpdate
```

扩展原则：

| 需求 | 扩展位置 |
|---|---|
| 支持新语言 | Program Index adapter + 通用查询实现 |
| 给 Planner 新能力 | `planner/actions` Handler + 参数 schema |
| 增加 TWE | TWE catalog/playbook；不能修改 project-first 的目标选择 |
| 增加验证器 | CaseInvariant verification query/backend |
| 增加 Agent | pipeline stage + case-scoped contract |
| 修改 artifact | `internal/artifacts` + JSON Schema 同步更新 |

`schema_version` 不从路径推断，必须由 artifact 自己声明。结构化 JSON 是权威来源，Markdown 只作为派生人读视图。

---

## 14. 验收与 Benchmark

### 14.1 广度

```text
structural_scope_coverage
module_cards_reviewed / module_cards_total
function_capsules_reviewed / function_capsules_total
unresolved_call_edge_count
```

### 14.2 Planner

```text
audit_lead_count
lead_to_case_conversion_rate
rejected_lead_rate
evidence_slice_count / token cost
```

### 14.3 Grounding

```text
observed_relation_ratio
grounded_invariant_ratio
executable_invariant_ratio
invariant_assessment_resolved_rate
```

### 14.4 vulnerable/fixed benchmark

- oracle symbol 的最小 Lead 排名；
- lead recall@K；
- 首次取得 oracle path 的查询次数和 token；
- vulnerable 是否形成真实 producer/source → authority 路径；
- fixed 是否观察到新增 propagation/guard；
- 同一 CaseInvariant 是否得到可解释的 violated/satisfied 差异；
- 最终 finding precision/recall 与对照组 FP。

最终不只衡量“文件或 CVE 是否命中”，还衡量 Planner 是否选择了正确关系、路径是否正确、Invariant 是否可执行、推理是否与代码证据一致。

---

## 15. 架构边界

函数指针、汇编、生成代码、动态注册、复杂宏、构建变体和外部依赖仍可能使程序图不完整。目标不是伪装成完全覆盖，而是让每个阶段明确区分：

```text
全仓结构上已观察到
工具路径推导得到
项目文档声称
LLM 安全语义推断
当前 scope/tool 下未知
```

最终原则：

> **01 阶段只提供可查询的全仓地图，不提前规定哪里危险；Planner 决定下一段要读的代码，工具验证 Planner 的问题，安全架构和项目不变量再从已取得的证据中形成。**
