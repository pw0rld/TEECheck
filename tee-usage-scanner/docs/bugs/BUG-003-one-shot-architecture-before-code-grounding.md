# BUG-003：01 阶段在代码事实之前一次性生成安全架构，弱指纹被放大为错误审计方向

> 状态：**Phase 1+2 已实现并实测 / Phase 3+4 未开始**
>
> Phase 1（Program Index、ProjectMap）与 Phase 2（Planner 运行时选目标、
> AuditLead、CoverageLedger、Pass A/B）已落地，`runs/recon-002` 产出了
> `repo_facts.v1.json`、`project_map.v1.json`、`audit_leads.jsonl`、
> `coverage_ledger.json`，且 Planner 自行提出的 lead 三条理由全部可回溯到
> 它本轮的成功观察。
>
> Phase 3（`formalize_invariant`、`CaseInvariantV2`、`InvariantAssessment`）与
> Phase 4（SecurityArchitecture 后移）尚未实现。
>
> 已知遗留：§6.1 的 "完成最低 coverage 前不能 done" 由 reconnaissance gate
> 实现，但该 gate 在预算内不可满足，见 BUG-006。
> 记录日期：2026-08-02
> 影响：01 Project Understanding、Project Invariants、Planner 的初始审计方向与 benchmark 可量化性
> 代表运行：`runs/44362-vuln-p9`
> 路径以 `tee-usage-scanner/` 为基准
>
> 本文区分两份证据：
>
> 1. `runs/44362-vuln-p9` 是 2026-08-01 的历史运行，其 Architecture prompt 收到了
>    `ProjectProfileV2`，但没有代码、调用图或数据流；
> 2. 当前源码中的 Architecture prompt 只收到 TWE、仓库 URL 和 commit，连 profile 都没有。
>
> 两种版本的共同缺陷是：**LLM 被要求在没有项目级程序事实和按需取证能力时，一次性生成完整安全架构。**
>
> **2026-08-02 方案修订**：取消由规则在 01 阶段预计算 `SecurityAnchors` 的设计。
> 01 只建立中性的程序索引和项目地图；审计目标由现有 Planner 在运行时选择，
> CodeQL/AST 作为 Planner 的通用程序查询引擎，而不是固定漏洞规则执行器。
>
> **2026-08-02 Invariant 修订**：不删除 invariant，但取消 Planner 前批量生成
> `ProjectInvariant`。保留 TWE 通用原则；Planner 取得项目证据后，按 Audit Lead
> 生成可执行的 `CaseInvariant`，Verifier 再单独产出 `InvariantAssessment`。

---

## 1. 一句话症状

**01 阶段先让 LLM 根据 TWE 和稀疏 fingerprint/仓库身份生成完整 ArchitectureModel，再据此生成项目不变量；由于架构阶段没有全仓调用关系、数据流和代码切片，弱关键词会被提升成安全语义，继而被 Invariant 和 Planner 继续放大。**

这不是简单的 prompt 质量问题。即便把 prompt 写得更谨慎，只要它没有可查询的仓库事实，模型仍无法可靠回答：

- 哪个函数是真实入口；
- 某个字段从哪里赋值、最终由谁检查；
- 一条安全检查是否支配所有到达 authority 的路径；
- 一个函数是否有跨文件调用者；
- 哪些代码受编译条件、feature 或平台配置控制；
- 文档中的组件和本次 commit 中的代码是否一致。

因此，修复方向不是“向 Architecture prompt 塞更多静态源码”，而是调整 01 阶段的数据流和职责边界。

---

## 2. 当前流程

当前 pipeline 顺序是：

```text
preprocess
  ↓
architecture.Run
  ↓
invariants.Run
  ↓
L3 Planner / fact layer / downstream review
```

`internal/pipeline/run.go:226-247` 证明 Architecture 和 Invariants 在 Planner 与事实调查之前执行。

当前 `internal/architecture/run.go:39-46` 虽然把完整仓库路径写入 `Input.RepoRoot`，但 `BuildLLM` 的用户 prompt 没有使用该路径，也没有执行任何代码检索。`internal/architecture/prompt.go:64-81` 实际只渲染：

```text
TWE prior knowledge
repository URL
commit
```

并明确声明：

```text
This run carries no repository fingerprint, so there is no scan evidence to ground against.
```

所以当前版本中的 `RepoRoot` 只是被传递，没有转化为模型可见的事实或工具能力。

随后 `ValidateAndDowngrade()` 只能检查 LLM 已经生成的引用，把错误的 `observed` 降级。它是生成后的拒绝/降级过滤器，不是生成前的 grounding 层；它无法告诉模型真实的调用者、控制流或字段传播路径。

`internal/invariants/prompt.go` 又把 ArchitectureModel 描述为 “already-validated”，并基于它实例化项目不变量。这里的 validated 只表示 schema、枚举、引用位置通过检查，不表示架构语义已经由程序分析证明。

---

## 3. `44362-vuln-p9` 中的已确认失败模式

### 3.1 历史 Architecture prompt 只有 condensed fingerprint，没有代码路径

该运行的真实 prompt 保存在：

```text
runs/44362-vuln-p9/blobs/
  63887f046b4b74f974ba06afcc5147a865363e05ccecbde7fed434853928ffa0.txt
```

它包含 TWE brief 和 condensed `ProjectProfileV2`。Profile 给出关键词命中的文件/行号，但没有：

- 函数定义与符号身份；
- callers/callees；
- CFG、支配关系；
- source-to-sink 路径；
- 字段赋值与传播；
- 构建目标和编译条件；
- 命中行附近的语义代码片段。

因此 Architecture LLM 只能把 fingerprint 标签直接翻译为安全语义。

### 3.2 架构几乎没有 observed 关系

`01_context/architecture.v1.json` 的状态分布是：

```text
Architecture elements:
  observed   1
  inferred   5
  unknown   19

Architecture relations:
  observed   0
  inferred   3
  unknown    2
```

也就是说，架构中的 data flow、boundary 和 lifecycle 没有任何一条由项目代码直接观察成立。

这类模型可以作为“探索问题清单”，但不应被下游当作已经建立的项目安全架构。

### 3.3 line 240 的关键词误报被连续放大

Fingerprint 把 `core/crypto/signed_hdr.c:240` 标成 freshness/continuity signal。Architecture 将它扩展为：

```text
role:freshness-state-handler
asset:freshness-value
flow:freshness-to-decision
lifecycle:freshness-value
```

Invariant 随后生成 `INV-STATE-001`，声称 line 240 存在 header freshness/continuity value，并要求 Planner 追踪它的赋值和 rollback guard。

但 Expert 后来读取 `signed_hdr.c:238-243` 后确认：line 240 只是 `calc_next_uuid` 中设置 RFC 4122 UUID version 5 的注释，不是安全 freshness 字段。运行事件 `events.jsonl:106` 已明确记录该结论。

失败放大链如下：

```text
词法关键词 “version”
  ↓
fingerprint: freshness candidate
  ↓
Architecture: freshness asset / role / flow / lifecycle
  ↓
Invariant: 项目具有 freshness obligation at line 240
  ↓
Planner: 花费轮次调查错误锚点
```

真正的 CVE 也与 version propagation 有关，但真实路径位于
`shdr_load_pub_key → check_update_version`，不能因为 line 240 也出现 “version” 就认为两个语义相同。这个例子表明：**TWE 先验和 benchmark 漏洞主题会让模型更容易确认关键词暗示，而不是帮助它证明实际代码路径。**

---

## 4. 根因判断

### 根因 A：把安全架构当成扫描输入，而不是扫描中逐步形成的假设地图

自然语言安全架构需要资产、边界、入口和数据流，但这些内容中的代码部分必须来自程序事实。当前流程要求模型在事实层之前一次性完成它们，顺序倒置。

### 根因 B：混合了“结构架构”和“安全架构”

当前 `ArchitectureModel` 同时表达：

- 项目有哪些组件、模块和入口；
- 哪些参与者可信；
- 哪些数据跨越信任边界；
- 哪些字段形成状态生命周期；
- 哪些位置承担安全 authority。

前一类可以通过仓库、构建系统和调用图确定；后一类需要结合 TWE、代码路径和人工/LLM 语义判断。把两者一次性生成，会使“模块猜测”直接变成“安全流猜测”。

### 根因 C：全仓广度和 LLM 深度没有分工

LLM 不适合把整个仓库源码一次塞入上下文，也不适合在没有源码时猜测完整架构。应由确定性索引覆盖全仓广度，由 Planner 浏览压缩后的项目地图、选择目标并按需读取代码。选择行为属于 Planner，不应由预处理规则提前固定。

### 根因 D：引用校验只能验证局部文本，不能验证关系

某一行确实包含 `version`，不等于该字段参与 rollback；某一行确实调用 crypto API，不等于 untrusted input 能到达该调用。单行 citation validator 无法证明跨函数关系、路径可达性、检查支配关系和配置可用性。

### 根因 E：Invariant 缺少 grounding gate

当前 invariant 只要求引用 Architecture ID。只要错误架构节点拥有合法 ID，错误语义就能通过引用完整性检查。`architecture_refs` 的存在证明“引用对象存在”，不能证明“对象语义成立”。

---

## 5. 建议的新架构

目标流程：

```text
Pinned full repository
  ↓
01A Program Index（CodeQL / AST / symbol，全仓、确定性）
  ↓
01B ProjectMapV0（中性的仓库、模块和函数简报）
  ↓
Planner Reconnaissance（运行时选择 Audit Leads）
  ↓
Planner Evidence Retrieval（按 Lead 读取代码和查询路径）
  ↓
Hypothesis / Verification / Case
  ↓
SecurityArchitecture + Case-specific Invariants
  ↺ 新证据和反证回写，而不是冻结一次性架构
```

这个方案不在 Planner 之前计算“哪里危险”。所谓锚点只是 Planner 当前选择调查的符号或符号关系，是运行时状态，不是 01 阶段的持久化安全结论。

### 5.1 01A：Program Index / Repository Facts

新增确定性产物，例如：

```text
01_context/repo_facts.v1.json
```

最低字段建议：

```json
{
  "scope": {
    "repo_url": "...",
    "commit": "...",
    "root": "...",
    "files_indexed": 1234,
    "languages": ["c"],
    "build_targets": ["..."]
  },
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

这一层可以组合：

- 文件树、manifest 和构建文件解析；
- Tree-sitter/编译数据库/符号索引；
- CodeQL 或 CPG 数据库；
- 直接调用图；
- 无法解析的函数指针、虚调用、宏和条件编译 gap。

它只回答“仓库中观察到了什么结构”，不生成漏洞，也不把未知边解释为不存在。

CodeQL/AST 在这里运行通用程序查询，而不是固定漏洞检测规则，例如：

```text
list symbols / types / fields
get callers / callees
get field readers / writers
get return-value consumers
get paths between two symbols
get local/global dataflow
get build conditions and reachability
```

因此它与传统规则 SAST 的边界是：工具提供地图和可复现路径，但不把某种 API、字段名或代码形状直接映射成 finding。

为了控制延迟，可先生成轻量 `repo_facts`，CodeQL DB 在同阶段补充 overlay；不必等待所有昂贵全局查询完成后才产生任何架构骨架。

### 5.2 01B：ProjectMapV0，而不是 Security Anchors

新增：

```text
01_context/project_map.v1.json
```

`ProjectMapV0` 是给 Planner 导航的中性压缩视图，不是完整 SecurityArchitecture。它可以包含：

```json
{
  "repository": {
    "documented_purpose": "...",
    "languages": ["c"],
    "build_targets": ["..."]
  },
  "modules": [
    {
      "path": "core/crypto",
      "function_count": 312,
      "exports": ["..."],
      "calls_modules": ["..."],
      "called_by_modules": ["core/kernel"]
    }
  ],
  "function_card_pages": ["..."]
}
```

Project map 可以由确定性事实与 LLM 的低风险摘要共同生成，但必须区分两者：模块、symbol、call edge 是事实；“模块可能负责什么”只是 documented/inferred description。

为了避免一次性上下文过大，信息分三层：

1. `Repository Card`：项目用途、构建、顶层模块和模块依赖；
2. `Module Card`：导出符号、主要类型、全局状态、调用关系；
3. `Function Capsule`：Planner 分页或按条件查询的函数简报。

Function Capsule 应包含中性行为事实，而不附加 `rollback candidate`、`dangerous parser` 一类漏洞标签：

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

这类胶囊没有声明漏洞，但能让 LLM 发现项目特有的语义不连续：producer 读取了 `subkey_version`，没有显示写入 `key.version`，而下游又读取 `key.version`。

### 5.3 Planner：运行时选择 Audit Leads

锚点选择由现有 Planner 负责。Planner 第一阶段应是 reconnaissance，不是立即生成 finding：

```text
Round 1  阅读 Repository Card，理解项目目的和模块关系
Round 2  选择需要理解的模块
Round 3  分页查看 Module Card / Function Capsule
Round 4  选择函数或跨函数关系，形成 Audit Lead
Round 5  请求源码、caller/callee、def-use、构建条件和路径
Round 6  提出、修正或否定安全假设
```

Audit Lead 不是漏洞结论，而是 Planner 下一步要回答的项目问题：

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
    "downstream consumer reads key.version for a decision"
  ],
  "requested_context": [
    "body:shdr_load_pub_key",
    "callers:shdr_load_pub_key",
    "def-use:subkey.subkey_version->pub_key.version",
    "body:check_update_version"
  ],
  "uncertainty": "high"
}
```

Planner 应获得这些通用 actions：

```text
list_modules
list_functions(module, page)
get_function_card
get_function_body
get_callers / get_callees
get_field_readers / get_field_writers
get_dataflow
get_paths_between
get_build_conditions
get_related_functions
```

选择目标时不使用固定漏洞匹配规则。Planner 可以围绕开放问题寻找：

- 哪些函数控制项目的重要状态或不可逆安全效果；
- 哪些 producer/consumer 对同一字段的契约不一致；
- 哪些检查和最终使用相隔很远；
- 哪些默认值、错误路径、恢复路径改变了语义；
- 哪些跨模块调用依赖未显式验证的假设；
- 哪些同类实现之间存在异常差异；
- 哪些单个函数看起来正常、组合后却产生风险。

这样保留了 LLM 发现项目特有新漏洞的空间。TWE 不应在第一轮决定目标；第一轮使用 project-first reconnaissance，之后 Planner 可通过现有 `twe_playbook_detail` action 按需检查已知漏洞家族，作为覆盖率补充。

### 5.4 Planner：按 Audit Lead 获取 Evidence Slices

新增：

```text
03_planner/evidence_slices/
```

对 Planner 选中的 Lead 做有预算的双向展开：

```text
source 向前：source → decode → transform → guard → authority
authority 向后：authority ← guard ← producer ← boundary/source
```

每个切片至少包含：

- 目标函数源码；
- callers/callees 和路径来源；
- 相关字段定义及 def-use；
- 相关结构体、全局状态；
- 编译条件和目标；
- 相关配置/文档；
- 已解析路径及 unresolved edge；
- 查询范围，尤其是 `not_found_in_scope` 的 scope。

状态/rollback 类路径还要显式支持生命周期边：

```text
load → authenticate → freshness check → use → update → persist
```

这一阶段才真正读取代码。选择依据来自 Planner 对项目地图的理解和当前问题；CodeQL/AST 负责回答它提出的调用、字段传播和路径问题。

### 5.5 将 SecurityArchitecture 后移

建议将 `architecture.v1` 迁移为 `architecture.v2`，逻辑上分两层：

```text
StructuralArchitecture
  modules / symbols / entrypoints / calls / build guards
  来源：RepoFacts，确定性为主

SecurityArchitecture
  actors / assets / trust zones / boundaries / flows /
  authorities / state lifecycles / assumptions
  来源：Planner 已获取的 EvidenceSlice + docs + 经验证的语义归纳
```

关键约束：

1. 每个 SecurityArchitecture 节点必须引用 structural node、文档事实或明确 unknown；
2. 每条 `observed` flow/lifecycle 必须引用工具路径或多段代码证据，单行关键词不够；
3. `inferred` 必须列出它依赖的 fact/path ID，不允许只依赖另一个自由生成的 inferred 描述；
4. `unknown` 是探索任务，不自动成为项目事实；
5. Architecture Agent 只对 Planner 已取得的证据做命名、归组和语义解释，不自行虚构仓库组件；
6. 架构是可版本化的：`ProjectMapV0 → Planner evidence → SecurityArchitecture → later revisions`。

这里追求的是**最小充分安全架构**，不是完整软件设计图。只需要覆盖安全路径上的 source、boundary、transformer、guard、authority、state 和部署假设；与安全决策无关的内部组件不必让 LLM 精读。

### 5.6 将 Invariant 改为 case-specific，并增加 grounding gate

Invariant 概念本身有价值：它把“这里看起来可疑”转换成“这段代码必须满足什么性质”。问题在于当前 invariant 生成得太早、粒度太大，并被当成 Planner 的项目事实输入。

建议拆成四层：

```text
L0 Security Principle   TWE 中的通用安全原则，不属于具体项目
L1 Audit Question       Planner 的 Audit Lead，尚未成为 invariant
L2 Case Invariant       绑定具体 symbol/path 的可验证代码契约
L3 Assessment           Verifier 对契约给出 satisfied/violated/unresolved
```

例如 CVE-2026-44362：

```text
L0 TWE Principle
  可信状态的 version/freshness 必须传播到执行安全决策的 guard。

L1 Audit Question
  subkey_version 是否完整传播到 pub_key.version？

L2 Case Invariant
  当 shdr_load_pub_key 对 SHDR_SUBKEY 成功返回时，输出 key.version
  必须取自 subkey.subkey_version，并在调用 check_update_version 前保持不变。

L3 Assessment
  vulnerable commit: violated，缺少 subkey_version → key.version 的传播边；
  fixed commit: satisfied，存在 key->version = subkey->subkey_version。
```

这比“项目必须使用 RPMB/monotonic counter 防止 rollback”更适合作为第一条 invariant。后者只有在继续证明项目存在可回滚持久状态后，才能升级为更高层的系统不变量。

#### CaseInvariantV2

`CaseInvariant` 不应只引用 Architecture ID，而应绑定 Lead、symbol、前置条件、代码路径和可执行查询：

```json
{
  "invariant_id": "case-inv-017",
  "lead_ref": "lead-017",
  "scope": {
    "repo": "https://github.com/OP-TEE/optee_os",
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
  "evidence_refs": [
    "slice:lead-017-producer",
    "slice:lead-017-callsite"
  ],
  "verification_queries": [
    {
      "tool": "codeql",
      "operation": "field_flow",
      "source": "subkey->subkey_version",
      "sink": "check_update_version argument 3"
    }
  ],
  "grounding": "path_bound",
  "related_twes": ["TWE-STATE-001"]
}
```

`related_twes` 应允许为空。正确顺序是 Planner 先从项目代码发现异常关系，再检查它是否映射到现有 TWE；无对应 TWE 时标记为 `project_specific_candidate`/catalog gap，而不是拒绝 invariant。

#### InvariantAssessment

Invariant 是“代码必须满足什么”，Assessment 才是“当前 commit 是否满足”。不要继续用同一个 `status` 混合规范和结果：

```json
{
  "invariant_id": "case-inv-017",
  "assessment": "satisfied|violated|unresolved",
  "evidence_refs": [
    "toolfact:rollback_version_propagation"
  ],
  "witness": {
    "producer": "shdr_load_pub_key",
    "missing_or_present_edge": "subkey->subkey_version -> key->version",
    "authority": "check_update_version"
  }
}
```

机械 grounding gate：

- 没有 Planner Lead 和项目证据的 TWE 只能保留为 catalog principle，不能产出 CaseInvariant；
- 必须绑定真实 symbol，不能只绑定文件行号或 Architecture 自由文本；
- 至少读取相关函数，或取得等价的 CodeQL/AST 程序事实；
- 必须有明确 precondition、required property 和 security effect/consumer；
- 必须说明什么证据会证明它成立或违反；
- verification plan 必须转成可执行 action/query，不只是一段模型文本；
- 仅引用 `unknown`/自由 `inferred` 信息时，只能保留为 Audit Lead；
- 每个负面结论必须记录查询 scope 和 unresolved edges。

#### 局部优先，逐层组合

CaseInvariant 应从便宜、确定、可执行的局部契约开始，再根据证据扩大：

```text
Local invariant
  producer 正确填充 version
        ↓
Interprocedural invariant
  version 完整传播到 guard
        ↓
System invariant
  guard 使用的历史最大值不能被攻击者回滚
```

这样 Planner 可以先验证字段传播，再决定是否投入预算追踪 secure storage/RPMB 的完整状态生命周期，避免从一个 `version` 关键词直接跳到宏大的系统义务。

Invariant 应在 Planner 已经找到具体代码关系以后产生，而不是在 Planner 之前批量生成。它的职责不再是告诉 Planner 去哪里找漏洞，而是把 Planner 已经发现的问题形式化为可证伪契约。

---

## 6. 代码级迁移建议

### Phase 0：先修数据契约，不大改下游

1. 给 `runfs` 增加 `RepoFactsPath`、`ProjectMapPath` 和 `EvidenceSlicesDir`；
2. 在 manifest 中记录唯一 `ScannedScope`：URL、commit、root、file count、scope hash；
3. Architecture、facts、Planner 和源码动作均校验自己使用同一 scope；
4. 保留 `architecture.v1` 输出兼容下游，但不再让它在 Planner 前承载未经调查的安全关系。

### Phase 1：建立中性 Project Map 和 Planner 浏览动作

新增或复用以下数据接口：

```go
type ProjectMap struct {
    Scope         artifacts.ScannedScope
    Repository    artifacts.RepositoryCard
    Modules       []artifacts.ModuleCard
    FunctionPages []artifacts.FunctionCardPageRef
}
```

给 Planner 增加 `list_modules`、`list_functions`、`get_function_card` 和通用 CodeQL/AST 查询 actions。不要把全仓函数卡一次性塞入 prompt，而应分页浏览和按需展开。

删除 Architecture prompt 中 “no repository fingerprint” 的路径，也不要恢复成“把整个 ProjectProfile JSON 塞回 prompt”。`RepoRoot` 由 Project Map builder 和查询 actions 消费，而不是作为一个模型看不到的字符串存在。

### Phase 2：把目标选择正式交给 Planner

Planner 增加显式 reconnaissance 状态，在完成最小项目浏览前不允许直接 `done`：

1. 阅读 Repository Card；
2. 覆盖主要 Module Cards；
3. 分页阅读 Function Capsules；
4. 输出一个或多个 Audit Leads；
5. 对 Lead 请求具体源码和程序路径；
6. 只有取得证据后才能建立 Case。

现有 fingerprint 可作为 Project Map 的补充检索信号，但不能直接建立 Lead、asset、flow、lifecycle 或 invariant。

### Phase 3：将 Invariant Builder 变成 Planner 的按需能力

停止在 `internal/pipeline/run.go` 中于 Planner 前无条件执行 `invariants.Run`。保留 TWE context 编译，并将 invariant formalization 暴露为 Planner action 或内部能力：

```text
formalize_invariant(
  lead_id,
  evidence_refs,
  subject_symbols,
  security_question
)
```

运行顺序调整为：

```text
repoIndex.Run
  ↓
projectMap.Run
  ↓
runL3Planner
  ├─ select Audit Lead
  ├─ retrieve evidence
  ├─ formalize CaseInvariant
  └─ execute verification query
  ↓
cases.Enrich / downstream review
  ↓
derive SecurityArchitecture and invariant assessments
```

为兼容现有 Expert/Challenger/Verifier/Arbiter，`project_invariants.v1.json` 可以暂时保留，但应在 Planner 之后由全部 CaseInvariant 派生，不能继续作为 Planner 的前置输入。下游每个 Case 只接收与自己相关的 invariant slice。

### Phase 4：后移 Architecture 并允许回写

Planner/Expert/Verifier 确认或否定某条架构假设后，写入 append-only architecture adjustment：

```text
01_context/architecture_updates.jsonl
```

例如 line 240 被确认是假 freshness signal 后，应机械地：

- 将对应 Lead 或 fingerprint signal 标记为 rejected；
- 使依赖它的 flow/lifecycle 失效；
- 将相关 CaseInvariant 标记为 withdrawn，或退回 Audit Lead 重新 grounding；
- 不让旧假设继续进入 Arbiter 的 context。

---

## 7. 验收标准

### 7.1 Program Index / Project Map

- `repo_facts.scope.commit == manifest.commit`；
- 输出 indexed file count、语言、build target 和 unresolved edge 数量；
- Function Capsule 必须绑定真实 symbol，不把注释关键词当成字段或行为；
- Project Map 中的确定性事实与 LLM 摘要状态明确分离；
- 01 阶段不产生安全锚点、finding 或 grounded invariant；
- 所有负面结论携带查询范围，禁止把 `not found in slice` 写成 `not present in repository`。

### 7.2 Planner / Security Architecture

- Planner 完成最低限度的 Repository/Module/Function reconnaissance 后才能结束；
- 每个 Audit Lead 记录选择理由、目标 symbol、所需上下文和不确定性；
- 每个 Case 必须由 Lead 和实际 EvidenceSlice 派生；
- 每个 CaseInvariant 必须绑定 Lead、真实 symbol、precondition、required property、security effect 和 executable query；
- `related_twes` 允许为空，新项目语义不能因 catalog 没有对应项而被丢弃；
- CaseInvariant 与 InvariantAssessment 分开存储，只有 Verifier/确定性验证能产出 satisfied/violated；
- 每个 observed architecture relation 至少有一个 path/fact reference；
- 每个 inferred relation 的依赖链最终落到 observed/documented fact；
- 单行关键词不能独立建立 data flow 或 state lifecycle；
- unknown-only 节点不能直接产生 grounded project invariant；

建议记录指标：

```text
structural_scope_coverage
module_cards_reviewed / module_cards_total
function_capsules_reviewed / function_capsules_total
audit_lead_count
lead_to_case_conversion_rate
evidence_slice_count / token cost
observed_relation_ratio
unresolved_call_edge_count
grounded_invariant_ratio
executable_invariant_ratio
invariant_assessment_resolved_rate
rejected_lead_rate
architecture_revision_count
```

### 7.3 Benchmark

对 vulnerable/fixed 成对 commit 同时评估：

- 漏洞侧能否形成真实 source/producer → authority 路径；
- 修复侧能否识别新增 guard/propagation，而不是仅靠最终标签不同；
- path 和 reasoning 是否正确，不只看 finding 文件名和状态；
- Planner 在两侧选出的 Audit Leads 是否覆盖 oracle 相关 symbol，并在代码证据上产生合理差异；
- 记录 oracle symbol 的最小排名、lead recall@K 和首次取得 oracle path 所需的查询/token；
- 同一 CaseInvariant 在 vulnerable/fixed 两侧是否得到可解释的 violated/satisfied 差异；
- token、查询次数、EvidenceSlice 数量与检出率的关系。

这比单独统计 recall 更能区分“模型碰巧说中漏洞”和“扫描器真正理解了项目代码”。

---

## 8. 设计参考及采用方式

### 8.1 OWASP Secure Code Review / Threat Modeling

- [OWASP Secure Code Review Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)

采用点：先理解资产、入口和信任边界，再进行 code-path tracing、state analysis 和 source-to-sink 数据流验证。TEECheck 中初始 Project Map 帮助 Planner 导航，后置 SecurityArchitecture 记录已经取得的安全关系，两者都不能替代代码证据。

### 8.2 CodeQL

- [CodeQL：About data flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)
- [GitHub CodeQL：Explore data flow paths](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-vs-code/explore-data-flow)

采用点：先把代码变成可查询的局部/全局数据流图，漏洞证据由具体 source-to-sink 路径和 path steps 构成。TEECheck 的 observed flow 应引用这类路径，而不是由 LLM 根据函数名生成。

### 8.3 Joern Code Property Graph

- [Joern：Code Property Graph](https://docs.joern.io/code-property-graph/)

采用点：将 AST、CFG、调用和数据依赖统一成可叠加的程序事实图。TEECheck 不一定必须采用 Joern，但 `RepoFacts + overlays` 的分层应借鉴这种“先建图，再查询和解释”的方式。

### 8.4 Meta Infer 的 compositional analysis

- [Meta：Finding inter-procedural bugs at scale with Infer](https://engineering.fb.com/2017/09/06/android/finding-inter-procedural-bugs-at-scale-with-infer-static-analyzer/)

采用点：全仓先做廉价过程摘要，在调用点组合，只有相关路径需要深入。对应 TEECheck 的取舍是“全仓结构摘要 + Planner 运行时选择目标并按需展开”，而不是全仓逐文件喂给 LLM。

### 8.5 IRIS

- [IRIS repository](https://github.com/iris-sast/iris)
- [IRIS paper](https://arxiv.org/abs/2405.17238)

采用点：LLM 用于生成/补充 source-sink 规格和过滤候选路径，跨文件程序路径仍由 CodeQL 等静态分析承载。对应 TEECheck：TWE/LLM 负责安全语义，fact layer 负责可达路径。

### 8.6 Antaeus

- [Antaeus: A System for LLM-Based Vulnerability Detection in Repository Scale](https://arxiv.org/abs/2607.01138)

采用点：先做轻量全仓函数优先级排序，再将局部函数上下文与仓库级功能、资源和信任边界结合审计。TEECheck 不照搬固定排序器，而是让 Planner 浏览 `ProjectMap/FunctionCapsules` 后形成 `AuditLead → EvidenceSlice → SecurityArchitecture`。

### 8.7 DREA

- [DREA: Goal-Directed Context Acquisition for Repository-Level Auditing](https://arxiv.org/abs/2607.13439)

采用点：将漏洞假设/规划与代码探索/检索分离，按当前假设获取上下文，并单独评估 reasoning correctness。对应 TEECheck：Planner 产生有边界的 Audit Lead，retrieval/fact actions 负责证明或否定，不用增大一次性 prompt 代替检索。

### 8.8 VulWeaver

- [VulWeaver](https://arxiv.org/abs/2604.10767)

采用点：先构建统一依赖图，再通过 program slicing 获取显式上下文，并补充定义、声明和用法等隐式上下文，最后让 LLM 推理。对应 TEECheck 的 EvidenceSlice 内容设计。

---

## 9. 修复后的预期边界

修复后仍不能保证扫描器覆盖所有代码路径：函数指针、汇编、生成代码、构建变体和外部依赖仍可能产生 gap。但系统应能够明确区分：

```text
全仓结构上已观察到
路径分析推导得到
项目文档声称
安全模型推断
当前 scope/tool 下未知
```

BUG-003 的完成标准不是生成一张更丰富的架构图，而是做到：

> **01 阶段只提供可查询的全仓地图，不提前规定哪里危险；Planner 决定下一段要读的代码，工具验证 Planner 的问题，安全架构和项目不变量再从已取得的证据中形成。广度由全仓事实层保证，深度由 Planner 驱动的按需展开保证。**
