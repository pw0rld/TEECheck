# TEECheck 与 tee-audit 融合：架构与实施

> 状态：Draft / 待评审
> 日期：2026-07-22
> 前身：本文合并自 `TEECHECK_TEE_AUDIT_MERGE_PROPOSAL.zh-CN.md`（架构提案 v3）与 `TEECHECK_TEE_AUDIT_MERGE_IMPLEMENTATION_PLAN.zh-CN.md`（实施计划 rev.2），原两份文档由本文取代
> 核心模型：TWE 前置知识 + 项目理解层 + CodeQL 事实层 + 多 Agent 审计
> 首个垂直切片：Rollback TWE + CVE-2026-44362 vulnerable/fixed

## 0. 本次合并所做的修订

合并时对两侧仓库的实际资产做了核对，以下前提相对原提案有实质变更。正文中以「**修订**」标注。

1. **v1 目标语言定为 C / TEE OS**。现有 45 个 benchmark 案例中 43 个是 C（OP-TEE OS ×20、TrustedFirmware-M ×9、OpenEnclave ×4、Occlum、Linux kernel）。原提案 §17 待决策第 9 条「第一批语言是 Go 还是 Go + Rust」就此结案，答案是两者都不是。
2. **融合形态定为吸收式**：单一 `teecheck` CLI、单一流程、单一 finding 语义，tee-audit 不再独立发布。原提案 §17 待决策第 13 条就此结案。
3. **新增资产三分**（§15.5）：tee-audit 的代码不是整体可用，必须按「原样搬 / 重建 / 退场」分类处置。这是原提案与原计划共同缺失的环节。
4. **TrustIR 的接入方式重写**（§6、§23）：原设计的 operation 式工具接口与 tee-audit 的实际形态不符，且 tee-audit 无 C 支持。改为「TrustIR-C 事实层」，并升格为全计划最大风险项。
5. **Python 不作为长期运行组件**（§15.7）。这是相对原提案非目标「不立即把 tee-audit 的全部 Python 重写成 Go」的实质变更，如不接受需回退 §15.7 与 §23。
6. **新增融合红线**（§15.6）：tee-audit stage 7 的「工具无产出时从 invariant 合成 finding」行为禁止移植。
7. **Benchmark 门禁增加对照组 FP 率**（§27）：单案例 differential 可被平凡通过。

---

# 第一部分：架构

## 1. 执行摘要

TEECheck 与 tee-audit 解决的是同一类问题：帮助安全研究人员审计 TEE 项目的源码、信任边界和安全流程。两者的分类法本就同构——tee-audit 的 `codeql/trustir/*/` 按 `flow / guard / binding / state / config / design / leakage` 组织，与 TEECheck `internal/twe/types.go` 的 `FamilyFlow..FamilyLeakage` 一一对应。融合是把同一套方法论的两次实现收敛成一次。

各自最值得保留的能力：

- TEECheck：Planner、多 Agent 协作、工具执行、事件记录、源码引用、人工复核、统计和 benchmark。
- tee-audit：TEE fingerprint、architecture dossier 与 taxonomy-guided invariants 的**方法**；16 个 TWE 定义与事实词表；`annotate → facts → fixed-queries` 的 CodeQL 使用架构。

本文采用以下核心定义：

> **TWE** 是从真实 TEE 漏洞和审计经验中总结出的前置安全知识。它以简洁场景告诉 Agent 应关注哪些信任边界、代码流程、攻击条件、保护机制和误报条件。

> **事实层（TrustIR）** 是 Agent 调查源码时使用的结构化代码事实来源。它由 LLM 标注、resolver 校验、生成 CodeQL 事实表、再由固定查询消费，把结果绑定到真实源码。

> **Project Understanding Layer** 负责先回答三个问题：仓库中客观存在什么、这些组件如何组成信任架构、该项目必须满足哪些具体安全不变量。由确定性 Fingerprint、带证据的结构化 Architecture Model 和项目专属 Invariants 组成。

合并后只有一条统一的多 Agent 审计流程：

```text
全部 TWE 前置知识
        +
Deterministic Fingerprint
        ↓
Architecture Agent 建立信任架构
        ↓
Invariant Agent 生成项目专属安全义务
        ↓
Investigator/Planner 根据 TWE 场景探索代码
        ↓
按需调用事实层、代码搜索和调用图
        ↓
形成有源码证据的 TWE Investigation / Case Pack
        ↓
Expert、Challenger、Verifier、Arbiter
        ↓
Human Review
        ↓
Benchmark、TWE 和工具持续改进
```

Fingerprint 回答「仓库里客观存在什么」，Architecture Model 回答「系统如何工作」，Invariant 回答「该项目必须保证什么」，TWE 回答「根据经验应该怀疑什么」，事实层回答「代码实际上证明了什么」。

**修订**：原提案把 TrustIR 与 CodeQL 并列为两种可选工具。实际上 TrustIR **就是** CodeQL 的一种使用方式，并列会让人误以为存在两套独立的静态分析能力。本文统一称「事实层」。

## 2. 目标与非目标

### 2.1 目标

- 将经验型 TWE 作为所有审计 Agent 默认拥有的前置知识。
- 融合 tee-audit 的平台/artifact/manifest Fingerprint，形成可引用的项目画像。
- 融合 parties、roles、assets、trust boundaries 和 data flows，形成结构化 Architecture Model。
- 让 TWE 与 Architecture Model 共同生成项目专属、可验证的 Security Invariants。
- 让 Agent 根据 TWE 场景在目标代码中寻找相似的实际安全流程。
- 建立绑定真实源码的事实层，作为 Agent 可调用的能力而非独立工作流。
- 保留 TEECheck 的探索能力、多 Agent 复核、事件追踪和人工闭环。
- 明确区分工具事实、Agent 判断和人工结论。
- 支持标准 TWE 实例、TWE 变体、多个 TWE 组合和 catalog gap。
- 使用同一 benchmark 评估 vulnerable/fixed、定位、误报和覆盖缺口。

### 2.2 非目标

- 不建设向量数据库或语义检索式 RAG。
- 不根据项目画像提前排除没有明显信号的 TWE。
- 不把每个 TWE 等价为一条 CodeQL query。
- 不把 Architecture Dossier 的自由文本或 LLM Invariant 直接当作代码事实或漏洞结论。
- 不要求事实层自动完成完整漏洞判定。
- 不把多 Agent 的模型共识当作真实漏洞证明。
- 不把 tee-audit 传统七阶段流水线搬入 TEECheck。
- **（修订）** 不保留 tee-audit 作为独立可运行产品。原提案的非目标「不立即把全部 Python 重写成 Go」已被 §15.7 取代——在 C 目标下不存在「重写与否」的选择，只有「用哪种语言新写」。

## 3. 核心概念

### 3.1 TWE：版本控制下的审计剧本

TWE（TEE Weakness Entry）是对一类 TEE 漏洞机制的经验抽象。每个 TWE 用简洁、稳定的语言描述：

- 漏洞故事；
- 攻击者能力；
- 典型信任边界；
- 应该先寻找什么；
- 找到以后如何继续追踪；
- 完整攻击链需要哪些证据；
- 哪些防御可以阻断攻击；
- 常见误报；
- 可能组合的其他 TWE；
- 工具可以提供哪些帮助。

TWE 的主要消费者是 AI Agent，不是 CodeQL 编译器。CodeQL、grep、tree-sitter、调用图都只是 Agent 执行 TWE 调查步骤时使用的工具。

### 3.2 TWE 不是 RAG

TWE 文件直接存放在仓库中，经过版本控制和代码评审。扫描开始时，系统将紧凑的 TWE 知识编译成统一前置上下文，提供给各审计 Agent。

当前不需要 embedding、vector database、top-k semantic retrieval、文档 chunk，或基于相似度决定哪些 TWE 可以被 Agent 看到。

如果未来 TWE 数量显著增长，可使用确定性的上下文编译方式（全部 TWE 短版常驻、扩展案例按 ID 加载）。这仍是普通文件加载和显式引用，不是 RAG。

上下文体积受 §11.1 的编译期硬上限约束。

### 3.3 事实层：结构化程序事实

事实层用于表达 Agent 在当前仓库中发现的程序事实：

trust boundary entrypoint；ECALL/OCALL、RPC、FFI、vsock、host callback；state object；persistence/restore operation；claim field；authority point；guard；binding relation；source/sink；code flow；suppressor；coverage gap。

**修订**：原提案设想事实层「可以接收 Agent 提出的定向调查目标」，即 operation 式按需提问。tee-audit 的实际形态是批处理：全量抽取 → LLM 标注 → 事实表 → 固定查询一次跑完。两者的差异及处理见 §6。

事实层的结果必须绑定到真实代码实体和位置。

### 3.4 Project Understanding Layer

```text
Repository
  -> Deterministic Fingerprint
  -> Structured Architecture Model
  -> Project-specific Security Invariants
  -> TWE-guided Investigation
```

#### Fingerprint：仓库中客观存在什么

由确定性代码扫描产生，吸收 tee-audit 已有的平台、trust artifact 和 manifest 识别能力，合并到 TEECheck Preprocessor。

应识别：

- TEE 平台：SGX、TDX、SEV/SNP、TrustZone、Nitro、Gramine、Open Enclave、OP-TEE 等；
- 语言、构建系统和 feature/build tags；
- 角色信号：validator、key manager、signer、relayer、oracle、bridge、worker、sequencer 等；
- trust artifacts：quote、report、measurement、PCR、report_data、nonce、sealed state、epoch、counter、key material 等；
- manifests：EDL、Gramine manifest、enclave config、Dockerfile、deployment YAML、EIF/SGX signing config 等；
- 候选边界、敏感路径和状态持久化信号。

Fingerprint 只记录带来源的候选事实。发现 `validator` 关键词只能产生 `candidate_role`，不能断言该组件就是安全架构中的 validator。

**修订**：tee-audit 的 Web3 role signal 在 C/TEE OS 目标下命中率低，检测器保留但不作为 v1 验收项。

#### Architecture Model：系统如何工作

Architecture Agent 使用 Fingerprint、manifest、repo map、关键源码和工具结果，建立结构化架构模型：parties、components 和 roles、trust zones、trust boundaries、assets、entrypoints、data flows、persistence/lifecycle、trust assumptions、deployment assumptions、unknowns。

结构化 JSON 是权威 artifact，Markdown Dossier 只作为人类可读视图。每个架构陈述必须带状态：

- `observed`：源码、manifest 或工具直接证明；
- `inferred`：由多项事实推断；
- `documented`：项目文档声明但代码尚未验证；
- `unknown`：当前无法判断。

所有 `observed` 和 `documented` 陈述必须带引用；`inferred` 必须列出其依赖事实。下游 Agent 不得把 inferred/documented 自动提升为 observed。

该区分只有在 citation 校验器足够严格时才有意义，校验器的要求见 §22。

#### Security Invariants：该项目必须保证什么

Invariant Agent 使用全部 TWE 前置知识和 Architecture Model，把通用漏洞经验实例化为项目专属安全义务：

```text
通用 TWE：Host 可能回滚 TEE 持久化状态。

项目架构：Host 保存 sealed WalletState；restore_wallet 恢复状态；
          transaction_counter 影响 sign_transaction。

项目 Invariant：在 restored WalletState 影响 SignTransaction 之前，
                 TEE 必须使用 Host 无法共同回滚的 freshness anchor
                 验证状态连续性。
```

每个 Invariant 至少包含：invariant ID 和 statement；related TWE；parties/assets/zones/boundaries；entrypoints 和 authority points；required properties/guards/bindings；expected defenses；architecture evidence；verification plan；unresolved assumptions。

Invariant 初始状态只能是 `proposed`。只有后续工具和 Agent 调查才能将其更新为 `grounded`、`satisfied`、`violated_candidate`、`unresolved` 或有证据支持的 `not_applicable`。

### 3.5 三层结论必须分离

```text
Tool Facts
        ↓
Agent Assessment
        ↓
Human Verdict
```

| 层 | 可以决定什么 | 不能决定什么 |
|---|---|---|
| 工具 | 实体、位置、路径、查询命中、检测到的 guard、覆盖范围 | 业务影响、完整攻击语义、最终漏洞 |
| Agent | 安全语义、攻击假设、跨组件关系、严重度建议、缺失证据 | 修改原始工具事实、伪造路径、取代人工结论 |
| Human | 最终漏洞结论、严重度、披露和修复决策 | 不应覆盖原始扫描记录，而应追加 verdict |

## 4. 两侧资产核对

本节数据来自对两个仓库的实测，替代原提案 §4 的定性描述。

### 4.1 能力对位

| 能力 | tee-audit | TEECheck | 融合归属 |
|---|---|---|---|
| Fingerprint / TEE 信号 | stage0 192行 + `patterns/tee_signals.py` 142行 | `preprocessor` 646行 | 合并信号库，两边都有实质内容 |
| 架构理解 | `stages/dossier.py` **97行** | 无 | tee-audit 出方法，不出代码量 |
| Invariant 生成 | `stages/invariants.py` **77行** | 无 | 同上 |
| CodeQL 编排 | `stages/codeql.py` 459 + `trustir/` 5782 | `internal/codeql` + `querygen.go` | tee-audit 架构胜（§6） |
| Triage / 定级 | `stages/triage.py` 193行 | `solver` 475行 | TEECheck 胜 |
| 深度验证 | `stages/deep_verify.py` **1329行** | `expert`715 + `challenger`274 + `verifier`942 | TEECheck 胜（多 Agent 独立复核） |
| 报告 | `stages/report.py` **2348行** | `report`191 + `stats`2298 | TEECheck 胜 |
| 报告复核 | `stages/report_review.py` **1419行** | `arbiter`584 + `review`741 | TEECheck 胜 |

tee-audit `stages/` 的 82%（report 2348 + report_review 1419 + deep_verify 1329 = 5096 行）落在 TEECheck 已更强的一侧。而它真正稀缺的 dossier + invariants 合计仅 174 行。

结论：两者不是对等的两半，而是 T 型互补。**tee-audit 贡献前半段（信号、架构方法、事实层架构与词表），TEECheck 贡献后半段（多 Agent、benchmark、review 闭环），中间的 CodeQL 层用 tee-audit 的架构重建。**

### 4.2 语言覆盖（决定 v1 目标的关键事实）

| | tee-audit | TEECheck |
|---|---|---|
| CodeQL 查询 | `codeql/trustir/` 22 个 `.ql` + `common/*.qll` 527行 | 1 个 `.ql`（`missing_subject_binding.ql`） |
| 支持语言 | **go / javascript / rust** | `engine.go` 注释提及 `rust`、`cpp` |
| Benchmark | — | **45 个案例中 43 个是 C** |

`trustir/codeql_runner.py` 的 pack 解析函数注释为 *"Return the query-pack directory for language (go/javascript/rust)"*，非这三种直接 `FileNotFoundError`。

`annotation_facts.py` docstring 进一步自述：*"Go is fully implemented (primary validation language); Rust mirrors the same predicates...; JS would emit Go-style clauses per the known gap."* 即真正端到端验证过的只有 Go。

因此 C 的事实层是**新建**而非包装。这是 §0 修订 1 与修订 4 的依据。

### 4.3 TEECheck 作为控制面的依据

- L3 Planner 能动态调用 sink catalog、ripgrep、文件读取、tree-sitter outline 和 `reverse_trace`。
- 已有 action/token/time budget 和 subprocess executor policy。
- 有 append-only events、content-addressed blobs 和 planner replay。
- 源码引用支持行号、字节区间和 SHA256 校验。
- 有人工 verdict、reason code、stats、curator 和 benchmark。

这五项是 tee-audit 完全没有的，也是「TEECheck 是控制面、主 CLI 和 Agent runtime」这一决策的依据。

### 4.4 TEECheck 现存问题

- Expert、Challenger、Verifier 和 Arbiter 通常使用同一模型，且下游角色会被上游结论影响。
- 部分通用 CodeQL/Joern adapter 尚未完成。
- 默认 heuristic 更适合生成候选，不适合证明完整 obligation 缺失。
- TWE 支线的 catalog 覆盖较小：`knowledge/twe/` 当前只有 3 个条目，而 tee-audit `spec/twe_catalog.yml` 已定义 16 个。

### 4.5 tee-audit 传统七阶段流水线

```text
Fingerprint -> Architecture Dossier -> Security Invariants -> Analysis Matrix
  -> CodeQL Scan -> Triage + Deep Verify -> Report Assembly -> Report Review
```

前三项正式融合为 Project Understanding Layer。其余不进入主流程（§15.5 C 类），原因见 §4.1 与 §15.6。

## 5. TWE 知识格式

### 5.1 推荐结构

```yaml
id: TWE-STATE-001
name: Trusted State Rollback
family: State

scenario: >
  An untrusted host restores an older version of TEE-protected state.
  The TEE accepts the stale state because integrity protection does
  not provide freshness.

attacker_capabilities:
  - control_host_storage
  - replay_previous_snapshot
  - restart_tee_instance

look_for:
  - host_to_tee_entrypoints
  - state_save_and_restore_flows
  - sealed_state_in_untrusted_storage
  - counters_epochs_versions
  - security_decisions_using_restored_state

investigation_steps:
  - enumerate_trust_boundary_interfaces
  - identify_security_sensitive_state
  - trace_state_persistence
  - trace_state_restore
  - determine_whether_storage_is_replayable
  - check_external_freshness_anchor
  - trace_restored_state_to_authority
  - construct_attack_sequence

required_evidence:
  - replayable_persistent_state
  - reachable_restore_path
  - missing_or_replayable_freshness_anchor
  - security_effect_after_restore

common_defenses:
  - hardware_monotonic_counter
  - remote_trusted_epoch
  - consensus_finalized_height
  - append_only_commitment
  - mandatory_reprovisioning

common_false_positives:
  - restored_state_is_non_security_cache
  - restore_path_is_test_only
  - downstream_system_rejects_stale_state

related_twes:
  - TWE-STATE-REPLAY
  - TWE-CONFIG-WEAK-MODE

tool_hints:
  - enumerate_boundary_entrypoints
  - enumerate_persistence_operations
  - trace_restore_to_authority
  - find_freshness_guards
```

ID 方案沿用 tee-audit 的编号（`TWE-<FAMILY>-<NNN>`）。这不是偏好问题——其 CodeQL
查询图纸在 `@id` 与 `@tags` 中引用这些编号 **207 次、覆盖 60 份查询**，是 PR-05 的
直接工作面。可读式 id（如 `TWE-STATE-ROLLBACK`）已废弃。

### 5.2 TWE 中不应包含的内容

- 大段具体 CodeQL；
- 某个项目的硬编码函数名；
- 直接写死漏洞结论；
- 只适用于一个 SDK 版本的行号；
- 仅靠关键词命中的签名规则。

平台/API pattern、CodeQL module 和查询模板通过单独的 adapter/tool metadata 关联到 TWE。

### 5.3 事实词表

**（新增）** TWE playbook 描述的是「怀疑什么」，事实层需要一份可枚举、可校验的**词表**来描述「代码里叫什么」。tee-audit `trustir/spec/enum_registry.yml`（181行）已定义该词表：`state_object_kind`、`authority_kind`、以及 `monotonic_counter_check` / `version_check` / `epoch_check` / `state_root_check` 等 suppressor 名。

词表是标注 prompt 与查询消费端的**共同约束**，必须只有一处定义。tee-audit v1 的致命 bug 之一正是 enum mismatch（§23.4）。

### 5.4 全部 TWE 如何进入上下文

由 `TWEContextCompiler`：

1. 读取所有 TWE 文件；
2. 校验 ID、family 和字段；
3. 转换成统一、紧凑的 Agent 上下文；
4. 在每个安全审计 Agent 的基础 prompt 中注入；
5. 记录 TWE catalog 版本和内容 hash；
6. **（新增）** 校验总体积不超过编译期上限，超限则编译失败而非截断。

系统可以根据代码信号调整调查顺序和预算，但不能因为初始画像没有发现某个 API 就把对应 TWE 从知识上下文中删除。

## 6. 事实层设计

> **（本节相对原提案 §6 重写）**

### 6.1 为什么不采用 operation 式接口

原提案设计了 `trustir_enumerate_boundaries` / `trustir_trace_flow` / `trustir_find_guards` / `trustir_check_binding` 等 11 个工具，即 **Agent 按需提问**的交互模型。

tee-audit 的实际形态是**批处理**：

```text
fetch_*.ql 全量抽取 functions/calls/params/field_reads
  -> enumerate_classify.py 由 LLM 分类语义角色
  -> resolver verify/reject
  -> annotation_facts.py 生成 GeneratedTrustFacts.qll
  -> 22 个固定查询一次跑完
  -> Solver -> JSON / Markdown / SARIF
```

`trace_flow`、`find_guards`、`check_binding` 在 tee-audit 里不是可调用的操作，**它们就是那些成品查询本身**。因此原提案的工具列表是一套新交互模型的设计，不是对既有能力的封装。

### 6.2 架构选择

采用 tee-audit 的 `annotate → facts → fixed-queries` 架构，**替换** TEECheck 现有 `internal/codeql/querygen.go` 的「Go 模板拼出整条 `.ql`」路线。

这里的「替换」是**路线选择**——事实表路线胜过模板路线，作为主路径的 CodeQL 语义；不是一次主路径改写操作（`querygen.go` 本就在旁路 twescan，不在主路径，见 §23.1 勘误）。

依据：`SealedStateRestoreWithoutVersion.ql` 的语义几乎全部由 `GeneratedTrustFacts::isClaimField / isAuthorityPoint / hasSuppressor` 构成，语言相关的只有 `import rust` 与 `DataFlow::Node` 两行。语言耦合被压缩进 `common/*.qll`（527行）与 clause 生成器。

- 现路线新增一门语言的成本 = O(查询数)；
- 新路线 = O(1)。

这也是查询数只有 22 个而非 22×N 的原因。

### 6.3 Agent 与事实层的交互

保留原提案「Agent 应能指定范围」的意图，但以事实表的形态实现：

- Agent 指定 scope（files/modules/symbols/TWE ID/depth），影响的是**标注阶段的候选集**与**查询的过滤条件**，不是发起一次独立的图查询；
- 事实层结果写 artifact，prompt 中只放摘要和 ref；
- Agent 需要细节时读取 artifact 或用源码工具。

### 6.4 输出必须结构化

```json
{
  "tool": "trustir_facts",
  "twe_id": "TWE-STATE-001",
  "repo_commit": "...",
  "roles": {
    "restore_operation": {
      "symbol": "restore_wallet",
      "file": "src/enclave/state.rs",
      "line": 81
    },
    "authority_point": {
      "symbol": "sign_transaction",
      "file": "src/enclave/sign.rs",
      "line": 142
    }
  },
  "paths": [],
  "guards": [],
  "coverage_gaps": [
    "host storage implementation not modeled"
  ],
  "artifact_ref": "sha256:..."
}
```

### 6.5 事实层不是最终裁判

可以证明或支持：某实体存在；某路径存在；在已建模范围内没有找到某类 guard；某个值流向 authority；某个路径属于 test-only；某次查询或构建没有完成。

单独不能证明：攻击者一定能满足全部前提；部署环境一定启用该路径；协议外层一定没有保护；业务影响和严重度；一个未命中的 query 等于不存在漏洞。

## 7. 统一多 Agent 流程

### 7.1 总体流程

```text
                    TWE Knowledge Context
                              |
Repository -> Deterministic Fingerprint
                              |
                      Architecture Agent
               parties / roles / boundaries /
                 assets / flows / assumptions
                              |
                       Invariant Agent
               project-specific obligations
                              |
                    Investigator/Planner
                              |
         +--------------------+--------------------+
         |                    |                    |
    事实层（CodeQL）        Code Search          Call Graph
   structured facts       read/ripgrep         reverse trace
         |                    |                    |
         +--------------------+--------------------+
                              |
                     TWE Investigation
                              |
                          Case Pack
                              |
             +----------------+----------------+
             |                                 |
         Expert                          Challenger
             |                                 |
             +----------------+----------------+
                              |
                           Verifier
                     targeted tool calls
                              |
                           Arbiter
                              |
                        Human Review
                              |
                Benchmark / TWE evolution
```

### 7.2 Fingerprint / Preprocessor

- 使用确定性扫描识别 TEE platform、语言、role signals、trust artifacts 和 manifests；
- 建立候选 entrypoints、boundaries、state/persistence signals 和 sensitive paths；
- 为每个信号保存文件、行号、pattern/parser 和置信来源；
- 不将角色关键词或 API 命中直接解释成架构事实；
- 输出 `ProjectProfile`。

### 7.3 Architecture Agent

输入：全部 TWE 前置知识；ProjectProfile；manifests 和 repo map；关键源码和文档引用。

职责：建立 parties、components、roles、assets、zones 和 boundaries；描述跨边界 data flows 和 state lifecycle；记录 trust/deployment assumptions 和 unknowns；将每个陈述分类为 observed/inferred/documented/unknown；为 observed/documented 提供引用，为 inferred 提供依赖事实；同时输出结构化 Architecture Model 和人类可读 Dossier。

它不生成漏洞，也不把「没有观察到」解释为「不存在」。

### 7.4 Invariant Agent

输入：全部 TWE 前置知识；Architecture Model；ProjectProfile 和相关 evidence refs。

职责：将通用 TWE 场景实例化为项目专属安全义务；将 invariant 绑定到 parties、assets、boundaries、entrypoints 和 authority points；列出 required guards/bindings/state properties 和 expected defenses；为每个 invariant 生成可执行 verification plan；允许生成无法归入现有 TWE 的 project-specific invariant 并标记 catalog gap；输出 `ProjectInvariant[]`，初始状态均为 `proposed`。

它不根据 proposed invariant 直接生成 finding。

### 7.5 Investigator / Planner Agent

输入：全部 TWE 前置知识；ProjectProfile；Architecture Model 的相关结构化对象；Project Invariants；repo map；工具列表和预算；已观察文件、实体和路径。

职责：按 TWE 场景主动寻找相似代码流程；按 Project Invariant 的 verification plan 建立具体调查任务；先执行便宜的边界/API/状态枚举；对有信号的方向继续追踪；动态组合多个 TWE；调用事实层获得结构化事实；形成 `TWEInvestigation` 和 bounded Case Pack；对现有 TWE 无法表达的问题标记 `catalog_gap`。

它不负责最终漏洞结论。`missing role` 是下一步任务，不是漏洞结论。

### 7.6 Expert Agent

输入：相同 TWE 前置知识；当前 Case 相关的 Architecture slice 和 Project Invariants；Case Pack；原始 ToolFact 引用；关键源码片段。

职责：解释代码事实的安全语义；构造完整攻击假设；列出攻击前提；指出缺失证据；判断是标准 TWE、变体、组合还是 catalog gap。所有代码事实必须有可验证引用。不得修改 ToolFact。

### 7.7 Challenger Agent

第一阶段只看到：TWE 前置知识；结构化 Architecture slice 和对应 Invariants；Case Pack 的原始源码和工具事实；**不包含 Expert 结论**的证据视图。

职责：独立判断是否存在问题；寻找 wrapper、lower layer、外部服务和协议保护；检查 test/debug/config/deployment 条件；检查 TWE 中列出的 common defenses 和 false positives；提出可以被工具验证的反例。

完成独立判断后，才进入 Expert/Challenger 结论比较阶段。

**已知限制（新增）**：第一阶段共享的 ToolFacts 本身是 Expert/Planner 调查方向的产物，Challenger 看到的是被 Expert 提问塑造过的事实集。真正的独立需要 Challenger 能自行发起事实层调用。v1 不解决，但不得因「第一阶段 prompt 不含 Expert 结论」这一断言测试通过就认为独立性已达成。

### 7.8 Verifier Agent

职责：将双方争议转换成具体工具问题；定向调用事实层/调用图；验证源码引用是否仍有效；检查攻击链的每一个必要环节；验证争议所依赖的 architecture statement 和 invariant assumption；区分「未找到」与「证明不存在」；记录 coverage gap 和工具失败。

可更新 invariant verification status，但保留原始 proposed artifact。

### 7.9 Arbiter Agent

不重新自由分析整个仓库，而是汇总：已确认 ToolFacts；相关 Architecture statements 的证据状态；Project Invariant 的验证状态；Expert 假设；Challenger 反例；Verifier 已解决和未解决问题；攻击链完整度；需要人工确认的内容。

输出的是 human review packet，不是自动披露结论。

## 8. Rollback TWE 走查示例

### 8.1 前置知识

> Sealing 通常提供机密性和完整性，但未必提供 freshness。Host 可能保存一个历史 sealed blob，在 TEE 重启或恢复时重新提供，从而使可信状态回到旧版本。

### 8.2 Project Understanding 前置结果

```text
Fingerprint：
  SGX / EDL / seal-unseal / host database /
  restore_wallet / transaction_counter

Architecture Model：
  Untrusted Host 保存 sealed WalletState
    -> restore_wallet 在 enclave 中恢复
    -> transaction_counter 影响 sign_transaction

Project Invariant：
  INV-STATE-001：在 restored WalletState 影响 SignTransaction 之前，
  enclave 必须使用 Host 无法一起回滚的 freshness anchor 验证连续性。
```

这些结果不直接生成 rollback finding，而是给 Investigator 提供项目语义、调查目标和 verification plan。

### 8.3 第一阶段：枚举信任边界

枚举 ECALL/OCALL；EDL；host/enclave bridge；RPC/vsock/protobuf handler；FFI；初始化、重启和恢复入口。

「查看全部 ECALL/OCALL」由工具完成，Agent 接收结构化列表，而不是把所有源码放进 prompt。

### 8.4 第二阶段：识别安全状态

寻找 sealed blob；key version；transaction counter；epoch/height；authorization state；spent marker；replay cache；policy version；provisioned key。

重点问题：该状态被恢复到旧版本后，是否改变安全决策。

### 8.5 第三阶段：追踪保存和恢复

```text
WalletState
  -> serialize/seal
  -> OCALL write_state
  -> host filesystem
  -> attacker supplies old blob
  -> OCALL read_state
  -> ECALL restore_wallet
  -> unseal
  -> recovered WalletState
```

事实层负责定位实体和路径，Agent 根据 TWE 提问：Host 能否选择任意历史 blob？version 是否和 state 一起被回滚？freshness 是否锚定在 Host 不能回滚的位置？restart 是否总会触发 restore？

### 8.6 第四阶段：追踪安全影响

```text
旧 WalletState -> 旧 transaction_counter -> sign_transaction -> 重复签名或双重授权
```

如果旧状态只影响性能缓存，不构成安全 rollback。如果影响签名、授权、key release、成员撤销或共识状态，则继续建立攻击链。

### 8.7 第五阶段：检查保护

hardware monotonic counter；TPM/NV counter；远端可信 epoch 服务；consensus finalized height；append-only commitment；hash-chained state；restore 后强制重新 provisioning；下游独立拒绝旧状态。

仅存在 blob 内部 version 不足以防 rollback，因为 Host 可以同时回滚 state 和 version。

### 8.8 第六阶段：形成可复核攻击路径

```text
1. 攻击者保存 epoch=50 的 sealed state。
2. 系统运行到 epoch=100，并撤销旧成员。
3. 攻击者重启 TEE。
4. Host 提供 epoch=50 的历史 blob。
5. TEE unseal 成功，但没有不可回滚的外部 freshness anchor。
6. TEE 恢复旧成员权限。
7. 攻击者通过可信入口触发 key release。
```

每一步必须关联源码事实、工具证据或明确标记为未验证假设。

### 8.9 v1 的实际验证目标

上述示例是 SGX/Rust 风格的教学用例。v1 的实际门禁是 C 目标下的 CVE-2026-44362（OP-TEE）：

```text
vulnerable：shdr_load_pub_key() 未把 subkey_version 写入运行时 key version，
            key->version 恒为 0，check_update_version() 收到零值，
            rollback database 无法推进，回滚检查被绕过。
fixed：     版本被传播到 rollback checking。
```

两者是同一个 TWE 的不同实例——8.1~8.8 描述的是「状态被整体回放」，44362 是「版本未传播导致 guard 空转」。rollback playbook 必须同时覆盖这两条路径（§20.2）。

## 9. 统一数据契约

### 9.1 ProjectProfile

```json
{
  "schema_version": "teecheck.project_profile.v2",
  "languages": [],
  "tee_platforms": [],
  "candidate_roles": [],
  "trust_artifacts": [],
  "manifests": [],
  "boundary_signals": [],
  "state_signals": [],
  "sensitive_paths": [],
  "evidence": []
}
```

主要由确定性扫描产生。候选角色和信号不能被下游当作已确认的架构事实。

### 9.2 ArchitectureModel

```json
{
  "schema_version": "teecheck.architecture.v1",
  "parties": [],
  "components": [],
  "roles": [],
  "assets": [],
  "trust_zones": [],
  "boundaries": [],
  "entrypoints": [],
  "data_flows": [],
  "state_lifecycles": [],
  "trust_assumptions": [],
  "deployment_assumptions": [],
  "unknowns": []
}
```

每个元素至少包含 statement、status、confidence、evidence 和 dependency refs。Markdown Dossier 从该模型派生，不是另一份权威数据。

### 9.3 ProjectInvariant

```json
{
  "schema_version": "teecheck.project_invariant.v1",
  "invariant_id": "INV-STATE-001",
  "statement": "Restored WalletState must be checked against a non-replayable freshness anchor before SignTransaction",
  "related_twes": ["TWE-STATE-001"],
  "parties": [],
  "assets": [],
  "boundaries": [],
  "entrypoints": ["restore_wallet"],
  "authority_points": ["sign_transaction"],
  "required_properties": ["state_freshness", "version_continuity"],
  "expected_defenses": ["external_epoch", "monotonic_counter"],
  "architecture_refs": [],
  "verification_plan": [],
  "unresolved_assumptions": [],
  "status": "proposed",
  "classification": "standard"
}
```

`classification`（可选，enum 与 §9.5 TWEInvestigation 对齐：`standard|variant|composition|catalog_gap`）
是 catalog gap 的一等信号：当某项义务不属于任何现有 TWE 时，Invariant Agent 设
`classification: catalog_gap`，下游据此识别，而不是解析 `related_twes` 里的 sentinel。
`related_twes` 仍保留 `minItems:1`（catalog gap 时填 sentinel `TWE-CATALOG-GAP`），因此
两处都指向同一事实，但**权威信号是 `classification`**。

### 9.4 TWEKnowledgeManifest

```json
{
  "schema_version": "teecheck.twe_knowledge.v1",
  "catalog_version": "...",
  "catalog_sha256": "...",
  "twe_ids": [],
  "context_sha256": "...",
  "context_token_estimate": 0
}
```

可以判断不同扫描结果是否使用了同一版本的审计经验。`context_token_estimate` 支持 §11.1 的预算核查。

### 9.5 TWEInvestigation

```json
{
  "schema_version": "teecheck.twe_investigation.v1",
  "investigation_id": "...",
  "twe_ids": ["TWE-STATE-001"],
  "invariant_ids": ["INV-STATE-001"],
  "architecture_refs": [],
  "classification": "standard|variant|composition|catalog_gap",
  "observed_flow": [],
  "filled_roles": {},
  "missing_roles": [],
  "required_evidence": [],
  "counterevidence": [],
  "coverage_gaps": [],
  "artifact_refs": []
}
```

### 9.6 ToolFact

必须记录：tool/version；repo commit；query/arguments hash；structured result；locations/path；success/error/truncated；artifact ref。

写入后不可被 Agent 修改。

### 9.7 UnifiedFinding

```json
{
  "schema_version": "teecheck.finding.v3",
  "finding_id": "...",
  "related_twes": ["TWE-STATE-001"],
  "related_invariants": ["INV-STATE-001"],
  "architecture_refs": [],
  "classification": "standard|variant|composition|catalog_gap",
  "summary": "...",
  "tool_facts": [],
  "agent_assessment": {
    "status": "supported|contested|needs_context|rejected",
    "severity": "high",
    "confidence": "medium"
  },
  "attack_path": [],
  "anchored_evidence": [],
  "unanchored_hypotheses": [],
  "coverage_gaps": [],
  "human_verdict": null
}
```

底层 Solver 产生的状态存入独立的 `tool_facts` 或 `static_assessment` 字段，不能被 Agent 覆盖。

### 9.8 ReviewRecord

以 TEECheck 现有人工 review 为基础，至少保留：TP/FP/needs context/design risk/no issue；reason code；severity/confidence override；实际检查过的 artifact refs；认可或否定攻击链的哪一步；TWE catalog/version；工具和 query version。

## 10. Artifact 布局

```text
runs/<run-id>/
├── 00_manifest.json
├── 00_twe_knowledge.json
├── 01_context/
│   ├── project_profile.json
│   ├── architecture.json
│   ├── architecture.md
│   └── invariants.json
├── 02_tool_facts/
│   ├── trustir/
│   ├── codeql/
│   └── callgraph/
├── 03_investigations/
│   └── investigation-NNN.json
├── 04_cases/
│   └── case-NNN.json
├── 05_agents/
│   ├── expert/
│   ├── challenger/
│   └── verifier/
├── 07_arbiter/
│   ├── findings.json
│   └── packets/
├── 08_review/
├── events.jsonl
└── blobs/
```

完整 enumeration、SARIF 和 CodeQL 输出保存在 tool artifacts 中。Architecture Model 和 Invariants 只生成一次并由所有调查复用。Case Pack 只包含当前调查相关的 architecture slice、invariants、实体、代表路径、关键代码片段、保护机制和 coverage gap。

CodeQL DB 按 commit 构建一次，作为显式 artifact 落在 run 目录中（§23.3）。

## 11. Token 与成本控制

### 11.1 TWE 上下文

- TWE 本身保持简洁。
- 全部 TWE 作为固定前置知识编译一次。
- 记录 context hash，避免运行中反复拼接不同版本。
- 扩展案例和长参考材料不进入核心 TWE prompt。
- **（新增）编译期硬上限**：16 个 playbook × 6 个注入点（Planner、Architecture、Invariant、Expert、Challenger、Verifier），context 成本是乘法级的。单个 playbook 的 compact 形态设 token 上限，超限则 `TWEContextCompiler` **编译失败**而非截断。具体阈值在 PR-02 内根据 rollback playbook 的实际体量确定并写死。

仅有事后指标（tokens per reviewed finding）不足以约束这一项。

### 11.2 工具结果

- CodeQL DB、enumeration 和查询结果必须缓存。
- 事实层调用按 repo/commit/args 去重。
- 大结果写 artifact，prompt 中只放摘要和引用。
- Agent 需要细节时读取 artifact 或用源码工具。

### 11.3 项目理解上下文

- ProjectProfile、Architecture Model 和 Invariants 每个 run 只生成一次。
- 下游 Agent 不重复生成项目架构。
- 完整 Architecture Model 保存在 artifact 中，Case Pack 只携带相关子图。
- Architecture statement 通过稳定 ID 引用。
- 不同 Agent 共享相同的结构化事实，但可以独立挑战 inferred/documented assumptions。

### 11.4 Agent 上下文

- Expert 和 Challenger 共享原始 TWE/Case Pack，但不共享第一阶段结论。
- Verifier 只接收具体争议和必要 evidence refs。
- Arbiter 接收结构化摘要，不重新加载全部仓库。
- 已验证的 ToolFact 不让不同 Agent 重复自然语言复述。

## 12. CLI 与配置

不暴露 `deterministic|exploratory|hybrid` 三种工作流。TWE 知识和事实层属于统一流程的一部分。

```bash
teecheck run <repo> \
  --mode llm \
  --knowledge-root knowledge \
  --facts auto \
  --max-cases 8 \
  --max-dialog-rounds 3
```

`--facts`（原 `--trustir`）表示事实层可用策略：

| 值 | 含义 |
|---|---|
| `auto` | Agent 按调查需要调用，正常默认 |
| `required` | 事实层初始化或关键检查失败则运行标为不完整 |
| `off` | 关闭，仅用于环境受限或 ablation |

测试 TWE 前置知识效果时可提供 `--disable-twe-knowledge`，仅用于实验对照，不是正常审计模式。

## 13. 风险与缓解措施

| 风险 | 后果 | 缓解措施 |
|---|---|---|
| **C 事实层从零构建失败** | PR-06 之后全部无法验收 | 大部分已退休：C 数据库构建（C-feasibility spike）与**事实表架构 differential**（C-fact-table spike，2026-07-23）均已在 CVE-2026-44362 上验证通过。剩余风险收窄为「LLM 标注+resolver 管线的质量」与「六族的 cpp 移植」，这是 PR-05 的实现工作而非可行性未知项；独立排期 |
| **`--build-mode=none` 不做真实编译** | 宏/`#ifdef` 走源码默认值，config 门控的弱点可能测不出 | spike 已记录该限制。TF-M 的 profile 宏类案例需真实构建才有保真度——PR-09 对照组中此类案例单独标注，不计入通过 |
| **内核级仓库的克隆与抽取成本** | 跑多案例时不可接受 | DB 按 commit 构建一次并落为显式 artifact（§23.3）；PR-09 对照组按体量分批 |
| TWE 过于抽象 | Agent 无法转成代码调查 | 每条 TWE 提供明确 steps、evidence、defenses |
| TWE 过于具体 | 只能匹配已知项目 | 禁止项目函数名进入核心场景，平台细节放 adapter |
| 全部 TWE 上下文增长 | Token 和注意力压力 | §11.1 编译期硬上限，超限即失败 |
| TWE 导致确认偏差 | Agent 只找支持证据 | Challenger 输入隔离，强制检查 defenses/false positives |
| 事实层被误当最终判定 | 静态结果被过度解释 | 分离 ToolFact、AgentAssessment、HumanVerdict |
| CodeQL/构建失败 | 覆盖缺口被误认为安全 | 强制 error/unresolved/coverage gap |
| **无证据时合成 finding** | 结论脱离证据（反向） | §15.6 红线；proposed invariant 不得直接成为 finding |
| **单案例门禁过拟合** | 「闭环跑通」不等于「有效」 | §27 对照组 FP 率 |
| 同模型多 Agent | 结论相关性过高 | 第一阶段输入隔离、结构化争议、人工标签 |
| 历史报告被当真值 | 指标失真 | 只使用人工标签和明确 oracle 作为 ground truth |
| 许可证不清晰 | 合并发布风险 | PR-00 内必须确定根仓库许可证 |

**修订**：原提案「Python/Go 双运行时导致部署复杂」一条随 §15.7 消失——不再维持双运行时。

## 14. 待决策事项

原提案列 14 条，其中 6 条已结案：

| # | 事项 | 状态 |
|---|---|---|
| 1 | TWE playbook schema 必填字段 | **已定**，见 §5.1 与 §20.2 |
| 2 | 首批经验型 TWE 包含哪些类型 | **已定**：16 个定义一次搬齐，playbook 从 rollback 开始（§20） |
| 3 | TWE 核心上下文长度预算 | **已定要有硬上限**，具体值 PR-02 内确定（§11.1） |
| 4 | ProjectProfile 中 role 保持 candidate 到什么阶段 | 待决；C 目标下优先级降低 |
| 5 | Architecture 与 Invariant 用一个会话还是两个 Agent | **待决** |
| 6 | observed/inferred/documented/unknown 的升降级规则 | 部分已定（§22 校验器给出降级规则），升级规则**待决** |
| 7 | Project Invariant 的正式状态机和人工修正接口 | **待决** |
| 8 | 事实层第一批必须提供哪些能力 | **已定**，见 §23.6 |
| 9 | 第一批正式支持语言 | **已定：C**（§0 修订 1） |
| 10 | Investigator 的轮次和工具预算 | **待决** |
| 11 | TWE composition 如何表达和测试 | **待决** |
| 12 | 哪些 Architecture/ToolFact 进 prompt，哪些只留 ref | 部分已定（§11.3） |
| 13 | tee-audit 独立 CLI 是否继续维护 | **已定：不维护**（§0 修订 2） |
| 14 | 许可证与 attribution | **已定处理时点**：PR-00 内必须给出结论（§18） |

新增待决：

| # | 事项 |
|---|---|
| 15 | §15.7（Python 不作为长期运行组件）是否接受？不接受则需回退 §23 为桥接设计 |
| 16 | §11.1 的 playbook token 上限取值 |
| 17 | §27 对照组 FP 率的具体上界 |

---

# 第二部分：实施

## 15. 实施原则

### 15.1 垂直切片优先

```text
识别 TEE/manifest/state/version
  -> 建立 rollback architecture
  -> 生成 project invariant
  -> 调查 version/restore flow
  -> 事实层形成路径事实
  -> 多 Agent 检查保护和反例
  -> vulnerable/fixed benchmark
```

只有该闭环通过后，才批量迁移其他 TWE。

### 15.2 兼容旧 artifacts

- 新 schema 使用明确版本号。
- 旧 `project_profile.json`、case、finding 和 review record 保持可读。
- 新字段优先通过 additive change 引入。
- 需要破坏性变更时增加 adapter，不原地覆盖历史 run。

### 15.3 事实不可变

- ToolFact 写入后不允许 Agent 修改。
- Agent 只能引用、解释、支持或挑战 ToolFact。
- Human verdict 追加到 Finding，不覆盖原始 tool/agent 状态。

### 15.4 每个 PR 必须有退出条件

没有满足当前 PR 的验收门禁，不开始依赖它的下一阶段。

### 15.5 资产三分

tee-audit 的 17.7k 行 Python 不是整体可用。导入后立即按下表处置，**不允许整包进入构建**：

| 类别 | 内容 | 处置 |
|---|---|---|
| **A 原样搬** | `trustir/spec/*.yml`（349行：`twe_catalog.yml` 16 个 TWE、`enum_registry.yml` 事实词表、`taxonomy.yml`、`exclusion.yml`）；`patterns/tee_signals.py` 信号库；`stages/dossier.py`(97) + `stages/invariants.py`(77) 的 prompt 方法；`annotation_facts.py` docstring 记录的 v1 踩坑 | 进 `knowledge/` 与规范文档，成为主线一等资产 |
| **B 重建** | `annotate → facts → fixed-queries` 架构；`codeql/trustir/rust/common/*.qll`(527行)；7 族查询；`enumerate_classify.py` 的降噪层 | 按 C 重写，rust/go/js 版本作为图纸 |
| **C 退场** | 七阶段编排器 `pipeline.py`；`stages/report.py`(2348)；`stages/report_review.py`(1419)；`stages/deep_verify.py`(1329)；`stages/triage.py`(193) | 不进主流程 |

C 类合计约 5100 行，占 `stages/` 的 82%。A 类的代码量只有约 400 行，价值在 YAML 资产和 prompt 设计，不在代码量。

本表取代原提案 §16「应保留、吸收和淘汰的组件」。

### 15.6 融合红线

`stages/report_review.py` 的 stage 7 ralph loop 自述行为是：

> *"generates findings from invariants when CodeQL produced nothing, and refines until quality threshold is met."*

即工具无产出时从 invariant 合成 finding，再迭代到「质量达标」。这与「工具失败不得解释为没有漏洞」同源违规——一个把无证据说成安全，一个把无证据说成漏洞，两者都让结论脱离证据。

该行为在 PR-00 即标记为**禁止进入主流程**，不进入清理候选队列。

### 15.7 Python 的长期地位

C 目标下，tee-audit 的语言耦合层（`enumerate_classify.py` 降噪、`resolver/`、`binder/`、`annotation_facts.py` clause 生成器，约 1700 行）全部需要按 C 重写；语言无关层（信号库、dossier/invariants 编排）约 400 行，在 Go 中实现成本很低。

因此不为其维持 Go↔Python 进程边界（含双份 schema、超时映射、输出限额、缓存层）。`tee-audit/` 目录收缩为：

```text
tee-audit/
├── LICENSE                  # MIT，保留
├── ATTRIBUTION.md           # 来源、基线 commit、作者署名、资产三分清单
├── spec/                    # A 类：YAML 资产，主线引用
├── codeql/trustir/          # 图纸：rust/go/js 查询，不进构建
└── src/                     # 原始 Python，保留只读，作实现对照
```

见 §14 待决 15。

## 16. 目录结构

```text
TEECheck/
├── tee-usage-scanner/              # Go 控制面与 Agent runtime
│   ├── cmd/teecheck/
│   ├── internal/
│   │   ├── artifacts/
│   │   ├── preprocessor/
│   │   ├── architecture/           # 新增（PR-04）
│   │   ├── invariants/             # 新增（PR-04）
│   │   ├── twecontext/             # 已存在，待提交
│   │   ├── investigations/         # 新增（PR-06）
│   │   ├── trustirfacts/           # 新增（PR-05）：C 事实层，接进主路径
│   │   ├── planner/
│   │   └── ...
│   ├── codeql/
│   │   └── trustir/cpp/            # 新增（PR-05）：common/*.qll + 7 族查询
│   └── knowledge/
│       └── twe/
│           ├── enum_registry.yml   # 自 tee-audit spec/ 搬入（PR-02）
│           ├── taxonomy.yml        # 同上
│           ├── exclusion.yml       # 同上
│           ├── catalog.yml         # 16 个 TWE 定义（PR-02）
│           └── playbooks/
│               └── rollback.yml    # 已存在，待提交
├── tee-audit/                       # 见 §15.7，收缩形态
├── teecheck-benchmark/
├── docs/
└── schemas/                         # 已存在于根目录（8 份），待提交
```

**注**：`schemas/`、`internal/twecontext/`、`knowledge/twe/playbooks/rollback.yml` 在工作区已实现但未提交。原计划中「`schemas/` 是否放根目录可在 PR-01 确认」已是既成事实。PR-00 的第一步是把这批工作落到 integration branch。

`schemas/` 只服务 Go 与 LLM 输出校验，不再是跨语言 canonical 定义。

## 17. PR 依赖关系

```text
PR-00 Import/资产三分/Provenance
        |
PR-01 Contracts/Run Layout
        |
PR-02 TWE 定义搬迁 + Playbook/Context
        |
PR-03 Project Fingerprint
        |
PR-04 Architecture/Invariant
        |
PR-05 TrustIR-C 事实层  ← 全计划最大风险项，建议单独立项
        |
PR-06 Rollback Investigation/Planner
        |
PR-07 Multi-Agent Review
        |
PR-08 Findings/Review/Report
        |
PR-09 Rollback Benchmark Gate
        |
PR-10 Generalization/Cleanup
```

PR-05 与其余 PR 的性质不同——其他 PR 是集成与改造，PR-05 是从零构建一个 C 语言的 CodeQL 事实层。它的失败会使 PR-06 之后全部无法验收，建议独立排期并先做可行性验证（§23.7）。

PR-03 与 PR-05 的底层开发可以并行，但 PR-06 必须等待 PR-02～PR-05 的稳定契约。

## 18. PR-00：仓库导入、资产三分、许可和基线

### 目标

把 tee-audit 正式纳入 TEECheck 历史，同时**在导入的同一个 PR 内完成资产三分**，避免 C 类 5100 行代码被构建继承。

### 修改

1. 先处理 TEECheck 当前 dirty worktree：把已完成但未提交的 `schemas/`、`internal/twecontext/`、`knowledge/twe/playbooks/`、benchmark 修改落到 integration branch。
2. 创建专用 integration branch。
3. 使用 `git subtree` 将 `pinshenxu/tee-audit` 导入顶层 `tee-audit/`，保留来源和提交历史。
4. 按 §15.5 执行资产三分，导入后立即：B/C 类移出构建范围（不删除，保留只读作对照）；在 `ATTRIBUTION.md` 中记录三分结果与理由。
5. 按 §15.6 在 `ATTRIBUTION.md` 标记 stage 7 ralph loop 为禁止移植行为。
6. 保留 tee-audit MIT LICENSE 和 attribution。
7. 明确 TEECheck 根仓库许可证。仓库内已混入 MIT（tee-audit）与 BSD-2-Clause（benchmark 中的 OP-TEE 源码），越晚决定成本越高，本 PR 内必须给出结论。
8. 记录双方基线 commit：TEECheck integration base；tee-audit `f8053a18190d5e6c4cfe0da3e66e0df770832dfe` 或实际导入时选定 commit。
9. 保存当前 CLI/help、artifact schema 和 benchmark summary 作为迁移基线。

### 不做

不调整主 pipeline；不修改 TWE 语义。

### 验收

- `git log -- tee-audit/` 能追溯导入来源。
- 仓库中不存在嵌套 `.git`。
- tee-audit LICENSE 保留，根仓库许可证已确定。
- `ATTRIBUTION.md` 列出 A/B/C 三类的完整文件清单。
- C 类文件不在任何构建或测试路径中。
- 当前 benchmark 数据未被改写。

## 19. PR-01：Canonical Contracts 与 Run Layout

### 目标

确定 Go 与 Agent 之间的数据边界，使后续实现可以并行。

由于不再有 Python 运行组件（§15.7），schema 的消费者只有 Go 代码与 LLM 输出校验，跨语言 round-trip 与 Pydantic 对齐要求随之删除。

### schema（工作区已有 8 份，本 PR 审定）

对应 §9 的契约定义：`ProjectProfile v2`、`ArchitectureModel v1`、`ProjectInvariant v1`、`TWEKnowledgeManifest v1`、`TWEPlaybook v1`、`ToolFact v1`、`TWEInvestigation v1`、`UnifiedFinding v3`。

### Go 修改点

- `internal/artifacts/`：补齐上述 Go structs；保留现有 v1/v2 读取兼容；区分 `Observed / Inferred / Documented / Unknown`；区分 ToolFact、AgentAssessment、HumanVerdict。
- `internal/runfs/`：增加 context、tool facts、investigations 路径（§10）；不改变历史 run 的读取路径。

### 验收

- 旧 ProjectProfile/Findings/ReviewRecord fixture 仍可读取。
- schema version 不依赖文件名推断。
- error/unresolved/coverage gap 有明确字段。
- LLM 输出对每个 schema 都有拒绝非法值的校验测试。

## 20. PR-02：TWE 定义搬迁、经验型 Playbook 与 Context Compiler

### 目标

16 个 TWE 的定义与事实词表已存在于 tee-audit `trustir/spec/`，而 TEECheck `knowledge/twe/` 目前只有 3 个条目。事实词表是后续**所有**查询与标注的共同前提，搬迁越晚，每个新增 TWE 都要回头返工。

因此本 PR 拆成两件事：**定义与词表一次搬齐**，**playbook 与查询按 rollback 优先**。

### 20.1 定义搬迁（一次做完）

| 源文件 | 行数 | 目标 | 说明 |
|---|---|---|---|
| `twe_catalog.yml` | 81 | `catalog.yml` | 16 个 TWE：FLOW×2、GUARD×3、BIND×3、STATE×2、CONFIG×2、DESIGN×2、LEAK×2 |
| `enum_registry.yml` | 181 | `enum_registry.yml` | 事实词表（§5.3） |
| `taxonomy.yml` | 49 | `taxonomy.yml` | 七族分类，与 `internal/twe/types.go` 的 `FamilyFlow..FamilyLeakage` 对齐 |
| `exclusion.yml` | 38 | `exclusion.yml` | test/example/vendor scope 排除规则 |

搬迁时需与 TEECheck 现有 `binding.yml`、`config.yml` 两个旧 Entry 对账，去重并记录映射。

### 20.2 Playbook（仅 rollback）

- `schemas/twe-playbook.v1.json` 必填字段见 §5.1。
- `knowledge/twe/playbooks/rollback.yml`（工作区已有雏形）须同时覆盖两条路径：
  - Host 回放持久化状态（§8.1~8.8 的形态）；
  - **版本/epoch 未传播导致 rollback guard 空转**（§8.9 的 CVE-2026-44362 形态）；
  - 以及状态恢复后影响 authority 的必要链条。
- 其余 15 个 TWE 本 PR 只搬定义，不写 playbook。

### 20.3 Context Compiler

- `internal/twe/`：旧 `Entry` 与新 `Playbook` 按 schema version 明确分层。
- `internal/twecontext/`（已实现，本 PR 审定）：读取全部 TWE；校验并稳定排序；编译紧凑 Agent context；输出 catalog/context SHA256；支持注入 Planner、Architecture、Invariant、Expert、Challenger、Verifier。

### 20.4 Token 预算

按 §11.1 实现编译期硬上限：单个 playbook compact 形态超限则编译失败；总 context size 写入 `00_twe_knowledge.json`；阈值在本 PR 内根据 rollback playbook 实际体量确定并写死。

### 测试

schema validation；ID/family uniqueness（16 个 TWE 与七族的完整对应）；deterministic context compilation；hash stability；rollback playbook 必填字段；旧 TWE 读取迁移测试；token 预算超限时编译失败。

### 验收

- `knowledge/twe/catalog.yml` 含全部 16 个 TWE 定义。
- 事实词表可被 PR-05 的标注层与查询层共同引用，无第二处定义。
- 不使用 RAG/embedding 即可向 Agent 提供全部 TWE。
- rollback.yml 能独立指导人工完成一次代码调查，且覆盖 §20.2 的两条路径。
- 同一 catalog 生成相同 context/hash。
- 不存在「未被画像选中所以 Agent 看不到」的 TWE。

## 21. PR-03：ProjectProfile v2 与 Deterministic Fingerprint

### 目标

将 tee-audit 的 TEE platform、trust artifact 和 manifest 扫描能力合并到 TEECheck Preprocessor。

### 来源（A 类资产）

`patterns/tee_signals.py`；`stages/fingerprint.py`(192)；`utils/manifest_parsers.py`；TEECheck 现有 `internal/preprocessor/`(646)。

### 实现策略

移植为 Go 的确定性扫描，保留来源说明和等价 fixtures。两边的信号库合并去重，不是单向覆盖。

Web3 role signal 在 C/TEE OS 目标下命中率低，保留检测器但不作为验收项。

### ProjectProfile v2 内容

见 §9.1。

### 规则

- role keyword 只能产生 candidate role。
- 没有匹配不能表达「不存在」。
- vendor/generated/test scope 必须显式标记（复用 §20.1 搬入的 `exclusion.yml`）。
- 所有信号都要有文件位置或 manifest ref。

### 验收（实测结果已回填）

- **平台信号**：OP-TEE 25/27、TF-M 8/9、Open Enclave 4/4、SGX 1/1、SEV-SNP 1/1；Rust 对照组 0 误报。达标。
  - 3 处未命中（CVE-2016-6129、CVE-2026-40257、CVE-2023-40271）都是只含 vendored 平台无关加密代码的单文件切片，文件里没有任何 TEE 记号——语料覆盖问题，非探测器缺陷。
  - `platform:optee` 在一个标为 Open Enclave 的数据集（CVE-2020-15107）上命中，已核实为**真阳性**：该数据集的 `enclave/core/CMakeLists.txt` 确实列有 `optee/*.c` 源码组，Open Enclave 本就支持 OP-TEE 后端，是 `case.yaml` 的单一平台标签表达不了。
- **artifact 信号**：OP-TEE 16/27、TF-M 3/9、Open Enclave 3/4。部分达标。
- **manifest 信号**：OP-TEE 0/27、TF-M 0/9、Open Enclave 1/4。**本语料无法达标**——数据集是部分 checkout，全库只有 2 个 `.edl` 和 4 个 `.mk`，不含任何 `.edl` 之外的清单文件。探测器已支持 OP-TEE/TF-M 清单格式（`user_ta_header_defines.h`、TF-M partition manifest），由单元测试而非语料测试守护。
- 每个信号可追溯到 detector 和文件位置。达标。
- ProjectProfile v1 consumers 不崩溃。达标。
- Fingerprint 不调用 LLM。达标。

**对 PR-04 的后果**：§7.3 把 manifests 列为 Architecture Agent 的输入之一，但在本 benchmark 上
36/44 的案例拿不到任何 manifest 信号。因此 PR-04 的 Architecture Agent **不得把 manifest 缺失
当作架构事实**（例如推断「没有声明的信任边界」），必须走 `CoverageWarnings`。真实完整仓库上
该输入是有的，只有这个评测语料没有。

## 22. PR-04：Architecture Agent 与 Invariant Agent

### 目标

形成一次生成、全流程复用的项目理解层。职责定义见 §7.3、§7.4。

### 新包

`internal/architecture/`、`internal/invariants/`。

tee-audit 的 `stages/dossier.py`(97行) 与 `stages/invariants.py`(77行) 是 A 类资产。代码量很小，价值在 prompt 设计与输出结构——以其为起点，不从零设计。

### Citation 校验器

这是唯一阻止 LLM 编造架构事实的机制，作为本 PR 的独立交付物：

- 复用 `internal/citations/`；
- 校验强度明确为：**引用位置存在 + 该位置确实包含所声明的符号**，而不仅是文件存在；
- 配套一组**故意造假的 fixture** 作为负例测试（不存在的文件、存在但符号不匹配、行号漂移）；
- 校验失败的 observed statement 降级为 inferred 或 unknown，不允许静默通过。

### 提示词约束

- 不允许把 proposed invariant 直接输出为 finding（§15.6）。
- 不允许把 documented/inferred statement 当作 observed。
- 不允许仅依赖模型训练知识声称某 API 已验证某属性。
- unknown 必须保留，不能为完成 JSON 而猜测。

### Rollback 验收场景

至少生成类似义务：

```text
加载或恢复的安全版本状态在影响 TA/key/authority 决策前，
必须被传播到 rollback check，并与不可共同回滚的版本状态比较。
```

### 验收

- observed statement 全部通过 citation 校验器，负例 fixture 全部被拒。
- inferred statement 能追溯到依赖事实。
- Invariant 能追溯到 TWE 与 architecture refs。
- `architecture.md` 由结构化模型派生。
- Case Pack 能提取相关 architecture slice，而不是携带完整 Dossier。

## 23. PR-05：TrustIR-C 事实层

> 架构依据见 §6。本节是其实施分解。

### 23.1 范围

新建 C 语言的 CodeQL 事实层，并把它**接进主路径**。

**（勘误）** 摸底后修正原计划的一处失实：`internal/codeql/querygen.go` 并**不在主路径**上。
调用链是 `querygen.go → internal/twepipeline → cmd/twescan`——一条独立的旁路实验命令
（rust/binding/config）。主路径 `teecheck run`（preprocessor → cases → expert → challenger →
verifier → arbiter）根本不 import `internal/codeql`。因此：

- PR-05 的真实工作是给主路径**新建**一条到事实层的集成，不是「替换」主路径里的现有件——主路径当前完全没有 CodeQL。
- `querygen.go`/`twepipeline`/`twescan` 作为旧旁路，其退役是 §28 已列的 PR-10 清理项，PR-05 **不碰**它们。
- 原验收「querygen 已从主路径移除」测不到东西（它从未进过主路径），删除。「无两套 CodeQL 语义并存」修正为「**主路径只有事实层一套语义**」——旁路 twescan 的旧语义与主路径不在同一条路径，不冲突，PR-10 退役。

### 23.2 首个切片：确定性骨架优先

事实层分两端：**消费端**（事实表 → 薄壳查询 → ToolFact）与**标注端**（LLM 对真实代码提出
role 标注 → resolver 校验 → 生成事实表）。C-fact-table spike（§23.7）已验证消费端在 C 上成立，
但标注端未验证，是最不确定的部分。

因此首个切片只做**确定性骨架**，标注端推迟：

- cpp 事实层查询包（rollback/STATE 一族，从 spike 查询包 `c-fact-table-spike-pack/` 起步）；
- `internal/trustirfacts` Go 包：DB 按 commit 构建、执行、ToolFact 持久化、error/unresolved/unsupported 映射、接进主路径的入口；
- 事实表先用**确定性方式**填充（如 spike 手工填、或从确定性 fingerprint 派生），**不含 LLM 标注**；
- 目标：先把确定性链路接通并在 CVE-2026-44362 上跑出 vuln/fixed differential，再在骨架之上加 LLM 标注（§23.3 的标注抽取移到骨架跑通之后）。

这符合垂直切片优先：先接通确定的部分并过 benchmark，把不确定的标注质量隔离到下一步。

### 23.3 交付内容

新增 `internal/trustirfacts/`（标注抽取端属**骨架跑通之后**，见 §23.2；首个切片只做以下确定性部分）：

- ~~标注抽取：LLM 对候选符号提出 role 标注~~ → 推迟。首片事实表用确定性方式填充，role 取值仍受 §20.1 搬入的 `enum_registry.yml` 约束；
- resolver：把标注的名字解析到真实符号，未解析的标记 unresolved；
- 事实生成：输出 `GeneratedTrustFacts.qll`；
- 通过现有 `internal/codeql/` engine 执行；
- CodeQL DB **每 run 按 commit 构建一次**，落到 run 目录作为显式 artifact（不是缓存副作用）。构建方式采用 spike 验证过的路径：`git clone <repository>@<revision>` 取全树 + `--build-mode=none`，输入取自 `case.yaml` 的 `repository`/`vulnerable_revision`/`fixed_revision`。**不得退回单文件或 stub 头文件方案**——spike 已证伪，两者抽出的函数数均为 0；
- ToolFact persistence；error/unsupported/unresolved mapping。

新增 `codeql/trustir/cpp/`：

- `common/GeneratedTrustFacts.qll`、`common/TestScope.qll` 等绑定层的 cpp 版；
- 7 族查询的 cpp 版（薄壳，语义在事实表）；
- rust/go/js 版本作为图纸对照。

### 23.4 必须避开的已知坑（A 类资产）

`annotation_facts.py` docstring 记录的 v1 教训，直接作为本 PR 的设计约束：

1. **不要用 exact-line `asExpr().getLocation()` 定位**——行号漂移即失效。改为按函数/参数/调用的**名字与签名**键控，让 CodeQL 解析真实数据流节点。
2. **role 字符串必须来自 `enum_registry.yml` 的受约束枚举**——v1 的 enum mismatch 是致命 bug。标注 prompt 与查询消费端引用同一份词表，不允许第二处定义。
3. `authoritySubjectOf` 等谓词必须真正填充，不能留 `none()`。

### 23.5 C 特有的降噪层

`enumerate_classify.py` 中约 44 处语言相关代码是**降噪补丁**（rust-all 0.2.4 的 API 缺陷、serde derive 展开、PyO3/clap shim 过滤）。这些对 C 不适用，但同类问题在 C 上以不同形态出现，必须对位处理：

- 宏展开产生的重复/合成符号；
- 头文件中重复定义与 `static inline`；
- 条件编译分支（`#ifdef CFG_*`）导致的不可达代码——spike 已确认这是 `--build-mode=none` 的固有限制而非可修复缺陷：不做真实编译，宏与 `#ifdef` 一律走源码默认值。因此本层的目标是**标注哪些结论受配置假设影响**，不是消除该影响；
- OP-TEE / TF-M 的平台适配层与内核核心的 scope 区分。

### 23.6 Rollback 最小能力

首个切片只强制实现：

1. 边界/加载入口的符号枚举；
2. version/state field 到 authority/rollback check 的路径追踪；
3. guard/version propagation 检查；
4. 结构化 location/path 输出。

（结案原提案 §17 待决第 8 条。）

### 23.7 前置可行性验证

本 PR 是全计划唯一的从零构建项。但其中**风险最大的一块已经被退休**——见
`tee-usage-scanner/docs/design/C-feasibility-spike.md`（2026-07-15，结论 PASS）。

已验证不再是风险的部分：

| 项 | spike 结论 |
|---|---|
| CodeQL C 工具链 | `cpp-all`/`cpp-queries` bundle 与 gcc 已就位 |
| C 数据库构建 | `git clone <repository>@<revision>` + 全树 `--build-mode=none`，得到完全可查询的 AST（libtomcrypt: 780 函数 / 7769 调用）。**不需要交叉编译工具链，不需要项目构建系统** |
| 单文件 fixture 方案 | 已证伪：`--build-mode=none` 对无头文件的单文件抽出 0 个函数；stub 头文件同样为 0。必须全树 |
| 端到端 differential | CVE-2016-6129 已跑通：vulnerable 命中、fixed 干净、scoped 后无误报 |

`case.yaml` 已经带 `repository` + `vulnerable_revision` + `fixed_revision`，构建所需输入齐备。

**事实表架构的验证已完成**（2026-07-23，结论 PASS，见
`tee-usage-scanner/docs/design/C-fact-table-spike.md` 与其查询包
`c-fact-table-spike-pack/`）：

- 在 CVE-2026-44362 上手写了一份 cpp `GeneratedTrustFacts.qll`（不经 LLM，只记录实体身份：`shdr_load_pub_key` 是 producer、`version` 是 rollback 字段、`check_update_version` 是 authority），薄壳查询做纯结构判定（producer 是否真的写了该字段）。
- vulnerable DB → **命中** `shdr_load_pub_key`（version 未传播）；fixed DB → **空**。事实表两版一字未改，differential 完全由代码结构决定。反向 sanity 查询确认两个 DB 是镜像。
- 即：**「C 上能不能用 CodeQL」和「C 上能不能用事实表架构」都已结案。**

仍未覆盖、属于 PR-05 正式工作的部分：

- 事实表是**手工填的**；从真实 TrustIR 生成这些子句的 LLM 标注 + resolver 管线尚未构建。本 spike 只证明了**消费端**（薄壳 + C 结构/数据流）成立，不涉及标注质量。
- 只验了 **STATE/rollback 一族一例**；其余六族的 cpp 薄壳与 `common/*.qll` 移植未验。
- 本例用**结构判据**（producer 是否写字段）即可判定；真正需要跨函数 C 数据流的族（FLOW、LEAK）可能撞上 `--build-mode=none` 的宏/`#ifdef` 限制。
- DB 每版 313 MiB，内核级案例更大——§23.3 的按 commit 缓存是硬要求。

### 23.8 spike 与本计划的分歧

spike 的「Next」提出 M2-C（DB 构建）+ **M4-C（每族生成 C/C++ QL 模板）**+ 语言分派。
其中 M4-C 是 `querygen.go` 那条「按族生成整条查询」的路线，与 §6.2 选定的事实表架构互斥。

spike 写于本融合计划之前，其 DB 构建结论完全有效并直接采用；其查询生成结论不采用。
理由见 §6.2：模板路线新增语言的成本是 O(查询数)，事实表路线是 O(1)。

spike 还记录了一件已发生的事：自定义 C Guard TWE 及其生成的查询已从 TWE catalog 移除，
CVE-2016-6129 不再映射到任何 TWE——这就是 `codeql/queries-cpp/guard/missing_length_check.ql`
在 `00e7d69` 中退场的原因。

### 验收

- 手工事实表的可行性验证通过（23.7）。
- Agent 给出 scope 后能得到绑定到真实代码的 ToolFact。
- accepted entity 来自权威枚举，不是模型臆测。
- CodeQL build failure、DB 构建失败、超时映射为 unresolved，不映射为「无问题」。
- 同一 commit 的 DB 只构建一次，路径在 run 目录中可见。
- 主路径只有事实层一套 CodeQL 语义（querygen 在旁路 twescan，PR-10 退役，不在主路径）。
- role 枚举与 `enum_registry.yml` 一致性有测试保证。

## 24. PR-06：Rollback Investigation 与 Planner 集成

### 目标

让 Planner 使用 TWE、Architecture 和 Invariant 主动执行 rollback 调查。职责定义见 §7.5。

### Planner 修改

- `internal/planner/prompt.go`：注入 TWEContext、Architecture slice 和 Project Invariants；明确「missing role 是下一步任务，不是漏洞结论」。
- `internal/planner/state.go`：保存 active investigations、filled/missing roles、required evidence、counterevidence、coverage gaps。
- `internal/planner/actions/`：注册事实层 actions；允许从 invariant verification plan 生成调用；观察结果使用 artifact refs。
- 新增 `internal/investigations/`：构建 `TWEInvestigation`（§9.5）；standard/variant/composition/catalog_gap 分类；攻击链 completeness 检查。

### Case Pack 修改

每个 Case Pack 增加：related TWE IDs、related invariant IDs、architecture slice refs、ToolFact refs、required evidence、missing links、common defenses/false positives、coverage gaps。

### Rollback 调查步骤

```text
1. 从 ProjectProfile/Architecture 获取 loader/restore/version/authority 表面。
2. 使用 TWE rollback playbook 生成调查问题。
3. 调用事实层枚举和解析真实实体。
4. 追踪 version/state 到 rollback check 和 authority。
5. 检查版本是否传播、freshness anchor 和外层 guard。
6. 生成 attack path 或明确 missing evidence。
7. 输出 TWEInvestigation 和 bounded Case Pack。
```

### 验收

- 在 CVE-2026-44362 vulnerable variant 中找到 `subkey_version -> key->version -> check_update_version` 相关流程和缺口。
- 在 fixed variant 中识别版本传播或对应保护。
- Planner 不因 query 未命中直接输出「安全」。
- Planner 不因 missing role 直接输出 confirmed finding。
- 每个 Investigation 可追溯到 TWE、Invariant、ToolFact 和源码。

## 25. PR-07：多 Agent 独立复核与定向验证

### 目标

将事实层产出纳入现有 Expert/Challenger/Verifier/Arbiter，同时修复当前顺序提示造成的自我确认问题。角色定义见 §7.6~§7.9。

### 实施要点

- Expert：输入 TWE、Architecture slice、Invariant、Case Pack 和 ToolFacts；不得修改 ToolFact。
- Challenger：两阶段隔离，第一阶段 prompt 不含 Expert 结论；已知限制见 §7.7。
- Verifier：将争议转换成事实层调用、reverse trace、grep 或 citation check；更新 invariant verification status 但保留原始 proposed artifact；区分未找到证据和证明不存在。
- Arbiter：输出明确分区——anchored ToolFacts；architecture evidence status；invariant verification status；Expert hypothesis；independent Challenger result；Verifier resolution；remaining coverage gaps；human review questions。

### 验收

- Challenger 第一阶段 prompt 不包含 Expert 结论（断言测试）。
- Agent 不能覆盖 ToolFact JSON。
- 无完整攻击链时不能使用 confirmed vulnerability 表述。
- vulnerable/fixed 两个 variant 的 Challenger 能识别关键差异。

## 26. PR-08：Unified Finding、SARIF、Review 与 Stats

### 目标

把新流程接入现有用户可见输出和人工反馈闭环。

### Finding v3

见 §9.7。

### SARIF

- 输出真实 `locations`；
- 输出 CodeQL `codeFlows`；
- properties 中记录 TWE、Invariant、coverage 和 Agent status；
- unresolved 不得静默消失。

### Human Review

见 §9.8。额外要求：将 ToolFact、AgentAssessment 和 HumanVerdict 分开展示；允许指出攻击链具体失败步骤。

### Stats

fingerprint evidence accuracy；architecture grounding rate；invariant grounded/satisfied/violated/unresolved；TWE investigation coverage；attack path completeness；CodeQL DB build failure 率；**TWE context size 与 tokens per reviewed finding**；reason codes per TWE/investigation step。

### 验收

- Finding 可追溯到 catalog/context hash、repo commit、ToolFact、Agent 和人工记录。
- Review UI 明确区分事实、假设和人工结论。
- SARIF 在具体文件/行显示结果。
- 历史 Finding/Review fixture 仍可读。

## 27. PR-09：Rollback Benchmark Gate

### 目标

用 source-backed vulnerable/fixed 数据证明首个闭环。

### 主案例

```text
teecheck-benchmark/datasets/CVE-2026-44362/
```

Oracle 要点：

- vulnerable：`shdr_load_pub_key()` 没有把 `subkey_version` 写入运行时 key version；rollback database 无法推进。
- fixed：版本被传播到 rollback checking。

### 必测层次

1. Fingerprint 找到 OP-TEE/签名/版本/加载相关信号。
2. Architecture Model 建立 signed TA/subkey、loader、rollback DB 和 authority 关系。
3. Invariant Agent 生成版本传播与 rollback protection invariant。
4. Investigator 找到关键流程。
5. 事实层输出真实位置或路径。
6. Expert/Challenger/Verifier 识别 vulnerable/fixed 差异。
7. Finding 命中 oracle location/family。

### 对照组（与主案例同为强制项）

单案例 differential 可被「到处报 rollback 问题」的 Agent 平凡通过：`vulnerable finding present` 恒真，`fixed finding absent` 靠 prompt 调整即可满足。单案例无法区分「真的定位到了版本传播缺口」与「过拟合」。

因此增加：

- **对照组 FP 率**：在其余 44 个 source-backed 数据集中，非 rollback family 的案例上跑同一条流程，rollback family finding 的数量必须低于设定上界（§14 待决 17）；
- **location 精度**：使用 oracle 的 `primary_file` 与 `fixed_sha256` 计算文件级命中，不只判 family 命中。

### Benchmark 指标

vulnerable finding present；fixed finding absent/satisfied/guarded；location match；对照组 FP 率达标；required evidence completion；no unsupported claim；unresolved 不计为通过；token/tool cost recorded。

### 第二案例

在扩展其他 TWE 前，再加入一个 source-backed 的「Host 回放 sealed/persistent state」案例（即 §8.1~8.8 的形态），覆盖：ECALL/OCALL 或等价边界；Host-controlled snapshot；restore flow；external freshness anchor；restored state 到 authority 的影响。

不使用没有真实来源的 synthetic case 代替正式 benchmark。

### 验收

- CVE-2026-44362 vulnerable/fixed differential 稳定通过。
- 对照组 FP 率达标。
- 失败时能判断问题发生在 Fingerprint、Architecture、Invariant、Investigation、Tool、Agent 或 Reporter 哪一层。
- benchmark 输出人工可审计 artifacts。

## 28. PR-10：扩展、迁移和清理

### 扩展顺序

§20.1 已搬入全部 16 个 TWE 的定义。本 PR 按以下顺序补齐 playbook 与查询：

1. Rollback/State continuity（PR-02 已完成）；
2. Attestation freshness；
3. Attested subject/public-key binding；
4. TCB/status/measurement guard；
5. Weak mode/config reaches authority；
6. Secret boundary exit/leakage；
7. Design/composition 类问题。

每个新 TWE 都必须具备：playbook；source-backed vulnerable/fixed；common defense fixture；事实层 coverage；Agent behavior assertions；review reason code 数据。

### 清理候选

在新路径稳定后处理：TEECheck 当前窄版 `twexpert`/`twepipeline`；重复 TWE catalog/status/schema；无上下文 AgentBus handler；旧 hotspot shim。

**已前移，不在此列**：

- tee-audit 七阶段 orchestrator 与 report/report_review/deep_verify → PR-00 资产三分的 C 类；
- `querygen.go` 旧 CodeQL 生成路径在旁路 twescan，非主路径 → 随 twepipeline/twescan 在 PR-10 退役。

所有删除都必须有：调用方清单；artifact 迁移说明；benchmark 等价或改进证据；明确弃用期。

## 29. 测试与 Benchmark 策略

### 29.1 TWE 知识测试

schema 完整性；TWE ID/family 唯一；每条 TWE 都有 attack scenario、investigation steps、required evidence 和 defenses；上下文编译稳定；catalog/context hash 可复现；**token 预算超限时编译失败**。

### 29.2 事实层测试

fully-qualified entity；同名/重载函数；invalid sink argument；accepted/rejected annotation；boundary enumeration；state restore flow；guard/binding detection；build/query failure；**role 枚举与 `enum_registry.yml` 的一致性**；**C 降噪层的宏/头文件/条件编译用例**。

### 29.3 Project Understanding 测试

platform、trust artifact 和 manifest 检测；candidate role 不被错误提升为 confirmed architecture role；observed architecture statement 必须通过 citation 校验器；**负例 fixture 必须被拒**；inferred statement 必须引用依赖事实；Architecture Model 能稳定生成相关子图；Invariant 必须关联 TWE、architecture refs 和 verification plan；proposed invariant 不直接生成 finding；fixed fixture 中的 expected defense 能使 invariant 变为 satisfied。

### 29.4 Agent 行为测试

TWE 能否驱动正确的第一步调查；Agent 是否继续补齐 missing roles；是否检查 common defenses；是否能识别 TWE variant/composition/catalog gap；Challenger 第一阶段 prompt 是否不含 Expert 结论；Verifier 是否把争议变成具体工具问题。

### 29.5 Vulnerable/fixed differential

每个核心 TWE 至少需要：vulnerable；fixed；protected by outer layer；test-only；deployment/config dependent；tool unresolved；关键词被封装的对抗样本。

### 29.6 关键指标

TWE investigation coverage；fingerprint evidence accuracy；architecture statement grounding rate；invariant grounding/satisfaction/unresolved rate；correct-flow discovery rate；required-evidence completion rate；location accuracy；vulnerable/fixed differential；**对照组 FP 率**；human precision/recall；false-positive reason distribution；事实层 cache/复用率；unresolved rate；**TWE context size**；tokens per reviewed finding；TWE-enabled 与 TWE-disabled ablation 差异。

## 30. 临时迁移开关

实施期间允许一个临时开关：

```text
--experimental-unified-pipeline
```

**该开关仅作 rollout 用途，不承担 A/B 语义。** PR-06～PR-08 的修改点是 `internal/planner/prompt.go`、`state.go` 以及 Expert/Challenger/Verifier/Arbiter 的**原地改造**，改造后 legacy path 已被污染，所谓 A/B 比较的是「新流程」与「被新流程改过的旧流程」，不构成有效对照。

PR-09 达到 benchmark 门禁后：

1. unified pipeline 变成默认；
2. legacy pipeline 进入弃用；
3. 删除临时开关；
4. 不保留 deterministic/exploratory/hybrid 三套长期产品语义。

## 31. Definition of Done

- [ ] tee-audit 以保留历史和 MIT attribution 的方式导入，且 `ATTRIBUTION.md` 记录完整的 A/B/C 资产三分清单。
- [ ] C 类资产不在任何构建或测试路径中；stage 7 ralph loop 行为已明确标记为禁止移植。
- [ ] 根仓库许可证已确定。
- [ ] 16 个 TWE 定义与事实词表已搬入 `knowledge/twe/`，无第二处定义。
- [ ] 全部 TWE 作为前置知识注入，无 RAG/embedding 依赖，且 context size 受编译期硬上限约束。
- [ ] rollback playbook 同时覆盖「状态整体回放」与「版本未传播」两条路径。
- [ ] ProjectProfile v2 能输出平台、artifacts 和 manifests。
- [ ] Architecture Model 的 observed facts 全部通过 citation 校验器，负例 fixture 全部被拒。
- [ ] Project Invariant 能追溯到 TWE 和 architecture refs。
- [ ] TrustIR-C 事实层可运行，输出不可变 ToolFact，接进主路径（querygen 旁路留待 PR-10）。
- [ ] Planner 能根据 rollback TWE/Invariant 找到目标流程。
- [ ] Challenger 第一阶段不读取 Expert 结论（并已记录其独立性限制）。
- [ ] Verifier 能执行定向事实层 check。
- [ ] ToolFact、AgentAssessment、HumanVerdict 分开持久化。
- [ ] CVE-2026-44362 vulnerable/fixed differential 通过，且对照组 FP 率达标。
- [ ] 失败和 unresolved 不被解释为安全；工具无产出时不合成 finding。
- [ ] 现有人工 review 和 stats 能消费新 Finding。
- [ ] 旧 artifacts 有兼容读取或明确迁移工具。

## 32. 推荐执行顺序

1. PR-00：提交工作区已有成果、subtree 导入、**资产三分**、许可证。
2. PR-01：冻结 Go 侧 contracts。
3. PR-02：**16 个 TWE 定义与词表一次搬齐** + rollback playbook + TWEContext + token 预算。
4. PR-03：完成 ProjectProfile v2。
5. PR-04：生成 rollback Architecture/Invariant + citation 校验器。
6. **PR-05：§23.7 可行性验证已通过；实现确定性骨架（cpp 事实层 + trustirfacts）并接进主路径，LLM 标注推迟（§23.2）。**
7. PR-06：接通 Planner 和 Case Pack。
8. PR-07：接通独立 Challenger 和 Verifier。
9. PR-08：接通 Finding、SARIF、review 和 stats。
10. PR-09：以 CVE-2026-44362 + 对照组 FP 率作为强制门禁。
11. PR-10：门禁通过后再补齐其余 15 个 TWE 的 playbook 与查询。

PR-03 与 PR-05 的底层开发可以并行。PR-05 建议独立排期。

## 33. 第一阶段交付物

```text
输入：CVE-2026-44362 vulnerable/fixed

系统：
1. 加载全部 16 个 TWE 前置知识；
2. Fingerprint 识别 OP-TEE、加载、签名和版本状态；
3. Architecture Agent 建立 subkey -> TA loader -> rollback DB；
4. Invariant Agent 生成 rollback version propagation invariant；
5. Planner 按 rollback playbook 驱动事实层；
6. 事实层绑定真实符号并输出版本传播路径；
7. Expert 提出攻击假设；
8. Challenger 独立检查其他版本传播和 guard；
9. Verifier 确认 vulnerable/fixed 差异；
10. Arbiter 生成人工复核包；
11. Benchmark 验证 family、location、differential 与对照组 FP 率。

输出：
- vulnerable：有证据支持的 rollback candidate；
- fixed：invariant satisfied/guarded，或至少不产生同一 finding；
- 对照组：无 rollback family 误报膨胀；
- 每个结论可追溯到 TWE、Architecture、Invariant、ToolFact 和源码。
```

## 34. 最终定位

> 一个以经验型 TWE 为前置安全知识，先通过 Fingerprint、Architecture Model 和 Project Invariants 理解项目，再以 CodeQL 事实层为代码证据来源、以多 Agent 为调查与复核主体、以人工标签和 benchmark 为最终质量依据的 TEE 安全审计平台。

从 rollback TWE 开始做垂直切片：先由 Fingerprint 识别 TEE、manifest、边界和状态信号，再由 Architecture Agent 建立 loader、restore path、trusted state 和 authority 的架构关系，由 Invariant Agent 生成项目专属 rollback obligation；随后证明 TWE 前置知识能够驱动 Investigator 找到正确代码流程、事实层能提供结构化证据，最后验证 Challenger、Verifier 和人工 review 能正确识别保护机制与误报。

在这一闭环稳定前，不扩张大量 TWE playbook，也不扩展到其他语言。
