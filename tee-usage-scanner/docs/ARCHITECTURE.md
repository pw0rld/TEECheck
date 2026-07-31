# TEECheck 架构

> 描述对象：`tee-usage-scanner/`，2026-07-31 的实现。
> 本文描述**系统是怎么构成的**——分层、契约、数据流、扩展点。不含进度评估与缺陷清单。

---

## 1. 系统要解决的问题

输入一个 TEE 项目的源码仓库，输出**可供人复核的漏洞候选**。

难点不在"找到可疑代码"，而在两件事：

1. **TEE 漏洞是领域特有的。** 回滚保护缺失、attestation 未绑定主体、宿主可控数据进入 enclave 安全决策——这些不是通用静态分析的目标，通用工具没有对应的规则。
2. **LLM 会编。** 一个能读代码、能讲故事的模型，会给出听起来完整但没有代码支撑的攻击链。

架构上的回应分别是：**把领域经验编码成前置知识**，和**把可复现的代码事实与 LLM 的判断分开存放**。

---

## 2. 四个承重的架构决定

这四条决定了其余一切的形状。

### 2.1 三层证据分离

| 层 | 谁产出 | 可否被推翻 | 载体 |
|---|---|---|---|
| **ToolFact** | 确定性工具（CodeQL） | **不能**——它是事实 | `artifacts.ToolFact` |
| **AgentAssessment** | LLM | 能 | `artifacts.Hypothesis` / `Challenge` / `VerificationMemo` |
| **HumanVerdict** | 人 | 只能追加，不覆盖 | `artifacts.HumanVerdict` |

这条分离是地基。它意味着：

- 工具失败必须记为 `unresolved`，**不得**解释成"没有漏洞"
- 工具没有产出时，**不得**凭 LLM 的说法合成 finding
- 人的结论是追加记录，原始工具事实与 Agent 判断都保留

`internal/artifacts` 用三个不同的类型表达这三层，而不是一个带 `source` 字段的通用类型——类型系统本身承担这条约束。

### 2.2 TWE 是前置经验，不是检索库

TWE（TEE Weakness Entry）是漏洞族的**调查剧本**：这类漏洞长什么样、攻击者需要什么能力、该按什么顺序查、什么证据才算数、常见防御与常见误报是什么。

全部 TWE 一次性编译成上下文注入各 Agent，**不做 embedding / 向量检索**。

理由：检索会因为项目画像没命中而让 Agent 看不到某个漏洞族，而"没想到去查"正是这类审计最主要的失败模式。宁可多花 token。

代价是上下文预算，所以做了**两级注入**：

- **brief 层**（≤250 token/条）——全部 TWE，进 system prompt
- **detail 层**（≤3000 token/条）——按需，Planner 用 `twe_playbook_detail` 动作拉取

承载：`knowledge/twe/`（数据）· `internal/twe`（目录加载与校验）· `internal/twecontext`（编译成上下文）

### 2.3 薄壳查询 + 事实表：把语言耦合压进数据

这是事实层最关键的设计。

一条 CodeQL 查询**不含任何漏洞逻辑**。所有实体身份——谁是生产者、哪个字段是回滚字段、哪个调用是裁决点——来自一张**事实表**，由 Go 侧物化成 `GeneratedTrustFacts.qll`：

```ql
predicate isClaimProducer(Function f, string role) {
  f.getName() = "shdr_load_pub_key" and role = "security_version"
}
predicate rollbackVersionField(string field) { field = "version" }
predicate producedStruct(string typeName) { typeName = "shdr_pub_key" }
predicate isRollbackAuthority(FunctionCall c, string kind) {
  c.getTarget().getName() = "check_update_version" and kind = "state_restore_acceptance"
}
```

查询本身只表达"生产者没有把回滚字段写进它产出的结构体"这个**结构性条件**：

```ql
where
  isClaimProducer(producer, role) and
  rollbackVersionField(field) and
  producedStruct(...) and
  isRollbackAuthority(auth, kind) and
  not writesOutputField(producer, field)
```

**由此得到两个性质：**

1. **差分可信。** 同一份事实表在漏洞版与修复版上逐字节相同，所以两次结果的差异只能来自真实代码结构，不可能来自表的偏置。
2. **换语言是 O(1) 的。** 语言差异全部落在事实表的填充方式上（C 的函数名 vs Rust 的路径），薄壳查询按语言各写一份，漏洞逻辑不重复。

事实表结构（`internal/trustirfacts/facttable.go`）：

```go
type FactTable struct {
	ClaimProducers      []ClaimProducerFact   // 函数 + 角色
	RollbackFields      []string              // 字段名
	ProducedStructs     []string              // 产出结构体类型名
	RollbackAuthorities []RollbackAuthorityFact // 调用 + 裁决种类
}
```

`role` / `kind` 的取值必须来自 `knowledge/twe/definitions/enum_registry.yml`——**只有一份词表**，事实表和（未来的）标注 prompt 共用。这条约束由 `facttable_test.go` 加载真实注册表来强制。

### 2.4 运行目录是一切的单位

一次扫描 = 一个 `runs/<run-id>/` 目录。所有中间产物按阶段编号落盘，加上一条 append-only 事件流和一个内容寻址的 blob 存储。

```
runs/<run-id>/
├── 00_manifest.json          仓库 URL、commit、focus、工具版本
├── 01_profile/               ProjectProfile（确定性指纹）
├── 01_context/               ProjectProfile v2、TWE 上下文、architecture dossier
├── 02_tool_facts/trustir/    ToolFact + 物化的查询包 + CodeQL DB
├── 03_investigations/        TWEInvestigation
├── 03_cases/                 CasePack
├── 04_planner/               evidence_bundle.json · rounds.jsonl（逐轮流式记录）
├── 04_expert/                Hypothesis
├── 05_challenger/            独立判断 + Challenge + 归一化调整记录
├── 06_verifier/              VerificationMemo
├── 07_arbiter/               findings.json + packets/（人读的复核包）
├── blobs/                    <sha256>.txt，内容寻址，自动去重
└── events.jsonl              append-only，seq 单调递增
```

**为什么这样设计：**

- 每个阶段的输入是上一阶段的**文件**，不是内存对象——任一阶段可单独重跑（`teecheck expert --run-dir ...`）
- prompt 与 response 全量落 blob，一次运行可完整回放
- 事件流的 `seq` 单调无缺口，所以"某件事有没有发生"是可判定的，而不是靠翻日志猜

---

## 3. 分层与数据流

```
                    目标仓库（源码）
                          │
   ┌──────────────────────┼──────────────────────┐
   │                      ▼                      │
   │  ① 预处理·画像   Fingerprint 确定性扫描      │
   │                  平台 / manifest / 信任构件  │
   │                          │                  │
   │  ③ TWE 前置知识 ─────────┤                  │
   │     全部剧本编译注入      │                  │
   │                          ▼                  │
   │                   ProjectProfile            │
   │                          │                  │
   │  ② 项目理解              ▼                  │
   │              ArchitectureModel              │
   │            （参与方/组件/数据流/信任边界）    │
   │                          │                  │
   │                          ▼                  │
   │              ProjectInvariant               │
   │          （把通用经验落成本项目的安全条件）   │
   └──────────────────────────┼──────────────────┘
                              ▼
   ④ 调查层        L3 Planner（有界轮次循环）
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
       源码探索动作                   fact_layer_query
   read_file / ripgrep /                      │
   tree_sitter_outline /                      ▼
   reverse_trace / list_dir            CodeQL 事实层
              │                               │
              │                          ToolFact
              │                      （不可挑战的证据）
              └───────────────┬───────────────┘
                              ▼
                TWEInvestigation + Candidate
                              │
                              ▼
                          CasePack
                    （有边界的复核单元）
                              │
   ⑤ 复核层                   ▼
        Expert ──→ Challenger ──→ Verifier ──→ Arbiter
       提出假设     两阶段独立挑战   重新校验证据   综合裁决
                              │
                              ▼
   ⑥ 输出                 Findings
                              │
                              ▼
                     report / review / feedback
                        （人工复核与知识沉淀）
```

阶段序列（实测自事件流，9 个）：

```
preprocess → architecture → invariants → l3_planner → cases_enrich
           → expert → challenger → verifier → arbiter
```

---

## 4. 各层职责

### ① 预处理 · 画像

| | |
|---|---|
| 输入 | 目标仓库源码 |
| 职责 | **确定性**扫描 TEE 平台、语言、framework、manifest、信任构件、边界信号 |
| 输出 | `ProjectProfile` / `ProjectProfileV2` |
| 承载 | `internal/preprocessor` · `internal/repofetch` |

这一层不含 LLM。它产出的每条信号都带 `EvidenceReference`，指向具体文件与行号，后续 Agent 可以引用。

### ② 项目理解

| | |
|---|---|
| 输入 | ProjectProfile、TWE 上下文、源码 |
| 职责 | 识别参与方、组件、角色、资产、入口点、数据流、状态生命周期、信任边界 |
| 输出 | `ArchitectureModel` + Architecture Dossier（人读版） |
| 承载 | `internal/architecture` |

**关键约束：** 每个元素带 `EvidenceState`——`observed` / `inferred` / `documented` / `unknown`。无法被源码支持的陈述降级为假设或 unknown，**不允许**以 observed 的身份进入下游。`internal/citations` 负责把引用绑到源码字节（SHA256）上做校验。

接着：

| | |
|---|---|
| 输入 | ProjectProfile、ArchitectureModel、TWE 上下文 |
| 职责 | 把通用漏洞经验实例化为**本项目**必须满足的安全条件 |
| 输出 | `ProjectInvariant[]`（status = `proposed`——是待验证的义务，不是结论） |
| 承载 | `internal/invariants` |

例："恢复后的安全版本必须由不可回滚的可信来源约束"。每条不变量带 `RelatedTWEs` 和验证计划。

### ③ TWE 前置知识

| | |
|---|---|
| 输入 | `knowledge/twe/definitions/`（目录、分类、枚举词表、排除规则）+ `knowledge/twe/playbooks/` |
| 职责 | 编译成本次运行共享的只读上下文 |
| 输出 | `01_context/twe_agent_context.txt` + `TWEKnowledgeManifest` |
| 承载 | `internal/twe`（加载校验）· `internal/twecontext`（编译） |

playbook 的字段结构：

```yaml
schema_version: teecheck.twe_playbook.v1
id / name / family
scenario                  漏洞场景叙述
attacker_capabilities     攻击者需要什么
look_for                  该找什么形状
investigation_steps       按什么顺序查
required_evidence         什么证据才算数
common_defenses           常见防御（防误报）
common_false_positives    常见误报（防误报）
related_twes / trustir_hints
```

### ④ 调查层：L3 Planner

| | |
|---|---|
| 输入 | TWE 上下文、ArchitectureModel、ProjectInvariant、ProjectProfile |
| 职责 | 把宽泛的安全问题拆成**有边界的调查**，决定用源码探索还是事实层查询 |
| 输出 | `TWEInvestigation` · `Candidate` · `EvidenceBundle` · `CasePack` |
| 承载 | `internal/planner`（+ `actions/`）· `internal/investigations` · `internal/cases` |

**运行机制是一个有界的轮次循环：**

```
每轮：  BuildRoundPrompt（含粘性的 playbook detail、已观察路径白名单）
          ↓
       LLM 返回 { thought, actions[] }
          ↓
       Registry 分发每个 action → 观察结果
          ↓
       写 RoundRecord 到 rounds.jsonl（流式，可中途查看）
          ↓
       预算未尽且未 done → 下一轮
```

**预算四维**：轮次上限、token 上限、墙钟上限、单动作超时（`internal/planner/budget.go`）。
**循环检测**：连续三次相同调用即拒绝（`loop_detect.go`）。
**反幻觉**：最终轮的 candidate 路径必须出自本次运行**实际观察过**的路径集合。

**动作注册表（`internal/planner/actions`）** 是 Planner 的能力边界：

| 动作 | 作用 |
|---|---|
| `list_dir` · `read_file` | 目录与文件读取（沙箱限制在 repo root 内） |
| `ripgrep` | 正则搜索，glob 可路径限定 |
| `tree_sitter_outline` | 文件结构大纲 |
| `reverse_trace` | 反向调用链——"谁调用了 X,谁又调用了它们" |
| `twe_playbook_detail` | 拉取某个 TWE 的完整剧本（detail 层） |
| `fact_layer_query` | **进入事实层的唯一入口** |
| `done` | 终结,提交 candidates + investigations |

注册表是可组装的：`NewDefaultRegistry` / `WithNav` / `WithFacts`——事实层需要 Engine 与查询包目录，所以单独一个构造函数。

### ⑤ 事实层：TrustIR / CodeQL

| | |
|---|---|
| 输入 | 一个 operation 名 + 钉死的 repository@commit |
| 职责 | 提取实体、传播、guard、调用路径与代码位置 |
| 输出 | **不可改写**的 `ToolFact` |
| 承载 | `internal/trustirfacts` · `internal/codeql` · `codeql/trustir/cpp/` |

**一次调用的完整链路：**

```
Request{Repository, Commit, Operation, QueryPackDir}
   ↓
factTableFor(repository)      ← 没有表 → StatusUnsupported（在 clone 之前返回,零成本）
   ↓
git clone + checkout          ← 事实层自己取源码,不复用 planner 的工作目录
   ↓
materializeQueryPack          ← 把 FactTable.Render() 写进这一份拷贝的 .qll
   ↓
codeql database create        ← --build-mode=none
   ↓
codeql database analyze       ← 薄壳查询
   ↓
ParseSARIF → ToolFact         ← 附 coverage_gaps
   ↓
Persist（schema 校验后落盘）
```

**ToolFact 的诚实性约束：**

- `status` ∈ `success` / `error` / `unsupported` / `unresolved`，四者语义不同，**都不等于"安全"**
- `coverage_gaps` 逐条声明本次查询没能覆盖什么（事实表是手写的、只有一族实现、`--build-mode=none` 不做真实构建、SARIF 位置不含符号名）
- `fact_id` 由 `arguments_sha256` 派生——内容寻址，相同输入必然同 id
- `locations` 始终序列化为数组：**"查过且为空"必须能被说出来**

### ⑥ 复核层：四个 Agent

| Agent | 输入 | 职责 | 输出 |
|---|---|---|---|
| **Expert** | CasePack、TWE、Architecture、Invariant、ToolFact | 提出漏洞假设：攻击前提、步骤、影响、缺失证据 | `Hypothesis` |
| **Challenger ①** | 与 Expert **相同的基础上下文,但不读 Expert 的结论** | 先独立分析,形成自己的判断 | `ChallengerIndependentView` |
| **Challenger ②** | 独立判断 + Expert 假设 | 对比双方,找反例、已有防御、不可达路径、错误假设 | `Challenge` |
| **Verifier** | 假设 + 挑战 + 源码 + ToolFact | 把争议转成具体工具问题,重新校验引用与路径；**区分"未找到"与"能证明不存在"** | `VerificationMemo` + 不变量状态追加 |
| **Arbiter** | 以上全部 + 原始证据 | 综合裁决,**不改写 ToolFact** | `Findings` + 人读复核包 |

**Challenger 的两阶段是刻意的架构设计**：单模型顺序流水线里，下游读到上游结论就会被锚定。先让它在不看 Expert 结论的条件下独立判断，再对比——这样"两者一致"才有信号价值。

**Arbiter 的输出闸门**：只有证据完整、路径可达、安全影响成立时才允许 `confirmed`。状态取值 `confirmed_candidate` / `likely_issue` / `needs_review`，且有机械清洗（`scrubConfirmedWording`）防止模型在自由文本里绕过这条规则。

**Agent 之间可以提问**：`internal/agentbus` 提供 `AskForCase`，注册的端点是 `scanner-001`（静态检查工具）、`expert-001`、`challenger-001`、`reviewer-001`。每个 case 的对话轮次有上限。

### ⑦ 输出与闭环

| 包 | 职责 |
|---|---|
| `internal/report` | 汇总报告 |
| `internal/review` | 人工复核界面与记录（`ReviewRecord`，5 档裁决 `true_positive` / `false_positive` / `needs_context` / `design_risk` / `no_issue_observed`，外加 `skip`；配 ReasonCode 分类） |
| `internal/stats` | 运行统计（token、各阶段产出量、复核指标） |
| `internal/feedback` | 把人的裁决沉淀回 `knowledge/learned/` |

---

## 5. 契约层

### 5.1 类型契约

`internal/artifacts` 是**唯一**的类型定义处，50 余个类型，跨阶段传递的一切都在这里。关键的几个：

```
ProjectProfile / ProjectProfileV2   画像
ArchitectureModel                   架构（Element + Relation + EvidenceState）
ProjectInvariant                    项目安全不变量
TWEInvestigation                    一次有边界的调查
CasePack                            复核单元
ToolFact / ToolLocation / ToolPathStep   不可挑战的证据
Hypothesis / Challenge / VerificationMemo  Agent 判断
Findings / FindingItem              裁决结果
HumanVerdict / ReviewRecord         人的结论
EvidenceBundle / RoundRecord        Planner 过程记录
```

### 5.2 Schema 契约

`internal/schema/schemas/` 下 8 份 JSON Schema，运行时校验：

```
project-profile.v2.json      architecture.v1.json
project-invariant.v1.json    twe-investigation.v1.json
twe-playbook.v1.json         twe-knowledge-manifest.v1.json
trustir-tool.v1.json         finding.v3.json
```

`schema_version` **永不从文件名或路径推断**——校验器检查解码后对象自己的字段。跨语言契约（未来若有非 Go 的实现）以 JSON Schema 为准，Go 类型是它的一个实现。

---

## 6. 横切设施

### 6.1 事件流与 blob 存储

`internal/events`。事件类型：

```
run_started / run_completed
stage_started / stage_completed
planner_round_started / planner_round_completed
llm_call_started / llm_call_completed
tool_call_started / tool_call_completed
claim_emitted            Agent 提出一条主张
value_normalized         某个字段被系统改写过（谁改的、改成什么）
```

`seq` 单调递增无缺口。大体积载荷不进事件流，进 blob：

```
blobs/<sha256>.txt        内容寻址,相同内容自动去重
events.jsonl              事件只存 "sha256:..." 引用
```

所以事件流本身始终是可读的小文件，而完整 prompt / 工具输出永远可取回。

### 6.2 子进程闸口

`internal/executor` 是**所有**子进程的唯一出口：git、CodeQL、ripgrep、semgrep、repomix。

```go
type Request struct {
	Name, Command string
	Args    []string
	WorkDir string
	Profile Profile   // Network / Write / Timeout / MaxOutputBytes
	RunID, Agent, CaseID string; Round int
}
```

统一在这里做超时、输出上限、网络与写权限的档位控制，并发 `tool_call_*` 事件。`executor.Bind` 把相关性 id 打上去，所以事实层深处的一次 `git clone` 仍然可以归属到发起它的那一轮。

### 6.3 LLM 客户端

`internal/llm`。两条 provider 路径：

- `NewOpenAIClient`——OpenAI 兼容端点，JSON 模式走 `response_format`
- `NewAnthropicClient`——GLM 的 Anthropic 兼容端点，JSON 模式走 assistant 预填

外层还有两个装饰：

- `NewRecordingClient`——把每次调用的 prompt/response 落 blob 并发事件，13 个调用点零改动接入
- `GenerateJSON`——生成 + 解析 + **一次有界纠正重问**，6 个 Agent 共用

### 6.4 运行目录与配置

`internal/runinit`（创建目录与 manifest）· `internal/runfs`（路径常量与 JSON 读写）· `internal/config`（CLI 与 provider 预设）。

---

## 7. 扩展点

想扩展这个系统时，改动落在哪里：

| 想做什么 | 改哪里 |
|---|---|
| **加一个 TWE 漏洞族** | `knowledge/twe/definitions/catalog.yml` 加条目 + `playbooks/` 加剧本 |
| **让某族可被确定性验证** | 写薄壳 `.ql` 进 `codeql/trustir/<lang>/<family>/`；在 `trustirfacts/request.go` 的 `operationQueries` 注册 operation |
| **支持新仓库** | 给 `facttable.go` 的 `knownFactTables` 加事实表（或接 LLM 标注管道 `annotate.go`） |
| **支持新语言** | 复制薄壳查询到 `codeql/trustir/<lang>/`，事实表的填充方式按语言写；漏洞逻辑不重复 |
| **给 Planner 加能力** | 实现 `actions.Handler` 接口，注册进 Registry，在 `prompt.go` 的 `actionArgSchemas` 加一行参数说明 |
| **加一个 Agent** | 新包 + `bus.Register` 注册端点 + 在 `pipeline/run.go` 的阶段序列里插入 |
| **加一种事件** | `events/event.go` 加类型常量与构造函数 |
| **改契约** | `artifacts/` 加类型 + `schema/schemas/` 加 JSON Schema，两边都要 |

---

## 8. 目录到架构的对应

```
tee-usage-scanner/
├── cmd/teecheck/              主 CLI:run 一把梭,也可单跑各阶段
├── cmd/twescan/               旧旁路(独占 solver / twepipeline / twexpert)
│
├── internal/
│   ├── pipeline/              ★ 总编排,阶段序列在这里
│   │
│   ├── preprocessor/ repofetch/          ① 预处理·画像
│   ├── architecture/ invariants/ citations/ symbolcheck/   ② 项目理解
│   ├── twe/ twecontext/ knowledge/       ③ TWE 前置知识
│   ├── planner/ planner/actions/         ④ 调查层
│   │   investigations/ cases/
│   ├── trustirfacts/ codeql/             ⑤ 事实层
│   ├── executor/ tools/ staticcheck/ repomix/   工具执行
│   ├── expert/ challenger/ verifier/ arbiter/   ⑥ 复核层
│   │   agentbus/ agentutil/
│   ├── report/ review/ stats/ feedback/  ⑦ 输出闭环
│   │
│   ├── artifacts/ schema/                契约
│   └── events/ llm/ config/ runfs/ runinit/     横切
│
├── knowledge/twe/             TWE 目录与剧本(数据,非代码)
├── codeql/trustir/            薄壳查询与事实契约
└── runs/                      运行产物
```

---

## 9. 一句话概括

**领域经验前置注入，确定性事实作证据，多个独立 Agent 交叉复核，人做最终裁决——四者的产出分别存放，互不覆盖。**
