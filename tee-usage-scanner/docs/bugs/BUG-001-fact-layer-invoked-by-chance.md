# BUG-001：确定性事实层的调用是偶然,不是操舵

> 状态：**未修复**
> 记录日期：2026-07-31
> 影响：CVE-2026-44362 —— 这个系统的 v1 验收案例,四次运行零检出
> 路径以 `tee-usage-scanner/` 为基准

---

## 1. 症状

**系统里唯一每次都答对的部件,在最需要它的那一侧从未被调用过。**

CVE-2026-44362(OP-TEE subkey 回滚保护绕过)在漏洞版和修复版上各跑两轮,四次运行**没有一次**检出该漏洞。

而同一个漏洞,把事实层单独钉在两个修订上跑,**两次都对**。

---

## 2. 复现

### 2.1 漏洞本身

OP-TEE 的 `core/crypto/signed_hdr.c`,两个修订的全部语义差异是一行:

```c
+ key->version = subkey->subkey_version;
```

`shdr_load_pub_key()` 解析 subkey 头,但**没有**把 `subkey_version` 拷进运行时的 `struct shdr_pub_key.version`。于是 `key->version` 恒为 0,下游 `check_update_version()`(在 `core/kernel/ree_fs_ta.c`)拿到 0,回滚数据库永不推进,回滚检查被绕过。

```
漏洞版  a9386bf987d95374a6f7f4c7bcf850115e0e1a4e
修复版  43ed01d216a9586e7e7591dff1f7fbf80923f93f
```

### 2.2 事实层单独跑 —— 正确

```go
// internal/trustirfacts,operation = cpp.state.rollback_version_propagation
Run(ctx, codeql.New(), Request{
    Repository: "https://github.com/OP-TEE/optee_os",
    Commit:     "<修订>",
    Operation:  OperationRollbackVersionPropagation,
})
```

| 修订 | `locations` | 判定 |
|---|---|---|
| `a9386bf`(漏洞版) | **1 条:`core/crypto/signed_hdr.c:262`** —— 正是 `shdr_load_pub_key` 的定义行 | ✅ 应该命中 |
| `43ed01d`(修复版) | **0 条** | ✅ 应该干净 |

首次 106.6 秒(含 clone + 46 万行抽取),复用已有 DB 再查约 20 秒,**0 次 LLM 调用**。

修复版那个 0 是**真实的否定**,不是空洞:三个谓词在该库里全部绑定成功 —— 生产者 `shdr_load_pub_key`、两个 authority 调用点(`ree_fs_ta.c:314` 与 `:639`)、以及 `writesOutputField` 成立。

### 2.3 完整流水线跑 —— 四次全错

`runs/gate-44362-{vulnerable,fixed}`(2026-07-30 11:00 / 11:15)
`runs/44362-{vulnerable,fixed}-p1`(2026-07-31 00:47 / 00:59)

| | 漏洞侧 ×2 | 修复侧 ×2 |
|---|---|---|
| `fact_layer_query` 调用次数 | **0 / 0** | 1 / 0 |
| finding 提到 `subkey_version` | **0 / 0** | 12 / 12 |
| finding 提到 `key->version` | **0 / 0** | 27 / 27 |
| arbiter 状态 | `likely_issue` / `needs_review` | `needs_review` / `needs_review` |

**漏洞真正所在的那一侧,这两个标识符一次都没出现过。**

两次漏洞侧给的都是同一个无关问题(`shdr_verify_signature` 的边界检查 / `img_size + hash_size` 溢出)。修复侧反而正确讨论了版本传播,并正确地拒绝确认。

> 计数方法:必须经 `jq` 解码后再匹配。Go 的 `json.Marshal` 把 `>` 转义成 `>`,直接 grep 原文件会把 `key->version` 数成 0。

---

## 3. 根因

### 3.1 主因:没有 TWE → operation 的映射

**先排除一个假设:不是"模型不知道事实层存在"。**

planner 的 system prompt 三处提到它:

| 位置 | 内容 |
|---|---|
| `internal/planner/prompt.go:85` | 职责句:"…calling the structured fact layer for real evidence…" |
| `internal/planner/prompt.go:89` | CRITICAL RULE:如何解读 `unresolved` / `unsupported` / 零命中 |
| `internal/planner/prompt.go:380` | 动作 schema:`{"operation": string, one of: cpp.state.rollback_version_propagation}` |

模型被告知了它的存在、用途、以及唯一合法 operation 的准确名字。

**缺的是:从某个 TWE 到某条 operation 的映射。**

prompt 说的是"调事实层拿真证据"(泛指)。没有任何地方说:*TWE-STATE-001 的 `required_evidence` 第 4 条 —— `freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input` —— 正好由 `cpp.state.rollback_version_propagation` 回答*。

而 TWE 剧本里描述这个检查的那句话,和查询检测的东西一字不差:

```
look_for: version_or_epoch_fields_that_are_declared_but_never_assigned_before_a_guard_reads_them
```

**用散文描述了它,可执行的查询也存在,两者之间没有连线。**

playbook 的 `trustir_hints` 本该承担这个连接,但它装的是五个抽象动词,没有一个是真实工具名:

```yaml
trustir_hints:
  - enumerate_boundary_entrypoints
  - enumerate_persistence_and_artifact_load_operations
  - trace_restore_or_version_to_authority
  - find_freshness_and_rollback_guards
  - compare_vulnerable_and_fixed_field_propagation
```

搜索 round-1 注入的 6788 字节 playbook 全文:`fact_layer_query`、`fact layer`、`rollback_version_propagation`、`cpp.state.` —— **全部 0 次命中**。

### 3.2 承载映射的字段存在,零消费者,而且值是错的

TWE 目录里每条都有 `query_modules`:

```yaml
- id: TWE-STATE-001
  query_modules: [state/SealedStateRestoreWithoutVersion.ql]
```

Go 侧:

```
internal/twe/definitions.go:39    QueryModules []string   ← 声明
internal/twe/definitions.go:99    校验非空
其余地方                            无人读取(全仓库 grep 只有这两行)
```

**唯一的非声明读取是它自己的校验。**

而且值本身是错的:`SealedStateRestoreWithoutVersion.ql` 在本仓库的 cpp 树里**不存在** —— cpp 树只有 `RollbackVersionNotPropagated.ql`。那个文件名只存在于兄弟目录 `tee-audit/codeql/trustir/{rust,javascript,go}/`。

**19 个条目的 `query_modules` 值全部指向本仓库不存在的文件。** 真实的 operation 词表在一个毫无关联的 Go map 里(`internal/trustirfacts/request.go` 的 `operationQueries`)。**两套命名系统,中间没有桥。**

`definitions.go:83-85` 的注释自陈:

```go
// It intentionally does not require query_modules to resolve to a real file
// on disk — wiring those module names to actual CodeQL packs is PR-05's
// responsibility, not this catalog's.
```

PR-05 在进度表里标着已完成。它负责的这条 wiring 从未做过。

### 3.3 同一个病的第二处:Agent 间提问 72 次 0 成功

arbiter 可以通过 `bus.AskForCase`(`internal/arbiter/run.go:387`)向其他 agent 提问。跨 6 次运行统计 blob:

| 运行 | 失败次数 |
|---|---|
| `44362-vulnerable-p1` | 6 |
| `44362-fixed-p1` | 7 |
| `gate-44362-vulnerable` | 6 |
| `gate-44362-fixed` | 7 |
| `optee-v2` | 11 |
| `optee-full` | 35 |
| **合计** | **72 次询问,成功 0 次** |

`Response from ...` 在所有 runs 的 blob 里**一次都没出现过**。

原因与 3.1 同构:`arbiter/run.go:224` 的 prompt 只说 `queries: 每项含 to_agent, kind, question`,**从不说有哪些 agent 存在**。

```
实际注册:  scanner-001  expert-001  challenger-001  reviewer-001
模型编的:  fact-layer  fact_layer  FactFerry  Investigator  investigator
           triage  CryptoAnalyzer  MacroAnalyzer  CallGraphAnalyzer
           grep  reverse-trace  Expert  Verifier  Architecture
```

连真实存在的 `expert-001` 也够不着 —— 它写的是 `Expert`。

**而它每一次运行都在要 `fact-layer`。** arbiter 一直想要确定性证据,bus 从来没法给它。

失败只作为一句散文回灌进下一轮 prompt(`arbiter/run.go:395`),**不产生任何事件**。这是 `events.jsonl` 唯一的实质缺口:它记录扫描器**做了什么**,不记录它**想做而被拒绝了什么**。

而这正是两次运行停在 `needs_review` 的自述理由:

> all three follow-up queries to resolve critical gaps failed (agents unavailable) … **Cannot elevate beyond needs_review.**

### 3.4 测量本身有缺陷:输入不是仓库

`../teecheck-benchmark/datasets/` 的 48 个目录中 **29 个只有 1 个文件**。CVE-2026-44362 的输入全部内容是:

```
vulnerable/core/crypto/signed_hdr.c
```

而漏洞的另一半 —— 消费 `key->version` 的 `check_update_version()` —— 在 `core/kernel/ree_fs_ta.c`,**不在输入里**。

**所以 §2.3 那张表是在扫描器看不见完整题面的条件下得出的。**

事实层之所以两次都对,是因为它**不用** `manifest.local_path`:自己 `git clone` 完整仓库再建库(`internal/trustirfacts/clone.go`)。**两个证据层在读不同的代码树。**

这一条不推翻主因(漏洞侧连"版本字段有没有被赋值"都没查过,而这在单文件里也看得出来),但它使"扫描器没用"这个结论**暂时下不了**。

---

## 4. 已排除的解释

| 假设 | 排除依据 |
|---|---|
| 模型不知道事实层存在 | prompt 三处提到,含准确的 operation 名(§3.1) |
| 事实层本身有问题 | 单独跑两个修订全对,三个谓词全部绑定成功(§2.2) |
| 修复版的 0 条是空洞的 | authority 谓词在库里绑到了 `ree_fs_ta.c:314` 与 `:639`,数据库是完整克隆(46 万行,2706 文件) |
| 管道没接通 | ToolFact→CasePack→四个 agent 的链路完整,`ae0eeaf` 之后 planner 也不再依赖模型回传 ref |
| 是单纯的采样抖动 | 分岔点的两侧 round-1 prompt 差 ~200 行 —— 上游 architecture / invariants 两个 LLM 阶段产出不同(见 §6) |

---

## 5. 已修但未改变结果的 9 处

本轮修复了 9 处同形状缺陷(**某样东西被产出了但没接到消费者**),**四次运行的结果没有任何变化**:

| 提交 | 修了什么 |
|---|---|
| `753c2be` | Case Pack 的 playbook 字段被 Merge 丢弃 |
| `c54cbfc` `d2e5076` | `JSONMode` 两个 provider 都不消费 |
| `61eacca` | LLM 对话只录 planner,其余 6 个 agent 不录 |
| `98e742b` | Challenger 评级被 `normalizeExploitability` 改写 |
| `460294b` | 子进程不经 executor,无事件 |
| `ae0eeaf` | ToolFact 引用靠模型回传,不回传就丢 |
| `fee11bd` | `producedStruct` 物化后无查询引用 |
| `d3e6134` | ripgrep 未知参数被 `json.Unmarshal` 静默吞掉 |
| `7561f04` | `Locations` 的 `omitempty` 让"查过为空"与"没填过"无法区分 |

**它们共同压着的那件事 —— 确定性证据到底会不会被采集 —— 一次都没被触碰。**

---

## 6. 一条未定论的观察

对 `gate-44362-*` 那一对,round-1 的**观察结果**逐字节相同(两份 playbook 4016 + 2772 字节完全一致,文件大纲仅 3 个行号差 1),分岔出现在 round 2 的一个动作上。

但完整 **prompt** 并不相同:

```
vulnerable  16,534 字节
fixed       15,379 字节
差异        ~45 行改动 + ~155 行增删
```

因为 planner 之前还有两个 LLM 阶段(`pipeline/run.go` 的 `architecture` 与 `invariants`)。它们产出了结构上不同的东西 —— 漏洞侧拿到 3 条不变量,其 INV-STATE-001 的验证计划锚在"lines 240 和 242-243",**那是 UUID 的 version 位**,是该文件里唯一出现 `version` 字符串的地方。

所以漏洞侧后续 8 轮追的是 UUID,round 8 还"正确地"把 INV-STATE-001 判成了误报。

**这条尚未定论**:它可能是主因的另一个表现(上游没有 TWE→operation 的约束,所以把靶子指错了),也可能是独立的第二个缺陷。**需要用完整仓库重跑之后再判。**

---

## 7. 修复方向

不是"再修一个 bug",是让两件事成立:

**A. 确定性证据的采集不再是采样结果。**

ToolFact 是不可挑战的那一层。一条不可变事实有没有被采集,不该取决于 LLM 当时的选择。

具体:case pack 或 invariant 命中一个有可执行 operation 的 TWE 时,流水线自己发这条查询,不问模型。模型仍然负责解释 ToolFact。

**触发点必须在 planner 之前。** `cases.Enrich` 在 `pipeline/run.go:234`,晚于 `l3_planner`(`:229`),所以 case pack 的 `related_twes` 用不上;可用的是 `cfg.Invariants`(带 `RelatedTWEs`)。

**B. 一次运行是对是错,由机器判定。**

现在 §2.3 那张表是人读 blob 得出的。`../teecheck-benchmark/evaluator/` 共 243 行,是词袋检索 + LLM 逐条判,**没有任何代码计算 TP/TN 或做 paired 判定**;44 份 oracle 里 0 份带 `twe_family`。

**在 A 成立之前,B 判出来的都是"证据缺失";在 B 成立之前,A 的改进无法被证明。两者必须一起做。**

---

## 8. 已知的陷阱

| # | 陷阱 |
|---|---|
| 1 | **不要靠加 prompt 文字解决采集率。** `d267e82`(把 operation 词表公布进 schema)之后,调用率从 0/3 变成 1/2。n=2,分不出改善和噪声。同一味药已经用过 |
| 2 | **换成完整仓库之前,"扫描器没用"下不了结论。** §3.4 |
| 3 | **修 `query_modules` 时不要只改值。** 19 个值全错说明这个字段从来没有被验证过;修完要有测试保证它指向的 operation 事实层真能执行 |
| 4 | **测试要检查"被引用"不是"被提到"。** `fee11bd` 的测试第一版撤掉引用后仍然通过 —— 因为旁边注释里出现了那个谓词名。对文本做子串搜索前必须先剥注释 |

---

## 9. 相关文件

```
internal/planner/prompt.go:85,:89,:380      事实层在 prompt 里的三处
internal/planner/actions/fact_layer_query.go  唯一入口
internal/trustirfacts/request.go            operationQueries — 真实词表
internal/trustirfacts/facttable.go          事实表(1 个仓库条目)
internal/twe/definitions.go:39,:99          QueryModules — 零消费者
knowledge/twe/definitions/catalog.yml       19 个条目,query_modules 全错
knowledge/twe/playbooks/rollback.yml:68     trustir_hints — 五个抽象动词
codeql/trustir/cpp/state/RollbackVersionNotPropagated.ql   唯一可执行查询
internal/arbiter/run.go:224,:387,:395       提问 prompt / 调用 / 失败被吞成一句散文
internal/agentbus/bus.go:40,:60             unknown agent(Ask 与 AskForCase 各一处)
```
