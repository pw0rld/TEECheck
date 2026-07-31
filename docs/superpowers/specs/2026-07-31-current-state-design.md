# TEECheck 现状绘像

> 测量日期：2026-07-31
> 分支：`merge/tee-audit-integration`，领先 `main` 193 次提交（main 最后一次移动是 2026-07-13）
> 本文每个数字都是当天在本机实测的。推断与测量分开标注；没测过的地方写"未验证"，不写估计值。

---

## 0. 一句话

**这套系统里唯一每次都答对的部件，四次运行里只被调用过一次。**

其余部分是一个多 Agent LLM 流水线，它在唯一一个有标准答案的案例上跑了四次，四次都没找到那个漏洞。

---

## 1. 这个系统要做什么

给它一个 TEE 项目的源码仓库 → 找出 TEE 特有的漏洞 → 人来复核。

它的立论是**三层证据分离**：

| 层 | 谁产出 | 能否被挑战 |
|---|---|---|
| **ToolFact** | 确定性工具（CodeQL） | **不能**——它是事实 |
| AgentAssessment | LLM | 能 |
| HumanVerdict | 人 | 只能追加，不能覆盖 |

这条分离是整套设计的地基：LLM 可以错，但它错不过 ToolFact。

---

## 2. 实际建成的样子

### 2.1 流水线（`internal/pipeline/run.go`，只有一条路）

```
preprocess → architecture → invariants → l3_planner → cases_enrich
           → expert → challenger → verifier → arbiter
```

9 个阶段，每个都发 `stage_started` / `stage_completed`。

### 2.2 规模

```
internal/            39 个包
生产代码             24,276 行
测试代码             23,962 行
go test ./...        41 个包，0 失败
```

### 2.3 代码量的分布，就是问题所在

| | 行数 | 覆盖面 |
|---|---|---|
| **LLM 推理层**<br>planner + 4 agent + architecture + invariants | **8,188** | 全部 |
| **确定性证据层**<br>trustirfacts + codeql | **2,275** | **1 条查询 / 7 族**<br>**1 个仓库 / 9 个** |
| **经验知识层**<br>knowledge/twe/playbooks | — | **2 个 playbook / 19 个 TWE** |

**推理层是事实层的 3.6 倍。而事实层是唯一每次都答对的那层。**

---

## 3. 已验证成立的部分（实测，非推断）

### 3.1 确定性事实层的差分成立

薄壳查询 `codeql/trustir/cpp/state/RollbackVersionNotPropagated.ql` 里**不含任何漏洞逻辑**。实体身份全部来自 Go 侧物化的事实表（`internal/trustirfacts/facttable.go`）：

```ql
f.getName() = "shdr_load_pub_key" and role = "security_version"
field = "version"
c.getTarget().getName() = "check_update_version" and kind = "state_restore_acceptance"
```

同一份事实表在两个修订上**逐字节相同**，差异只能来自真实代码结构。

在 CVE-2026-44362 上实测（clone → 建库 → 查询 → ToolFact）：

| 修订 | 结果 | 判定 |
|---|---|---|
| `a9386bf`（漏洞版） | **1 条命中**，`core/crypto/signed_hdr.c:262`（`shdr_load_pub_key` 的定义行） | ✅ 应该命中 |
| `43ed01d`（修复版） | **0 条** | ✅ 应该干净 |

首次 106.6 秒（含 clone + 46 万行抽取），复用已有 DB 再查约 20 秒。**0 次 LLM 调用。**

三个谓词在修复版库里全部绑定成功（生产者、两个 authority 调用点 `ree_fs_ta.c:314` 与 `:639`、字段写入），所以那个 0 是**真实的否定**，不是空洞。

### 3.2 运行记录是完整的

`runs/<id>/events.jsonl` 实测：

```
seq 1..126             无缺口
9 个 stage             全部 started/completed 配对
planner 20 个动作      ↔ 20 对 tool_call 事件，一一对应（连 done 都记）
19 次 LLM 调用         全部配对，按 agent 归属
73 个 blob 引用        盘上 73 个，0 缺失
```

每个 agent 的完整 prompt 与 response 都落 blob，可回放。

### 3.3 单元测试基线可信

41 个包全绿。本轮五处修复每处都做过 fire drill（撤销改动 → 确认测试变红 → 还原）。

---

## 4. 已验证不成立的部分（实测）

### 4.1 四次运行，零检出

CVE-2026-44362 的漏洞版和修复版各跑两轮（`runs/gate-44362-*`、`runs/44362-*-p1`）：

| | 漏洞侧 | 修复侧 |
|---|---|---|
| `fact_layer_query` 调用 | 0 / 0 | 1 / 0 |
| arbiter 状态 | `likely_issue` / `needs_review` | `needs_review` / `needs_review` |
| finding 提到 `subkey_version` | **0 次 / 0 次** | 12 次 / 12 次 |
| finding 提到 `key->version` | **0 次 / 0 次** | 27 次 / 27 次 |

**漏洞真正所在的那一侧，这两个标识符一次都没出现过。**

漏洞侧两次给出的都是同一个无关问题（`shdr_verify_signature` 的边界检查 / `img_size + hash_size` 溢出）。修复侧反而正确讨论了版本传播，并正确地拒绝确认。

### 4.2 事实层的调用是偶然，不是操舵

四次运行里 `fact_layer_query` 被调用 **1 次**。

planner 的 system prompt **确实**三处提到事实层（`internal/planner/prompt.go:85` 职责句、`:89` 结果解读规则、`:380` 动作 schema 里枚举了唯一合法 operation）。所以不是"模型不知道它存在"。

缺的是**从某个 TWE 到某条 operation 的映射**。prompt 说的是"调事实层拿真证据"（泛指），没有任何地方说：*TWE-STATE-001 的 `required_evidence` 第 4 条，正好由 `cpp.state.rollback_version_propagation` 回答*。

而 TWE 目录里本来有承载这个映射的字段：

```yaml
- id: TWE-STATE-001
  query_modules: [state/SealedStateRestoreWithoutVersion.ql]
```

`internal/twe/definitions.go:39` 声明它、`:99` 校验它非空、**其余地方无人读取**。而且 **16 个条目的 `query_modules` 值全部指向本仓库不存在的文件**——真实词表在一个毫无关联的 Go map（`internal/trustirfacts/request.go` 的 `operationQueries`）里。**两套命名系统，中间没有桥。**

`definitions.go:83-85` 的注释自陈："wiring those module names to actual CodeQL packs is PR-05's responsibility"——而 PR-05 在进度表里标着已完成。

### 4.3 Agent 间提问机制成功率为零

arbiter 可以通过 `bus.AskForCase`（`internal/arbiter/run.go:387`）向其他 agent 提问。跨 6 次运行统计 blob：

| 运行 | 失败次数 |
|---|---|
| 44362-vulnerable-p1 | 6 |
| 44362-fixed-p1 | 7 |
| gate-44362-vulnerable | 6 |
| gate-44362-fixed | 7 |
| optee-v2 | 11 |
| optee-full | 35 |
| **合计** | **72 次，成功 0 次** |

`Response from ...` 在所有 runs 的 blob 里一次都没出现过。

原因同 4.2：`arbiter/run.go:224` 的 prompt 只说 `queries: 每项含 to_agent, kind, question`，**从不说有哪些 agent 存在**。实际注册的是 `scanner-001` / `expert-001` / `challenger-001` / `reviewer-001`；模型编出来的是 `fact-layer`、`Investigator`、`CryptoAnalyzer`、`grep`、`Expert`……连真实存在的 `expert-001` 也够不着，因为它写的是 `Expert`。

**它每一次运行都在要 `fact-layer`。** arbiter 一直想要确定性证据，而 bus 从来没法给它。

失败只作为一句散文回灌进下一轮 prompt（`arbiter/run.go:394`），**不产生任何事件**——这是 `events.jsonl` 唯一的实质缺口：记录了扫描器**做了什么**，不记录它**想做而被拒绝了什么**。

而这正是两次运行停在 `needs_review` 的自述原因：

> all three follow-up queries to resolve critical gaps failed (agents unavailable) … **Cannot elevate beyond needs_review.**

### 4.4 评测输入不是仓库

`teecheck-benchmark/datasets/` 48 个目录中 **29 个只有 1 个文件**。CVE-2026-44362 的输入是：

```
vulnerable/core/crypto/signed_hdr.c        ← 全部内容
```

而漏洞的另一半——消费 `key->version` 的 `check_update_version()`——在 `core/kernel/ree_fs_ta.c`，**不在输入里**。

**过去所有"扫描器没找到"的结论，都是在它看不见题面的条件下得出的。** 事实层之所以两次都对，是因为它**不用** `local_path`：自己 clone 完整仓库再建库。两个证据层在读不同的代码树。

### 4.5 没有任何东西能自动判断一次运行是对是错

`teecheck-benchmark/evaluator/` 共 243 行：词袋 token 重叠检索（`rag.go:113`）+ LLM 逐条判。`batch.go` 只是对 `{"vulnerable","fixed"}` 各跑一遍收判决——**没有任何代码计算 TP/TN、没有 paired 判定、没有拒绝给 ERROR 变体打分**。

44 份 oracle 里 **0 份**带 `twe_family` 或 `in_twe_scope`。

所以 §4.1 那张表是我手工读 blob 得出的。仓库里没有任何东西能自动发现它。

---

## 5. 一个反复出现的缺陷形状

本轮排查中，**同一个形状出现了 11 次**：

> **某样东西被产出了，但没接到消费者；或者模型必须猜一个它看不见的封闭词表。**

已确认的实例：

| # | 实例 | 状态 |
|---|---|---|
| 1 | Case Pack 的 playbook 字段产出后被 Merge 丢弃 | 已修 |
| 2 | `JSONMode` 标志两个 provider 都不消费 | 已修 |
| 3 | LLM 对话只录 planner，其余 6 个 agent 不录 | 已修 |
| 4 | Challenger 的评级被 `normalizeExploitability` 改写 | 已修 |
| 5 | 子进程不经 executor，无事件 | 已修 |
| 6 | ToolFact 引用靠模型回传，模型不回传就丢 | 已修（`ae0eeaf`） |
| 7 | `producedStruct` 事实物化后无查询引用 | 已修（`fee11bd`） |
| 8 | ripgrep 未知参数被 `json.Unmarshal` 静默吞掉 | 已修（`d3e6134`） |
| 9 | `ToolFact.Locations` 的 `omitempty` 让"查过为空"与"没填过"无法区分 | 已修（`7561f04`） |
| 10 | `query_modules` 零消费者，且 16 个值全部指向不存在的文件 | **未修** |
| 11 | arbiter 的 agent 名字词表不公开，72 次询问 0 成功 | **未修** |

**前 9 处修完，四次运行的结果没有任何变化。** 因为它们共同压着的那件事——确定性证据到底会不会被采集——一次都没被触碰。

### 5.1 可机械化的检测器

第 7 处的修复顺带产出了一个能抓住整类问题的测试（`internal/trustirfacts/facttable_consumed_test.go`）：

> 事实表渲染出的每个**非空**谓词，必须被查询包里某条查询引用。

它的第一版是**坏的**——fire drill 撤掉引用后仍然通过，因为旁边的注释里出现了那个谓词名。**它检查的是"被提到"，不是"被引用"。** 现在搜索前先剥注释，另有一条测试守着剥注释本身。

这个教训适用于整类："某字段的全部非声明读取都在 `_test.go` 里"是同一个检测器的另一种形式。

---

## 6. 目标状态

不是"再修一个 bug"，而是让这两件事成立：

**A. 确定性证据的采集不再是采样结果。**

ToolFact 是不可挑战的那一层。一条不可变事实到底有没有被采集，不该取决于 LLM 当时的选择。四次运行 1 次命中的现状，说明它现在就是采样结果。

**B. 一次运行是对是错，由机器判定，不由人读 blob。**

在 A 成立之前，B 判出来的都是"证据缺失"；在 B 成立之前，A 的改进无法被证明。**两者必须一起做。**

---

## 7. 明确不在本轮范围内

- **模型异构**（expert=GLM / challenger=Claude）——v1 GLM-only，v2 材料
- **扩展其余 6 族 CodeQL 查询**——在 §4.2 的映射修好之前，新查询在设计上不可达，只会变成第 12、13 处"产出了没人消费"
- **LLM 事实表标注管道**（让事实层认识第 2 个仓库）——同上，先证明 1 个仓库上的闭环成立
- **`cmd/twescan`**（308 行 + 独占的 solver/twepipeline/twexpert）——旧旁路，可退役但不阻塞主线

---

## 8. 风险

| # | 风险 | 说明 |
|---|---|---|
| 1 | **强制调用事实层后，agent 仍得不出正确结论** | 那说明问题不在"要不要查"，而在 agent 的角色定位。这是架构问题，需要重新设计，不是修 bug |
| 2 | **加 prompt 文字这条路已经证明效果有限** | `d267e82`（公布 operation 词表）后，调用率从 0/3 变成 1/2。n=2，分不出改善和噪声。**不要再用同一味药** |
| 3 | **单文件 fixture 使很多历史结论作废** | §4.1 那张表是在错误输入下得出的。换成完整仓库重跑之前，"扫描器没用"这个结论下不了 |
| 4 | **完整仓库跑的代价未测** | optee_os 41MB，repomix/repomap 要处理整棵树。单侧耗时未知 |
| 5 | **本文档自身会过时** | 前一版快照（2026-07-23）在 8 天内积累了 9 处错误断言，其中 1 处是修文档的人当天亲手造成的 |

---

## 9. 验收标准

1. 在 CVE-2026-44362 的**完整仓库**两个修订上各跑一次，漏洞侧的 `fact_layer_query` 调用次数 ≥ 1，且其 ToolFact 出现在 `03_investigations/*.json` 的 `tool_fact_refs` 中
2. arbiter 的 agent 间询问成功率 > 0，且失败的询问产生事件
3. 存在一条命令，读两侧运行产物 + oracle，输出 PASS/FAIL **和理由**，并且它对 §4.1 那次运行输出 FAIL——理由是"漏洞侧的 finding 未覆盖 oracle 的 required_evidence"
4. `go test ./...` 保持 0 失败
