# BUG-002：Benchmark 单文件输入与完整 CodeQL 仓库分裂，真实命中被“不可达”反证压成漏报

> 状态：**诊断中 / 未修复**
> 记录日期：2026-08-01
> 影响：CVE-2026-44362 vulnerable run `runs/44362-vuln-p9`
> 路径以 `tee-usage-scanner/` 为基准
> 本文区分“已确认事实”和“根因猜测”；除明确标为已确认的内容外，仍需修复后用 vulnerable/fixed paired run 验证。
>
> **2026-08-01 修订**（逐条比对 `runs/44362-vuln-p9` 产物与源码后）：
> 新增 §3.4、§3.5 两条已确认事实；§3.3 轮次由“第 6 轮”更正为“第 3 轮和第 6 轮”；
> §3.8 更正 —— 机械 gate 的下限是 `likely_issue` 而非 `needs_review`；
> 猜测 C 整节重写（原表述被运行记录否定）；猜测 D 降级；
> 猜测 E 补两条已确认事实；实验 1 补 clone 生命周期前提；§8 失败链重排。

---

## 1. 一句话症状

**确定性 CodeQL 事实层已经准确命中 CVE-2026-44362 并算出了调用方位置，但那个位置没有出现在 Planner 看到的观测里；Planner 转而在只有一个文件的 benchmark fixture 上做 `reverse_trace`，得到“零调用者”，Challenger 将其升级为完整仓库不可达，最终 Arbiter 输出 `needs_review`；benchmark 因而把漏洞侧计为 FN。**

这不是“查询没有扫出来”，而是正确 ToolFact 的关键字段在传给 Planner 时被丢弃，随后被一份错误范围的负面证据取代。

---

## 2. 复现运行

运行目录：

```text
runs/44362-vuln-p9
```

Manifest：

```text
repository  https://github.com/OP-TEE/optee_os
commit      a9386bf987d95374a6f7f4c7bcf850115e0e1a4e
local_path  ../teecheck-benchmark/datasets/CVE-2026-44362/vulnerable
```

本地输入目录的全部源码只有：

```text
core/crypto/signed_hdr.c
```

最终 finding：

```json
{
  "finding_id": "inv-state-001-b335ed7765ea",
  "status": "needs_review",
  "files": ["core/crypto/signed_hdr.c"]
}
```

Benchmark evaluator 只把以下 Arbiter 状态当作检出：

```go
"likely_issue":        true,
"confirmed_candidate": true,
```

因此该 vulnerable run 即使文件命中正确，只要保持 `needs_review`，仍会被判为 FN。

---

## 3. 已确认事实

### 3.1 ToolFact 已经准确命中漏洞

产物：

```text
runs/44362-vuln-p9/02_tool_facts/trustir/
  trustir-cpp-cpp.state.rollback_version_propagation-39aac16b6e84fd57.json
```

关键内容：

```text
status     success
operation  cpp.state.rollback_version_propagation
location   core/crypto/signed_hdr.c:262
producer   shdr_load_pub_key
field      version
authority  check_update_version
related    core/kernel/ree_fs_ta.c:314, :639
```

ToolFact 的结论是：

```text
TWE-STATE-001: producer shdr_load_pub_key never propagates rollback
field 'version'; authority check_update_version therefore checks a
default version.
```

漏洞版与修复版的关键差异也正是：

```c
+ key->version = subkey->subkey_version;
```

所以本次漏报不能归因于事实查询没有命中。

### 3.2 CodeQL 与 Planner 读取的是不同范围的代码树

Planner、preprocessor、architecture、invariants 和源码动作使用
`manifest.local_path`，即只有 `signed_hdr.c` 的 benchmark fixture。

事实层则根据 `repository + commit` 另行 clone 完整 OP-TEE 仓库，并在
约 46 万行 C/C++ 上建立 CodeQL DB。数据库元数据记录：

```text
creationMetadata.sha = a9386bf987d95374a6f7f4c7bcf850115e0e1a4e
baselineLinesOfCode  = 459962
buildMode            = none
```

数据库 `src.zip` 内的漏洞 revision 明确存在真实调用链：

```c
res = shdr_load_pub_key(..., &pub_key);

res = check_update_version(subkey_ver_db, pub_key.uuid,
                           pub_key.version);

FTMN_CALL_FUNC(..., shdr_verify_signature2, &pub_key, shdr);
```

### 3.3 Planner 的“零调用者”只是在单文件 fixture 内成立

`04_planner/rounds.jsonl` 的第 3 轮和第 6 轮各执行了一次，参数完全相同：

```json
{"file": "core/crypto/signed_hdr.c", "symbol": "shdr_load_pub_key", "depth": 2}
```

两次输出也完全相同：

```text
shdr_load_pub_key (target in core/crypto/signed_hdr.c)
  (no callers found)
```

因为 Planner 的 RepoRoot 只有 `signed_hdr.c`，该结果最多只能解释为：

```text
在当前仅包含一个源码文件的扫描范围内没有找到调用者。
```

它不能解释为：

```text
完整 OP-TEE revision 中不存在调用者，代码不可达。
```

完整 CodeQL 源码树与 ToolFact 已经证明第二种解释为假。

### 3.4 Planner 自己调用了事实层，但观测里没有调用方位置

事实层的 prefetch 是生效的：CodeQL DB 目录时间戳 `14:55:43`，早于 l3_planner
阶段。Planner 随后在第 2 轮又自己发起了一次 `fact_layer_query`，命中缓存，
耗时 8.9 秒，`ok: true`。它拿到的观测是：

```json
{
  "tool_fact_ref": ".../trustir-cpp-cpp.state.rollback_version_propagation-....json",
  "status": "success",
  "operation": "cpp.state.rollback_version_propagation",
  "location_count": 1,
  "locations": [{"path": "core/crypto/signed_hdr.c", "start_line": 262}],
  "coverage_gaps": [...]
}
```

所以 Planner **知道** `signed_hdr.c:262` 已经命中。

但这份观测里没有 ToolFact 的 `findings[].message`，也没有
`findings[].related`——而 `ree_fs_ta.c:314` / `:639` 的
`check_update_version` 只存在于 `related` 里（见 §3.1）。

事实层已经算出了调用方所在的文件和行号，交给 Planner 的压缩视图把这个字段
丢掉了。Planner 因此转而用 `reverse_trace` 去单文件 fixture 里找调用者，
得到零结果（§3.3）。

### 3.5 Planner 的 done 自述与它自己的执行记录矛盾

Case Pack 的 `coverage_gaps` 里写着：

```text
No fact_layer_query (cpp.state.rollback_version_propagation) was executed
due to budget constraints
```

而该查询在 5 轮之前刚刚执行成功（§3.4）。这不是接线断裂，是模型在 done
payload 里的自述不可信——与 BUG-001 里 `"tool_fact_refs": []` 是同一类缺陷：
**凡是由模型复述、而非由执行记录派生的字段，都可能与运行事实相反。**

### 3.6 错误范围的负面证据进入了裁决链

Planner 把下面这句话写进 Investigation/Case Pack 的
`counterevidence`：

```text
shdr_load_pub_key has zero callers found via reverse_trace, suggesting
the subkey delegation path may be unreachable in the current codebase.
```

Challenger phase 1 进一步升级为：

```json
{
  "issue_present": false,
  "reasoning": "... the entire subkey delegation chain ... is
                dead/unreachable code in the current codebase."
}
```

Verifier 虽然确认 version propagation gap 和另一个 weak-key guard
缺陷均真实存在，仍因上述 dead-code 争议输出：

```text
status = contested
```

最终 Arbiter 选择 `needs_review`。

### 3.7 Case Pack 同时携带互相矛盾的事实

`03_cases/case-001.json` 同时包含：

1. 一个 `status=success` 且准确命中的 `tool_fact_ref`（绝对路径，可解析）；
2. `coverage_gaps` 中的 “No fact_layer_query ... was executed due to budget constraints”（§3.5，与执行记录矛盾）；
3. “zero callers / path may be unreachable” counter-evidence；
4. 7 个 `missing_links` 和 8 条 `required_evidence`，其中多条要求做的正是事实层已经做完的事（“Trace callers ... to determine if upstream callers perform freshness checks”）；
5. 没有 `observed_flow` 字段。

ToolFact 引用本身到达了 Case Pack（BUG-001 的接线是好的），但它携带的
producer/authority 位置没有在 Planner 调查期间被用于构造 flow、消解
missing role 或修正 coverage gap——原因见 §3.4：Planner 从未看见那些位置。

### 3.8 已被后续阶段解决的 gap 没有从 Case Pack 消失（但它不是本次 FN 的原因）

后续 Agent 已经解决至少这些事项：

- line 240 是 UUID v5 注释，不是 freshness field；
- `check_attrs` 已验证 attribute offsets 的边界；
- `shdr_verify_signature2` 的后半段已读取；
- version propagation gap 已由 ToolFact 确认；
- 完整 CodeQL 树已经给出 rollback authority 位置。

但是 Arbiter 的 `attackChainComplete()` 仍直接读取原始
`CasePack.MissingLinks`，而不是读取一个经过 Verifier 消解后的状态。

本次 gate 输入为：

```text
CasePack.MissingLinks       7 条
Expert.NeedsVerification    true
Verifier.Status             contested
Verifier contradiction     1 条（零调用者争议）
```

因此 `attackChainComplete()` 返回 false。

**但这不足以造成本次漏报。** 该 gate 只管 “confirmed” 这个措辞
（`internal/arbiter/chain.go`）：

```go
func sanitizeFindingItem(item artifacts.FindingItem, complete bool) artifacts.FindingItem {
	if complete { return item }
	if isConfirmedStatus(item.Status) { item.Status = "likely_issue" }
	...
}
```

即 gate 的作用是把 `confirmed_candidate` 降级为 `likely_issue`，**它永远不会
产出 `needs_review`**。而 `likely_issue` 在 evaluator 里已经算检出（§2）。

`needs_review` 也不是轮次耗尽的兜底路径——那条路径硬编码
`Confidence: "low"` 和 summary “Reached maximum dialog rounds without final
arbiter judgment”（`internal/arbiter/run.go:426`），而本次 finding 是
`confidence: medium` 且带完整 summary。

**结论：`needs_review` 是 Arbiter 模型在 `likely_issue` 与 `needs_review`
之间自己选的。** 陈旧 MissingLinks 的代价是拿不到 `confirmed_candidate`，
不是拿不到检出。

---

## 4. 根因猜测（按优先级）

### 猜测 A：Benchmark 把 patch fixture 当成 repository，是首要根因

Benchmark 的 fixture 适合验证“补丁文件的 vulnerable/fixed 内容是否正确”，
但不适合作为需要调用链、信任边界和跨文件状态传播的完整审计输入。

本例漏洞跨越：

```text
core/crypto/signed_hdr.c
  shdr_load_pub_key -> pub_key.version

core/kernel/ree_fs_ta.c
  shdr_load_pub_key -> check_update_version(pub_key.version)
```

只给 Planner 前一个文件，会系统性制造：

- false zero-caller；
- false missing authority；
- false missing guard；
- 无法构造 observed flow；
- architecture/invariant 只能围绕局部关键词猜测。

**猜测：只要让 Planner 在完整 `repository@revision` 上运行，并仅把
fixture 文件作为 focus/scan path，而不是 RepoRoot，本例的 dead-code
争议就会消失，最终状态至少应提升到 `likely_issue`。**

### 猜测 B：负面工具结果缺失 scope/provenance，导致 not-found 被当成 absent

`reverse_trace` 返回裸文本 `(no callers found)`，没有同时返回：

- RepoRoot；
- 索引文件数；
- 是否是完整 checkout；
- 支持哪些语言/间接调用；
- 结论应解释为 `not_found_in_scope` 还是 `proven_absent`。

这违反项目自己的证据边界：工具未找到不等于证明不存在。

**猜测：即使 benchmark 暂时仍传单文件，只要 reverse_trace 把结果标成
`not_found_in_scope (1 source file)`，Challenger 就不应再把它作为
`issue_present=false` 的决定性反证。**

### 猜测 C：事实层观测丢弃了 findings.message 与 related locations

> 早前版本的本节写的是“prefetch 只传引用，Planner 不知道已经命中”。
> 运行记录否定了这个说法：prefetch 生效，且 Planner 第 2 轮自己调用了
> `fact_layer_query` 并收到 `status: success` 与 `locations[0] =
> signed_hdr.c:262`（§3.4）。以下是修正后的表述。

Planner 收到的观测形状（`internal/planner/actions` 的
`factLayerQueryOutput`）只有：

```text
tool_fact_ref, status, operation, location_count, locations, coverage_gaps
```

持久化的 ToolFact 里还有两个字段没有出现在观测中：

```text
findings[].message   producer/authority 的结论叙述
findings[].related   core/kernel/ree_fs_ta.c:314 / :639  check_update_version
```

也就是说，**事实层已经确定性地算出了调用方所在的文件和行号，而 Planner
看到的那份视图恰好把它删掉了**。Planner 于是改用 `reverse_trace` 在单文件
fixture 里找调用者，得到零结果，并把它写成 counterevidence。

这是本项目反复出现的同一种缺陷形状：**证据被算出来，却没有接到需要它的
那一环**（BUG-001 §3 已记录 9 例）。

**猜测：把 `findings[].message` 和 `findings[].related` 补进
`fact_layer_query` 的观测，dead-code 推断链在第 2 轮就会被切断——因为
`ree_fs_ta.c` 会直接出现在 Planner 眼前，而它已经证明自己会追问
（p8 主动 `read_file core/include/signed_hdr.h`）。**

### 猜测 D：MissingLinks/RequiredEvidence 是只增不减的陈旧状态（不在本次 FN 的关键路径上）

> 优先级已下调。§3.8 证明该 gate 的下限是 `likely_issue`，而
> `likely_issue` 已算检出，所以它不可能是本次 FN 的原因。它是
> **`confirmed_candidate` 的天花板问题**，不是 `needs_review` 的成因。

Planner 产出初始 checklist，Expert/Verifier 可以在文本里回答它们，但没有
结构化步骤把已解决项从 Case Pack 中移除。Arbiter 的机械 gate 因而永久读取
旧状态。

**猜测：需要一个 verifier resolution artifact，逐项标记
`resolved / contradicted / still_missing`，并让 Arbiter 对 resolution 后的状态
做 completeness check。否则只要 Planner 稍微保守地列出 required evidence，
几乎所有 case 都无法 confirmed。**

### 猜测 E：Agent Bus 的 follow-up 上下文不足以纠正早期工具误判

Arbiter 追问 Challenger/Expert 时，`busEvidence()` 只提供：

- Target files/symbols；
- ToolFacts；
- Case Pack source snippets。

它不提供 Planner 的原始 `reverse_trace` observation、工具 scope、完整源码树或
可执行工具。两个 Agent 只能回答“看不到 reverse_trace 数据，无法核验”，
不能主动打开 `ree_fs_ta.c` 推翻 dead-code 判断。

两条已确认的补充事实：

1. Arbiter 交给两个 Agent 的 evidence **确实包含 `ree_fs_ta.c`**——ToolFact
   的 related locations 已经渲染进去了。但两个 Agent 仍然回答
   “There is no roadmap, no caller/call-graph data”。也就是说，
   **related location 以当前的渲染形式不被模型读作调用方证据**，补上字段
   本身不等于说清楚它是什么。
2. `events.jsonl` 里有 4 条 `bus_query_failed`，全部是 `verifier-001` 向
   `fact-layer` 提问，而注册的 Agent 是
   `challenger-001, expert-001, reviewer-001, scanner-001`。Agent 词汇表
   已对 Arbiter 发布，但 **Verifier 侧仍在猜一个不存在的端点**。

**猜测：follow-up 必须携带被质疑 observation 的原始内容与 scope，或者允许
Verifier/Arbiter 对同一完整 repository root 重新执行查询。**

---

## 5. 输出/评分层的次生问题

这些不是本次 FN 的首个触发点，但修复 `needs_review` 后会继续阻塞更严格的
benchmark。

### 5.1 Finding ID 没有 TWE family

当前 ID：

```text
inv-state-001-b335ed7765ea
```

Evaluator 对带 `twe_family: State` 的 oracle 要求 ID 形如：

```text
TWE-STATE-...
```

当前 CVE-2026-44362 oracle 尚未填写 `twe_family`，所以本次只卡在 status；
一旦按 benchmark README 补回 family，现有 ID 会造成第二次匹配失败。

### 5.2 Finding 没有 structured locations

ToolFact 有 `core/crypto/signed_hdr.c:262`，但最终 finding 的
`locations` 为空。未来 oracle 填 `primary_line` 后，即使状态和 family 正确，
仍会匹配失败。

### 5.3 两个不同弱点被合并为同一个 finding

Arbiter 把下面两件事放进同一个 `inv-state-*` finding：

1. TWE-STATE-001 version propagation gap（本 benchmark 的目标）；
2. `shdr_verify_signature2` weak-key guard operand mismatch（另一个 Flow/Guard 类问题）。

这会稀释主漏洞的证据和分类，并使 family/位置语义不稳定。猜测应按
TWE/invariant/attack path 拆成独立 findings，而不是只按 target file 合并。

---

## 6. 建议的最小验证实验

先不要修改 benchmark 的 detection status，也不要把 `needs_review` 算 TP。
按以下顺序做最小实验，逐一验证上面的猜测：

### 实验 1：完整仓库、同一 revision、同一模型重跑

> 前提澄清：run 目录里**没有**可直接复用的完整工作树。事实层的 clone 落在
> `os.MkdirTemp` 里，并由 `defer os.RemoveAll(work)` 删除
> （`internal/trustirfacts/db.go:52-56`）。留下的只有 CodeQL DB 内的
> `src.zip`（6.1 MB）。所以本实验需要三选一：保留该 clone、解压 `src.zip`、
> 或另做一次 checkout——这决定了它是十几行改动还是每次 run 多一次
> 46 万行的克隆。

1. checkout 完整 OP-TEE `a9386bf...`；
2. Planner/architecture/invariants/actions 全部使用该完整 checkout；
3. focus 仍限制到 `core/crypto/signed_hdr.c`，但 reverse trace 可跨文件；
4. 保持其余配置与 p9 一致。

预期：

```text
reverse_trace(shdr_load_pub_key)
  -> core/kernel/ree_fs_ta.c
```

Challenger 不再以 dead code 判 `issue_present=false`，Verifier 不再因此
`contested`，Arbiter 至少输出 `likely_issue`。

### 实验 2：只修改 reverse_trace 的 scope 表达

仍使用单文件 fixture，但将结果改为结构化：

```json
{
  "status": "not_found_in_scope",
  "repo_root": ".../vulnerable",
  "indexed_files": 1,
  "complete_repository": false,
  "conclusion": "full-repository reachability unresolved"
}
```

预期：Challenger 不得把它转写成 `dead/unreachable code`。

### 实验 3：把 findings.message 与 related locations 补进事实层观测

改的是 `fact_layer_query` 返回给 Planner 的观测形状，而不是 prefetch 的接线
——prefetch 本来就是通的，Planner 也确实调用过（§3.4）。缺的是那两个字段。

预期：Planner 在第 2 轮就看到 `ree_fs_ta.c:314/:639 check_update_version`，
直接调查 `shdr_load_pub_key -> check_update_version`，不再依赖单文件
`reverse_trace` 去推断可达性。

### 实验 4：跑 vulnerable/fixed paired gate

修复后必须同时满足：

| revision | ToolFact | Arbiter | Benchmark |
|---|---|---|---|
| vulnerable `a9386bf` | 1 location | `likely_issue` 或 `confirmed_candidate` | TP |
| fixed `43ed01d` | 0 locations | 不报告同一 TWE-STATE issue | TN |

只把漏洞侧状态抬高而让修复侧也报同一问题，不算修复成功。

---

## 7. 暂不建议的“修复”

| 做法 | 原因 |
|---|---|
| 把 `needs_review` 加入 benchmark detection statuses | 会把真正不确定的结果也算 TP，掩盖裁决问题 |
| 仅在 Arbiter prompt 中强调“相信 ToolFact” | 无法消除错误 scope 的 counter-evidence；Arbiter 拿到的 ToolFact 里已经有 `ree_fs_ta.c`，两个 Agent 仍答“没有 call-graph 数据”（猜测 E 补充事实 1） |
| 直接硬编码 CVE-2026-44362 为 confirmed | 破坏 benchmark 独立性，无法推广到其他案例 |
| 删除 attack-chain gate | gate 本身保护 confirmed 语义；应修复其输入状态，而不是取消证据要求 |
| 只增加 Planner token/round budget | p9 已用 85k token；问题是上下文范围和证据 wiring，不是单纯预算不足 |

---

## 8. 当前判断

本次运行的直接失败链已较明确：

```text
事实层已算出调用方 ree_fs_ta.c:314/:639
  -> 但 fact_layer_query 观测丢弃 findings.message / related
  -> Planner 改用 reverse_trace 找调用者
  -> 单文件 fixture 作为 Planner RepoRoot，局部未找到
  -> 无 scope 的 “no callers found”
  -> Challenger 推导完整项目 dead code
  -> Verifier contested
  -> Arbiter 模型自选 needs_review（而非 gate 强制）
  -> evaluator 不计 detection
  -> vulnerable FN
```

链条上有两处独立的断点，各自都足以单独修复：**观测丢字段**（§3.4）和
**Planner scope 与事实层 scope 不一致**（§3.2）。陈旧 MissingLinks（§3.8）
不在这条链上。

最高优先级不是调 prompt 或放宽评分，而是让一次审计中的 Planner、源码工具、
CodeQL 事实层和 Agent follow-up 对同一个 `repository@commit`、同一个明确标注的
scope 说话。

