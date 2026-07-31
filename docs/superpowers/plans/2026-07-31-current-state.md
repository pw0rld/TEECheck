# 让确定性证据被采集，并让运行结果可被机器判定 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 CVE-2026-44362 的漏洞侧在一次真实运行中调用事实层、把 ToolFact 记进调查记录，并让一条命令能自动判定这次运行是对是错。

**Architecture:** 三段。第一段接线（TWE→operation 映射、agent 名字词表），让模型能选中它够不着的东西；第二段去掉选择权（命中即触发），让不可变证据的采集不再是采样结果；第三段判卷（paired gate），让结论不再靠人读 blob。

**Tech Stack:** Go 1.23+，CodeQL 2.26.1（`tools/codeql`，已装），GLM（`~/.teecheck.env`）

## Global Constraints

- **不删测试来让测试变绿。** 每处改动配一个覆盖它的测试，并做 fire drill（撤销改动 → 确认测试变红 → 还原）
- **不新增 env-gated `t.Skip` 集成测试。** 已有 4 个，是弱测试；优先写不依赖外部二进制的测试
- **测试必须检查"被引用"，不是"被提到"。** 对文本做子串搜索前先剥注释（见 `internal/trustirfacts/facttable_consumed_test.go` 的 `qlComment`）
- **不做 spec §7 列为范围外的事**：模型异构、其余 6 族查询、LLM 标注管道、退役 twescan
- **不靠加 prompt 文字解决采集率**（spec §8 风险 2）。prompt 改动只用于公开封闭词表，不用于劝说模型
- 所有 CVE-2026-44362 相关常量：漏洞版 `a9386bf987d95374a6f7f4c7bcf850115e0e1a4e`，修复版 `43ed01d216a9586e7e7591dff1f7fbf80923f93f`，仓库 `https://github.com/OP-TEE/optee_os`，operation `cpp.state.rollback_version_propagation`

---

### Task 1: 修 `query_modules`，建立 TWE → operation 映射

**Files:**
- Modify: `tee-usage-scanner/knowledge/twe/definitions/catalog.yml`
- Modify: `tee-usage-scanner/internal/twe/definitions.go:83-100`
- Create: `tee-usage-scanner/internal/twe/queryops.go`
- Test: `tee-usage-scanner/internal/twe/queryops_test.go`

**Interfaces:**
- Produces: `twe.OperationFor(tweID string) (string, bool)` — 返回该 TWE 对应的可执行 operation 名，第二个返回值 false 表示这一族尚无查询
- Consumes: `trustirfacts.SupportedOperationStrings()`（已存在，`request.go`）

**背景:** spec §4.2。`query_modules` 有 16 个值，全部指向本仓库不存在的 `.ql`（那些文件名来自 `tee-audit` 的 rust/js/go 树）。真实词表在 `internal/trustirfacts/request.go` 的 `operationQueries`。两套命名，没有桥。

- [ ] **Step 1: 写失败的测试**

`internal/twe/queryops_test.go`：

```go
package twe

import "testing"

// catalog.yml 里每个声称有查询的 TWE，其 operation 必须是事实层真的能执行的。
// 在此之前 query_modules 的 16 个值全部指向本仓库不存在的文件。
func TestOperationFor_OnlyNamesExecutableOperations(t *testing.T) {
	defs, err := LoadDefinitions("../../knowledge/twe/definitions/catalog.yml")
	if err != nil {
		t.Fatal(err)
	}
	var mapped int
	for _, d := range defs {
		op, ok := OperationFor(d.ID)
		if !ok {
			continue
		}
		mapped++
		if !isExecutableOperation(op) {
			t.Errorf("%s maps to %q, which the fact layer cannot execute", d.ID, op)
		}
	}
	if mapped == 0 {
		t.Fatal("no TWE maps to any operation — the bridge does not exist")
	}
}

// TWE-STATE-001 是唯一有可执行查询的那一条。
func TestOperationFor_StateRollback(t *testing.T) {
	op, ok := OperationFor("TWE-STATE-001")
	if !ok {
		t.Fatal("TWE-STATE-001 must map to an operation")
	}
	if op != "cpp.state.rollback_version_propagation" {
		t.Fatalf("op = %q", op)
	}
}

// 没有查询的族必须诚实地返回 false，而不是指向一个不存在的文件。
func TestOperationFor_UnimplementedFamiliesReportFalse(t *testing.T) {
	for _, id := range []string{"TWE-FLOW-001", "TWE-GUARD-001", "TWE-BIND-001"} {
		if op, ok := OperationFor(id); ok {
			t.Errorf("%s claims operation %q, but no query exists for its family", id, op)
		}
	}
}
```

- [ ] **Step 2: 运行,确认失败**

Run: `cd tee-usage-scanner && go test -run TestOperationFor ./internal/twe/`
Expected: FAIL — `undefined: OperationFor`

- [ ] **Step 3: 实现**

`internal/twe/queryops.go`：

```go
package twe

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"

// tweOperations is the bridge the catalog's query_modules field was meant to
// be and never was: it names, for each TWE that has one, the fact-layer
// operation that answers it. definitions.go declared QueryModules, validated
// it non-empty, and nothing else read it — while all 16 values named .ql
// files that exist only in the sibling tee-audit rust/javascript/go trees.
//
// An entry here is a promise that trustirfacts can execute the operation;
// TestOperationFor_OnlyNamesExecutableOperations enforces it. A TWE with no
// entry reports false — "this family has no executable query yet" is a real
// answer and must be sayable.
var tweOperations = map[string]string{
	"TWE-STATE-001": string(trustirfacts.OperationRollbackVersionPropagation),
}

// OperationFor returns the fact-layer operation that answers tweID.
func OperationFor(tweID string) (string, bool) {
	op, ok := tweOperations[tweID]
	return op, ok
}

func isExecutableOperation(op string) bool {
	return trustirfacts.IsSupportedOperation(op)
}
```

- [ ] **Step 4: 从 catalog.yml 删掉那 16 个说谎的值**

`query_modules` 的每个值都指向不存在的文件。删除该字段，并去掉 `definitions.go:99` 的非空校验（它强制维护一份全是假值的清单）。

`internal/twe/definitions.go`，删除：

```go
	if len(d.QueryModules) == 0 {
		return fmt.Errorf("%s: query_modules must be non-empty", d.ID)
	}
```

以及结构体字段 `QueryModules []string`。同时删除 `:83-85` 那句自陈——它指认的 PR-05 责任现在由 `queryops.go` 承担：

```go
// Validate checks a single Definition. It intentionally does not require
// query_modules to resolve to a real file on disk — wiring those module names
// to actual CodeQL packs is PR-05's responsibility, not this catalog's.
```

`catalog.yml` 里 19 处 `query_modules: [...]` 全部删除（每条 TWE 一行）。

- [ ] **Step 5: 运行,确认通过**

Run: `cd tee-usage-scanner && go test -count=1 ./internal/twe/ ./internal/trustirfacts/`
Expected: ok

- [ ] **Step 6: Fire drill**

把 `tweOperations` 里的值改成 `"cpp.state.nonexistent"`，确认 `TestOperationFor_OnlyNamesExecutableOperations` 变红，然后还原。

- [ ] **Step 7: Commit**

```bash
git add tee-usage-scanner/internal/twe/ tee-usage-scanner/knowledge/twe/definitions/catalog.yml
git commit -m "twe: bridge TWE ids to the operations the fact layer can execute"
```

---

### Task 2: 公开 agent 名字词表,并记录被拒绝的询问

**Files:**
- Modify: `tee-usage-scanner/internal/agentbus/bus.go`
- Modify: `tee-usage-scanner/internal/arbiter/run.go:224`（prompt）、`:387-395`（询问循环）
- Test: `tee-usage-scanner/internal/agentbus/bus_test.go`(Names + 失败事件)

**Interfaces:**
- Produces: `(*agentbus.Bus).Names() []string` — 已注册 agent 名的有序列表

**背景:** spec §4.3。72 次询问 0 成功，模型编了 `fact-layer`、`Investigator`、`CryptoAnalyzer` 等名字，连真实存在的 `expert-001` 也够不着（它写 `Expert`）。失败只作为散文回灌，不产生事件。

- [ ] **Step 1: 写失败的测试**

`internal/agentbus/bus_test.go` 追加：

```go
// 模型必须能被告知有哪些 agent 存在,否则它只能猜——跨 6 次运行 72 次询问
// 全部失败于编造的名字。actions.Registry.Names() 是同一代码库里的模板。
func TestBus_NamesListsRegisteredAgents(t *testing.T) {
	b := New(3)
	b.Register("expert-001", func(context.Context, Query) (Response, error) { return Response{}, nil })
	b.Register("challenger-001", func(context.Context, Query) (Response, error) { return Response{}, nil })

	got := b.Names()
	if len(got) != 2 || got[0] != "challenger-001" || got[1] != "expert-001" {
		t.Fatalf("Names() = %v, want a sorted [challenger-001 expert-001]", got)
	}
}
```

- [ ] **Step 2: 运行,确认失败**

Run: `cd tee-usage-scanner && go test -run TestBus_Names ./internal/agentbus/`
Expected: FAIL — `b.Names undefined`

- [ ] **Step 3: 实现 Names()**

`internal/agentbus/bus.go`：

```go
// Names returns the sorted list of registered agent names. The arbiter
// renders it into its prompt: to_agent is a closed vocabulary, and a model
// that cannot see it can only guess. Across six runs it guessed 72 times and
// was right zero times, reaching for "fact-layer", "Investigator" and
// "CryptoAnalyzer" — and missing the real "expert-001" by writing "Expert".
func (b *Bus) Names() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.handlers))
	for name := range b.handlers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
```

- [ ] **Step 4: 把词表渲进 arbiter 的 prompt**

`internal/arbiter/run.go:224` 当前是：

```go
- queries: array of objects (optional, each with: to_agent, kind, question)
```

改为把 `bus.Names()` 渲进去（bus 已经在 `RunWithBus` 的参数里）：

```go
fmt.Sprintf("- queries: array of objects (optional, each with: to_agent, kind, question). "+
	"to_agent MUST be one of: %s — any other value is rejected and the query is lost.",
	strings.Join(bus.Names(), ", "))
```

- [ ] **Step 5: 让被拒绝的询问产生事件 —— 落点在 bus,不在 arbiter**

**预检发现的修正:** `internal/arbiter/run.go` 全文**零处** `events.`——它拿不到 recorder，`arbitrateLLM` 的签名里也没有 cfg。在那里发事件需要先改签名。

更好的落点是 `bus.AskForCase` 自身：失败发生在 `agentbus/bus.go:60`，bus 同时知道 from/to 两个名字，而且 `AskForCase` 有**三个**调用者——`arbiter/run.go:387`、`verifier/run.go:325`、`feedback/run.go:245`。在 bus 里发一次，三处全覆盖；在 arbiter 里发，只覆盖一处还要改三个签名。

`internal/events/event.go` 增加：

```go
const TypeBusQueryFailed = "bus_query_failed"

func BusQueryFailed(runID, fromAgent, toAgent, reason string) Event { ... }
```

`internal/agentbus/bus.go` 给 Bus 加一个可选 recorder（零值时不发事件，保持 `New(maxRounds)` 对现有测试的兼容），并在两条失败路径上发：

```go
	if !ok {
		b.emitFailed(q.FromAgent, q.ToAgent, "unknown agent")
		return Response{}, fmt.Errorf("unknown agent: %s", q.ToAgent)
	}
```

以及 handler 返回错误的那条路径（`bus.go:64`）。

`pipeline/run.go:255` 的 `buildPipelineBus(cfg, forAgent)` 增加 recorder 参数——`rec` 在该处已在作用域内（`:142` 就在用它发 `RunStarted`）。

- [ ] **Step 6: 写失败事件的测试**

`internal/agentbus/bus_test.go` 追加：

```go
// 一次打向不存在 agent 的询问,必须在事件流里留下痕迹。在此之前它只作为
// 一句散文回灌进下一轮 prompt——两次运行停在 needs_review 的自述理由
// ("follow-up queries failed (agents unavailable)")在 events.jsonl 里完全不可见,
// 跨 6 次运行 72 次失败一条记录都没有。
func TestBus_UnknownAgentEmitsFailureEvent(t *testing.T) {
	rec := eventstest.NewRecorder(t)     // 按 internal/events/eventstest 现有形状
	b := NewWithRecorder(3, rec, "run-1")
	b.Register("expert-001", okHandler)

	_, err := b.AskForCase(context.Background(), "case-001", Query{
		FromAgent: "arbiter-001", ToAgent: "fact-layer", Question: "?"})
	if err == nil {
		t.Fatal("unknown agent must error")
	}
	ev := rec.OfType("bus_query_failed")
	if len(ev) != 1 {
		t.Fatalf("want exactly one bus_query_failed, got %d", len(ev))
	}
	if ev[0].ToAgent != "fact-layer" || ev[0].FromAgent != "arbiter-001" {
		t.Errorf("event must name both ends: %+v", ev[0])
	}
}

// 没有 recorder 的 Bus 必须照常工作——现有测试全部用 New(maxRounds)。
func TestBus_NilRecorderIsSafe(t *testing.T) { ... }
```

- [ ] **Step 7: 运行 + Fire drill**

Run: `cd tee-usage-scanner && go test -count=1 ./internal/agentbus/ ./internal/arbiter/ ./internal/events/`
Expected: ok

Fire drill：注释掉 `Emit(events.BusQueryFailed(...))`，确认 `TestArbiter_RejectedBusQueryEmitsEvent` 变红，还原。

- [ ] **Step 8: Commit**

```bash
git add tee-usage-scanner/internal/agentbus/ tee-usage-scanner/internal/arbiter/ tee-usage-scanner/internal/events/
git commit -m "agentbus,arbiter: publish the agent vocabulary and record refused queries"
```

---

### Task 3: 命中即触发 — 事实层的采集不再由模型决定

**Files:**
- Modify: `tee-usage-scanner/internal/pipeline/run.go`（`runL3Planner` 内,`planner.Run` 调用之前）
- Test: `tee-usage-scanner/internal/pipeline/prefetch_test.go`

**Interfaces:**
- Consumes: `twe.OperationFor`（Task 1）、`trustirfacts.RunAndPersist`（已存在）、`artifacts.ProjectInvariant.RelatedTWEs`
- Produces: 预取的 ToolFact 路径列表,注入 `planner.RunConfig`

**背景:** spec §6-A。ToolFact 是不可挑战的那一层；一条不可变事实有没有被采集，不该是采样结果。四次运行 1 次命中。

**触发点必须在 planner 之前。** `cases.Enrich` 在 `pipeline/run.go:239`，晚于 `l3_planner`（`:234`），所以 case pack 的 `related_twes` 用不上。planner 之前可用的是 `cfg.Invariants`（`internal/invariants/build.go` 产出，带 `RelatedTWEs`）。

- [ ] **Step 1: 写失败的测试**

`internal/pipeline/prefetch_test.go`：

```go
// 只要本次运行的 Invariant 关联到一个有可执行查询的 TWE,流水线就自己发这条
// 查询,不问模型。四次运行里模型只选中过一次;而这条查询在 CVE-2026-44362 上
// 两个修订都答对(漏洞版 1 条命中,修复版 0 条)。
func TestPrefetchFactLayer_FiresOnInvariantRelatedTWE(t *testing.T) {
	// invariants 含一条 RelatedTWEs: ["TWE-STATE-001"]
	// 用 fake trustirfacts.Engine(internal/trustirfacts/enginefake_test.go 的形状)
	// 断言:Engine 被调用一次,operation == "cpp.state.rollback_version_propagation"
	// 断言:返回的 ToolFact 路径出现在传给 planner 的 RunConfig 里
}

// 没有可执行查询的族不触发任何调用,也不产生 unsupported 的 ToolFact。
func TestPrefetchFactLayer_SkipsFamiliesWithoutAQuery(t *testing.T) {
	// invariants 只关联 TWE-FLOW-001
	// 断言:Engine 零调用
}
```

- [ ] **Step 2: 运行,确认失败**

Run: `cd tee-usage-scanner && go test -run TestPrefetchFactLayer ./internal/pipeline/`
Expected: FAIL

- [ ] **Step 3: 实现**

在 `runL3Planner` 里，构造 `planner.RunConfig` 之前：

```go
	// Collect the deterministic evidence this run's invariants call for,
	// before the planner starts. Whether an immutable fact gets collected
	// must not depend on the model's choice: across four runs on
	// CVE-2026-44362 the planner reached for the fact layer once, while the
	// query itself answers both revisions correctly (1 hit vulnerable, 0
	// fixed). The model still interprets the ToolFact — it just no longer
	// decides whether one exists.
	prefetched := prefetchFactLayer(ctx, eng, queryPackDir, cfg, invariants, exec)
```

`prefetchFactLayer` 遍历 `invariants[].RelatedTWEs`，对每个 `twe.OperationFor` 返回 true 的，调一次 `trustirfacts.RunAndPersist`，去重后返回路径列表。

- [ ] **Step 4: 把预取结果接进 planner**

`planner.RunConfig` 增加字段 `PrefetchedToolFactRefs []string`，在 `planner.go` 里与 `executedToolFactRefs` 合并（`ae0eeaf` 已经建好了 union 的位置）：

```go
	inv.ToolFactRefs = unionStrings(inv.ToolFactRefs,
		unionStrings(executedToolFactRefs, cfg.PrefetchedToolFactRefs))
```

- [ ] **Step 5: 让 planner 知道证据已经在手**

在 round prompt 里渲染已预取的 ToolFact 摘要（status + location_count + 路径），说明它**不必**再调 `fact_layer_query` 拿同样的东西。这是陈述事实，不是劝说——与 Global Constraints 里"prompt 只用于公开词表"一致。

- [ ] **Step 6: 运行 + Fire drill**

Run: `cd tee-usage-scanner && go test -count=1 ./internal/pipeline/ ./internal/planner/`
Expected: ok

Fire drill：把 `prefetchFactLayer` 的调用注释掉，确认两个新测试变红，还原。

- [ ] **Step 7: Commit**

```bash
git add tee-usage-scanner/internal/pipeline/ tee-usage-scanner/internal/planner/
git commit -m "pipeline: collect the fact layer's evidence instead of hoping the model asks"
```

---

### Task 4: 用完整仓库跑一次,而不是单文件 fixture

**Files:**
- Create: `teecheck-benchmark/datasets/CVE-2026-44362/README.md`（记录为什么用完整仓库）
- 无代码改动——这一步是测量

**背景:** spec §4.4。29/48 数据集只有 1 个文件；44362 的输入里没有 `check_update_version`。过去所有"没找到"的结论都是在它看不见题面时得出的。

- [ ] **Step 1: 准备两个完整 checkout**

```bash
cd /tmp && git clone https://github.com/OP-TEE/optee_os optee-vuln
cd optee-vuln && git checkout a9386bf987d95374a6f7f4c7bcf850115e0e1a4e
cd /tmp && cp -r optee-vuln optee-fixed
cd optee-fixed && git checkout 43ed01d216a9586e7e7591dff1f7fbf80923f93f
```

- [ ] **Step 2: 跑漏洞侧**

```bash
cd tee-usage-scanner
set -a && . ~/.teecheck.env && set +a
go run ./cmd/teecheck run /tmp/optee-vuln \
  --run-id 44362-vuln-fullrepo \
  --repo-url https://github.com/OP-TEE/optee_os \
  --commit a9386bf987d95374a6f7f4c7bcf850115e0e1a4e \
  --focus tee
```

记录：耗时、token、`fact_layer_query` 调用次数、`tool_fact_refs` 是否非空。

- [ ] **Step 3: 跑修复侧**

同上，`--run-id 44362-fixed-fullrepo`，commit `43ed01d2…`。

- [ ] **Step 4: 记录结果**

在 `README.md` 里写下两侧的：arbiter status、finding 提到 `subkey_version` / `key->version` 的次数、ToolFact 的 `locations`。

**不要在这一步下结论。** 数据先落盘。

---

### Task 5: paired gate — 让机器判卷

**Files:**
- Create: `teecheck-benchmark/gate/gate.go`
- Create: `teecheck-benchmark/gate/gate_test.go`
- Create: `teecheck-benchmark/cmd/gate/main.go`

**Interfaces:**
- Consumes: `runs/<id>/07_arbiter/findings.json`（JSON，不 import 扫描器的 Go 类型——两个模块之间无依赖，且这个边界保证 gate 只看扫描器**公开发布**的东西）
- Consumes: `datasets/<case>/oracle.yaml`

**背景:** spec §4.5、§6-B。

三层判定：

| 层 | 检查 | 数据来源 |
|---|---|---|
| ① | 扫的是不是那两个修订的那些文件 | `oracle.files[].vulnerable_sha256` / `fixed_sha256` |
| ② | 两侧状态组合是不是（漏洞侧报了，修复侧没报） | `findings[].status` |
| ③ | 报的是不是那个漏洞 | `findings[].files` ⊇ `oracle.primary_file`；证据文本覆盖 `oracle.required_evidence` 的关键实体 |

- [ ] **Step 1: 写失败的测试,用真实产物**

`gate_test.go` 用 `runs/44362-vulnerable-p1` 和 `runs/44362-fixed-p1` 的实际 `findings.json`（复制进 `testdata/`）：

```go
// 2026-07-30 那一对运行:两侧都是 needs_review,漏洞侧的 finding 讲的是
// shdr_verify_signature 的边界问题,一次都没提 subkey_version。gate 必须判 FAIL,
// 理由落在第 ③ 层——而不是因为状态组合。
func TestGate_2026_07_30_Pair_FailsOnEvidence(t *testing.T) {
	got := Evaluate(loadTestdata(t, "44362-vulnerable-p1"), loadTestdata(t, "44362-fixed-p1"), loadOracle(t, "CVE-2026-44362"))
	if got.Pass {
		t.Fatal("this pair must not pass")
	}
	if got.FailedLayer != 3 {
		t.Errorf("FailedLayer = %d, want 3 (evidence), not a status-combination failure", got.FailedLayer)
	}
	if !strings.Contains(got.Reason, "subkey_version") {
		t.Errorf("Reason must name the missing evidence entity: %s", got.Reason)
	}
}

// 一次真正的检出必须 PASS。用手写的合成产物,不用真实运行——目前没有任何一次
// 运行是 PASS 的,拿不到真样本。
func TestGate_SyntheticCorrectDetection_Passes(t *testing.T) { ... }

// 部分失败的批次不许被算成满分。
func TestGate_ErrorVariantIsNotScored(t *testing.T) { ... }
```

- [ ] **Step 2: 运行,确认失败**

Run: `cd teecheck-benchmark && go test ./gate/`
Expected: FAIL — `undefined: Evaluate`

- [ ] **Step 3: 实现三层判定**

第 ③ 层用**机械匹配**，不用 LLM：从 `oracle.required_evidence` 抽取代码实体（下划线标识符、`->` 字段访问、函数名），要求它们出现在 finding 的 `summary` + `evidence` 里。理由：确定性、免费、不会说谎；LLM 判官自己也会错，而现有 evaluator 的 243 行里根本没有 pass/fail 逻辑。

- [ ] **Step 4: 决定 `needs_review` 算不算检出**

`Evaluate` 需要一个明确规则。**建议:不算检出**——理由是 §4.1 里两次 `needs_review` 都伴随"证据链未完成"的自述，把它算作检出会让 gate 对"我不知道"给分。

把这个决定写进 `gate.go` 的文档注释，连同理由。

- [ ] **Step 5: CLI**

```bash
go run ./cmd/gate -vulnerable runs/44362-vuln-fullrepo -fixed runs/44362-fixed-fullrepo -oracle datasets/CVE-2026-44362/oracle.yaml
```

输出 PASS/FAIL + 逐层结果 + 理由。

- [ ] **Step 6: 对 Task 4 的运行跑一次 gate**

记录结果。这是第一个**会变红也会变绿**的数字。

- [ ] **Step 7: Commit**

```bash
cd teecheck-benchmark && git add gate/ cmd/gate/
git commit -m "gate: decide whether a paired run actually found the bug"
```

---

## Self-Review

**Spec coverage:**
- §6-A（采集不再是采样） → Task 1 + Task 3
- §6-B（机器判定） → Task 5
- §4.3（agent 词表 + 事件缺口） → Task 2
- §4.4（输入是仓库不是单文件） → Task 4
- §9 验收 1 → Task 3 + Task 4；验收 2 → Task 2；验收 3 → Task 5；验收 4 → 每个 Task 的 Step

**未覆盖且有意为之:** spec §7 的四项范围外内容；§5 表中第 10、11 处由 Task 1、2 覆盖。

**类型一致性:** `OperationFor` 返回 `(string, bool)`，Task 3 直接用；`PrefetchedToolFactRefs []string` 与 `ae0eeaf` 里已有的 `executedToolFactRefs []string` 同型，共用 `unionStrings`。

**已知薄弱处:** Task 2 Step 6 与 Task 5 Step 1/3 的测试体只写了断言意图，实现时需照现有测试的写法填充——比在这里写死一份可能与现有 harness 不符的代码好。

**顺序依赖:** Task 3 依赖 Task 1（要 `OperationFor`）。Task 5 的第 ① 层依赖 Task 4 产出的运行。Task 2 独立，可并行。
