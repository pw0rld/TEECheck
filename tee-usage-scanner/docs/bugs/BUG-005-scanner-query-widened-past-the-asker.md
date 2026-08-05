# BUG-005：scanner 把提问拓宽成全仓匹配，四次收窄都无效，调查停在最后一环

> 状态：**已确认（实测）/ 未修**
> 记录日期：2026-08-05
> 影响：agent bus 的 `scanner-001`、Expert/Challenger/Verifier/Arbiter 的取证能力、finding 能否闭合
> 代表运行：`runs/recon-002`（OP-TEE `a9386bf987d95374a6f7f4c7bcf850115e0e1a4e`，首次跑完整条管线）
> 路径以 `tee-usage-scanner/` 为基准

---

## 1. 一句话症状

**下游四个 agent 没有自己的工具，取证全靠向 `scanner-001` 提问。`searchTerms` 按"长得像标识符"从自然语言里抽关键词，于是散文词 `ONLY`、`definition/body` 和泛用类型 `TEE_Result` 一并成为搜索项；关键词之间是 OR，一个宽项就淹没了精确项。Arbiter 连续四次收窄提问，最后一次明确写"不要包含任何其他词"，仍然拿回 65 KB–670 KB 的结果被截断在 32 KB。它要的那 3 行始终没到。**

结果：`recon-002` 的唯一 finding 停在 `needs_review`，卡在它自己指出的"攻击链最后一个缺失环节"上。

---

## 2. 实测输入输出

### 2.1 Arbiter 的四次提问（输入）

来自 `runs/recon-002/events.jsonl` 的 `bus_query` 事件：

```text
1. Locate all callers of tee_fs_htree_open across the codebase, especially in
   core/tee/tee_fs_*.c and secure-storage integration files. For each call site,
   identify what value is passed as the min_counter parameter ...

2. Locate the body of the function nv_counter_get_ree_fs() — likely in
   core/tee/tee_ree_fs.c or a related file. Show the full function body
   including what backing store it reads the counter from (RPMB write-counter,
   hardware fuse, REE file).

3. Search ONLY for the exact string 'nv_counter_get_ree_fs' (no other search
   terms) to find its function definition/body. Show the complete function body
   including what backing store it reads from.

4. Find the function definition using regex: 'TEE_Result nv_counter_get_ree_fs'.
   Do not include any other words in the search string.
```

第 3、4 次已经在**显式指示不要扩大范围**。

### 2.2 `searchTerms` 实际抽出的词（输出）

对同一批问题跑 `internal/pipeline.searchTerms`：

```text
问题 2 → ["REE" "RPMB" "core/tee/tee_ree_fs.c" "nv_counter_get_ree_fs"]
问题 3 → ["ONLY" "definition/body" "nv_counter_get_ree_fs"]
问题 4 → ["TEE_Result" "nv_counter_get_ree_fs"]
```

`ONLY` 和 `definition/body` 是**散文**，不是代码。它们进来是因为形状：

- `ONLY` 命中 `identifierRE` 的 `[A-Z]{2,}[A-Z0-9_]*` 分支（SCREAMING_CASE）；
- `definition/body` 命中 `[A-Za-z_][A-Za-z0-9_]*(?:[./][A-Za-z0-9_]+)+` 分支（路径形状），因为中间有一个斜杠。

`TEE_Result` 是真的标识符，但它是 OP-TEE 几乎每个函数的返回类型。

### 2.3 各词在仓库里的命中量（输出）

```bash
grep -rn --include='*.c' --include='*.h' <term> <pinned checkout> | wc -l
```

```text
nv_counter_get_ree_fs        3      ← 模型真正想要的
ONLY                       284
RPMB                       372
TEE_Result                6109      ← 同一次查询里的另一项
```

关键词之间是 OR（`staticcheck.CheckRequest.Keywords`），所以问题 4 的实际搜索是
`TEE_Result` ∪ `nv_counter_get_ree_fs` = 6109 + 3。

Arbiter 自己在 finding 里记下了它观察到的数量：**"the scanner capped results (6243 results ...)"** —— 和上面的量级吻合。

### 2.4 被截断的响应（输出）

`bus_response_truncated` 事件，6 次 bus 查询里 **5 次**触发：

```text
verifier-001 -> scanner-001   原始 670843 B   上限 32768 B
arbiter-001  -> scanner-001   原始  65599 B   上限 32768 B
arbiter-001  -> scanner-001   原始 669540 B   上限 32768 B
arbiter-001  -> scanner-001   原始 270566 B   上限 32768 B
arbiter-001  -> scanner-001   原始 563615 B   上限 32768 B
```

最小的一次是 32 KB 上限的 2 倍，最大的一次是 20 倍。

### 2.5 最终后果（输出）

`runs/recon-002/07_arbiter/findings.json`：

```text
status: needs_review   severity: low   confidence: high

"...Despite multiple targeted attempts, the scanner was unable to retrieve the
 body of nv_counter_get_ree_fs due to result capping and query parsing
 limitations... This case is held at needs_review solely to allow manual
 verification of the nv_counter_get_ree_fs function body, which is the final
 missing link in the attack chain."
```

它要的是 **3 行**。

---

## 3. 根因

`internal/pipeline/run.go` 注册的 `scanner-001` handler：

```go
terms := searchTerms(q.Question)
req := staticcheck.CheckRequest{RepoRoot: scannerRoot, Keywords: terms, ExtraArgs: scannerExtra}
findings, runErr := scReg.RunAll(ctx, req)
```

`searchTerms`（`internal/pipeline/scannerquery.go`）的判定标准是**词的形状**：

```go
// 匹配：路径形状 | snake_case | camelCase | SCREAMING_CASE
var identifierRE = regexp.MustCompile(
    `[A-Za-z_][A-Za-z0-9_]*(?:[./][A-Za-z0-9_]+)+|[A-Za-z_][A-Za-z0-9_]*_[A-Za-z0-9_]*|[a-z]+[A-Z][A-Za-z0-9]*|[A-Z]{2,}[A-Z0-9_]*`)
```

这个函数本身是一次修复的产物——它替换掉的 `strings.Fields(question)` 会把 `the` 和 `of` 也当关键词，那次产生了 80 MB 的回答。形状过滤把最坏情况挡住了，但留下两个缺口：

**缺口一：形状不等于意图。**英文里全大写的强调词（`ONLY`、`NOT`、`MUST`）和带斜杠的短语（`definition/body`、`and/or`）与代码标识符同形。提问者越是想强调"只搜这一个"，越容易写出这类词，**收窄的努力反而扩大了搜索**。

**缺口二：所有词等权。**`nv_counter_get_ree_fs`（3 行）和 `TEE_Result`（6109 行）在 `Keywords` 里没有区别。一个泛用类型足以让精确项在截断中消失。

截断本身是对的：`capResponse`（`internal/agentbus/cap.go`）保留 answer、按预算保留 facts，并附上明确提示——

```text
[PREVIEW ONLY — this answer was 563615 bytes and was capped at 32768.
 N of M results are NOT shown. Do not read the absence of a result here as
 evidence that it does not exist; the complete answer is recorded at sha256:...]
```

提示写得清楚，也确实emitted 了事件。**问题不在上限，在于送进去的搜索就是错的。**

---

## 4. 另一个背景事实：下游 agent 没有自己的工具

`recon-002` 全程 41 次 `tool_call_started`，按 agent 分：

```text
planner-001    27 次（六个浏览动作 + read_file + ripgrep + done + open_audit_lead）
repo-index     13 次（git clone/checkout、codeql database create/query/decode）
expert-001      0
challenger-001  0
verifier-001    0
arbiter-001     0
```

Expert、Challenger、Verifier、Arbiter 的**全部取证能力就是向 bus 提问**。所以 `scanner-001` 的检索质量直接决定这四个 agent 能不能闭合一条链——这次它决定了不能。

---

## 5. 处置建议

按代价排序，互不排斥。

**A. 让提问者能指定精确匹配（建议先做）**

`agentbus.Query` 已经有 `Kind` 字段，Arbiter 这四次分别用了 `code_search` 和 `regex_search`。handler 现在忽略它。让 `Kind == "regex_search"` 或引号内的内容走**逐字匹配、不做形状抽取**，模型第 3、4 次的收窄就会生效——它已经用对了协议，只是没人听。

**B. 词项按选择性排序，并报告被丢弃的项**

先用命中量最少的词搜；若结果仍超预算，回答里写明"`TEE_Result` 命中 6109 行，已从本次检索中排除"。现在被截断的是**结果**，更该被截断的是**过宽的词**——而且要说出来。

**C. 过滤英文强调词**

`ONLY`/`NOT`/`ALL`/`MUST` 这类词形状像 SCREAMING_CASE 但从不是代码。一份小的停用词表即可，且必须**带测试**，否则下一次换个词又漏。

**D. 给下游 agent 直接的浏览动作**

Planner 已经有 `find_symbols` / `get_function_card` / `get_callers`，它们接的是程序索引而不是文本搜索——`find_symbols("nv_counter_get_ree_fs")` 会直接返回定义及其 id，不存在 6109 行的问题。四个下游 agent 拿不到这些动作，只能退回文本检索。这是最彻底的修法，也是改动最大的。

---

## 6. 与其他 bug 的关系

- **BUG-002**：同样是"agent 看到的不是它以为的东西"。BUG-002 是 scanner 指向了错误的树；本文是它指向了正确的树，但检索被拓宽到无法使用。
- **BUG-004**：都由 `runs/recon-002` 暴露，都属于"工具的回答形状让模型无法完成本可完成的一步"。

---

## 7. 复现

```bash
cd tee-usage-scanner
# 事件里的四次提问与五次截断
python3 - <<'EOF'
import json
for line in open('runs/recon-002/events.jsonl'):
    e=json.loads(line)
    if e.get("type")=="bus_query":
        print(f"Q {e['agent']} -> {e['to_agent']} kind={e.get('kind')}: {e['question'][:120]}")
    if e.get("type")=="bus_response_truncated":
        print(f"  截断 {e['original_bytes']} B -> {e['max_output_bytes']} B")
EOF
```

`searchTerms` 的抽词结果（放一个临时测试进 `internal/pipeline`）：

```go
func TestProbeTerms(t *testing.T) {
	for _, q := range []string{
		"Search ONLY for the exact string 'nv_counter_get_ree_fs' (no other search terms) to find its function definition/body.",
		"Find the function definition using regex: 'TEE_Result nv_counter_get_ree_fs'. Do not include any other words in the search string.",
	} {
		t.Logf("terms = %q", searchTerms(q))
	}
}
```

```text
terms = ["ONLY" "definition/body" "nv_counter_get_ree_fs"]
terms = ["TEE_Result" "nv_counter_get_ree_fs"]
```

各词的命中量：

```bash
SRC=runs/recon-002/02_tool_facts/trustir/src/df16a35bfd62a0e59aec9b4e
for t in TEE_Result ONLY RPMB nv_counter_get_ree_fs; do
  printf "%-24s %s\n" "$t" "$(grep -rn --include='*.c' --include='*.h' "$t" $SRC | wc -l)"
done
```

```text
TEE_Result               6109
ONLY                      284
RPMB                      372
nv_counter_get_ree_fs       3
```
