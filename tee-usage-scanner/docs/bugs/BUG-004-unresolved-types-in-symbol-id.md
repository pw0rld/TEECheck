# BUG-004：未解析类型进入 SymbolID，Planner 无法可靠引用一个函数

> 状态：**已确认 / 部分缓解，根因待决策**
> 记录日期：2026-08-04
> 影响：Program Index 的符号身份、Planner 的浏览动作、reconnaissance gate 能否完成
> 代表运行：`runs/recon-001`（OP-TEE `a9386bf987d95374a6f7f4c7bcf850115e0e1a4e`，首次真实全仓运行）
> 路径以 `tee-usage-scanner/` 为基准
>
> 已修：拒绝信息现在会指出"你发来的是某些已有 id 的前缀"并列出候选（commit `0972f72`）。
> 未修：`error` / `<error-type>` 仍然出现在 SymbolID 里，见 §7。

---

## 1. 一句话症状

**CodeQL 在 `--build-mode=none` 下解析不出 14% 的参数类型，把它们记为 `ErroneousType`；这个类型的字符串形式（`error` / `<error-type>`）经由函数签名进入 `SymbolID`，而 `SymbolID` 是 Planner 引用一个函数的唯一方式。于是 28% 的符号 id 里带着看起来像噪音的 token，模型倾向于把它裁掉，裁掉后的 id 不存在，动作被拒绝。**

在 `runs/recon-001` 中，这条链导致 `get_callers` 一次都没有成功执行 —— 而它是 reconnaissance gate 唯一的关系查询要求。

---

## 2. 链路：从源码到 prompt

```text
源码
  core/tee/fs_dirfile.c:124
  TEE_Result tee_fs_dirfile_open(bool create, uint8_t *hash, ...)
        │
        │  codeql database create --build-mode=none
        │  （无 -I，无 -D：见 §4）
        ▼
CodeQL 数据库
  参数 create 的类型解析失败 → ErroneousType
  ErroneousType.toString() == "error"
        │
        │  codeql/index/cpp/Symbols.ql
        │  select ..., d.getFunction().getParameterString(), ...
        ▼
signature 列
  "(error create, uint8_t * hash, uint32_t min_counter, ...)"
        │
        │  internal/artifacts/index_types.go
        │  MakeSymbolID(lang, file, line, name, signature)
        │  = lang ":" file ":" line ":" name signature
        ▼
SymbolID
  cpp:core/tee/fs_dirfile.c:124:tee_fs_dirfile_open(error create, uint8_t * hash, ...)
        │
        │  internal/planner/actions/project_map.go
        │  list_functions / get_function_card / get_callers 打印 id
        ▼
Planner prompt
```

关键在于**签名是身份的一部分，不是附加说明**。`MakeSymbolID` 把它拼进 id，所以只要打印 id 就必然打印签名，也就必然打印 `error`。

---

## 3. 实测输入输出

### 3.1 源码（输入）

`core/tee/fs_dirfile.c`，pinned checkout `runs/recon-001/02_tool_facts/trustir/src/df16a35bfd62a0e59aec9b4e/`：

```c
111: static TEE_Result write_dent(struct tee_fs_dirfile_dirh *dirh, size_t n,
112:                              struct dirfile_entry *dent)

124: TEE_Result tee_fs_dirfile_open(bool create, uint8_t *hash, uint32_t min_counter,
125:                                const struct tee_fs_dirfile_operations *fops,
126:                                struct tee_fs_dirfile_dirh **dirh_ret)
```

### 3.2 CodeQL 抽取（输出）

对同一数据库运行探针查询：

```ql
from ErroneousType t, Parameter p, FunctionDeclarationEntry d
where p.getType() = t and d = definitionOf(p.getFunction()) and
      d.getFile().getRelativePath() = "core/tee/fs_dirfile.c"
select t.toString(), p.getName(), d.getFunction().getName(),
       d.getFunction().getParameterString()
```

```text
| error | n      | write_dent            | tee_fs_dirfile_dirh * dirh, error n, dirfile_entry * dent |
| error | create | tee_fs_dirfile_open   | error create, uint8_t * hash, uint32_t min_counter, ...  |
| error | oidlen | tee_fs_dirfile_rename | ..., const void * oid, error oidlen                       |
| error | oidlen | tee_fs_dirfile_find   | ..., const void * oid, error oidlen, ...                  |
```

对照 §3.1：

| CodeQL 抽出 | 源码实际 |
|---|---|
| `error n` | `size_t n` |
| `error create` | `bool create` |
| `error oidlen` | `size_t oidlen` |

**全部是标准库 typedef**（`stdbool.h` 的 `bool`、`stddef.h` 的 `size_t`），不是项目自定义的复杂类型。

### 3.3 Planner 读到的内容（输出）

`runs/recon-001` round 2，`list_functions {"module":"core/tee","page":0}`：

```text
core/tee — page 0 of 9, 43 function(s) on this page

write_dent  core/tee/fs_dirfile.c:111  id=cpp:core/tee/fs_dirfile.c:111:write_dent(tee_fs_dirfile_dirh * dirh, error n, dirfile_entry * dent)
    called by 4
    touches: tee_fs_dirfile_dirh.fh, tee_fs_dirfile_dirh.fops, tee_fs_dirfile_operations.write
tee_fs_dirfile_open  core/tee/fs_dirfile.c:124  id=cpp:core/tee/fs_dirfile.c:124:tee_fs_dirfile_open(error create, uint8_t * hash, uint32_t min_counter, const tee_fs_dirfile_operations * fops, tee_fs_dirfile_dirh ** dirh_ret)
    calls 9
    called by 1
    ...
```

round 4，`get_function_card`：

```text
tee_fs_dirfile_open  core/tee/fs_dirfile.c:124
module: core/tee
id: cpp:core/tee/fs_dirfile.c:124:tee_fs_dirfile_open(error create, uint8_t * hash, uint32_t min_counter, const tee_fs_dirfile_operations * fops, tee_fs_dirfile_dirh ** dirh_ret)

calls (direct_resolved_calls_only): cpp:core/tee/fs_dirfile.c:111:write_dent(tee_fs_dirfile_dirh * dirh, error n, dirfile_entry * dent), ...
```

### 3.4 模型的动作（输出）

round 4 用完整 id 成功打开卡片：

```json
{"symbol_id": "cpp:core/tee/fs_dirfile.c:124:tee_fs_dirfile_open(error create, uint8_t * hash, uint32_t min_counter, const tee_fs_dirfile_operations * fops, tee_fs_dirfile_dirh ** dirh_ret)"}
→ ok=true
```

round 5 对同一个函数问 caller，把括号整段去掉：

```json
{"symbol_id": "cpp:core/tee/fs_dirfile.c:124:tee_fs_dirfile_open"}
→ ok=false
```

### 3.5 拒绝信息（当时的输出）

```text
not_found_in_indexed_repository: "cpp:core/tee/fs_dirfile.c:124:tee_fs_dirfile_open"
is not in the program index. The index holds definitions the extractor could see;
a symbol absent here may still exist in a macro, in assembly, or in a translation
unit that was skipped. This is not evidence that it does not exist — use
find_symbols by name, or ripgrep.
```

拒绝**在事实上是正确的** —— 那个短 id 确实不在索引里。但它没有说出真正的问题（少了签名），所以模型没有恢复。同一轮它又用同样的短形式问了 `open_dirh`，同样被拒。

### 3.6 后果（输出）

`runs/recon-001/04_planner/coverage_ledger.json`：

```json
{
  "modules_total": 35,
  "modules_reviewed": 5,
  "function_capsules_total": 11603,
  "function_capsules_reviewed": 3,
  "leads_open": 0,
  "by_sample": [{
    "sample_index": 0,
    "recon_mode": "indexed",
    "recon_status": "recon_budget_exhausted",
    "capsules_reviewed": 3,
    "relation_queries_run": 0,
    "rounds_used": 6,
    "recon_rounds_used": 6,
    "leads_opened": 0
  }]
}
```

`relation_queries_run: 0`。reconnaissance gate 的五项要求里，"至少一次 `get_callers`" 是唯一一项**完全没有进展**的，它被这个 bug 挡住了。6 轮 reconnaissance 预算随后耗尽。

---

## 4. 根因

`internal/codedb/manager.go` 用 `--build-mode=none` 建库（§23.3 的既定决策：C 项目没有可靠的 build system 接入路径，spike 只证明了这一种模式可跑通）。这意味着抽取时：

- 没有 `-I` include 搜索路径；
- 没有 `-D` 宏定义。

`stdbool.h`、`stddef.h` 这些头文件找不到，`bool` 和 `size_t` 就没有声明。CodeQL 不会因此丢弃函数 —— 它保留函数，把无法解析的参数类型记为 `ErroneousType`。

`ErroneousType` 有两种字符串形式，取决于它出现在什么位置：

| 形式 | 出现位置 | 计数 |
|---|---|---|
| `error` | 直接作为参数类型 | 2695 个 id |
| `<error-type>` | 作为指针/数组的元素类型，如 `const <error-type> *` | 997 个 id |
| 合计（去重） | | **3242 个 id，占 11603 的 27.9%** |

数据库级统计（探针查询）：

```text
已定义函数的参数总数            25265
类型为 ErroneousType 的         3520   (13.9%)
类型为 UnknownType 的               0
```

---

## 5. 为什么模型会去裁它

这不能证明，但呈现方式明显在邀请这个动作，三个因素叠加：

**5.1 id 的前半段刚刚印过。** 行首是 `write_dent  core/tee/fs_dirfile.c:111`，紧接着 `id=cpp:core/tee/fs_dirfile.c:111:write_dent(...)`。看起来"完整、自成一体"的 `cpp:file:line:name` 恰好是重复的那部分，而括号里的东西读起来像是**附带打印的参数列表**。

**5.2 没有任何地方说签名属于 id。** 输出里没说；`get_function_card` / `get_callers` 的 arg schema（`internal/planner/prompt.go` 的 `actionArgSchemas`）也没说。

**5.3 签名里有明显的垃圾 token。** 28% 的 id 含 `error` 或 `<error-type>`。一个读起来不像类型的词，是会被当成噪音裁掉的。

规模上的佐证：

```text
SymbolID 长度        中位 96 B   p90 161 B   最长 488 B
全部 SymbolID 合计   1197 KiB，其中签名占 500 KiB (42%)
一页 list_functions  11149 B，其中 43 个 id 的签名占 2473 B (22%)
```

最长的一个：

```text
cpp:core/pta/veraison_attestation/cbor.c:305:generate_cbor_evidence(const char * eat_profile,
int psa_client_id, int psa_security_lifecycle, const <error-type> * psa_implementation_id,
error psa_implementation_id_len, const char * measurement_type, const <error-type> * signer_id,
error signer_id_len, ...)                                                          ← 488 字节
```

---

## 6. 签名不能直接删

最直觉的修法是把签名从 id 里去掉，只留 `lang:file:line:name`。**这会破坏身份**，实测：

```text
distinct 完整 SymbolID           11603
distinct lang:file:line:name     11302
去掉签名后会撞车的 id 组          301   (2.6%)
```

例子：

```text
2 x cpp:core/arch/arm/include/arm32.h:218:write_cpsr
2 x cpp:core/arch/arm/include/ffa.h:192:ffa_target_info_set
2 x cpp:core/arch/arm/include/kernel/tee_l2cc_mutex.h:41:tee_get_l2cc_mutex
```

头文件里的 `static inline`，同一文件同一行在不同编译配置下产生了两个签名不同的定义。删签名会把 301 组不同的定义合并成一个 —— 正是 `SymbolID` 当初存在的理由（见 `index_types.go` 中 `SymbolID` 的注释）。

---

## 7. 处置

### 7.1 已修：拒绝信息指出前缀匹配（commit `0972f72`）

`internal/planner/actions/project_map.go` 的 `unknownSymbolNote` 现在先检查这个 id 是不是已有 id 的前缀 —— 丢签名正好长这样 —— 是就把候选完整列出：

```text
not_found_in_indexed_repository: "cpp:core/tee/fs_dirfile.c:124:tee_fs_dirfile_open"
is not a complete symbol_id. A symbol_id is lang:file:line:name(signature), and the
signature is part of it — two definitions can agree on everything before it. 1 id(s)
in the index begin with what you sent:
  cpp:core/tee/fs_dirfile.c:124:tee_fs_dirfile_open(error create, uint8_t * hash, ...)
Ask again with one of these, copied exactly.
```

列出候选**不等于替它选**：多个定义共享前缀时全部列出，由调用方挑，和 `find_symbols` 同一套纪律。完全匹配不上的 id 保持原措辞，不会把模型送去找一个不存在的后缀。

测试：`TestBrowsingActions_ADroppedSignatureIsNamedAsSuch`、
`TestBrowsingActions_AnIdThatMatchesNothingSaysSoDifferently`，两者都做过 fire drill。

这**缓解**了症状，没有消除根因：id 里仍然有 `error`，仍然长，仍然重复。

### 7.2 待决策

三个方向，互不排斥：

**A. 签名里把 `ErroneousType` 渲染成 `?`**

改 `codeql/index/cpp/Symbols.ql`，不再直接用 `getParameterString()`，而是自己拼参数串，遇到 `ErroneousType` 输出 `?`。

- 好处：`?` 一看就是"没解析出来"，而 `error` 会被误读成一个真的叫 error 的类型；语义诚实。
- 代价：**所有 SymbolID 的字面值都会变**。已有 run 的索引、artifact 和引用全部失效，必须重建。

**B. 给 CodeQL 补 include 路径**

治本 —— 能拿到真实类型，`error` 从源头消失，签名也会短一些。

- 代价：要为每个项目配 `-I`，与 `--build-mode=none` 的初衷（不依赖项目构建系统）冲突。可能的折中：只补 libc 的标准头，覆盖 `bool` / `size_t` 这类占多数的情况。
- 需要先量化：单靠标准头能消掉多少比例的 3520 个 ErroneousType。

**C. 改打印格式，不改 id 本身**

停止 `name  file:line  id=lang:file:line:name(sig)` 这种前半段重复的写法；id 单独一行、明确标注整串都是身份。

- 好处：改动最小，不影响 id 字面值，不需要重建索引。
- 代价：`error` 仍在 id 里；治标。

**建议顺序：先 C（低风险、直接针对 §5.1/§5.2），再量化 B 的收益，A 留到需要重建索引的时机一并做。**

---

## 8. 与其他 bug 的关系

- **BUG-003**：本文的 Program Index 就是 BUG-003 §5.1 的产物。BUG-003 关心的是 01 阶段不要预判危险；本文关心的是它产出的身份**能不能被引用**。索引是中性的，但一个引用不了的中性事实等于没有。
- **BUG-002**：同样是"事实层和工具层看到的不是同一个东西"。BUG-002 是两棵源码树不一致；本文是同一棵树里，索引给出的身份和模型能复述的身份不一致。

---

## 9. 复现

```bash
cd tee-usage-scanner
./teecheck run https://github.com/OP-TEE/optee_os \
  --repo-url https://github.com/OP-TEE/optee_os \
  --commit a9386bf987d95374a6f7f4c7bcf850115e0e1a4e \
  --run-id recon-001 \
  --focus tee --output-dir runs --knowledge-root knowledge
```

统计 `error` token 的占比：

```bash
python3 - <<'EOF'
import json, re
caps = json.load(open('runs/recon-001/01_context/repo_facts.v1.json'))["capsules"]
bad = [c for c in caps
       if re.search(r'[(, ]error[ ,)]', c["symbol_id"]) or "<error-type>" in c["symbol_id"]]
print(f"{len(bad)} / {len(caps)} = {100*len(bad)/len(caps):.1f}%")
EOF
```

数据库级探针（`ErroneousType` 计数），置于一个带 `codeql/cpp-all` 依赖的 qlpack 中：

```ql
import cpp
import Index

from string bucket, int n
where
  bucket = "parameters total" and
  n = count(Parameter p | exists(definitionOf(p.getFunction())) | p)
  or
  bucket = "parameters whose type is ErroneousType" and
  n = count(Parameter p |
        p.getType() instanceof ErroneousType and exists(definitionOf(p.getFunction())) | p)
select bucket, n
```
