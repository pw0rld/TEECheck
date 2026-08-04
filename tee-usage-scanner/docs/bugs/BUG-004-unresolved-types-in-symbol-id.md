# BUG-004：未解析类型进入 SymbolID，Planner 无法可靠引用一个函数

> 状态：**根因已确认（实测）/ 部分缓解，处置待决策**
> 记录日期：2026-08-04
> 影响：Program Index 的符号身份、Planner 的浏览动作、reconnaissance gate 能否完成
> 代表运行：`runs/recon-001`（OP-TEE `a9386bf987d95374a6f7f4c7bcf850115e0e1a4e`，首次真实全仓运行）
> 路径以 `tee-usage-scanner/` 为基准
>
> 已修：拒绝信息现在会指出"你发来的是某些已有 id 的前缀"并列出候选（commit `0972f72`）。
> 未修：`error` / `<error-type>` 仍然出现在 SymbolID 里，见 §7。
>
> **2026-08-04 根因修订**：初稿写的是"build-mode=none 没有 include 路径"。实测推翻 ——
> 12163 条 `#include` 全部解析成功，但 `<stdbool.h>` 解析到了 C++ TR1 转发头、
> `<stddef.h>` 解析到了不含 `size_t` 的 Linux UAPI 头。见 §4.3。

---

## 1. 一句话症状

**CodeQL 在 `--build-mode=none` 下把 `<stdbool.h>` / `<stddef.h>` 解析到宿主机上不适用的头文件，导致 14% 的参数类型解析失败、被记为 `ErroneousType`；这个类型的字符串形式（`error` / `<error-type>`）经由函数签名进入 `SymbolID`，而 `SymbolID` 是 Planner 引用一个函数的唯一方式。于是 28% 的符号 id 里带着看起来像噪音的 token，模型倾向于把它裁掉，裁掉后的 id 不存在，动作被拒绝。**

在 `runs/recon-001` 中，这条链导致 `get_callers` 一次都没有成功执行 —— 而它是 reconnaissance gate 唯一的关系查询要求。

---

## 2. 链路：从源码到 prompt

```text
源码
  core/tee/fs_dirfile.c:124
  TEE_Result tee_fs_dirfile_open(bool create, uint8_t *hash, ...)
        │
        │  codeql database create --build-mode=none
        │  （include 解析到了宿主机的错误头文件：见 §4）
        ▼
CodeQL 数据库
  <stdbool.h> 解析到 /usr/include/c++/10/tr1/stdbool.h（C++ 转发头，
  对 C 文件不定义 bool）→ 参数 create 的类型成为 ErroneousType
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
这是线索：失败的不是难解析的类型，而是本该最容易解析的那些 —— 见 §4.3。

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

## 4. 根因：include 解析到了错误的头文件

初稿把根因写成"`--build-mode=none` 没有 include 搜索路径，头文件找不到"。**这是错的。**
实测表明头文件全部找得到 —— 找到的是**不适用的那一份**。

### 4.1 现象规模

`ErroneousType` 有两种字符串形式，取决于它出现在什么位置：

| 形式 | 出现位置 | 计数 |
|---|---|---|
| `error` | 直接作为参数类型 | 2695 个 id |
| `<error-type>` | 作为指针/数组的元素类型，如 `const <error-type> *` | 997 个 id |
| 合计（去重） | | **3242 个 id，占 11603 的 27.9%** |

数据库级统计：

```text
已定义函数的参数总数            25265
类型为 ErroneousType 的         3520   (13.9%)
类型为 UnknownType 的               0
```

### 4.2 数据库里有 38708 个编译错误

```ql
from string msg, int n
where n = strictcount(CompilerError e | e.getMessage() = msg | e) and n > 20
select msg, n order by n desc
```

```text
compiler errors                 38708
files with >=1 compiler error    1878   (2707 个文件中的 69%)

identifier 'size_t' is undefined                 7005
identifier 'NULL' is undefined                   3325
identifier 'true' is undefined                   2828
identifier 'uint32_t' is undefined               2544
There was an error during this compilation       1692
expected a ';'                                   1689
identifier 'uint8_t' is undefined                1510
identifier 'bool' is undefined                   1184
identifier 'false' is undefined                  1011
variable 'bool' is not a type name                947
```

`parameters typed 'bool'` 和 `parameters typed 'size_t'` 在整个数据库里都是 **0**。

### 4.3 但 include 全部解析成功了

```text
#include directives seen           12163
#includes that resolved to a file  12163      ← 100%
files named stdbool.h in db            1
files named stddef.h  in db            1
```

一个都没缺。问题在于**解析到了哪里**：

```ql
from string included, string target, int n
where n = strictcount(Include i |
      i.getIncludeText().regexpMatch("[<\"](stdbool|stddef|stdint|string)\\.h[>\"]") and
      included = i.getIncludeText() and target = i.getIncludedFile().getAbsolutePath() | i)
select included, target, n order by n desc
```

```text
| <stdint.h>  | <src>/lib/libutils/isoc/include/stdint.h        | 557 |   ← 正确
| <stdbool.h> | /usr/include/c++/10/tr1/stdbool.h               | 310 |   ← 错误
| <string.h>  | <src>/lib/libutils/isoc/include/string.h        | 224 |   ← 正确
| <string.h>  | /usr/include/linux/string.h                     | 165 |   ← 错误
| <stdint.h>  | /usr/include/c++/10/tr1/stdint.h                | 125 |   ← 错误
| <stddef.h>  | /usr/include/linux/stddef.h                     | 100 |   ← 错误
| <stdint.h>  | /usr/lib/gcc/.../include/stdint.h               |   4 |
```

两个致命的：

- **`/usr/include/c++/10/tr1/stdbool.h`** 是 C++ TR1 的转发头，内容只有
  `#include <tr1/cstdbool>`。对一个 C 文件，它什么都不定义 —— 所以
  `identifier 'bool' is undefined` 出现 1184 次。
- **`/usr/include/linux/stddef.h`** 是 Linux UAPI 头，`grep -c size_t` 返回
  **0**。所以 `identifier 'size_t' is undefined` 出现 7005 次。

CodeQL 在 `build-mode=none` 下搜索的是**宿主机**的 include 目录。OP-TEE 是
freestanding 的 ARM 安全内核，它自己的构建恰恰用 `-nostdinc` 把这些目录排除掉：

```make
# mk/clang.mk:28
nostdinc$(sm) := -nostdinc -isystem $(shell $(CC$(sm)) -print-file-name=include)
# mk/compile.mk:118, 202, 273 —— 每条编译规则都带上它，外加 -ffreestanding
```

**所以这不是"没有 include 路径"，是"用了一套被目标项目明确排除的 include 路径"。**
后者更糟：它不会报"找不到文件"，而是安静地产出错误的类型。

### 4.4 CodeQL 的三种 build mode，全部实测

`tools/codeql/cpp/codeql-extractor.yml` 声明抽取器支持三种：

```yaml
build_modes:
  - autobuild
  - manual
  - none
```

以下全部对同一棵 pinned checkout（`a9386bf`，3292 文件）执行。

#### `autobuild` —— 失败，需要交叉编译器

```bash
codeql database create <out> --language=cpp --build-mode=autobuild --source-root=<src>
```

autobuilder 找到了 OP-TEE 的 Makefile 并真的跑了 `make`，默认选中
`PLATFORM=vexpress`，走到第一个编译动作才失败：

```text
cpp/autobuilder: trying to run make
  CHK     out/arm-plat-vexpress/conf.mk
  CHK     out/arm-plat-vexpress/include/generated/conf.h      ← 生成成功
  CC      out/arm-plat-vexpress/core/include/generated/.asm-defines.s
/usr/bin/bash: arm-linux-gnueabihf-gcc: 未找到命令
make: *** [mk/compile.mk:252] 错误 127
cpp/autobuilder: No supported build command succeeded.
A fatal error occurred: Exit status 1
```

耗时 7 秒，**数据库未创建**。

两个副产品值得记下：

1. **`make` 不需要交叉编译器就能生成 `include/generated/conf.h`**（366 行，742 个
   `CFG_*` 的取值）。这推翻了本文初稿对方案 B 失败原因的解释 —— 见下。
2. autobuild 会在源码树里留下 `out/`（6.0 MB）和 `_codeql_detected_source_root`。
   **它污染的是整个 run 都在读的那棵 pinned checkout**，用完必须清理。

#### `manual` —— 未执行，前提缺失

```bash
codeql database create <out> --language=cpp --build-mode=manual \
  --command="make PLATFORM=vexpress-qemu_virt"
```

本机一个交叉编译器都没有：

```text
aarch64-none-elf-gcc      -
aarch64-linux-gnu-gcc     -
arm-none-eabi-gcc         -
arm-linux-gnueabihf-gcc   -
```

即便装上，代价见 §4.5。

#### `none` —— 当前采用，试了四种参数组合

**基线（现状）**：建库成功，3520 个 `ErroneousType`，38708 条编译错误。

**变体 1：追加 `-I`** —— 建库成功，**几乎无效**：

```text
ErroneousType                          3520 → 3492   (-28，0.8%)
<stdbool.h> 解析到 gcc 正确头的次数        0 → 3      (仍有 310 走 tr1)
建库耗时                                        1m43s
```

选项确实生效了（gcc 的 `stdbool.h` 第一次进库），但 CodeQL 自己的搜索顺序压过它。
`core/tee/fs_dirfile.c` 的四个 `error` 参数一个都没变。

**变体 2：`-nostdinc`**（照抄 OP-TEE 自己的编译标志）—— **抽取为 0**。

**变体 3：`-include <生成的 conf.h>`** —— **抽取为 0**。

**变体 4：`-ffreestanding`** —— **抽取为 0**。

失败信息都是同一句：

```text
CodeQL detected code written in C/C++ but could not process any of it
using the 'none' build mode.
```

逐个隔离测试后确认，三个标志**各自单独**就足以让抽取归零：

| frontend_options | 建库结果 |
|---|---|
| （无） | 成功 |
| `-I<任意路径>` | 成功 |
| `-nostdinc` | **抽取为 0** |
| `-ffreestanding` | **抽取为 0** |
| `-include<file>` | **抽取为 0** |

也就是说：**`build-mode=none` 只接受 `-I` 这类纯追加式的选项。**任何改变头文件
搜索基准或预置内容的标志都会让它整个停摆。而 `-I` 恰恰是唯一无法覆盖
`<stdbool.h>` 已经解析到 tr1 的那一条 —— 能用的没用，有用的不能用。

本文初稿把变体 2 的失败归因于"缺 `generated/conf.h`"。那个解释是错的：`conf.h`
可以由 `make` 单独生成（见上），补上之后（变体 3）抽取仍然为 0，而且 `-include`
本身就是致命项。

### 4.5 `manual` traced build 不是纯粹的升级

即便装上交叉编译器，`manual` 也有实质代价：

| | `build-mode=none`（现状） | `manual` traced build |
|---|---|---|
| 覆盖 | 全仓 3292 文件、11603 定义 | 仅该配置实际编译到的文件 |
| 类型 | 14% 参数解析失败 | 全部正确 |
| 平台 | 40 个 `core/arch/arm/plat-*` 全在 | 40 选 1 |
| 条件编译 | 742 个 `CFG_*` 全走默认分支 | 仅该配置为真的分支 |
| §7 负面证据阶梯 | 最高 `not_found_in_indexed_repository` | 可达 `proved_unreachable_under_build_target` |

`repo_facts.capabilities.build_reachability` 报 `unavailable` 正是因为这一点。
**traced build 是取得那一级证据的唯一途径**，但索引会从"全都有、类型不准"
变成"一个配置、类型准确"。

对当前阶段（Planner 做 reconnaissance，需要"这个项目由哪些部分组成"）覆盖面更
重要；对将来要证明"某路径在某构建目标下不可达"时，traced build 是必需的。
两者不是二选一 —— 可以按需要各建一个库。

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

§4.4 的实测把选项收窄了：**方案 A（追加 `-I`）无效，方案 B（`-nostdinc`）会让抽取归零。**
剩下三条，互不排斥。

**C1. 把抽取质量写进 `repo_facts.index_note`（建议先做）**

索引自己知道它有 1878 个文件解析出过错、38708 条编译错误，但 `index_note` 现在是
空字符串。消费者因此无从判断"这个索引的类型信息有多可信" —— 这次是人工跑探针
查询才发现的。

`internal/repoindex` 应当在建库后读取 `CompilerError` 计数，写成类似：

```json
"index_note": "38708 extraction errors across 1878 of 2707 files; 13.9% of
parameter types on defined functions did not resolve. Signatures in symbol_id
may contain 'error' or '<error-type>' where a type could not be determined.
Type information is unreliable; structure (definitions, call edges) is not
affected."
```

结构信息（定义、调用边、字段访问）**不受影响** —— 那些不依赖类型解析。受影响的
只有签名里的类型名。这个区分必须写清楚，否则读者会把整个索引都打折。

**C2. 签名里把 `ErroneousType` 渲染成 `?`（推荐，证据已足）**

改 `codeql/index/cpp/Symbols.ql`，不再直接用 `getParameterString()`，自己拼参数串，
遇到 `ErroneousType` 输出 `?`。

§4.3 让这条的理由从"好看一点"变成"不撒谎"：`error` 会被读成"有个类型叫 error"，
而事实是"这个 translation unit 的 include 解析错了，类型未知"。`?` 说的是后者。

- 代价：**所有 SymbolID 的字面值都会变**，已有 run 的索引与引用全部失效，必须重建。
- 因此适合与任何一次需要重建索引的改动一起做。

**C3. 为需要 build reachability 的场景另建一个 `manual` traced 库**

不替换现有的 none 库，而是**并存**（§4.5）：none 库负责覆盖面，traced 库负责
"某路径在某构建目标下是否可达"。前提是装交叉编译器并选定 `PLATFORM=`。

在 §7 负面证据阶梯上，`proved_unreachable_under_build_target` 只有 traced 库能给。
现在 `capabilities.build_reachability` 报 `unavailable` 就是这个原因，而那是诚实的。

**已否决**

| | 为什么 |
|---|---|
| `none` + 追加 `-I` 修复解析 | 实测 3520 → 3492，CodeQL 自身搜索顺序压过它（§4.4） |
| `none` + `-nostdinc` / `-ffreestanding` / `-include` | 三者各自单独就让抽取归零（§4.4） |
| `autobuild` | 跑到第一个编译动作即失败，需要交叉编译器（§4.4） |
| 用 `manual` traced build 取代 `none` | 40 个平台只覆盖 1 个，742 个 `CFG_*` 只有一种取值（§4.5） |
| 从 id 里删掉签名 | 301 组定义会撞车（§6） |

**注**：`autobuild` 与 `manual` 都会在源码树里留下 `out/`（6.0 MB）和
`_codeql_detected_source_root`。那棵树是整个 run 共用的 pinned checkout，
如果将来接入这两种模式，`internal/codedb` 必须在建库后清理，否则下一个
stage 读到的树和 `source_scope_resolved` 记录的不是同一个东西 —— 那正是
BUG-002 的形状。

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

复现 §4.2 的编译错误统计与 §4.3 的 include 去向（同一 qlpack）：

```ql
// 编译错误按消息聚合
import cpp
from string msg, int n
where n = strictcount(CompilerError e | e.getMessage() = msg | e) and n > 20
select msg, n order by n desc
```

```ql
// 标准头解析到了哪里
import cpp
from string included, string target, int n
where n = strictcount(Include i |
      i.getIncludeText().regexpMatch("[<\"](stdbool|stddef|stdint|string)\\.h[>\"]") and
      included = i.getIncludeText() and
      target = i.getIncludedFile().getAbsolutePath() | i)
select included, target, n order by n desc
```

复现 §4.4 方案 A（追加 `-I`，实测无效）与方案 B（`-nostdinc`，实测抽取归零）：

```bash
SRC=runs/recon-001/02_tool_facts/trustir/src/df16a35bfd62a0e59aec9b4e
GCCINC=$(ls -d /usr/lib/gcc/*/*/include | head -1)

# A：追加 include 路径 —— ErroneousType 3520 → 3492
codeql database create /tmp/db-A --language=cpp --build-mode=none --source-root=$SRC \
  -O cpp.frontend_options="-I$GCCINC" \
  -O cpp.frontend_options="-I$SRC/core/include" \
  -O cpp.frontend_options="-I$SRC/lib/libutils/ext/include" \
  -O cpp.frontend_options="-I$SRC/lib/libutils/isoc/include"

# B：照抄 OP-TEE 的 -nostdinc —— "could not process any of it"
codeql database create /tmp/db-B --language=cpp --build-mode=none --source-root=$SRC \
  -O cpp.frontend_options="-nostdinc" \
  -O cpp.frontend_options="-ffreestanding" \
  -O cpp.frontend_options="-isystem$GCCINC" \
  -O cpp.frontend_options="-I$SRC/core/include"
```
