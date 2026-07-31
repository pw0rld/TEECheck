# 安装 CodeQL(确定性事实层的执行引擎)

> 最后验证：2026-07-29,CodeQL 2.26.1,Linux x86_64
> 本文的每个数字都是在这台机器上实测的,不是估算 —— 估算的地方会写明。

---

## 0. 为什么需要它

TEECheck 的证据分三层:

| 层 | 谁产出 | 能否被挑战 |
|---|---|---|
| **ToolFact** | 确定性工具(CodeQL) | **不能** —— 它是事实 |
| AgentAssessment | LLM | 能 |
| HumanVerdict | 人 | 只能追加 |

没有 CodeQL,最底下这层是空的,所有 finding 都只有 LLM 的说法支撑。装上之后,`fact_layer_query` 这个 planner 动作才能真的返回 ToolFact 而不是 `status: unsupported`。

**注意范围**:装好引擎只解决一半。当前只有 **1 个 operation** 有可执行查询(`cpp.state.rollback_version_propagation`),TWE 目录里 19 条弱点类中其余 18 条的 `query_modules` 填的是规划中的模块名,`.ql` 文件尚未编写。ToolFact 自己会在 `coverage_gaps` 里如实声明这一点。

---

## 1. 资源需求(实测)

| 项 | 实测值 |
|---|---|
| 下载(`codeql-bundle-linux64.tar.zst`) | **551 MB** |
| 解压后磁盘占用 | **1.7 GB** |
| 建库:optee_os(41 MB 源码,`--build-mode=none`,`--threads=2`) | **1 分 38 秒**,产出 **262 MB** |
| 事实层端到端(clone + 建库 + 查询 + SARIF→ToolFact) | **118 秒** |
| 内存峰值 | 可用 6.0 GB → 5.8 GB(4 核 / 14 GB 机器,未吃紧) |

**磁盘规划**:引擎 1.7 GB 是一次性的。CodeQL 数据库是每个目标仓库一份,体积约为源码的 **6 倍**(optee_os 41 MB → 262 MB;这是单次观测,不同代码库差异很大)。**数据库用完要删**,否则扫几个真实项目就会吃掉几 GB。

**CPU/内存**:CodeQL 抽取 C/C++ 时吃内存。官方建议每核 ≥2 GB。4 核机器上建议 `--threads=2`,给扫描器和 LLM 请求留余量。

---

## 2. 安装步骤

### 2.1 先立护栏(重要,在下载之前做)

bundle 解压后 1.7 GB,且**内含单个超过 GitHub 100 MB 硬上限的二进制**。它是工具,不是项目代码,**绝不能提交进仓库**。

仓库根目录的 `.gitignore` 已包含:

```
/tools/
```

下载前先确认它生效:

```bash
cd <repo-root>
mkdir -p tools && touch tools/.probe
git check-ignore -v tools/.probe    # 应输出 .gitignore:<行号>:/tools/
rm tools/.probe
```

`git check-ignore` 有输出才算数 —— `git status` 看着干净不等于规则生效。

### 2.2 下载并校验

```bash
cd <repo-root>/tools
VER=v2.26.1
BASE=https://github.com/github/codeql-action/releases/download/codeql-bundle-$VER

curl -fL --retry 3 -o codeql-bundle.tar.zst "$BASE/codeql-bundle-linux64.tar.zst"
curl -fsL -o expected.txt "$BASE/codeql-bundle-linux64.tar.zst.checksum.txt"

cat expected.txt
sha256sum codeql-bundle.tar.zst
```

两个 SHA256 必须一致。2.26.1 的期望值:

```
02cb5f5d2ae8332ffc65b889eac2c88a4b57f5c66c5ebddc90ebf1c24eefcf67
```

**为什么用 bundle 而不是纯 CLI**:纯 CLI(`codeql-linux64.zip`,526 MB)不含查询包,还要另外 `codeql pack download`。bundle 只大 25 MB 却自带 `codeql/cpp-all` 等标准包,`codeql/trustir/cpp/qlpack.yml` 依赖的正是 `codeql/cpp-all`,用 bundle 就不必联网拉包。

### 2.3 解压

本机 `tar` 不支持 `--zstd`,用管道:

```bash
zstd -dc codeql-bundle.tar.zst | tar -xf -
rm codeql-bundle.tar.zst expected.txt
du -sh codeql        # 应约 1.7G
```

### 2.4 放上 PATH

主流水线用 `codeql.New()`,它硬编码 `bin: "codeql"` 并走 PATH 查找(`internal/codeql/engine.go`),**没有配置项可以指定路径**。所以必须让 `codeql` 出现在 PATH 上。

```bash
ln -sf <repo-root>/tools/codeql/codeql /usr/local/bin/codeql
```

**不要**把 `export PATH=...` 写进 `~/.zshenv` 或 `~/.teecheck.env`。zsh 的加载顺序是 `.zshenv` → `.zprofile` → `.zshrc`,后面的 profile 会重设 PATH,写在前面的会被覆盖 —— 这个坑本文作者踩过。

### 2.5 验证

```bash
codeql --version        # CodeQL command-line toolchain release 2.26.1.
```

再从**生产代码路径**验证一次,而不是只看命令行:

```bash
cd <repo-root>/tee-usage-scanner
cat > /tmp/avail_test.go <<'EOF'
package codeql
import "testing"
func TestProbe(t *testing.T) { t.Logf("Available() = %v", New().Available()) }
EOF
cp /tmp/avail_test.go internal/codeql/zz_avail_test.go
go test -run TestProbe -v ./internal/codeql/     # 应输出 Available() = true
rm internal/codeql/zz_avail_test.go
```

`command -v codeql` 成功但 `Available()` 返回 false 是可能的 —— 两者查的 PATH 未必相同(测试进程从 profile 继承环境)。以后者为准。

---

## 3. 端到端验证事实层

装好引擎不代表管道通。下面这一步真的跑一次 clone → 建库 → 查询 → ToolFact,约 **2 分钟**。

事实表(`internal/trustirfacts/facttable.go` 的 `knownFactTables`)目前只有一个条目:`github.com/op-tee/optee_os`。所以验证必须用这个仓库。

```bash
cd <repo-root>/tee-usage-scanner
cat > internal/trustirfacts/zz_live_test.go <<'EOF'
package trustirfacts

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

func TestLive_FactLayerEndToEnd(t *testing.T) {
	runDir := "/tmp/factprobe"
	os.RemoveAll(runDir)
	os.MkdirAll(runDir, 0o755)

	rec, err := events.NewJSONLRecorder(runDir + "/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := events.NewBlobStore(runDir + "/blobs")
	if err != nil {
		t.Fatal(err)
	}
	exec := &executor.LocalExecutor{Recorder: rec, Blobs: blobs}

	// NOTE: codeql.New() alone leaves the CodeQL subprocesses unrecorded.
	// Production wires an executor onto the Engine — see newFactEngine in
	// internal/pipeline/run.go. Request.Exec below only covers this
	// package's own git clone/checkout.
	eng := codeql.New()
	eng.Exec = executor.Bind(exec, executor.Binding{RunID: "factprobe", Agent: "probe"})

	fact, err := Run(context.Background(), eng, Request{
		RunDir:       runDir,
		Repository:   "https://github.com/OP-TEE/optee_os",
		Commit:       "HEAD",
		Operation:    OperationRollbackVersionPropagation,
		QueryPackDir: "../../codeql/trustir/cpp",
		Exec:         exec,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	b, _ := json.MarshalIndent(fact, "", "  ")
	t.Logf("ToolFact:\n%s", string(b))
}
EOF
go test -count=1 -run TestLive_FactLayerEndToEnd -v -timeout 40m ./internal/trustirfacts/
rm internal/trustirfacts/zz_live_test.go
```

### 该看到什么

```json
"status": "success",
"fact_id": "trustir-cpp-cpp.state.rollback_version_propagation-a1ead1e1dd8821da",
"arguments_sha256": "a1ead1e1dd8821da...",
"coverage_gaps": [ 4 条 ]
```

`status` 是 `success` 而不是 `unsupported`,就说明管道通了。`fact_id` 的后缀即 `arguments_sha256` 的前缀 —— 内容寻址,相同输入必然得到相同 fact_id。

### 关键:`locations` 应该是空的

这条查询找的是"声称生产者**没有**写回滚字段"。optee_os 的 HEAD 是**修复版**,`core/crypto/signed_hdr.c` 里 `shdr_load_pub_key` 确实写了:

```c
key->version = subkey->subkey_version;
```

所以 `not writesOutputField(...)` 不成立,**命中 0 条,`locations` 因 `omitempty` 而不出现在 JSON 里**。

**这是正确结果,不是失败。** 如果修复版反而报出了 `shdr_load_pub_key`,说明查询或事实表有问题。要看到阳性结果,需要 checkout 到 CVE-2026-44362 的漏洞前修订。

### 顺带验证物化是否正确

```bash
cat /tmp/factprobe/02_tool_facts/trustir/querypack/*/common/GeneratedTrustFacts.qll
```

应看到 Go 里的事实表被准确渲染成 QL 谓词:

```ql
f.getName() = "shdr_load_pub_key" and role = "security_version"
field = "version"
c.getTarget().getName() = "check_update_version" and kind = "state_restore_acceptance"
```

这一步证明 `FactTable.Render()` 生效 —— 事实表只声明"谁是生产者、哪个字段是回滚字段",**不含漏洞逻辑**;漏没漏由真实代码结构决定。同一份事实表在漏洞版和修复版上逐字节相同,这正是差分能成立的原因。

---

## 4. 清理

数据库和克隆的源码会累积,用完删掉:

```bash
rm -rf /tmp/factprobe
rm -rf <repo-root>/tools/optee_os <repo-root>/tools/optee_db
```

引擎本身(`tools/codeql`,1.7 GB)保留。

---

## 5. 已知问题

1. **主流水线没有 CodeQL 路径的配置项。** `codeql.New()` 只查 PATH。`NewWithBin` 存在,`cmd/twescan` 也有 `--bundle` flag,但 `internal/pipeline/run.go` 用的是 `New()`。应补一个 `--codeql-bin` / `TEECHECK_CODEQL_BIN`,与 `--llm-max-tokens` 同类。
2. **只有 1 个 operation 可执行。** `internal/trustirfacts/request.go` 的 `operationQueries` 只映射了 `OperationRollbackVersionPropagation`。
3. **事实表只有 1 个仓库条目。** `knownFactTables` 只认 `github.com/op-tee/optee_os`;其余仓库走 `StatusUnsupported`。LLM 标注管道(§23.2)尚未建成。
4. **SARIF 位置不含符号名。** `internal/codeql` 的 `ParseSARIF` 未实现 related-location 解析,ToolFact 的 `Locations` 里 `Symbol` 为空。
5. **`--build-mode=none` 不做真实构建。** 宏与 `#ifdef` 分支按源码默认值解析,与某个具体 target 的实际编译结果可能不同。

以上第 2–5 条,ToolFact 会在自己的 `coverage_gaps` 里逐条声明,不会静默。
