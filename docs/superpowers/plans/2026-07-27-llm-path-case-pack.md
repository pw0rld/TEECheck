# llm 路径 Case Pack 生成 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 planner 在 llm 路径下直接产出 Case Pack（candidates 与 investigations 都转），使 playbook 经验字段首次真正到达 expert / challenger / verifier / arbiter；同时堵住 `filled_roles` 的幻觉符号，避免接通管道放大它。

**Architecture:** 新增 `internal/planner/casepacks.go` 承担 pack 构造、去重、编号、落盘；`internal/planner/shim.go` 的 `WriteHotspotShim` 从 llm 路径退休；`internal/cases` 拆成 `Run`（legacy 不变）与 `Enrich`（llm 只补 snippets/knowledge_hints）。新增 `internal/symbolcheck` 作为"声明的符号必须真出现在源码里"的单一实现点，由 `internal/investigations` 与 `internal/architecture` 共用。

**Tech Stack:** Go（标准库 + 仓内既有包），无新第三方依赖。

**Spec:** `docs/superpowers/specs/2026-07-27-llm-path-case-pack-design.md`（commit `d896c2e` + `56fc075` + 本次范围扩展）

---

## Global Constraints

以下要求对**每个任务**都生效：

1. **legacy 路径逐字节不变。** `internal/cases.Run` 的签名与行为、`pipeline/run.go:184` 那一分支、`internal/scanner`/`mapper`/`repomap`/`hotspots` 一律不改。
2. **不新增 `artifacts.CasePack` 字段。** CaseID 保留各生产者自设的值（investigation 派生的即 `inv-...`），仅文件名统一为 `case-%03d.json`。
3. **去重只在集合完全相等时发生。** 交集非空但不相等 ⇒ 不合并。
4. **`TargetFiles` 为空的 pack 不落盘。**
5. **符号校验只做整文件、大小写不敏感的子串包含**，不做行号邻近性检查，不加最小长度限制。
6. **不动** `internal/citations`、`internal/verifier`、`planner/prompt.go` 的上下文窗口、`planner/actions/legacy_keyword_scan.go`、硬编码的 `caseTemplate` 表本身。
7. **不重跑** flow / guard 对照测量（合入后单独进行）。
8. 每个任务结束时 `go build ./...` 与 `go test ./...` 在 `tee-usage-scanner` 模块内全绿；既有的 `internal/collabrun` live-endpoint 失败是已知例外。
9. 提交信息用英文，正文说明**为什么**这样改，不只是改了什么。

---

## File Structure

| 文件 | 职责 |
|---|---|
| `internal/symbolcheck/symbolcheck.go`（新） | 唯一的"声明符号是否出现在文件中"实现 |
| `internal/symbolcheck/symbolcheck_test.go`（新） | 同上单测 |
| `internal/investigations/validate.go`（改） | `validateRoleLocations` 追加符号校验 |
| `internal/architecture/validate.go`（改） | `:248-254` 改调 `symbolcheck`，`citedRegionContains` 不动 |
| `internal/planner/casepacks.go`（新） | `BuildFromCandidate` / `Merge` / `Write` |
| `internal/planner/casepacks_test.go`（新） | 去重、空目标、编号稳定性单测 |
| `internal/planner/planner.go`（改） | `processInvestigations` 不再自行写盘 |
| `internal/planner/shim.go`（改） | 删 `WriteHotspotShim` |
| `internal/cases/run.go`（改） | 新增 `Enrich`，`Run` 不动 |
| `internal/cases/enrich_test.go`（新） | `Enrich` 单测 |
| `internal/pipeline/run.go`（改） | `:159` 改调 `cases.Enrich` |
| `internal/pipeline/casepack_delivery_test.go`（新） | 消费者侧读回测试 |

任务顺序按依赖排：符号校验（1–2）→ pack 构造与去重（3）→ 接线（4–5）→ 端到端读回（6）。

---

## Task 1: `internal/symbolcheck` 包

**Files:**
- Create: `internal/symbolcheck/symbolcheck.go`
- Test: `internal/symbolcheck/symbolcheck_test.go`

**Interfaces:**
- Consumes: 无
- Produces: `func FileContainsSymbol(repoRoot, path, symbol string) (bool, error)` — 供 Task 2 与 Task 3 使用

- [ ] **Step 1: 写失败的测试**

`internal/symbolcheck/symbolcheck_test.go`：

```go
package symbolcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRepo(t *testing.T, rel, body string) string {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFileContainsSymbol_Present(t *testing.T) {
	root := writeRepo(t, "src/a.c", "int main(void) { return der_decode_sequence(); }\n")
	got, err := FileContainsSymbol(root, "src/a.c", "der_decode_sequence")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("want true for a symbol that is present")
	}
}

// The exact shape the 2026-07-27 audit found: a fabricated symbol that
// looks like a real one in the same file.
func TestFileContainsSymbol_AbsentLookalike(t *testing.T) {
	root := writeRepo(t, "src/a.c", "LTC_SET_ASN1(x);\nder_decode_sequence(y);\n")
	got, err := FileContainsSymbol(root, "src/a.c", "der_decode_sequence_flexi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("want false for a symbol that does not appear in the file")
	}
}

func TestFileContainsSymbol_CaseInsensitive(t *testing.T) {
	root := writeRepo(t, "src/a.c", "void TEE_Malloc(void);\n")
	got, err := FileContainsSymbol(root, "src/a.c", "tee_malloc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("want true — matching is case-insensitive")
	}
}

func TestFileContainsSymbol_AbsolutePath(t *testing.T) {
	root := writeRepo(t, "src/a.c", "int helper(void);\n")
	abs := filepath.Join(root, "src/a.c")
	got, err := FileContainsSymbol(root, abs, "helper")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("want true — an absolute path must not be re-joined to repoRoot")
	}
}

func TestFileContainsSymbol_MissingFile(t *testing.T) {
	root := t.TempDir()
	if _, err := FileContainsSymbol(root, "nope.c", "x"); err == nil {
		t.Fatal("want an error for a file that does not exist")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```
cd tee-usage-scanner && go test ./internal/symbolcheck/ -v
```
预期：编译失败，`undefined: FileContainsSymbol`

- [ ] **Step 3: 写实现**

`internal/symbolcheck/symbolcheck.go`：

```go
// Package symbolcheck answers one question, in one place: does a symbol a
// model claimed to have located actually appear in the source file it named?
//
// This is deliberately NOT part of internal/citations. That package's job
// stops at proving a byte range exists and hashes consistently; "does this
// content contain X" is a project-understanding-layer question (see the
// reasoning at internal/architecture/validate.go's citedRegionContains).
//
// It exists as a shared package rather than as a few lines inlined at each
// call site because three layers need the same answer — architecture model
// validation, TWE investigation role validation, and (next) verifier
// citation validation — and this project has already been bitten once by
// two places that were supposed to agree and did not.
package symbolcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FileContainsSymbol reports whether symbol occurs as a case-insensitive
// substring anywhere in repoRoot/path. An absolute path is used as-is.
//
// Whole-file containment is intentional. It provably catches the observed
// failure — a symbol that exists nowhere in the named file — without
// introducing an arbitrary "how many lines counts as near the declared
// line" constant. The cost is that a symbol present in the file but at a
// different line than declared still passes; that trade is recorded in the
// design doc's risk section.
func FileContainsSymbol(repoRoot, path, symbol string) (bool, error) {
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(repoRoot, path)
	}
	body, err := os.ReadFile(full)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	return strings.Contains(strings.ToLower(string(body)), strings.ToLower(symbol)), nil
}
```

- [ ] **Step 4: 运行测试确认通过**

```
cd tee-usage-scanner && go test ./internal/symbolcheck/ -v
```
预期：5 个测试全部 PASS

- [ ] **Step 5: 提交**

```bash
git add tee-usage-scanner/internal/symbolcheck/
git commit -m "symbolcheck: single implementation point for declared-symbol verification"
```

---

## Task 2: investigations 的角色符号校验 + architecture 改调共享包

**Files:**
- Modify: `internal/investigations/validate.go`（`validateRoleLocations`，当前在 :183）
- Modify: `internal/architecture/validate.go`（:248-254 那段）
- Test: `internal/investigations/validate_test.go`（追加）

**Interfaces:**
- Consumes: Task 1 的 `symbolcheck.FileContainsSymbol`
- Produces: `Adjustment{Kind: "unresolved_role_symbol"}` — 一个新的调整类别，与既有的 `"unresolved_role_location"` 并列

**已核实的既有签名（照抄，勿猜）：**

```go
// internal/investigations/validate.go:37
type Adjustment struct {
	InvestigationID string `json:"investigation_id"`
	Kind            string `json:"kind"` // 该字段的行内注释枚举了合法值，本任务必须把 "unresolved_role_symbol" 加进去
	Reason          string `json:"reason"`
}
```

- [ ] **Step 1: 写失败的测试**

追加到 `internal/investigations/validate_test.go`（沿用该文件既有的构造辅助；若没有，按下面自带）：

```go
func TestValidateRoleLocations_DemotesHallucinatedSymbol(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src", "pk", "rsa")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	// The file exists and the line is real; only the symbol is fabricated.
	// This is the exact shape the 2026-07-27 audit found in
	// inv-flow-001-3a998d336f97.json.
	body := "LTC_SET_ASN1(siginfo, 1, OCTET_STRING, tmpbuf, siglen);\nder_decode_sequence(out, outlen, siginfo, 2);\n"
	if err := os.WriteFile(filepath.Join(src, "rsa_verify_hash.c"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	inv := artifacts.TWEInvestigation{
		InvestigationID: "inv-test-001",
		FilledRoles: map[string]artifacts.ToolLocation{
			"checks_that_do_not_dominate": {
				Path:      "src/pk/rsa/rsa_verify_hash.c",
				StartLine: 141,
				Symbol:    "der_decode_sequence_flexi",
			},
		},
	}

	got, adjustments := validateRoleLocations(inv, root)

	if _, still := got.FilledRoles["checks_that_do_not_dominate"]; still {
		t.Fatal("role with a symbol absent from the file must not stay filled")
	}
	if !containsString(got.MissingRoles, "checks_that_do_not_dominate") {
		t.Fatalf("demoted role must land in MissingRoles, got %v", got.MissingRoles)
	}
	var found bool
	for _, a := range adjustments {
		if a.Kind == "unresolved_role_symbol" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want an unresolved_role_symbol adjustment, got %+v", adjustments)
	}
}

func TestValidateRoleLocations_KeepsRealSymbol(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "a.c"), []byte("void der_decode_sequence(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := artifacts.TWEInvestigation{
		InvestigationID: "inv-test-002",
		FilledRoles: map[string]artifacts.ToolLocation{
			"r": {Path: "src/a.c", StartLine: 1, Symbol: "der_decode_sequence"},
		},
	}
	got, adjustments := validateRoleLocations(inv, root)
	if _, ok := got.FilledRoles["r"]; !ok {
		t.Fatal("a role whose symbol really appears in the file must stay filled")
	}
	if len(adjustments) != 0 {
		t.Fatalf("want no adjustments, got %+v", adjustments)
	}
}

// An empty Symbol must behave exactly as before this change: the file
// existence check alone decides.
func TestValidateRoleLocations_EmptySymbolUnchanged(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "a.c"), []byte("nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := artifacts.TWEInvestigation{
		InvestigationID: "inv-test-003",
		FilledRoles: map[string]artifacts.ToolLocation{
			"r": {Path: "src/a.c", StartLine: 1},
		},
	}
	got, adjustments := validateRoleLocations(inv, root)
	if _, ok := got.FilledRoles["r"]; !ok {
		t.Fatal("a role with no declared symbol must be unaffected by the symbol check")
	}
	if len(adjustments) != 0 {
		t.Fatalf("want no adjustments, got %+v", adjustments)
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
```

> 若 `containsString` 在该包内已存在，删掉上面这份，用既有的。

- [ ] **Step 2: 运行测试确认失败**

```
cd tee-usage-scanner && go test ./internal/investigations/ -run TestValidateRoleLocations -v
```
预期：`DemotesHallucinatedSymbol` FAIL（角色仍然 filled），另两个 PASS

- [ ] **Step 3: 改 `validateRoleLocations`**

在 `internal/investigations/validate.go` 的循环里，把 `os.Stat` 那段替换为：

```go
	for role, loc := range inv.FilledRoles {
		full := loc.Path
		if !filepath.IsAbs(full) {
			full = filepath.Join(repoRoot, loc.Path)
		}
		if _, err := os.Stat(full); err != nil {
			reason := fmt.Sprintf("role %q location %q does not resolve to a real file under the repository", role, loc.Path)
			adjustments = append(adjustments, Adjustment{InvestigationID: inv.InvestigationID, Kind: "unresolved_role_location", Reason: reason})
			demoted = append(demoted, role)
			continue
		}
		// File existence proves nothing about content. Without this, a
		// fabricated symbol in a real file stands as located evidence and —
		// once the Case Pack pipe is connected — reaches Expert as fact.
		if loc.Symbol != "" {
			ok, err := symbolcheck.FileContainsSymbol(repoRoot, loc.Path, loc.Symbol)
			if err != nil || !ok {
				reason := fmt.Sprintf("role %q declares symbol %q which does not appear in %s", role, loc.Symbol, loc.Path)
				adjustments = append(adjustments, Adjustment{InvestigationID: inv.InvestigationID, Kind: "unresolved_role_symbol", Reason: reason})
				demoted = append(demoted, role)
				continue
			}
		}
		kept[role] = loc
	}
```

同时：

1. 更新该函数的文档注释，说明它现在校验两件事（文件存在 + 符号出现）
2. import 块加入 `symbolcheck` 包
3. **把 `"unresolved_role_symbol"` 加进 `Adjustment.Kind` 的行内枚举注释**（`validate.go:39`）——该注释是这些字符串常量唯一的文档，漏掉它就等于新类别没有定义

- [ ] **Step 4: 运行测试确认通过**

```
cd tee-usage-scanner && go test ./internal/investigations/ -v
```
预期：全部 PASS（含该包既有测试）

- [ ] **Step 5: 让 architecture 改调共享包**

`internal/architecture/validate.go` 中，把 :248-254 那段替换为：

```go
			ok, err := symbolcheck.FileContainsSymbol(repoRoot, ref.File, symbol)
			if err != nil {
				return fmt.Sprintf("could not read cited file %s: %v", ref.File, err), false
			}
			if !ok {
				return fmt.Sprintf("cited file %s does not contain declared symbol %q", ref.File, symbol), false
			}
			continue
```

失败文案逐字保持不变。**`citedRegionContains`（:288）不动、不搬。**

- [ ] **Step 6: 运行 architecture 既有测试确认无回归**

```
cd tee-usage-scanner && go test ./internal/architecture/ -v
```
预期：全部 PASS，无需修改任何既有断言

- [ ] **Step 7: 提交**

```bash
git add tee-usage-scanner/internal/investigations/ tee-usage-scanner/internal/architecture/
git commit -m "investigations: a located role must name a symbol that exists"
```

---

## Task 3: `casepacks` 构造、去重与落盘

**Files:**
- Create: `internal/planner/casepacks.go`
- Test: `internal/planner/casepacks_test.go`

**已核实的既有类型（照抄，勿猜）：**

```go
// internal/artifacts/types.go:461
type Candidate struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Priority     string   `json:"priority"`
	Paths        []string `json:"paths"`
	Symbols      []string `json:"symbols,omitempty"`
	WhySelected  []string `json:"why_selected"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	SinkCategory string   `json:"sink_category,omitempty"`
	Confidence   float64  `json:"confidence"`
}
```

**Interfaces:**
- Consumes: `artifacts.Candidate`（上方）、`artifacts.CasePack`（`types.go:156`）、`artifacts.Manifest`
- Produces:
  - `func BuildFromCandidate(cand artifacts.Candidate, manifest artifacts.Manifest, idx int) artifacts.CasePack`
  - `func Merge(rich, thin []artifacts.CasePack) []artifacts.CasePack`
  - `func Write(runDir string, packs []artifacts.CasePack) error`
  — Task 4 使用这三个

- [ ] **Step 1: 写失败的测试**

`internal/planner/casepacks_test.go`：

```go
package planner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func rich(id string, files ...string) artifacts.CasePack {
	return artifacts.CasePack{
		SchemaVersion:    "teecheck.case_pack.v1",
		CaseID:           id,
		TargetFiles:      files,
		Priority:         "medium",
		CommonDefenses:   []string{"a dominating check already constrains the value"},
		RequiredEvidence: []string{"the check dominates every path"},
	}
}

func thin(id string, prio string, files ...string) artifacts.CasePack {
	return artifacts.CasePack{
		SchemaVersion: "teecheck.case_pack.v1",
		CaseID:        id,
		TargetFiles:   files,
		Priority:      prio,
		WhySelected:   []string{"why-" + id},
	}
}

// 14 of the 29 measured runs have exactly this shape: both sides name the
// same file. The rich pack must win and absorb the thin one's why_selected.
func TestMerge_EqualSetsMerge(t *testing.T) {
	got := Merge(
		[]artifacts.CasePack{rich("inv-1", "a.c")},
		[]artifacts.CasePack{thin("cand-1", "high", "a.c")},
	)
	if len(got) != 1 {
		t.Fatalf("want 1 merged pack, got %d", len(got))
	}
	if len(got[0].CommonDefenses) == 0 {
		t.Fatal("merged pack must keep the rich pack's playbook fields")
	}
	if len(got[0].WhySelected) == 0 {
		t.Fatal("merged pack must absorb the thin pack's why_selected")
	}
	if got[0].Priority != "high" {
		t.Fatalf("merged priority must be the higher of the two, got %q", got[0].Priority)
	}
}

// Never observed in the 29 measured runs, but the rule exists to make a
// wrong merge impossible: a partial overlap must NOT collapse two cases.
func TestMerge_PartialOverlapDoesNotMerge(t *testing.T) {
	got := Merge(
		[]artifacts.CasePack{rich("inv-1", "a.c", "b.c")},
		[]artifacts.CasePack{thin("cand-1", "low", "a.c")},
	)
	if len(got) != 2 {
		t.Fatalf("want 2 packs — a partial overlap must not merge, got %d", len(got))
	}
}

func TestMerge_DisjointDoesNotMerge(t *testing.T) {
	got := Merge(
		[]artifacts.CasePack{rich("inv-1", "a.c")},
		[]artifacts.CasePack{thin("cand-1", "low", "b.c")},
	)
	if len(got) != 2 {
		t.Fatalf("want 2 packs for disjoint targets, got %d", len(got))
	}
}

func TestMerge_OneSideEmptyKeepsTheOther(t *testing.T) {
	got := Merge([]artifacts.CasePack{rich("inv-1", "a.c")}, nil)
	if len(got) != 1 {
		t.Fatalf("want the rich pack alone, got %d", len(got))
	}
	got = Merge(nil, []artifacts.CasePack{thin("cand-1", "low", "b.c")})
	if len(got) != 1 {
		t.Fatalf("want the thin pack alone, got %d", len(got))
	}
}

// An investigation with every role missing yields a pack with no files to
// look at. Handing that to Expert asks it to hypothesise about nothing.
func TestMerge_DropsEmptyTargets(t *testing.T) {
	got := Merge([]artifacts.CasePack{rich("inv-empty")}, nil)
	if len(got) != 0 {
		t.Fatalf("a pack with no target files must not survive, got %d", len(got))
	}
}

func TestMerge_RichPacksSortFirstAndOrderIsStable(t *testing.T) {
	a := Merge(
		[]artifacts.CasePack{rich("inv-1", "z.c")},
		[]artifacts.CasePack{thin("cand-1", "low", "a.c")},
	)
	b := Merge(
		[]artifacts.CasePack{rich("inv-1", "z.c")},
		[]artifacts.CasePack{thin("cand-1", "low", "a.c")},
	)
	if len(a) != 2 || a[0].CaseID != "inv-1" {
		t.Fatalf("rich packs must come first, got %+v", a)
	}
	for i := range a {
		if a[i].CaseID != b[i].CaseID {
			t.Fatal("ordering must be identical across runs")
		}
	}
}

func TestWrite_UsesCaseGlobFilenames(t *testing.T) {
	runDir := t.TempDir()
	if err := Write(runDir, []artifacts.CasePack{rich("inv-1", "a.c"), thin("cand-1", "low", "b.c")}); err != nil {
		t.Fatal(err)
	}
	// The exact glob every downstream stage uses.
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("want 2 files matching case-*.json, got %d: %v", len(paths), paths)
	}
	if _, err := os.Stat(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json")); err != nil {
		t.Fatalf("numbering must start at 001: %v", err)
	}
}

func TestBuildFromCandidate_CarriesPathsAndWhySelected(t *testing.T) {
	cand := artifacts.Candidate{
		Paths:       []string{"src/a.c"},
		Symbols:     []string{"f"},
		Priority:    "high",
		WhySelected: []string{"reached from an untrusted entrypoint"},
	}
	pack := BuildFromCandidate(cand, artifacts.Manifest{LocalPath: "/tmp/repo", Commit: "abcdef1234", Focus: "tee"}, 0)
	if len(pack.TargetFiles) != 1 || pack.TargetFiles[0] != "src/a.c" {
		t.Fatalf("target files not carried: %+v", pack.TargetFiles)
	}
	if len(pack.WhySelected) == 0 {
		t.Fatal("why_selected not carried")
	}
	if pack.CaseID == "" {
		t.Fatal("a thin pack still needs a CaseID")
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

```
cd tee-usage-scanner && go test ./internal/planner/ -run 'TestMerge|TestWrite|TestBuildFromCandidate' -v
```
预期：编译失败，`undefined: Merge` / `Write` / `BuildFromCandidate`

- [ ] **Step 3: 写实现**

`internal/planner/casepacks.go`：

```go
package planner

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// priorityRank orders priorities so a merge can keep the higher one.
var priorityRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// BuildFromCandidate converts one planner candidate into a "thin" Case Pack:
// it carries where to look and why, but none of the TWE playbook knowledge a
// TWEInvestigation-derived pack carries. Thin packs exist so that a run whose
// model emitted candidates but no investigations still produces reviewable
// cases — investigations is an optional field in the done payload, and its
// reliability on large repositories has never been measured.
func BuildFromCandidate(cand artifacts.Candidate, manifest artifacts.Manifest, idx int) artifacts.CasePack {
	repoName := sanitizeSlug(filepath.Base(manifest.LocalPath))
	if repoName == "" {
		repoName = "repo"
	}
	commit := manifest.Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}
	return artifacts.CasePack{
		SchemaVersion: "teecheck.case_pack.v1",
		CaseID:        fmt.Sprintf("%s@%s:%s:candidate:%03d", repoName, commit, sanitizeSlug(manifest.Focus), idx+1),
		Focus:         manifest.Focus,
		Priority:      cand.Priority,
		TargetFiles:   append([]string{}, cand.Paths...),
		TargetSymbols: append([]string{}, cand.Symbols...),
		WhySelected:   append([]string{}, cand.WhySelected...),
	}
}

// targetKey is the identity a merge compares: the sorted, deduplicated set of
// target files. Two packs merge ONLY when this is identical.
func targetKey(p artifacts.CasePack) string {
	seen := map[string]bool{}
	out := make([]string, 0, len(p.TargetFiles))
	for _, f := range p.TargetFiles {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\x00")
}

// Merge combines investigation-derived (rich) and candidate-derived (thin)
// packs into the final list to persist.
//
// Two rules, both deliberate:
//
//   - Packs merge ONLY when their target-file sets are exactly equal. A
//     partial overlap does NOT merge. A redundant case costs one extra Expert
//     call, which is visible and measurable; a wrong merge silently destroys
//     a finding. Across the 29 measured L3 runs, 14 pairs were exactly equal
//     and partial overlap never once occurred — so this rule currently costs
//     nothing.
//   - A pack with no target files is dropped. It comes from an investigation
//     whose roles were all missing, i.e. a record of "I looked and located
//     nothing". That record stays in 03_investigations/; it is the next
//     investigative task (prompt.go's CRITICAL RULES), not a review unit.
//
// Rich packs sort before thin ones so numbering is stable across runs.
func Merge(rich, thin []artifacts.CasePack) []artifacts.CasePack {
	var out []artifacts.CasePack
	byKey := map[string]int{}

	for _, p := range rich {
		key := targetKey(p)
		if key == "" {
			continue
		}
		byKey[key] = len(out)
		out = append(out, p)
	}
	for _, p := range thin {
		key := targetKey(p)
		if key == "" {
			continue
		}
		if at, ok := byKey[key]; ok {
			out[at] = absorb(out[at], p)
			continue
		}
		byKey[key] = len(out)
		out = append(out, p)
	}
	return out
}

// absorb folds a thin pack into the rich pack that shares its target set.
// The rich pack is the base — it carries the playbook knowledge, which is the
// whole reason this pipe exists.
func absorb(base, extra artifacts.CasePack) artifacts.CasePack {
	seen := map[string]bool{}
	for _, w := range base.WhySelected {
		seen[w] = true
	}
	for _, w := range extra.WhySelected {
		if !seen[w] {
			seen[w] = true
			base.WhySelected = append(base.WhySelected, w)
		}
	}
	if priorityRank[extra.Priority] > priorityRank[base.Priority] {
		base.Priority = extra.Priority
	}
	return base
}

// Write persists packs as 03_cases/case-%03d.json — the filename shape every
// downstream stage globs for. The planner previously wrote
// <investigation_id>.json here, which no consumer's glob matched, so the
// richest pack in the run was never read by anyone (PR-06, bf9ead6).
func Write(runDir string, packs []artifacts.CasePack) error {
	for i, pack := range packs {
		path := filepath.Join(runfs.CasePacksDir(runDir), fmt.Sprintf("case-%03d.json", i+1))
		if err := runfs.WriteJSON(path, pack); err != nil {
			return fmt.Errorf("write case pack %s: %w", pack.CaseID, err)
		}
	}
	return nil
}
```

**已核实**：`sanitizeSlug` 位于 `internal/cases/run.go:298`，未导出，`internal/planner` 中**没有**同名辅助。因此本任务需在 `casepacks.go` 内写一份最小实现：

```go
// sanitizeSlug mirrors internal/cases' unexported helper of the same name.
// It is duplicated rather than exported from there on purpose: exporting it
// would make the llm path import the legacy case-building package, which
// this change exists to disentangle.
func sanitizeSlug(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
```

> 实现者：先读 `internal/cases/run.go:298` 的实际实现，让本份的行为与它一致（上面是形状示意，以那边为准）。两份行为不一致会让 CaseID 在两条路径下形态不同。

- [ ] **Step 4: 运行测试确认通过**

```
cd tee-usage-scanner && go test ./internal/planner/ -run 'TestMerge|TestWrite|TestBuildFromCandidate' -v
```
预期：9 个测试全部 PASS

- [ ] **Step 5: 提交**

```bash
git add tee-usage-scanner/internal/planner/casepacks.go tee-usage-scanner/internal/planner/casepacks_test.go
git commit -m "planner: build, dedup and persist Case Packs under the consumer's glob"
```

---

## Task 4: planner 接线 + 垫片退休

**Files:**
- Modify: `internal/planner/planner.go`（`processInvestigations` 约 :489-532；调用点约 :456-461）
- Modify: `internal/planner/shim.go`（删 `WriteHotspotShim`）
- Test: `internal/planner/rollback_investigation_test.go`（改既有断言）

**Interfaces:**
- Consumes: Task 3 的 `BuildFromCandidate` / `Merge` / `Write`
- Produces: llm 路径下 `03_cases/case-%03d.json` 已落盘且含富字段；`01_repo_map/`、`02_hotspots/` 不再由 planner 写

- [ ] **Step 1: 先确认既有测试现在测什么**

```
cd tee-usage-scanner && go test ./internal/planner/ -run TestRollback -v
```
`rollback_investigation_test.go:123` 断言 `len(result.CasePacks) == 1`。**这正是让缺陷藏住的那个断言**：它证明 pack 被造出来，不证明有人能读到。本任务把它改成从消费者的 glob 读回。

- [ ] **Step 2: 改 `processInvestigations` —— 不再自行写盘**

删掉 `internal/planner/planner.go` 中的这一段（当前 :524-529）：

```go
		if cfg.RunDir != "" {
			path := filepath.Join(runfs.CasePacksDir(cfg.RunDir), pack.CaseID+".json")
			if err := runfs.WriteJSON(path, pack); err != nil {
				errs = append(errs, artifacts.RoundError{Round: -1, Action: "case_pack.write:" + pack.CaseID, Error: err.Error()})
			}
		}
```

`packs = append(packs, pack)` 保留。`investigations.Persist`（:507）**保留不动** —— `03_investigations/` 的记录仍要写。

- [ ] **Step 3: 在调用点合并两路并落盘**

**已核实的插入位置**：`planner.go` 现有代码为

```go
	invs, packs, invErrors := processInvestigations(donePayload.Investigations, cfg, state)   // :456
	if len(invErrors) > 0 {
		bundle.Errors = append(bundle.Errors, invErrors...)
	}                                                                                         // :459

	return RunResult{Bundle: bundle, Err: runErr, Investigations: invs, CasePacks: packs}      // :461
```

新代码插在 :459 的 `}` 之后、`return` 之前。注意 `invErrors` 此时已被并入 `bundle.Errors`，所以新错误要**直接追加到 `bundle.Errors`**，不能再往 `invErrors` 里加（那样会被丢弃）：

```go
	// Both halves of the done payload become Case Packs. candidates and
	// investigations are independent lists with no id linking them
	// (prompt.go's done schema), and investigations is optional — so
	// neither can be derived from the other, and dropping either loses runs.
	//
	// bundle.Candidates is used rather than donePayload.Candidates because
	// convertCandidates (:440) has already dropped hallucinated paths.
	var thin []artifacts.CasePack
	if manifest, err := runfs.LoadManifest(cfg.RunDir); err != nil {
		bundle.Errors = append(bundle.Errors, artifacts.RoundError{
			Round: -1, Action: "case_pack.manifest", Error: err.Error()})
	} else {
		for i, cand := range bundle.Candidates {
			thin = append(thin, BuildFromCandidate(cand, manifest, i))
		}
	}
	merged := Merge(packs, thin)
	if cfg.RunDir != "" {
		if err := Write(cfg.RunDir, merged); err != nil {
			bundle.Errors = append(bundle.Errors, artifacts.RoundError{
				Round: -1, Action: "case_pack.write", Error: err.Error()})
		}
	}
```

然后把 :461 的 `CasePacks: packs` 改为 `CasePacks: merged`。

> **manifest 加载失败时不静默降级**：上面记一条 `RoundError` 并跳过瘦 pack，富 pack 仍照常落盘。不要用零值 Manifest 兜底——那会产出 `repo@:...` 这种残缺 CaseID，看起来正常但来源不明。

- [ ] **Step 4: 删除 `WriteHotspotShim`**

删掉 `internal/planner/shim.go` 中的 `WriteHotspotShim` 函数及其在 `internal/pipeline` 的调用点。若删后 `shim.go` 为空，删除该文件。用以下命令确认无残留引用：

```
cd tee-usage-scanner && grep -rn "WriteHotspotShim" --include="*.go" .
```
预期：无输出

- [ ] **Step 5: 改既有断言为消费者侧读回**

把 `rollback_investigation_test.go:123-126` 那段改成：

```go
	// Read back through the exact glob every downstream stage uses. The
	// previous assertion checked result.CasePacks — it passed for four days
	// while no consumer could see the file on disk.
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("want 1 pack visible to the downstream glob, got %d: %v", len(paths), paths)
	}
	var pack artifacts.CasePack
	if err := runfs.ReadJSON(paths[0], &pack); err != nil {
		t.Fatal(err)
	}
	if len(pack.CommonDefenses) == 0 || len(pack.CommonFalsePositives) == 0 {
		t.Fatalf("the playbook knowledge must survive to disk: %+v", pack)
	}
```

- [ ] **Step 6: 运行 planner 全包测试**

```
cd tee-usage-scanner && go test ./internal/planner/... -v
```
预期：全部 PASS

- [ ] **Step 7: 提交**

```bash
git add tee-usage-scanner/internal/planner/
git commit -m "planner: emit Case Packs directly, retire the hotspot shim"
```

---

## Task 5: `cases.Enrich`

**Files:**
- Modify: `internal/cases/run.go`（新增 `Enrich`，`Run` 一个字符不改）
- Modify: `internal/pipeline/run.go:159`
- Test: `internal/cases/enrich_test.go`

**Interfaces:**
- Consumes: Task 4 落盘的 `03_cases/case-*.json`
- Produces: `func Enrich(cfg config.Config) error` — 供 `pipeline` 在 llm 分支调用

- [ ] **Step 1: 写失败的测试**

`internal/cases/enrich_test.go`：

```go
package cases

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestEnrich_AddsSnippetsAndLeavesEverythingElseAlone(t *testing.T) {
	runDir := t.TempDir()
	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "src", "a.c"), []byte("int f(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{LocalPath: repoRoot, Focus: "tee"}); err != nil {
		t.Fatal(err)
	}

	before := artifacts.CasePack{
		SchemaVersion:    "teecheck.case_pack.v1",
		CaseID:           "inv-1",
		TargetFiles:      []string{"src/a.c"},
		TargetSymbols:    []string{"f"},
		CommonDefenses:   []string{"d"},
		RequiredEvidence: []string{"e"},
	}
	packPath := filepath.Join(runfs.CasePacksDir(runDir), "case-001.json")
	if err := runfs.WriteJSON(packPath, before); err != nil {
		t.Fatal(err)
	}

	knowledgeRoot := t.TempDir()
	if err := Enrich(config.Config{RunDir: runDir, KnowledgeRoot: knowledgeRoot}); err != nil {
		t.Fatal(err)
	}

	var after artifacts.CasePack
	if err := runfs.ReadJSON(packPath, &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Snippets) == 0 {
		t.Fatal("Enrich must add snippets for the target files")
	}
	if after.CaseID != before.CaseID ||
		len(after.CommonDefenses) != 1 ||
		len(after.RequiredEvidence) != 1 ||
		len(after.TargetFiles) != 1 {
		t.Fatalf("Enrich must not disturb any other field: %+v", after)
	}
}

func TestEnrich_NoPacksIsNotAnError(t *testing.T) {
	runDir := t.TempDir()
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{LocalPath: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := Enrich(config.Config{RunDir: runDir, KnowledgeRoot: t.TempDir()}); err != nil {
		t.Fatalf("a run with zero packs must not fail the pipeline: %v", err)
	}
}
```

**已核实的既有签名（照抄，勿猜）：**

```go
runfs.ManifestPath(runDir string) string                        // paths.go:12
runfs.LoadManifest(runDir string) (artifacts.Manifest, error)   // paths.go:112
runfs.CasePacksDir(runDir string) string                        // paths.go:28
collectSnippets(repoRoot string, paths, symbols []string) []artifacts.PromptSnippet  // cases/run.go:153
knowledge.LookupForCase(knowledgeRoot string, pack artifacts.CasePack, n int) ([]artifacts.KnowledgeHint, error)
```

- [ ] **Step 2: 运行测试确认失败**

```
cd tee-usage-scanner && go test ./internal/cases/ -run TestEnrich -v
```
预期：编译失败，`undefined: Enrich`

- [ ] **Step 3: 写 `Enrich`**

追加到 `internal/cases/run.go`（**不修改 `Run`**）：

```go
// Enrich is the llm path's counterpart to Run. The Planner has already
// written the Case Packs — it knows which TWE investigation and which
// candidate produced each one, and that knowledge cannot be recovered from
// a hotspot index. Enrich therefore adds only the two things the Planner
// has no cheap way to produce: source snippets for the target files, and
// knowledge-base hints looked up from the pack itself.
//
// Run stays exactly as it was and continues to serve the legacy path.
func Enrich(cfg config.Config) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	if err := knowledge.EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return fmt.Errorf("ensure knowledge layout: %w", err)
	}
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(p, &pack); err != nil {
			return fmt.Errorf("read case pack %s: %w", p, err)
		}
		pack.Snippets = collectSnippets(manifest.LocalPath, pack.TargetFiles, pack.TargetSymbols)
		hints, err := knowledge.LookupForCase(cfg.KnowledgeRoot, pack, 4)
		if err != nil {
			return fmt.Errorf("lookup knowledge for %s: %w", pack.CaseID, err)
		}
		pack.KnowledgeHints = hints
		if err := runfs.WriteJSON(p, pack); err != nil {
			return fmt.Errorf("write case pack %s: %w", p, err)
		}
	}
	fmt.Printf("Enriched %d case pack(s) in %s\n", len(paths), runfs.CasePacksDir(cfg.RunDir))
	return nil
}
```

- [ ] **Step 4: 运行测试确认通过**

```
cd tee-usage-scanner && go test ./internal/cases/ -v
```
预期：新增 2 个测试 PASS，该包既有测试全部仍 PASS

- [ ] **Step 5: 改 pipeline 的 llm 分支**

`internal/pipeline/run.go:159`：

```go
		if err := cases.Enrich(stageCfg); err != nil {
			return "", fmt.Errorf("cases enrich: %w", err)
		}
```

`:184` 的 legacy 分支**一个字符都不改**。

- [ ] **Step 6: 提交**

```bash
git add tee-usage-scanner/internal/cases/ tee-usage-scanner/internal/pipeline/run.go
git commit -m "cases: split Enrich out of Run for the llm path"
```

---

## Task 6: 端到端投递测试

**Files:**
- Test: `internal/pipeline/casepack_delivery_test.go`

**Interfaces:**
- Consumes: Task 3–5 的全部产物
- Produces: 无（纯测试）

这是 spec 验收标准 1 的最终形态，也是本次事故最直接的防线。

- [ ] **Step 1: 写测试**

`internal/pipeline/casepack_delivery_test.go`：

```go
package pipeline

import (
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// The 2026-07-27 defect in one test: the Planner produced the richest Case
// Pack in the run and no consumer could see it, because the filename it
// wrote did not match the glob every consumer uses. Any future change that
// re-breaks the delivery must fail here.
//
// This asserts from the CONSUMER side on purpose. The assertion that
// previously existed (len(result.CasePacks) == 1) proved only that the pack
// was constructed.
func TestCasePacksReachDownstreamGlob(t *testing.T) {
	runDir := t.TempDir()

	// Stand in for a Planner run that produced one investigation-derived
	// pack carrying playbook knowledge.
	pack := artifacts.CasePack{
		SchemaVersion:        "teecheck.case_pack.v1",
		CaseID:               "inv-flow-001-deadbeef",
		TargetFiles:          []string{"src/a.c"},
		RelatedTWEs:          []string{"TWE-FLOW-001"},
		RequiredEvidence:     []string{"the check dominates every path"},
		CommonDefenses:       []string{"a dominating check already constrains the value"},
		CommonFalsePositives: []string{"the caller validated it earlier"},
	}
	if err := runfs.WriteJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), pack); err != nil {
		t.Fatal(err)
	}

	// Every stage that reads case packs uses this glob. Keep this list in
	// sync with the consumers in expert/challenger/verifier/arbiter/stats.
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("downstream glob sees %d packs, want 1", len(paths))
	}

	var got artifacts.CasePack
	if err := runfs.ReadJSON(paths[0], &got); err != nil {
		t.Fatal(err)
	}
	for name, field := range map[string][]string{
		"related_twes":           got.RelatedTWEs,
		"required_evidence":      got.RequiredEvidence,
		"common_defenses":        got.CommonDefenses,
		"common_false_positives": got.CommonFalsePositives,
	} {
		if len(field) == 0 {
			t.Errorf("%s did not survive to the consumer — the playbook layer is disconnected again", name)
		}
	}
}
```

- [ ] **Step 2: 运行**

```
cd tee-usage-scanner && go test ./internal/pipeline/ -run TestCasePacksReachDownstream -v
```
预期：PASS

- [ ] **Step 3: 全量构建与测试**

```
cd tee-usage-scanner && go build ./... && go test ./... 2>&1 | tail -40
cd ../teecheck-benchmark && go build ./... && go test ./... 2>&1 | tail -20
```
预期：两模块全绿，仅 `internal/collabrun` 的 live-endpoint 失败（已知例外）

- [ ] **Step 4: 提交**

```bash
git add tee-usage-scanner/internal/pipeline/casepack_delivery_test.go
git commit -m "pipeline: assert Case Packs reach the consumer glob"
```

---

## 完成后（不在本计划范围内，记录以免遗忘）

1. **重跑 flow.yml 与 guard.yml 对照测量。** 两份既有结论（`notes/2026-07-26-*`、`notes/2026-07-27-*`）比较的是 candidate 路径，而 playbook 字段走的是被丢弃的通道，因此都不成立。重跑前应在两份 note 顶部加一行作废声明。
2. **写"证据链诚实性"的 spec** —— verifier 的 citation 校验只查 sha256、challenger 虚构 independent view 的表述、arbiter 把未验证的引用写成 "Validated Fact"。本计划新建的 `internal/symbolcheck` 是那份工作的现成材料。
3. **web 观察窗** —— 用户已列为高优先级。其前置阻塞（六个阶段零事件、只有 planner 的 LLM 对话被记录）与本次审计发现的是同一件事。
