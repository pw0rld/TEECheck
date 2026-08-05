# BUG-006：reconnaissance gate 在预算内不可能被满足，覆盖率被钉死在 0.04%

> 状态：**已确认（算术 + 两次实测）/ 未修**
> 记录日期：2026-08-05
> 影响：Planner 的项目覆盖范围、`CoverageLedger` 的意义、任何 finding 的适用范围
> 代表运行：`runs/recon-001`、`runs/recon-002`（OP-TEE `a9386bf987d95374a6f7f4c7bcf850115e0e1a4e`）
> 路径以 `tee-usage-scanner/` 为基准

---

## 1. 一句话症状

**indexed 模式的 gate 最少需要 22 个动作才能满足，而 reconnaissance 预算只提供 18 个动作槽位。差额 −4。gate 因此永远无法靠达标放行，每一次运行都只能走"预算耗尽"逃生口——两次实测无一例外。**

后果不是"这次没看够"，是**看不够是结构性的**：`recon-002` 审了 35 个模块中的 5 个、11603 个函数中的 5 个（**0.04%**），而这已经接近预算允许的上限。

---

## 2. 算术

### 2.1 预算（`internal/planner/budget.go`、`planner.go`）

```go
MaxReconRounds:   6      // budget.go:57
cfg.MaxActionsPerRound = 3   // planner.go:155（默认值）
```

```text
reconnaissance 动作槽位 = 6 轮 × 3 动作 = 18
```

### 2.2 gate 的最低要求（`internal/planner/recon.go`）

```go
reconMinModules = 5      // recon.go:62
reconMinSymbols = 15     // recon.go:66
reconMinSpread  = 3      // recon.go:71
```

indexed 模式的五项要求，翻译成必须成功的动作数：

| 要求 | 动作 | 最少次数 |
|---|---|---|
| 读 repository card | `get_repository_card` | 1 |
| 列出 5 个模块的函数 | `list_functions` | 5 |
| 打开 15 张函数卡 | `get_function_card` | 15 |
| 至少一次关系查询 | `get_callers` | 1 |
| 卡片跨 ≥3 个模块 | （由上面 15 张承担） | 0 |
| | **合计** | **22** |

```text
18 槽位 − 22 最低要求 = −4
```

**gate 不是"很难满足"，是"不可能满足"。**

注意 `list_modules` 不计入任何一项（`recon.go:160`，有意为之：读模块清单是定位，不是审阅模块），所以模型每调用它一次，可用槽位就少一个而计数不动。

---

## 3. 两次实测

### 3.1 结果

```text
recon-001  recon_status=recon_budget_exhausted  capsules=3   modules=5/35  relation=0  leads=0
recon-002  recon_status=recon_budget_exhausted  capsules=5   modules=5/35  relation=1  leads=1
```

两次都是逃生口放行。gate 从未靠自身条件满足过。

### 3.2 前 6 轮的动作去向

`recon-002`，reconnaissance 预算内的 16 个动作：

```text
list_functions         5  ← 计数
get_function_card      5  ← 计数
read_file              2    不计数
get_repository_card    1  ← 计数
list_modules           1    不计数
get_callers            1  ← 计数
find_symbols           0    不计数（该轮失败）
```

对 gate 计数的成功动作：**12 个**。要求 22 个。

`recon-001`，13 个动作里计数的 10 个，`get_callers` 0 次（symbol_id 少签名被拒，见 BUG-004）。

### 3.3 覆盖率

```text
modules_reviewed          5 / 35        = 14%
function_capsules_reviewed 5 / 11603    = 0.04%
unreviewed_clusters       30 个模块
```

即便把 18 个槽位**全部**用于 `get_function_card`（那样就不满足其他四项），上限也只有 18 张卡 —— 仍是 11603 的 0.16%。

---

## 4. 根因

两个数字是各自选定的，从未一起验算过。

`recon.go` 的注释把 floors 说明为"防'没读就下结论'的下限，不是覆盖目标"，并解释了 5/15/3 的来由。`budget.go` 的注释则写：

```go
// 六个 reconnaissance 轮是 indexed gate 在每轮三个动作下的开销：
// repository card、列 5 个模块、开 15 张函数卡加一次关系查询共十九个动作，
// 而会花一轮决定下一步看哪里的模型需要余量。
```

**这段注释里的加法是错的。**1 + 5 + 15 + 1 = 22，不是 19。按 19 算，6 × 3 = 18 仍然不够，但差额只有 1，看起来像"紧但可行"。按真实的 22 算，差额是 4，且没有任何余量给"决定下一步"。

这是我写 Task 8 时的错误，两个常量分别在两个文件里，没有一处代码或测试把它们放在一起检查过。

---

## 5. 为什么测试没有发现

`internal/planner/recon_test.go` 里的 `browse()` helper 直接调用 `r.Observe(...)` 22 次，不经过预算：

```go
func browse(r *ReconState) {
	r.Observe("get_repository_card", "", true)
	for m := 0; m < reconMinModules; m++ { r.Observe("list_functions", ..., true) }
	for i := 0; i < reconMinSymbols; i++ { r.Observe("get_function_card", ..., true) }
	r.Observe("get_callers", ..., true)
}
```

它证明的是"做满这些动作就能满足 gate"，**不是"预算够不够做满这些动作"**。两个数字之间的关系从未被断言过。

`recon_loop_test.go` 里的端到端测试用的是脚本化 mock，它们验证逃生口能放行、ledger 记录正确 —— 恰恰因为逃生口工作正常，测试全绿，而 gate 永远失效这件事被掩盖了。

---

## 6. 后果，按严重程度

**6.1 gate 是装饰性的。**它从不 gate 任何东西，只是让每次运行先烧掉 6 轮再放行。BUG-003 §6.1 要求"Planner 在完成最低限度的 ORIENT/MAP coverage 前不能直接 done" —— 这条实际上没有生效过。

**6.2 每个 finding 的适用范围是 0.04%，而这一点没有写在 finding 里。**`recon-002` 的结论说 `fs_htree.h/c` 无漏洞，那是对的；但读结论的人无从知道整个 run 只看了 5 个函数。`coverage_ledger.json` 记了，`07_arbiter/findings.json` 没有。

**6.3 计划的验收标准写反了。**计划里写"没有 run 以 `recon_incomplete` 结束 —— 出现即说明预算太小"。实际每次都以 `recon_budget_exhausted` 结束，那是**另一个**逃生口，含义相同却不触发这条判据。

---

## 7. 处置

**A. 加一个把两个数字绑在一起的测试（先做，且必须做）**

```go
// gate 的最低动作数必须落在 reconnaissance 预算之内，否则 gate 从不生效，
// 只是每次运行先烧掉那些轮次。这两个常量在两个文件里，除了这个断言之外
// 没有任何东西让它们保持一致。
func TestReconBudget_CanReachTheIndexedGate(t *testing.T) {
	const needed = 1 + reconMinModules + reconMinSymbols + 1
	b := NewDefaultBudget()
	if slots := b.MaxReconRounds * defaultActionsPerRound; slots < needed {
		t.Fatalf("gate 需要 %d 个动作，预算只有 %d 个槽位", needed, slots)
	}
}
```

这需要把 `MaxActionsPerRound` 的默认值 3 提成一个具名常量，现在它是 `planner.go` 里的一个字面量。

**B. 调数字。**三种改法，代价不同：

| 改法 | 效果 | 代价 |
|---|---|---|
| `MaxReconRounds` 6 → 10 | 30 槽位 vs 22，留 8 个余量 | 每次运行多 4 轮 LLM 调用 |
| `MaxActionsPerRound` 3 → 5 | 30 槽位 | 单轮 prompt 与观察量变大 |
| `reconMinSymbols` 15 → 8 | 需求降到 15 | 削弱 floor 的意义 |

倾向前两者之一：floors 是按"看懂这个项目需要多少"选的，不该为了迁就预算而降。

**C. 把覆盖范围写进 finding。**`unreviewed_clusters` 已经在 ledger 里；arbiter 的 finding 应当携带同一事实，否则 `severity: low` 与 `confidence: high` 会被读成"整个项目低风险"，而实际含义是"被看过的那 0.04% 里低风险"。

**D. 把 `recon_budget_exhausted` 也纳入验收判据。**它和 `recon_incomplete` 一样是"没达标就放行"，计划只列了后者。

---

## 8. 与其他 bug 的关系

- **BUG-004**：`recon-001` 的 `get_callers` 零次成功是 symbol_id 少签名导致的；即便它成功了，那次也只有 10 个计数动作，仍然到不了 22。**两个 bug 独立，各自都足以让 gate 失效。**
- **BUG-005**：同由 `runs/recon-002` 暴露。BUG-005 是下游 agent 取不到证据，本文是 Planner 看不够代码 —— 一前一后，同一条链的两端。

---

## 9. 复现

```bash
cd tee-usage-scanner
# 算术
python3 -c "
need = 1 + 5 + 15 + 1
slots = 6 * 3
print(f'gate 最低动作数 {need}，reconnaissance 槽位 {slots}，差额 {slots-need}')
"
# 两次运行的实际结果
for r in recon-001 recon-002; do
  python3 -c "
import json
l=json.load(open('runs/$r/04_planner/coverage_ledger.json')); s=l['by_sample'][0]
print(f\"$r  status={s['recon_status']}  capsules={s['capsules_reviewed']}/{l['function_capsules_total']}  modules={l['modules_reviewed']}/{l['modules_total']}\")
"
done
```

```text
gate 最低动作数 22，reconnaissance 槽位 18，差额 -4
recon-001  status=recon_budget_exhausted  capsules=3/11603  modules=5/35
recon-002  status=recon_budget_exhausted  capsules=5/11603  modules=5/35
```
