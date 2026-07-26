# Flow Playbook 对照测量

> 日期：2026-07-26
> 对象：`knowledge/twe/playbooks/flow.yml`（TWE-FLOW-001，commit `e7a0263`）
> 划分：`teecheck-benchmark/datasets/split.v1.json`（dev 23 / holdout 21，种子 20260724）

---

## 方法

4 个 Flow 族案例 × 2 个臂，vulnerable 变体，各跑一次：

- **baseline**：知识根只含 `rollback.yml`（把 `flow.yml` 从知识根副本中删除）
- **withflow**：知识根含 `rollback.yml` + `flow.yml`

其余参数一致：`--mode llm --focus tee --max-cases 2 --max-hotspots 4`，并用 `--repo-url` / `--commit` 传入各案例的上游坐标。

**命中判定**：planner 产出的候选路径是否等于该案例 oracle 的 `primary_file`。holdout 案例的 oracle 只在运行结束后用于评分，编写 playbook 期间未打开。

## 结果

| 案例 | 半区 | baseline | withflow | 判定 |
|---|---|---|---|---|
| CVE-2019-1010293 | dev | 0 候选 | 1 候选 → `core/arch/arm/mm/tee_mmu.c` | **HIT**（0 → 正确） |
| CVE-2021-44421 | dev | 1 候选 **HIT** | 1 候选 **HIT** | 无变化（两臂都正确） |
| CVE-2019-0876 | **holdout** | 0 候选 | 1 候选 → `enclave/core/sgx/calls.c` | **MISS**（oracle 为 `report.c`） |
| CVE-2021-43619 | **holdout** | 0 候选 | 1 候选 → `secure_fw/partitions/firmware_update/tfm_fwu_req_mngr.c` | **HIT**（0 → 正确） |

**正确命中数**：dev 1 → 2；holdout 0 → 1（另有 1 个误报）。

八次运行全部 `exit=0`、`termination=llm_done`、跑满 8 轮。

## 判定（对照 spec 验收标准 5）

标准原文：开发集提升 **且** holdout 有可比提升 → 说明学到的是类而非实例；若只有开发集涨 → 判定实例级污染，playbook 重写。

**两侧都提升。** 决定性的一点是 `CVE-2021-43619`：它在 holdout 中，其 patch、oracle、源码在编写 playbook 全程未被打开，而 playbook 让 planner 从"0 候选"变为**精确指向 oracle 认定的文件**。这不可能来自记忆，只能来自 playbook 陈述的类级义务。

**结论：未发现实例级污染的证据；playbook 保留。**

## 必须同时说明的限制

1. **这是 smoke signal，不是测量。** 每臂 n=2、每格单次运行、LLM 非确定性。不得据此做百分比声称。
2. **holdout 出现 1 个误报**：`CVE-2019-0876` 指向 `calls.c` 而非 `report.c`——同目录、貌似合理但错误。有 finding ≠ finding 正确。
3. **详版一次都没被拉取。** withflow 臂的 `twe_playbook_detail` 调用次数为 **0**；改进完全来自 250-token 的 **brief 档**。反倒是 baseline 臂调了 2 次（拉 rollback 的详版）却一无所获。分层注入让常驻成本从 14.4K 降到 4K 这一点成立，但**详版档的价值尚未被任何数据支持**。
4. **fixture 是文件级抽取**（1–4 个文件），不是完整仓库。本结果不能外推到"在几万文件的 optee_os 里定位"。
5. 数据泄漏风险仍在：这些是公开 CVE，命中可能部分来自模型记忆而非推理（见 spec §8）。

## 一处方法论自查

首版分析脚本对整个 evidence bundle 做子串匹配来判命中，导致 0 候选的基线运行被误标为 HIT。已改为只比对候选的 `paths` 字段。上表为修正后的数据。
