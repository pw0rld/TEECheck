# Guard Playbook 对照测量 — 负面结果,已撤回

> 日期：2026-07-27
> 对象：`knowledge/twe/playbooks/guard.yml`（TWE-GUARD-004，commit `e675324`，已于本次撤回）
> 结论：**未测得收益，playbook 撤回；`TWE-GUARD-004` 目录条目保留。**

---

## 方法

4 个 Guard 族案例 × 2 个臂，vulnerable 变体：

- **baseline**：知识根含 `rollback.yml` + `flow.yml`（仅移除 `guard.yml`）
- **withguard**：三份齐全

命中判定：候选的 `paths` 是否等于 oracle 的 `primary_file`（不使用整个 evidence bundle 的子串匹配——上一轮该做法产生过假 HIT）。

## 结果

| 案例 | 半区 | baseline | withguard |
|---|---|---|---|
| CVE-2023-40271 | dev | HIT | HIT |
| CVE-2026-45614 | dev | HIT | HIT |
| CVE-2016-6129 | holdout | HIT | 第 1 轮无候选 / **第 2 轮 HIT** |
| CVE-2026-33662 | holdout | HIT | HIT |

**baseline 4/4 命中；withguard 4/4（复跑后）。收益为零。**

## 两个发现

### 1. `flow.yml` 已经覆盖了全部 4 个 Guard 案例

本轮 baseline 含 `flow.yml`，它单独就命中 4/4。`guard.yml` 面对的不是"从零到一"，而是"已经全中之后还能加什么"——**它没有加上任何东西**。

这否证了扩展 spec §1.2 的估算（"3 份 playbook 覆盖 13 个案例"）：`flow.yml` 的类级义务（未验证输入到达特权操作、检查未支配全部路径、验证只覆盖部分声称内容）本身就跨越了 Guard 族的这些案例。**按 TWE 族划分 playbook，与按"义务形状"划分，并不重合。**

### 2. 一次未能重现的"回退"（记录以自我纠正）

第 1 轮 `CVE-2016-6129 / withguard` 产出 0 候选，而 baseline 命中。当时据此提出一个假说：GUARD-004 的检查清单让 planner 逐条走完后判定"验证是完备的"，从而放过真漏洞——即"清单授权了过度自信"。planner 的自述确实写着 "Cryptographic verification ... is comprehensive ... (INV-GUARD-004-001)"。

**复跑未重现**：第 2 轮 withguard 正常命中。baseline 两轮均稳定命中，withguard 一次 0 一次 HIT，符合 LLM 非确定性下的噪声特征。

**因此该假说的证据不成立，予以撤回。** 记录在此是因为：一个有推理外观的假阴性极易被当作机制性发现，而单次运行不足以支撑它。这也说明本项目的 A/B 测量在 n=1 时**不足以判定单个案例的方向**，只能看聚合趋势。

## 处置

- **撤回 `guard.yml`** —— 每份 playbook 的 brief 档常驻在 7 个 agent 的每次调用中；没有实测收益的知识不应支付这个成本。同时移除 `TestShippedGuardPlaybook`。
- **保留 `TWE-GUARD-004` / `TWE-LEAK-003` / `TWE-LEAK-004` 三个目录条目** —— 它们在运行时是惰性的（`LoadDefinitions` 目前无非测试调用者），零成本，且记录了由真实 dev CVE 归纳出的弱点类，将来若写对应 playbook 可直接使用。

## 对后续的影响

1. **不要按 TWE 族逐一补 playbook。** 收益取决于新 playbook 是否带来 `flow.yml` 尚未表达的**义务形状**，而不是它是否对应一个新族。Leakage 的两份（时序、残留内存）在这一点上比 Guard 更有希望——时序侧信道与残留内存的义务确实不在 `flow.yml` 的表达范围内——但同样必须先测。
2. **测量方法需要加强。** n=2/半区、单次运行，不足以分辨小效应。若要继续，应对每格重复 3 次取多数，或扩大案例数。本次正是靠一次复跑才避免把噪声写成机制。

## 限制

同前次：fixture 为文件级抽取；公开 CVE 存在训练泄漏风险；样本量小。
