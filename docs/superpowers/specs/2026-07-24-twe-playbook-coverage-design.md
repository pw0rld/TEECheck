# TWE Playbook 覆盖面 — 设计文档

> 日期：2026-07-24
> 分支：`merge/tee-audit-integration`
> 状态：设计待确认
> 前置：`2026-07-24-tiered-twe-playbook-injection-design.md`（分层注入已实现，详版预算 3000 token）

---

## 0. 给不熟悉本项目的读者

TEECheck 用多个 LLM Agent 审计 TEE（可信执行环境）代码。它靠 **TWE Playbook**——一份 YAML 形式的"调查方法论"——告诉 Agent 该找什么、什么算证据、什么是常见误报。目前**只有 1 份** playbook（`rollback.yml`，State 族）。

`teecheck-benchmark` 有 44 个真实 OP-TEE CVE，每个都带 vulnerable/fixed 两份源码和上游修复补丁，用于检验"漏洞版能否命中、修复版是否干净"。

本设计解决：**该写哪些 playbook、内容从哪来、怎么防止"用考题编复习资料"。**

---

## 1. 关键测量结果（本设计的依据）

### 1.1 benchmark 的真实 TWE 族分布

从 `c3e3e28^`（该提交以"无来源"为由删除了这些字段）恢复出 44 个 case 的原始归类：

| 族 | 数量 | 典型 CWE |
|---|---:|---|
| **Flow** | **14** | 输入校验 ×5、类型混淆 ×2、越界读 ×2 |
| **(超出 TWE 范围)** | **12** | 整数溢出 ×4、弱密码原语、清理不全 |
| **Leakage** | **9** | 时序侧信道 ×4、初始化不当 ×2、信息暴露 ×2 |
| **State** | **5** | ← 现有唯一 playbook 覆盖的族 |
| **Guard** | **4** | 签名校验 ×2、部分比较 ×1 |
| Binding / Config / Design | **0** | — |

### 1.2 由此得到的三个结论

1. **只需 3 份新 playbook，不是 15 份。** Binding/Config/Design 在此 benchmark 上样本为 0。写 **Flow + Leakage + Guard**，覆盖从 5 个 case 升到 **32 个**。
2. **理论召回上限是 32/44 = 73%。** 12 个 case 是通用内存安全/算术缺陷，**TWE 引导按设计就找不到**（`oracleSpec.TWEFamily` 的原始注释即定义："或为空，当该弱点在 TWE 范围之外——通用内存安全、算术、资源或并发缺陷，无需 TEE 信任推理"）。报告分数时必须同时给出这个上限，否则 73% 会被误读为失败。
3. **现有唯一 playbook 押在最小的族上。** State 仅占 5/44（11%）。2026-07-24 探针在一个 Flow 族 CVE 上扑空，统计上是必然而非偶然。

### 1.3 恢复数据的使用边界（重要）

这些 `twe_family` 值来自被删除的提交，删除理由是"无来源"（推测为 LLM 赋值）。因此：

- ✅ **可用于优先级决策**——决定先写哪份 playbook，是规划输入，判断错了只影响投入顺序。
- ❌ **不得恢复为打分真值**——那会把"LLM 编造的 oracle 给 LLM 打分"这个问题请回来。

除非经人工复核确认。本设计**不**恢复 `twe_family` 到 oracle 文件。

---

## 2. 范围（2026-07-24 收窄）

### 2.1 发现：TWE 目录与本 benchmark 存在分类错位

把开发集案例与 `catalog.yml` 的条目定义逐一对照后发现：

| 族 | 开发集实际案例 | 对应 TWE 条目 | 匹配度 |
|---|---|---|---|
| **Flow** | 未对齐范围跳过末页、`num_params=127`、无效指针对齐、攻击者控制的格式/索引 | `TWE-FLOW-001` 宿主机数据到达 enclave 安全决策 | 🟡 说得过去——都是"不可信输入未充分校验" |
| **Leakage** | 内存池残留、FPU 状态、iovec 长度、RSA 时序 ×2 | `TWE-LEAK-001` 秘密进入日志/错误/元数据；`TWE-LEAK-002` 秘密相关的输出长度或结构 | 🟠 部分匹配——时序不是"输出长度或结构"，残留内存不是"日志/错误" |
| **Guard** | 截断的 ChaCha20-Poly1305 tag 比较、ECDH 点不在曲线上 | `TWE-GUARD-001/002/003` 全部是 attestation 相关 | 🔴 **不匹配**——这是"密码学校验不完整"，与 attestation 无关 |

**根因**：TWE 目录是 tee-audit 为 Web3/SGX **证明中心**场景所建，而本 benchmark 是 **OP-TEE 内核**的真实 CVE（参数校验、内存管理、密码学实现）。两套分类天生错位。这也解释了 §1.3 中那些 `twe_family` 标签当初为何被判定"无来源"——它们是硬套的。

### 2.2 收窄后的范围：先写一份

**本期只写 `flow.yml`（TWE-FLOW-001）**，理由：
- Flow 是唯一匹配度可接受的族，且样本最多（全集 14，开发集 8，holdout 6）。
- 它能以最小投入验证本设计的核心假设：**写一份对路的 playbook，真的能提升命中吗？**
- 验证之后再决定 Leakage / Guard 怎么办（可能需要新增 TWE 条目，那是另一个议题）。

§1.2 中"3 份覆盖 32 个 case"的估计据此作废——Guard 那 4 个即使写了 `TWE-GUARD-001` 的 playbook 也救不了。

---

## 3. 内容来源（每条都要可追溯）

| 来源 | 供给 playbook 的字段 | 可追溯性 |
|---|---|---|
| `knowledge/twe/definitions/enum_registry.yml`（13 类 **154 个词**：`guard_kind`、`trust_source_role`、`trust_sink_role`、`claim_field_role`…） | `look_for`、`required_evidence` 的**结构骨架** | 从 tee-audit 原样迁移 |
| tee-audit 的 60 份 `.ql`（每族的 `isSource` / `isSink` / `isBarrier`；**barrier / sanitizer 就是防御的机器形态**） | `look_for`、`common_defenses`、`trustir_hints` | 上游代码 |
| **开发集那一半 CVE 的 `patches/fix.patch`** | **具体 API 名、代码模式、因果**（例：`ADD_OVERFLOW(mem->offs, mem->size, &req_size) \|\| mem->mobj->size < req_size` → `TEE_ERROR_SECURITY`） | OP-TEE 维护者所写 |
| 开发集 oracle 的 `required_evidence` / `fixed_evidence` | 证据判定标准 | 数据集自带 |

**禁止**：凭模型印象编写 `look_for` / `common_defenses` / `common_false_positives`。每条内容应能指回上述四类来源之一。

---

## 4. 抽象纪律（本设计的核心风控）

playbook 只描述**类**，绝不描述**实例**。

- ❌ 实例级：「检查 `set_rmem_param` 里 offs+size 是否校验了 `mobj->size`」
- ✅ 类级：「宿主机提供的内存引用：验证 offset+size 子区间落在 cookie 选中的对象内，且该加法不会溢出」

**可执行的审查规则**：

1. **playbook 中不得出现任何 holdout 案例的函数名、文件名或 CVE 编号。**
2. 开发集的函数名/API 名**只能作为举例**出现在说明性字段（`scenario`、`common_defenses` 的解释性文字），**不得进入 `look_for` 或 `required_evidence`**——这两个字段是 Agent 的搜索指令，写成实例即是背答案。
3. 实现阶段对每份 playbook 跑一次机械检查：以 holdout 案例的 `primary_file` 与 `primary_function` 为词表，grep playbook 全文，命中即失败。

理由：若 playbook 写成实例级，holdout 上会立刻暴露（开发集涨、holdout 不涨）。**抽象纪律是实践，holdout 是标尺。**

---

## 5. Holdout 划分

**方式**：按 `(TWE 族, CWE)` 分层，50/50，固定种子 `20260724`，跨层交替起始方以避免单元素层偏斜。

**实测结果（已算出，写死不再重算）**：

| | 总数 | Flow | Guard | Leakage | State | 超出范围 |
|---|---:|---:|---:|---:|---:|---:|
| **dev** | **23** | 8 | 2 | 5 | 2 | 6 |
| **holdout** | **21** | 6 | 2 | 4 | 3 | 6 |

### 5.1 一次已发生的污染（必须记录）

`CVE-2019-1010292` 原本分到 holdout，但它的 `patches/fix.patch` 与 `oracle.yaml` 在 2026-07-24 的设计探索中被展示过（作为"patch 能提供什么原料"的举例），且 2026-07-24 的端到端探针也在其 fixture 上运行过。

**处置**：将其**移入 dev**，划分改为 23/21。代价是少一个 holdout 样本，收益是 holdout 保持纯净。

**纪律**：此后 holdout 的 21 个案例，其 patch、oracle、源码在编写 playbook 的全过程中不得打开。编写 playbook 的实施者应在**全新上下文**中工作，只被授予开发集材料。

**落盘**：划分结果写入 `teecheck-benchmark/datasets/SPLIT.md`（人可读、可核验，含种子与生成方法），随本次变更提交并**冻结**。

**纪律**：holdout 的 22 个案例，其 patch、oracle、源码在编写 playbook 的全过程中**不得打开**。

---

## 6. 验收标准

| # | 标准 |
|---|---|
| 1 | `flow.yml` 写成并通过 `twecontext.Load` + `Compile`（brief ≤250、detail ≤3000 token，fail closed） |
| 2 | 机械检查通过：playbook 全文不含任何 holdout 案例的 `primary_file` / `primary_function` / CVE 编号 |
| 3 | `SPLIT.md` 已提交且划分与 §5 表格一致 |
| 4 | **开发集**上的 confirmed finding 数较基线（当前 1 份 playbook）有提升 |
| 5 | **holdout** 上有可比提升——这是判定"学到的是类不是实例"的关键。若开发集涨而 holdout 不涨，判定为实例级污染，playbook 必须重写 |
| 6 | 报告任何召回数字时，同时给出 32/44 = **73% 的理论上限**与 12 个超范围案例的说明 |
| 7 | `go build ./...`、`go test ./...` 全绿（既有 `internal/collabrun` live-endpoint 失败除外） |

---

## 7. 非目标

- **本期不写 Leakage / Guard 的 playbook**——§2.1 的分类错位使其收益存疑；先用 Flow 验证核心假设再定（可能需新增 TWE 条目，属另一议题）。
- **不写 Binding / Config / Design 的 playbook**——此 benchmark 上样本为 0，无法测量收益。（真实世界可能需要，届时另议。）
- **不恢复 `twe_family` / `in_twe_scope` 到 oracle 文件**作为打分真值（§1.3）。
- **不追求 >73% 召回**——超出部分是设计边界，不是缺陷。
- **不改动 benchmark 的校验器、打分逻辑或 oracle 内容。**
- **不新增 TWE 条目**——16 条锚点固定，只补 playbook。
- 不改动分层注入机制本身（前置 spec 已实现）。

---

## 8. 已知残余风险（对外时必须写明）

1. **同仓库泛化**：44 个案例全部来自 `optee_os`。同类型的两个 CVE 可能共享代码惯例，因此本 holdout 测出的"泛化"弱于跨项目泛化。不得声称为跨项目结论。
2. **数据泄漏**：这些是公开 CVE，其漏洞版、修复版与补丁大概率在 GLM 的训练语料中。命中可能来自记忆而非推理。原始 oracle 有 `leakage_suspect` 字段（同样在 `c3e3e28` 被删）——本设计不恢复它，但报告时应说明该风险存在。
3. **样本量**：holdout 中 TWE 范围内仅 16 个案例，统计力有限；差异需谨慎解读，不宜做精确的百分比声称。

---

## 9. 待实现阶段确认

- 三份 playbook 各自对应的确切 TWE ID（从 `catalog.yml` 的 16 条中选定）。
- `SPLIT.md` 的具体格式（至少含：种子、方法、两组案例 ID 列表、族/CWE 分布表）。
- 机械泄漏检查以脚本还是测试形式落地。
