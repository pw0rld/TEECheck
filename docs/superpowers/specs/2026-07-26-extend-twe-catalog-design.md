# 扩展 TWE 目录以覆盖 OP-TEE 实际弱点类 — 设计文档

> 日期：2026-07-26
> 分支：`merge/tee-audit-integration`
> 状态：设计待确认
> 前置：`2026-07-24-twe-playbook-coverage-design.md`（划分已冻结、Flow playbook 已验证有效）

---

## 0. 给不熟悉本项目的读者

TEECheck 用 LLM Agent 审计 TEE 代码。它靠两层知识引导 Agent：

- **TWE 目录**（`knowledge/twe/definitions/catalog.yml`）——16 条弱点类的**锚点**（id / family / name），从上游项目 tee-audit 原样迁移；
- **Playbook**（`knowledge/twe/playbooks/*.yml`）——每一类的**调查方法论**，注入 Agent 的 prompt，是真正驱动行为的东西。

2026-07-26 的对照测量已经证明：写一份对路的 playbook 能让 Agent 从"零候选"变成精确命中 oracle 认定的文件，且能泛化到从未打开过的 holdout 案例。

本设计解决下一个障碍：**benchmark 里 13 个案例所属的弱点类，在 TWE 目录里没有对应条目。**

---

## 1. 问题：目录与语料错位

把 benchmark 开发集的案例与 `catalog.yml` 逐条对照：

| 开发集案例 | 现有对应条目 | 匹配度 |
|---|---|---|
| 截断的 ChaCha20-Poly1305 认证 tag 比较（CWE-187）<br>ECDH 公钥点不在选定曲线上（CWE-347） | `TWE-GUARD-001/002/003`：仅看有效性的证明消费 / 忽略 TCB 评估 / 缺新鲜性检查 | 🔴 **全不匹配**——三条都是 attestation 专用，与"密码学校验不完整"无关 |
| RSA-OAEP 无效 label hash 的时序差异<br>RSA PKCS#1 v1.5 解密时序差异（CWE-385 ×2） | `TWE-LEAK-002`：秘密相关的**输出长度或结构**暴露 | 🟠 时序不是"输出长度或结构" |
| 内存池分配超出请求量且未清理（CWE-226）<br>enclave 进入时 FPU 扩展状态（CWE-665）<br>host 控制的 iovec 长度（CWE-200） | `TWE-LEAK-001`：秘密进入**日志 / 错误 / 元数据** | 🟠 残留内存不是"日志/错误/元数据" |

**根因**：TWE 目录由 tee-audit 为 **Web3/SGX 证明中心**场景构建（16 条中大量是 attestation 与 binding），而本 benchmark 是 **OP-TEE / TF-M 内核**的真实 CVE——参数校验、内存管理、密码学实现。

**关键判断**：错位在**条目**层面，不在**族**层面。Guard 族（"一个检查存在但不完整"）本身完全适配；Leakage 族（"秘密流向不该到的地方"）也适配。**因此扩展的是条目，不是分类体系。** 7 个族保持不变。

---

## 2. 机械约束（已核实）

`internal/twe/definitions.go` 的 `Definition.Validate()`：

| 字段 | 约束 | 对本设计的影响 |
|---|---|---|
| `id` | 必须匹配 `^TWE-[A-Z0-9-]+$` | `TWE-GUARD-004` / `TWE-LEAK-003` / `TWE-LEAK-004` 均合法，且与现有编号（GUARD 至 003、LEAK 至 002）不冲突 |
| `family` | 必须属于 `ValidFamilies` 的 7 族 | 复用 Guard / Leakage，无需新族 |
| `query_modules` | 必须非空，**但刻意不要求指向真实存在的 `.ql` 文件**（代码注释：wiring those module names to actual CodeQL packs is PR-05's responsibility） | 可填写规划中的模块名，属既定设计而非欺骗 |
| `required_trustir` | 必须非空、无空项、无重复；**不校验是否存在于 `enum_registry.yml`** | 可命名事实角色而不必同步扩展枚举；但见 §5 的约束 |

结论：新增条目在机械层面成本很低。真正的风险是出处与循环性（§3、§4）。

---

## 3. 出处诚实性（硬要求）

`catalog.yml` 首行现为：

```
# Migrated verbatim from tee-audit's trustir/spec/twe_catalog.yml (PR-02 ...)
```

新增条目后该声明不再成立。**必须**：

1. 修改文件头，明确区分「迁移自 tee-audit 的 16 条」与「TEECheck 本地扩展的条目」，并说明扩展的依据（来自 benchmark 开发集的真实 CVE）。
2. 每个新增条目带一条注释，注明它由哪些开发集 CVE 支撑。
3. **不得**让新条目看起来像 tee-audit 的原始产出。将来若上游 tee-audit 更新其 catalog，维护者必须能一眼分清哪些是自己加的。

---

## 4. 循环性纪律

新条目的定义**只能来自开发集案例**。holdout 的 Leakage / Guard 案例（其 patch、oracle、源码）在定义新 TWE 与撰写对应 playbook 的全过程中不得打开——与 Flow playbook 相同的纪律，且已有机械护栏（`teecheck-benchmark/evaluator/runner/leakage_test.go`）覆盖 playbook 文本。

**注意护栏的边界**：它扫描 `knowledge/twe/playbooks/*.yml`，**不扫描 `catalog.yml`**。新增条目的 `name` 字段同样不得包含 holdout 案例的标识——本设计要求把 `catalog.yml` 一并纳入该护栏的扫描范围（见 §6 验收标准 4）。

---

## 5. 新增的三个条目

每条由 **≥2 个开发集案例**支撑。

### TWE-GUARD-004 — 密码学校验不完整
- **family**: Guard
- **含义**：一个密码学校验被执行了，但没有覆盖它所声称保证的全部输入或全部字节——校验存在，因此看起来安全，但可被绕过。
- **开发集依据**：截断的 ChaCha20-Poly1305 tag 比较（只比对部分字节）；ECDH 使用未验证是否在选定曲线上的公钥点（未校验输入的域约束）。

### TWE-LEAK-003 — 秘密相关的时序可观测量
- **family**: Leakage
- **含义**：可信侧的执行时间（或其它非数据型可观测量）依赖于秘密或依赖于对秘密的校验结果，使不可信侧可据此区分。
- **开发集依据**：RSA-OAEP 无效 label hash 的时序差异；RSA PKCS#1 v1.5 解密的时序差异。

### TWE-LEAK-004 — 残留或未初始化内存跨边界
- **family**: Leakage
- **含义**：跨信任边界交付的缓冲区、寄存器或分配区携带了上一使用者的内容或未初始化内容。
- **开发集依据**：内存池分配超出请求量且未清理；enclave 进入时的 FPU 扩展状态；host 控制的 iovec 长度导致读出请求范围之外的内容。

**`required_trustir`**：优先复用 `enum_registry.yml` 已有词汇；确实无对应词时可命名新角色（`Validate` 不校验），但必须在条目注释中标注"该角色尚未进入 enum_registry"，避免与事实层默认已对齐的错觉。**本期不扩展 `enum_registry.yml`**——它是 LLM 标注提示与查询层共享的单一定义点，扩展它会波及尚未建成的事实层，属另一议题。

**`query_modules`**：填写规划中的模块名（如 `guard/IncompleteCryptographicVerification.ql`），并在条目注释注明该查询尚不存在。

---

## 6. 范围与后续

**本期只做目录扩展 + 一份 playbook。**

1. 新增上述 3 个 `catalog.yml` 条目（一次加齐——它们共同覆盖 13 个案例，且互相独立、无需分批验证）。
2. **只写 `TWE-GUARD-004` 的 playbook**——它由 2 个开发集案例支撑、边界最清晰。
3. Leakage 两条的 playbook 待 Guard 测量后再定（沿用 Flow 那轮"先拿信号"的做法）。

---

## 7. 验收标准

| # | 标准 |
|---|---|
| 1 | 3 个新条目通过 `twe` 包的加载与 `Validate`（id 格式、族、非空字段、无重复角色） |
| 2 | `catalog.yml` 文件头已修订，迁移条目与本地扩展条目可清晰区分；每个新条目注明其开发集依据 |
| 3 | `guard.yml`（TWE-GUARD-004）写成，通过 `twecontext.Load` + `Compile`（brief ≤250、detail ≤3000 token，fail closed） |
| 4 | 泄漏护栏的扫描范围**扩展到 `catalog.yml`**，且全部通过 |
| 5 | 新 playbook 的 `look_for` / `required_evidence` 为类级；每条内容可追溯至 enum registry、tee-audit 的 `.ql` 谓词、或某个**开发集** CVE 的 patch/oracle |
| 6 | 对照测量：Guard 族的 dev 与 holdout 案例各取样，比较有无 `guard.yml` 的表现；结论按前次标准判定（两侧都提升 → 学到类；仅 dev 提升 → 实例级污染，重写） |
| 7 | `go build ./...`、`go test ./...` 两模块全绿（既有 `internal/collabrun` live-endpoint 失败除外） |

---

## 8. 非目标

- **不新增 family**——7 族不变（§1 的判断：错位在条目层面）。
- **不扩展 `enum_registry.yml`**——单一定义点，波及事实层，属另一议题。
- **不编写 `.ql` 查询**——`query_modules` 填规划名即可，实现属 PR-05 范围。
- **本期不写 Leakage 的两份 playbook**——待 Guard 测量后决定。
- **不修改 tee-audit 迁移来的 16 个原始条目。**
- 不改动 benchmark 的 oracle、打分逻辑或已冻结的划分。

---

## 9. 已知风险

1. **这些条目是 TEECheck 自定义的，不具备 tee-audit 那样的上游背书。** 它们由 5 个真实 CVE 归纳而来，但归纳过程是我们做的。对外表述时应与迁移条目区分。
2. **`required_trustir` 可能引用不在枚举表中的角色**，使事实层无法产出对应事实。这在事实层仅有 1 个 operation 的现状下影响有限，但会在事实层扩建时显现。
3. **Guard 与 Leakage 的开发集样本量小**（各 2–3 个案例支撑一条）。归纳出的类可能过窄或过宽，只有 holdout 测量能暴露。
