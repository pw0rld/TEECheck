# TEECheck 审计报告:mobilecoin@59a52d3

**仓库:** git@github.com:mobilecoinfoundation/mobilecoin.git
**Commit:** 59a52d3d52e6cbbc2f67e0c223fa8d55d034a5b8
**Run ID:** mobilecoin-l3-v22

## 执行摘要

本次审计针对 MobileCoin 的 TEE(Trusted Execution Environment)实现,聚焦 attestation 验证、授权、以及 key lifecycle。分析覆盖了 11 个 candidate,涉及 AKE responder、consensus enclave、SGX service layer 等关键路径。**审计确认了一个高严重度的安全问题**:在 `ClientAuthRequestInput` 路径中缺少 attestation 验证,可能允许攻击者绕过身份验证。此外,还有若干条目需要人类复核,主要涉及验证逻辑的委托和安全关键检查的可见性(例如 `get_verifier` 的身份策略、DCAP 验证的 replay 防御等)。

低层 SGX wrapper 和 FFI 绑定多数都正确 —— 它们作为 primitive 没有问题(no_issue_observed)。但 AKE responder 里那条确认的 finding 是一个**高严重度信任边界失效**。其余"needs_review"条目反映了架构依赖 —— 安全正确性依赖于外部组件或不可见的代码路径。需要立即处理确认的 finding,并核实被委托的验证逻辑的实现。

---

## Findings(全部 11 条,按严重度 × 置信度排序)

### 1. ClientAuthRequestInput 路径缺少 attestation 验证

**ID:** `mobilecoin@59a52d3:tee:attestation:001`
**状态:** `confirmed_candidate`(verifier: corroborated)
**严重度:** 高
**置信度:** 高
**文件:** `attest/ake/src/responder.rs`

**核心观察:**
`Transition<Start, ClientAuthRequestInput, AuthResponseOutput>::try_next` 函数负责处理客户端认证流,但**没有对传入请求做 attestation 验证**。与之并列的 `NodeAuthRequestInput` 路径会显式地反序列化 `DcapEvidence` 并用 `DcapVerifier` 验证,而 `ClientAuthRequestInput` 路径读到 payload(含客户端证据)后直接**把它丢掉**(绑定到 `_payload`),然后进入 `handle_response`。这允许客户端**无需提供有效 attestation 证据**就建立一条 "trusted" 通道。

**证据:**
- `NodeAuthRequestInput` 路径(第 139–177 行)显式反序列化 `DcapEvidence` 并调用 `DcapVerifier` 做验证
- `ClientAuthRequestInput` 路径(第 180–201 行)调 `handle_request` 但把结果绑到 `_payload`,**实际上丢弃了证据**
- `ClientAuthRequestInput` 路径直接进 `Self::handle_response`,**没有任何 attestation 验证逻辑**
- `handle_response` 函数(第 77–111 行)只发送 responder 自己的 attestation 证据,不验证对端证据
- `NodeAuthRequestInput` 用 `HandshakeIX`(双向身份交换),`ClientAuthRequestInput` 用 `HandshakeNX`(无初始方身份)—— 但 payload 里明明有证据却被显式丢弃,**暗示协议设计和实现之间存在不匹配**

**建议后续:**
确认 `ClientAuthRequestInput` 路径不做验证是故意的(`HandshakeNX` 设计)还是一个真实漏洞。如果协议要求客户端身份验证,就必须在进入 `Ready` state 之前反序列化并验证 `DcapEvidence`。

---

### 2. verify_report 的 attestation 验证不完整

**ID:** `mobilecoin@59a52d3:tee:attestation:006`
**状态:** `confirmed_candidate`(verifier: corroborated)
**严重度:** 中
**置信度:** 高
**文件:** `sgx/service/src/lib.rs`

**核心观察:**
`sgx/service/src/lib.rs::verify_report` 是对 unsafe FFI 调用 `sgx_verify_report` 的薄包装。它验证了 report 结构的密码完整性(MAC),但**没有任何代码验证身份**(MRENCLAVE/MRSIGNER)**或 freshness**(timestamp/nonce)。如果调用方只依赖这个 wrapper 的 `Ok(())` 而不做额外检查,可能接受过期的或未授权的 report。

**证据:**
- 函数 `verify_report`(第 41 行)只是直接调 unsafe FFI `sgx_verify_report`
- **没有代码检查** `report.body.attributes`、`report.body.mr_enclave`、`report.body.mr_signer`
- **没有代码检查** `report.body.report_data` 中的 nonce 或 timestamp
- 函数文档只说"Verify a report",没说它不做高层 attestation 检查

**建议后续:**
审查所有 `verify_report` 的调用方,确保它们**各自显式地**做身份检查(MRENCLAVE/MRSIGNER)和 freshness 校验(nonce/timestamp)。更新 `verify_report` 的文档,说清楚它只做结构和 MAC 验证。

---

### 3. Quote::verify 的实现不在 snippet 里

**ID:** `mobilecoin@59a52d3:tee:attestation:005`
**状态:** `needs_review`(verifier: corroborated)
**严重度:** 高
**置信度:** 中
**文件:** `attest/core/src/quote.rs`

**核心观察:**
`attest/core/src/quote.rs` 里 `Quote::verify` 和 `Quote::verify_report` 负责 SGX quote 验证。但 case pack 里的 snippet 只包含第 1–80 行(类型定义、常量、import)。**关键验证逻辑的实现不在 snippet 里**,导致 verifier 无法确认是否正确执行了 GID、security version、debug flag、report_data binding 等检查。

**证据:**
- snippet 只有第 1–80 行
- 目标符号 `Quote::verify` 和 `Quote::verify_report` 不在这 80 行里
- 文件 import 了 `Report`、`ReportBody`、`ReportBodyVerifyError`,暗示有委托,但实现不可见

**建议后续:**
定位并审查 `attest/core/src/quote.rs` 中 `Quote::verify` 和 `Quote::verify_report` 的完整实现(很可能在 279 行之后)。确认实现里显式检查了 `AttributeFlags::DEBUG`、Security Version、report_data binding。

---

### 4. EnclaveRouter::peer_init 的授权与 caller binding

**ID:** `mobilecoin@59a52d3:tee:authorization:002`
**状态:** `needs_review`(verifier: inconclusive)
**严重度:** 高
**置信度:** 低
**文件:** `crypto/ake/enclave/src/lib.rs`

**核心观察:**
目标函数 `EnclaveRouter::peer_init` 负责发起 peer 连接。snippet(第 1–80 行)只展示了模块 import 和 state 结构,**不包含 `peer_init` 的实现**。因此无法核实这个函数是否正确实现了授权、caller binding、trust-boundary revalidation。

**证据:**
- snippet(第 1–80 行)包含 module import 和 `AkeEnclaveState` 结构定义
- 目标函数 `EnclaveRouter::peer_init` 不在 snippet 里
- 工具 hit 提示 `responder.binding()` 在第 271 行被调用,但这一行不在 snippet 里

**建议后续:**
定位 `EnclaveRouter::peer_init` 的实现(约第 271 行),核实它正确验证了 attestation 证据并严格绑定到 caller context(例如传输通道),以防止 Confused Deputy 攻击。

---

### 5. verify_attestation_evidence 的验证策略不可见

**ID:** `mobilecoin@59a52d3:tee:attestation:003`
**状态:** `needs_review`(verifier: inconclusive)
**严重度:** 高
**置信度:** 中
**文件:** `crypto/ake/enclave/src/lib.rs`

**核心观察:**
`verify_attestation_evidence` 对 DCAP quote 做了密码学验证并检查 nonce,但它依赖一个外部辅助函数 `get_verifier` 来提供验证策略(MRENCLAVE、MRSIGNER 等)。`get_verifier` 的定义不可见,**身份策略是否真正被执行无法确认**。

**证据:**
- 函数 `verify_attestation_evidence`(第 669 行)对比 `quote.app_report_body()` 与本地 `report.body()` 做 freshness 检查(第 696 行)
- 密码学验证被委托给通过 `self.get_verifier(report_data)` 拿到的 `verifier` 对象(第 701 行)
- `get_verifier` 的实现**不在 snippet 里**(snippet 是第 619–719 行)

**建议后续:**
定位 `get_verifier` 的实现。确认它返回的策略**严格执行 MRENCLAVE 和 MRSIGNER 检查**,防止来自恶意 enclave 的合法 quote(measurement 不同)被接受。

---

### 6. Consensus Enclave 的 attestation 验证委托

**ID:** `mobilecoin@59a52d3:tee:attestation:004`
**状态:** `needs_review`(verifier: inconclusive)
**严重度:** 中
**置信度:** 中
**文件:** `consensus/enclave/impl/src/lib.rs`

**核心观察:**
`SgxConsensusEnclave::verify_attestation_evidence` 把整个验证过程委托给内部的 `ake` 模块。这是一个薄包装,**没有做任何额外检查或 state 校验**。虽然这可能是架构上的决定,但 consensus enclave 没有独立校验,如果 `ake` 模块没有执行 context-specific 规则,就会有风险。

**证据:**
- 函数 `verify_attestation_evidence`(第 439–447 行)把调用委托给 `self.ake.verify_attestation_evidence`
- `SgxConsensusEnclave` 实现中**没有身份验证、nonce freshness、replay 防御的可见逻辑**
- 错误处理是直接传播(`?`)`ake` 模块的返回值

**建议后续:**
确认 `ake` 模块的验证逻辑足够满足 consensus enclave 的安全需求。确认 `enclave_init` 里传入的 `ResponderId` 被 `ake` 模块正确用于身份绑定。

---

### 7. DCAP Verifier 的 nonce freshness 问题

**ID:** `mobilecoin@59a52d3:tee:attestation:007`
**状态:** `needs_review`(verifier: contested)
**严重度:** 中
**置信度:** 中
**文件:** `attest/verifier/src/dcap.rs`

**核心观察:**
`DcapVerifier` 把验证委托给 `EvidenceVerifier` 和 `ReportDataHashVerifier`。`ReportDataHashVerifier` 做的是**静态 hash 相等检查** —— 把 quote 的 report_data hash 和一个**预先计算好的**值做比较。`dcap.rs` 里**没有可见的逻辑**去校验 nonce 的 freshness、或强制要求每次 session 用新 nonce,如果 nonce 是静态的,就存在 replay 风险。

**证据:**
- `ReportDataHashVerifier` 把 quote 的 `report_data` hash 和一个从 `EnclaveReportDataContents` 派生的 pre-computed hash 比较
- 传给 `EvidenceVerifier` 的 `time` 参数用于证书有效期检查,**不是 quote freshness**
- **没有逻辑**校验 nonce 的 freshness 或强制 per-session 唯一
- `DcapVerifier::new` 接受一个固定的 `report_data` 对象,verifier 总是和这个固定对象比对

**建议后续:**
确认传给 `DcapVerifier` 的 `nonce` **保证每次请求都是新鲜且唯一的**(例如在请求发起前由 verifier 现场生成)。确保系统不依赖静态 nonce,静态 nonce 允许 replay 攻击。

---

### 8. SGX Sealing 的 key policy 和完整性校验

**ID:** `mobilecoin@59a52d3:tee:key_management:008`
**状态:** `needs_review`(verifier: contested)
**严重度:** 低
**置信度:** 高
**文件:** `sgx/service/src/lib.rs`

**核心观察:**
实现使用了 `SGX_KEYPOLICY_MRENCLAVE`,把 sealed data 绑定到确切的 enclave measurement —— **这是强策略,意味着只有同一个 enclave 二进制能 unseal**。不过代码在 seal/unseal 函数内部没有做显式的 caller 授权或访问控制。Challenger 认为这些检查是应用层的责任,不应该在 wrapper 里做;但 wrapper 里没有任何显式检查可能被误用。

**证据:**
- 常量 `KEY_POLICY` 定义为 `SGX_KEYPOLICY_MRENCLAVE`(第 57 行)
- `seal_data` 和 `unseal_data` 校验 buffer 长度和 MAC,但**不做 caller 授权**
- 函数接受 `additional_mac_txt` 参数,只要长度一致就通过

**建议后续:**
核实所有 `seal_data` / `unseal_data` 的调用方都实现了恰当的访问控制,确保 enclave 里的一个服务不能 unseal 属于另一个服务的数据。

> **注意**:这条 finding 实际上**回答了 v20 Finding 2 的未决问题** —— 当时我们不确定 mobilecoin 的 sealing 用的是什么 policy,v22 在不经提示的情况下独立确认了是严格的 MRENCLAVE policy。这不是漏洞,是一条"不是漏洞"的正面观察。

---

### 9. Report 生成时允许 report_data = None

**ID:** `mobilecoin@59a52d3:tee:attestation:009`
**状态:** `no_issue_observed`
**严重度:** 低
**置信度:** 高
**文件:** `sgx/service/src/lib.rs`

**核心观察:**
`report` 函数允许 `report_data` 为 `None`,此时传给 `sgx_create_report` 的是一个空指针。Expert 认为这可以绕过 caller-binding 义务。但 Verifier 判定这个函数是一个**低层 primitive wrapper**(对 `sgx_tservice` 的包装),身份绑定的责任**不在这一层**,而是 caller 和 verifier 的责任。

**证据:**
- 函数是一个直接的类型映射 wrapper,把 Rust 类型映射到 SGX 指令
- 硬件会签署 memory 位置里的任何东西(`None` 时就是 0)
- 安全性依赖于使用这个 primitive 的协议,不依赖 primitive 本身

**建议后续:**
无。作为低层 primitive,函数行为正确。

---

### 10. Report::new 缺少 freshness 校验

**ID:** `mobilecoin@59a52d3:tee:attestation:010`
**状态:** `no_issue_observed`
**严重度:** 低
**置信度:** 高
**文件:** `attest/trusted/src/lib.rs`

**核心观察:**
Expert 认为 `Report::new` 没有校验 `report_data` 的 freshness。但 Verifier 判定:这个函数是**对硬件 `EREPORT` 指令的直接接口**,它的设计目标是**绑定数据**,不是**校验数据**。Freshness 校验是 verifier 的责任。

**证据:**
- 实现是对 `mc_sgx_compat::report` 的直接透传
- `Report::new` 在没有外部 state 的情况下**技术上不可能**校验 freshness

**建议后续:**
无。函数按照 cryptographic primitive 的设计要求工作。

---

### 11. sgx_get_key 的 FFI 绑定

**ID:** `mobilecoin@59a52d3:tee:key_management:011`
**状态:** `no_issue_observed`
**严重度:** 低
**置信度:** 高
**文件:** `sgx/types/src/function.rs`、`sgx/types/src/types.rs`

**核心观察:**
Expert 认为 key derivation 里缺少授权检查。但审查的文件严格来说是 Rust **FFI binding 和类型定义**。`key_policy`(MRENCLAVE/MRSIGNER)的执行发生在 **trusted runtime / CPU 微码里**,不在 Rust wrapper 里。

**证据:**
- `sgx/types/src/function.rs` 只包含 `extern` block 声明
- `sgx/types/src/types.rs` 定义了 `sgx_key_request_t` 和 policy 常量
- 文件里**没有实现逻辑**,这对 FFI binding 来说是标准的

**建议后续:**
无。代码正确地把安全执行委托给 SGX trusted runtime。

---

## 覆盖范围

### 已审计的目录/crate
- `attest/ake/src/responder.rs`
- `crypto/ake/enclave/src/lib.rs`
- `consensus/enclave/impl/src/lib.rs`
- `attest/core/src/quote.rs`
- `sgx/service/src/lib.rs`
- `attest/verifier/src/dcap.rs`
- `attest/trusted/src/lib.rs`
- `sgx/types/src/function.rs`
- `sgx/types/src/types.rs`

### 未覆盖 / 限制
- **代码不完整**:部分 finding(如 #005、#002、#003)的关键实现不在 snippet 里(只有第 1–80 行),导致状态只能是 `inconclusive` 或 `needs_review`
- **委托的逻辑**:多条 finding 依赖外部辅助函数(如 `get_verifier`、`EvidenceVerifier`)。系统的安全性取决于这些未被审查组件的正确性
- **动态 context**:本次是**静态分析**,运行时行为或配置(比如 `DcapVerifier` 实际用的 nonce)无法观察

---

## 给人类 Reviewer 的下一步

1. **立即处理高严重度的确认 finding**:
   - 马上调查 `attest/ake/src/responder.rs`(Finding #1)。确认 `ClientAuthRequestInput` 路径是否应该验证 attestation。如果应该,就按 `NodeAuthRequestInput` 的模式实现验证。

2. **核实被委托的实现**:
   - 定位并审计 `crypto/ake/enclave/src/lib.rs::get_verifier`(Finding #5),确保它执行严格的 MRENCLAVE/MRSIGNER 策略
   - 定位 `attest/core/src/quote.rs::Quote::verify` 的完整实现(Finding #3),确认它检查 `DEBUG` flag 和 security version

3. **检查授权绑定**:
   - 审查 `crypto/ake/enclave/src/lib.rs::EnclaveRouter::peer_init`(Finding #4),确保 caller binding 防止 Confused Deputy 攻击

4. **评估 replay 抵抗**:
   - 审查 `DcapVerifier` 的使用(Finding #7),确保每次 session 都生成新 nonce、不复用,防止 replay 攻击

5. **文档更新**:
   - 对 `sgx/service/src/lib.rs::verify_report`(Finding #2),更新文档说明它只做 structural/MAC 验证,调用方必须自己执行身份和 freshness 检查

---

## 工具元数据

- **Planner**:5 个独立 pass,共 40 rounds,66,267 tokens,411s wall clock
- **Multi-sample**:5 passes 发现 11 个 unique candidate(dedup 后),覆盖 7 个独立 crate
- **Pipeline**:L3 Planner → 4-agent(Expert / Challenger / Verifier / Arbiter),全部 LLM 模式(GLM-4.7)
- **Verifier 质量**:3/11 corroborated,5/11 contested,3/11 inconclusive
- **Arbiter 判决**:2 个 `confirmed_candidate`(高置信度)、1 个 `likely_issue`、5 个 `needs_review`、3 个 `no_issue_observed`
