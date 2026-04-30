# 基于 Example 复核的 CVE 申请草稿

这些草稿用于人工 review 和负责任披露前的准备工作。它们不是最终漏洞结论。每个草稿都明确列出在提交给 CNA、GitHub Security Advisory 或上游安全联系人之前仍需确认的事项。

## 提交准备度汇总

| 草稿 | 候选问题 | 准备度 | 建议 |
| --- | --- | --- | --- |
| PHALA-DCAP-ATTRS | Phala Blockchain DCAP verifier 跳过 `misc_select` 和 `attributes` 检查 | 高 | 最适合优先披露的候选。 |
| PHALA-MASTERKEY-DOS | Phala Blockchain master key unseal 路径在 sealed data 异常时 panic | 中 | 如果攻击者写入/破坏 sealed storage 的前提在部署中成立，可以提交。 |
| QOS-UNVERIFIED-TIME | qos `timestamp_ms` 信任 unsafe parse 出来的 attestation doc timestamp | 中低 | 需要 PoC 证明攻击者能影响 timestamp 或突破 trust boundary。 |
| QOS-NONCELESS-ATTESTATION | qos post-boot attestation request 使用 `nonce: None` | 中低 | 需要 relying-party replay PoC；如果 timestamp/public key binding 足够，可能只是设计风险。 |

## 草稿 PHALA-DCAP-ATTRS

### 标题

Phala Blockchain SGX DCAP verifier 未校验 enclave attributes 和 `misc_select`，可能允许 debug 或配置不符合预期的 enclave 绕过 policy。

### 受影响产品

- 项目：`phala-network/phala-blockchain`
- 已复核 commit：`654b1b6`
- 受影响组件：`crates/sgx-attestation/src/dcap.rs`
- 受影响函数：`verify`

受影响版本范围尚未确定。提交前需要确认第一个引入该行为的 commit，以及当前 `main` 或已发布 tag 是否仍包含相同行为。

### 漏洞类型

- CWE 候选：CWE-295 Improper Certificate Validation、CWE-345 Insufficient Verification of Data Authenticity，或 CWE-693 Protection Mechanism Failure。
- 类型：远程证明 policy 校验不完整。

### 摘要

SGX DCAP 验证路径会解析并加密校验 quote collateral，但明确跳过 SGX report `misc_select` 和 `attributes` 的校验。这些字段编码 enclave 配置属性，例如 debug mode 和其他 attribute bits。如果 verifier 输出被用于信任 worker/runtime，则带有不允许属性的 enclave quote 可能被接受为有效。

### 技术细节

在 `crates/sgx-attestation/src/dcap.rs` 中，verifier 的验证路径包含如下安全相关注释：

```rust
// Seems we verify MR_ENCLAVE and MR_SIGNER is enough
// skip verify_misc_select_field
// skip verify_attributes_field
```

该函数继续执行 collateral/certificate/signature 检查，并随后用 `mr_enclave`、`isv_prod_id`、`isv_svn` 和 `mr_signer` 构造 `pruntime_hash`，但没有强制校验预期的 `attributes` mask 或 `misc_select` policy。

已复核源码：

- <https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/sgx-attestation/src/dcap.rs#L27-L53>

### 安全影响

如果攻击者能够提交一个 measurement/signing identity 符合预期、但 enclave 配置不符合 policy 的 DCAP quote，该 quote 可能被 verifier 接受。最重要的疑似影响是：debug enclave 或具有非预期 SGX attributes 的 enclave 可能被当作生产可信代码接受。

实际影响取决于：

- 生产部署是否依赖该 verifier 进行 worker admission 或 trust decision。
- 在 Phala 的威胁模型中，仅校验 enclave identity 是否被认为足够。
- 在受影响部署中，debug mode 或其他 forbidden attributes 是否能与原本允许的 `mr_enclave`/`mr_signer` 组合出现。

### 攻击前提

- 攻击者可以向 verifier 提交 DCAP quote。
- 提交的 quote 通过 collateral/signature 和 measurement 检查。
- quote 包含生产 policy 应拒绝的 attributes 或 `misc_select` 值。
- 下游 trust decision 使用 verifier 结果，且没有独立强制校验这些字段。

### PoC 大纲

1. 生成或获取一个 DCAP quote，其 `mr_enclave`/`mr_signer` 满足 allowlist，但 `attributes.flags` 包含不允许的 bit，例如 DEBUG。
2. 将 quote 和 collateral 提交给受影响的 `verify` 函数。
3. 观察验证不会因为 `attributes` 或 `misc_select` 而拒绝。
4. 确认返回的 `ConfidentialReport` 或 verifier 输出被调用方当作可接受结果。

该 PoC 仍需在受影响 build 上实现。

### 修复建议

- 使用 mask 为 `misc_select` 和 `attributes` 增加显式 policy 检查，类似 Intel DCAP/QVL 的 policy validation。
- 除非显式配置允许，否则生产环境拒绝 debug enclave。
- 增加 negative fixture 测试，覆盖 debug 和 attribute 不符合预期的情况。
- 文档化所有有意允许的非默认 attributes。

### 暂定严重性

如果 verifier 输出用于生产 trust gate，则为高危。暂定 CVSS：

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1

如果攻击者必须已经控制允许的 signer 或本地部署配置，则严重性应下调。

### 披露前问题

- 该 verifier 是否用于生产 worker admission？
- 是否存在任何地方显式允许 debug enclave 或非默认 SGX attributes？
- 哪个 release 首次引入该 skip？
- 该问题是否已经被修复，或被新的 attestation stack 取代？

## 草稿 PHALA-MASTERKEY-DOS

### 标题

Phala Blockchain master key recovery 路径在 sealed key data 异常时 panic，导致拒绝服务。

### 受影响产品

- 项目：`phala-network/phala-blockchain`
- 已复核 commit：`654b1b6`
- 受影响组件：`crates/phactory/src/system/master_key.rs`
- 受影响函数：`seal`、`try_unseal`

受影响版本范围尚未确定。

### 漏洞类型

- CWE 候选：CWE-248 Uncaught Exception、CWE-755 Improper Handling of Exceptional Conditions。
- 类型：安全关键状态恢复过程中的 panic 导致拒绝服务。

### 摘要

master key sealing/unsealing 代码在恢复路径上使用 `expect` 和 `assert!`。如果 sealed master key storage 格式异常、被破坏或完整性签名无效，进程会 panic，而不是返回可恢复错误。在攻击者能够影响 sealed storage 或触发损坏数据恢复的部署中，这可能导致 TEE service 拒绝服务。

### 技术细节

已复核代码包含：

- `sys.seal_data(...).expect("Seal master key failed")`
- `sys.unseal_data(...).expect("Unseal master key failed")`
- `MasterKeySeal::decode(...).expect("Failed to decode sealed master key")`
- `assert!(identity_key.verify_data(...), "Broken sealed master key")`
- `assert!(identity_key.verify_data(...), "Broken sealed master key history")`

已复核源码：

- <https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/phactory/src/system/master_key.rs#L45-L117>

`try_unseal` 上方源码注释也说明该函数 “could panic a lot”。

### 安全影响

格式异常或损坏的 sealed key data 可能在 key recovery 期间终止进程。这会阻止服务启动或恢复，并造成可用性损失。如果 sealed storage 位于 enclave trust boundary 之外，并可能被不可信 host、被攻陷 volume 或故障注入修改，则该漏洞更强。

### 攻击前提

- 攻击者可以修改、损坏、替换或截断 sealed master key file，或可以影响 sealing backend 返回异常数据。
- 服务在启动、handover 或 recovery 期间调用 `try_unseal`。
- panic 会终止或重启服务，并造成实际 outage。

### PoC 大纲

1. 定位 `master_key_file_path` 使用的 sealed master key file。
2. 用随机字节替换它，或构造一个编码合法但签名无效的 `MasterKeySeal`。
3. 启动或触发调用 `try_unseal` 的组件。
4. 观察程序在 decode 或 signature verification 处 panic，而不是返回错误。

该 PoC 仍需在受影响部署上实现。

### 修复建议

- 将 `seal` 和 `try_unseal` 改为返回 `Result`。
- 用 typed errors 替换 `expect` 和 `assert!`。
- 将无效 sealed data 视为安全事件，并 fail closed，但不要让进程 panic。
- 增加测试覆盖 malformed sealed data、无效签名、截断文件和 sealing backend failure。

### 暂定严重性

严重性取决于攻击者对 sealed storage 的访问能力，中到高。对于本地不可信存储修改，暂定 CVSS：

`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = 5.5

如果远程或低权限攻击者能够影响 sealed file，严重性可能更高。

### 披露前问题

- 在部署威胁模型中，sealed storage 是否被视为 attacker-controlled 或 host-controlled？
- panic 会杀死 enclave/service，还是会触发干净恢复？
- master key storage 是否通过文件系统权限、measured storage 或 host policy 保护？

## 草稿 QOS-UNVERIFIED-TIME

### 标题

QuorumOS 从未验证签名的 unsafe-parsed Nitro attestation document 中派生 trusted current time。

### 受影响产品

- 项目：`tkhq/qos`
- 已复核 commit：`df1e355`
- 受影响组件：`src/qos_nsm/src/nsm.rs`
- 受影响函数：`NsmProvider::timestamp_ms` for `Nsm`

受影响版本范围尚未确定。

### 漏洞类型

- CWE 候选：CWE-345 Insufficient Verification of Data Authenticity、CWE-347 Improper Verification of Cryptographic Signature、CWE-829 Inclusion of Functionality from Untrusted Control Sphere。
- 类型：信任未验证 attestation metadata 来做 freshness decision。

### 摘要

`timestamp_ms` 实现会请求一个不带 nonce 的 Nitro attestation document，使用 `unsafe_attestation_doc_from_der` 解析它，并在未验证 attestation document 签名或证书链的情况下返回其中 timestamp。该 timestamp 随后被用作验证另一个 attestation document 的当前时间。如果攻击者能够影响 NSM provider response，就可能在 attestation verification 中造成 backdating 或 time manipulation。

### 技术细节

在 `src/qos_nsm/src/nsm.rs` 中，`timestamp_ms` 请求一个 attestation document：

```rust
types::NsmRequest::Attestation {
    user_data: None,
    nonce: None,
    public_key: None,
}
```

随后用如下调用解析返回的 DER：

```rust
nitro::unsafe_attestation_doc_from_der(&document)?
```

并返回：

```rust
Ok(attestation_document.timestamp)
```

已复核源码：

- <https://github.com/tkhq/qos/blob/df1e355/src/qos_nsm/src/nsm.rs#L41-L54>

该 timestamp 会被 `key.rs` 中的 `verify_and_extract_attestation_doc_from_der` 消费，用于派生 attestation verification 的 `current_time_seconds`：

- <https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/key.rs#L280-L290>

### 安全影响

如果 `NsmProvider` 输出可被伪造、替换，或可以由不可信 provider 实现，verifier 在检查 attestation validity window 时可能使用攻击者控制的时间。这可能导致 stale 或 expired attestation documents 被接受，或有效 document 被拒绝。

如果生产 `Nsm` 实现始终直接与可信本地 Nitro Secure Module 通信，且 OS/device boundary 被视为可信，则影响较低。

### 攻击前提

- 攻击者可以影响 `nsm_process_request` 输出、替换 `NsmProvider`、攻陷 NSM device path，或以其他方式控制传给 `unsafe_attestation_doc_from_der` 的 DER document。
- 返回的 timestamp 被用于验证安全敏感的远程 attestation document。
- 系统不存在独立 trusted time source 或 monotonicity check。

### PoC 大纲

1. 实现或注入恶意 `NsmProvider`，使其返回包含伪造或过期 timestamp 的 attestation response。
2. 触发 `verify_and_extract_attestation_doc_from_der`。
3. 证明伪造 timestamp 被接受为 `current_time_seconds`。
4. 展示一个本应 expired 或超出有效时间窗口的 attestation document 被接受。

提交 CVE 前需要该 PoC；否则该问题可能被归类为 hardening concern。

### 修复建议

- 不要从 unsafe-parsed attestation document 派生 trusted time。
- 使用符合威胁模型的 trusted monotonic 或 platform time source。
- 如果必须使用 attestation document，则在信任 timestamp 前验证其签名和证书链。
- 为本地 attestation request 增加 nonce/challenge binding。
- 约束或封闭 `NsmProvider` 抽象，避免生产代码使用不可信 provider 提供 time。

### 暂定严重性

如果攻击者可以影响 `NsmProvider` 或 NSM response，则为中危。暂定 CVSS：

`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = 5.5

如果远程路径可以影响 provider response，严重性可能升高；如果 NSM/OS access 完全可信，则严重性下降。

### 披露前问题

- 是否有任何生产代码可以使用非硬件 `NsmProvider`？
- `/dev/nitro_enclaves` 或等价 NSM access 是否属于 trusted computing base？
- 哪些安全决策依赖 `timestamp_ms`？
- 架构中是否已有 trusted time source？

## 草稿 QOS-NONCELESS-ATTESTATION

### 标题

QuorumOS post-boot Nitro attestation documents 生成时未包含 verifier nonce，削弱 replay resistance。

### 受影响产品

- 项目：`tkhq/qos`
- 已复核 commit：`df1e355`
- 受影响组件：`src/qos_core/src/protocol/services/attestation.rs`
- 受影响函数：`live_attestation_doc`、`get_post_boot_attestation_doc`

受影响版本范围尚未确定。

### 漏洞类型

- CWE 候选：CWE-294 Authentication Bypass by Capture-replay、CWE-345 Insufficient Verification of Data Authenticity。
- 类型：远程证明缺少 challenge freshness。

### 摘要

post-boot attestation request 包含应用层 `user_data` 和 ephemeral public key，但设置 `nonce: None`。如果没有 verifier-provided nonce 或等价 challenge，relying party 可能无法区分 fresh attestation document 和针对同一 manifest/key material 的 replayed document。

### 技术细节

在 `src/qos_core/src/protocol/services/attestation.rs` 中，`get_post_boot_attestation_doc` 构造：

```rust
NsmRequest::Attestation {
    user_data: Some(manifest_hash),
    nonce: None,
    public_key: Some(ephemeral_public_key),
}
```

已复核源码：

- <https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/attestation.rs#L23-L33>

### 安全影响

如果 relying party 将该 attestation document 作为当前 live enclave instance 的证明，攻击者可能 replay 针对同一 manifest 的旧有效 document。这可能削弱 provisioning 或 post-boot verification 期间的 freshness guarantee。

影响取决于其他 signed fields 是否提供足够 freshness：

- Nitro attestation documents 包含 timestamps。
- `public_key` 将 attestation 绑定到 ephemeral key。
- 如果 ephemeral key 每次 boot 都变化，且 relying party 只加密给 attested public key，replay 的可利用性可能较低。

### 攻击前提

- 攻击者可以捕获一个先前有效的 post-boot attestation document。
- relying party 在没有 challenge nonce 或严格 freshness window 的情况下接受 attestation。
- replayed document 的 `user_data` 和 `public_key` 对攻击者或目标 workflow 仍然有用。

### PoC 大纲

1. 捕获某个 manifest 的有效 post-boot attestation document。
2. 在之后的 provisioning 或 verification flow 中向 relying party replay 该 document。
3. 证明 relying party 在没有 fresh challenge nonce 的情况下接受它。
4. 展示具体安全后果，例如将 secret provision 给非预期或 stale instance。

提交 CVE 前需要该 PoC。如果无法证明 relying-party acceptance，该问题可能只适合作为架构 hardening 建议。

### 修复建议

- 在 `live_attestation_doc` 和 `get_post_boot_attestation_doc` 中接受 verifier-provided nonce/challenge。
- 将 nonce 放入 `NsmRequest::Attestation`。
- 要求 relying party 拒绝缺失、重复或过期 nonce。
- 保留 `user_data` 和 `public_key` binding，但不要把它们当作 freshness 的替代品。

### 暂定严重性

根据 relying-party 行为，中到高。如果 replay 可以导致 secret provisioning 到 stale 或 unauthorized context，暂定 CVSS：

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1

如果 timestamps 和 ephemeral-key binding 能阻止实际 replay，严重性应下调，或不应作为 CVE 提交。

### 披露前问题

- 哪些 relying party 消费 `live_attestation_doc` 输出？
- relying party 是否强制 timestamp freshness？
- ephemeral public key 是否每次 boot 都重新生成且绝不复用？
- replayed document 是否会导致 key shares 或 secrets 被释放？

