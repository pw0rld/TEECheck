# 私有安全通报草稿：PHALA-DCAP-ATTRS

**发送渠道**：GitHub Security Advisory，不建议公开 Issue。  
**建议提交地址**：https://github.com/phala-network/phala-blockchain/security/advisories/new  
**状态**：CVE 预申请候选，需维护者确认受影响版本和生产使用路径。  

## 表单字段

**标题**

SGX 远程证明信任策略未校验 `misc_select` 和 `attributes`，可能导致 debug 或配置不符合策略的 enclave 被信任

**严重性，暂定**

高危，条件是该验证器输出或运行时身份 / 允许列表键被用于生产 worker 准入、密钥交接或其他信任决策。暂定：

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1

如果攻击者必须已经控制允许列表中的签名身份、生产配置不允许调试构建、当前生产路径已迁移，或下游还有独立属性策略校验，严重性应下调。

**CWE 候选**

- CWE-295 证书验证不当
- CWE-345 数据真实性验证不足
- CWE-693 保护机制失效

**受影响产品**

`phala-network/phala-blockchain`

**受影响版本**

待确认。当前复核锚点为 commit `654b1b6`。请维护者确认 `main`、最新 release tag，以及首次引入该行为的版本范围。

## 正文，可直接粘贴

### 摘要

我们报告 `phala-network/phala-blockchain` 中一个潜在的 SGX 远程证明策略绕过问题。直接问题位于 DCAP 验证器：`crates/sgx-attestation/src/dcap.rs` 会执行 quote collateral、证书链和签名验证，但明确跳过 SGX report 中 `misc_select` 和 `attributes` 字段的验证。

更广泛的模式是，pRuntime 的信任身份 / 允许列表键看起来由 `mr_enclave`、`isv_prod_id`、`isv_svn` 和 `mr_signer` 构造，但没有包含 `attributes` 和 `misc_select`。我们在 DCAP 路径、IAS 派生路径、旧版 IAS 路径，以及基于本地证明的密钥交接检查中都观察到了同样的身份构造方式。

`attributes` 和 `misc_select` 是安全相关字段，因为它们编码 enclave 运行时配置，包括调试模式和其他 SGX 属性位。如果该验证器输出或允许列表身份被用于生产 worker 准入或运行时信任决策，那么一个 measurement / signer identity 被接受、但 attributes 违反生产策略的 enclave，可能会被当作生产可信 enclave。

### 受影响组件

- 仓库：`phala-network/phala-blockchain`
- 已复核 commit：`654b1b6`
- 主要文件：`crates/sgx-attestation/src/dcap.rs`
- 主要函数：`verify`
- 主要复核链接：https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/sgx-attestation/src/dcap.rs#L27-L53

出现相同运行时身份构造方式的相关路径：

- `pallets/phala/src/utils/attestation.rs::validate_dcap`
- `pallets/phala/src/utils/attestation.rs::IasFields::extend_mrenclave`
- `pallets/phala/src/utils/attestation_legacy.rs::IasFields::extend_mrenclave`
- `crates/phactory/src/prpc_service.rs::measurement_of`
- `crates/sgx-api-lite/src/lib.rs::verify`

复核链接：

- `validate_dcap`：https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation.rs#L205-L264
- `IasFields::extend_mrenclave`：https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation.rs#L102-L109
- legacy `IasFields::extend_mrenclave`：https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation_legacy.rs#L97-L104
- `measurement_of`：https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/phactory/src/prpc_service.rs#L2312-L2322
- `sgx_api_lite::verify`：https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/sgx-api-lite/src/lib.rs#L102-L123

### 技术细节

已复核的 DCAP 验证路径包含明确注释，说明这些字段被跳过：

```rust
// Seems we verify MR_ENCLAVE and MR_SIGNER is enough
// skip verify_misc_select_field
// skip verify_attributes_field
```

该函数继续执行 DCAP collateral、证书和签名相关验证，并用 `mr_enclave`、`isv_prod_id`、`isv_svn`、`mr_signer` 等身份字段构造 `pruntime_hash`。但是，已复核路径没有强制执行预期的 `attributes` mask，也没有执行 `misc_select` policy。

外层 DCAP 验证路径 `pallets/phala/src/utils/attestation.rs::validate_dcap` 调用 `sgx_attestation::dcap::verify` 后，只检查：

- `pruntime_hash` 是否在 `pruntime_allowlist` 中；
- `report_data[..32]` 是否匹配预期的 `user_data_hash`；
- `tcb_status` 和 `advisory_ids` 是否映射到可接受的 confidence level。

我们没有在该外层路径中观察到补偿性的 `attributes` 或 `misc_select` policy 检查。

同样的遗漏也出现在 IAS 派生身份模型中。`crates/sgx-attestation/src/ias.rs::EnclaveQuoteBody` 会解析 `misc_select` 和 `attributes`，但 `pallets/phala/src/utils/attestation.rs::IasFields` 只保留 `mr_enclave`、`mr_signer`、`isv_prod_id`、`isv_svn`、`report_data` 和 `confidence_level`。随后 `IasFields::extend_mrenclave()` 只用如下字段构造允许列表键：

```rust
mr_enclave || isv_prod_id || isv_svn || mr_signer
```

旧版 IAS 路径 `pallets/phala/src/utils/attestation_legacy.rs` 使用同样的 `extend_mrenclave()` 结构。

pRuntime 密钥交接代码也看起来复用了这个身份模型。`crates/phactory/src/prpc_service.rs::measurement_of(report)` 从本地证明 report 中取 `mr_enclave`、`mr_signer`、`isv_prod_id` 和 `isv_svn` 构造运行时 measurement，但没有包含 `report.body.attributes` 或 `report.body.misc_select`。`sgx_api_lite::verify(report)` 验证本地 report MAC，但不强制执行生产 enclave 属性策略。

这与完整的远程证明策略验证不同。quote 的密码学有效性只能证明 quote 格式正确且由平台签署；依赖方仍然需要判断 enclave 配置是否符合生产策略。在生产 SGX 部署中，debug enclave 通常不应被信任，因为调试模式会改变 enclave 内存机密性的安全假设。

### 安全影响

如果该验证器或运行时身份位于生产信任路径上，攻击者可能能够提交一个 measurement / signer identity 通过允许列表检查、但 SGX attributes 违反生产策略的证明，例如设置 debug bit。

潜在影响包括：

- debug enclave 被接受为生产可信 worker；
- 含有非默认或被禁止 SGX attributes 的 enclave 被准入；
- 下游信任决策依赖一个没有执行完整证明策略的验证结果；
- 同一个不完整身份被复用到 DCAP、IAS 派生、旧版 IAS 和本地交接检查中；
- 如果密钥、任务或信任权限被 provision 给该 enclave，可能导致机密性和完整性损失。

实际可利用性取决于部署细节。特别需要确认受影响验证器和允许列表身份是否仍用于生产 worker 准入 / 交接决策，以及下游代码是否独立执行 `attributes` / `misc_select` 校验。

### 攻击前提

- 攻击者可以提交或影响被该验证器消费的 DCAP quote。
- 被提交 quote 能通过 collateral、证书、签名和身份检查。
- quote 包含生产策略应拒绝的 `attributes` 或 `misc_select` 值。
- 验证结果或派生 runtime hash 被信任决策消费，并且之后没有强制校验这些被跳过字段。

### 复现计划

目前尚未附带完整 PoC quote。预期复现路径如下：

1. 生成或获取一个 DCAP quote，使其 `mr_enclave` / `mr_signer` 满足配置的 allowlist。
2. 确保该 quote 携带不允许的 SGX attribute，例如 `SGX_FLAGS_DEBUG`。
3. 将 quote 和 collateral 提交给 `crates/sgx-attestation/src/dcap.rs::verify`。
4. 观察验证不会因为 `attributes` 或 `misc_select` 而失败。
5. 确认返回的 `ConfidentialReport`、`pruntime_hash` 或派生运行时身份是否在没有进一步属性校验的情况下，被 worker 准入、密钥交接或其他信任门使用。

如有帮助，我们可以配合提供私有 negative fixture 或 PoC quote。

### 修复建议

- 使用 mask 对 `misc_select` 和 `attributes` 增加显式 policy 检查。
- 除非配置显式允许，否则生产环境拒绝 debug enclave。
- 将 `attributes` / `misc_select` 纳入 pRuntime 信任身份，或在任何允许列表查询前强制校验这些字段。
- 为 debug enclave 和意外属性位增加反向测试。
- 为 DCAP 和 IAS 派生 report body 增加测试，并覆盖依赖 `measurement_of(report)` 的本地证明交接路径。
- 文档化所有有意允许的非默认 SGX attributes 以及允许原因。
- 确保所有下游信任决策要么消费已经完整策略校验的结果，要么自行执行显式策略校验。

### 需要维护者确认的问题

1. `crates/sgx-attestation/src/dcap.rs::verify` 是否用于当前生产 worker 准入 / 信任决策路径？
2. 该路径是否已经在 `main` 或最近 release 中被新的远程证明栈取代？
3. 生产部署中是否会有意接受 debug enclave？
4. `PRuntimeAllowList` 的语义是只授权 measurement / signer identity，还是授权完整生产 enclave 配置？
5. 是否有任何下游代码针对 DCAP、IAS 派生、旧版 IAS 和本地交接路径独立执行 `attributes` 和 `misc_select` 策略？
6. `attributes` / `misc_select` 是否应纳入 runtime hash，或是否应在查询 allowlist 前被强制检查？
7. 哪个 release 首次引入被跳过的检查和当前运行时身份构造方式？
8. 在 CVE 分配或 advisory 发布前，维护者是否希望先接收私有 PoC fixture？

## 发送前检查清单

- [ ] 重新确认 commit `654b1b6` 的 permalink 仍能打开。
- [ ] 检查 `main` 和最新 release tag 是否仍有相同逻辑。
- [ ] 决定是否附带 debug-attribute negative fixture。
- [ ] 补充当前 `main` 上 `validate_dcap`、`extend_mrenclave`、`measurement_of` 是否仍为相同字段集合。
- [ ] 填写报告人 credit / handle。
- [ ] 约定披露窗口，默认可用 90 天。
