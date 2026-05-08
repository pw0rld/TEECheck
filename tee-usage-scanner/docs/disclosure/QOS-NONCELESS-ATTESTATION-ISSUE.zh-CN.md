# 私有安全通报草稿：QOS-NONCELESS-ATTESTATION

**发送渠道**：GitHub Security Advisory，不建议公开 Issue。  
**建议提交地址**：https://github.com/tkhq/qos/security/advisories/new  
**状态**：CVE 预申请候选；依赖方路径已定位，PoC 会决定是否达到 CVE 级别。  

## 表单字段

**标题**

Post-boot Nitro 远程证明文档未绑定验证方 nonce，可能在依赖方流程中削弱重放防护

**严重性，暂定**

条件性高危。若重放可导致密钥配置或仲裁份额释放到过期或未授权上下文，暂定：

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1

如果时间戳窗口、临时密钥绑定或依赖方行为已经阻止实际重放，严重性应下调，甚至不应作为 CVE 提交。

**CWE 候选**

- CWE-294 通过捕获重放绕过认证
- CWE-345 数据真实性验证不足

**受影响产品**

`tkhq/qos`

**受影响版本**

待确认。原始复核锚点为 commit `df1e355`。该行为此前在 main commit `b2ea15b` 上已再次确认仍存在相同代码形态；提交前仍需重新确认当前 `main` 和最新 release tag。

## 正文，可直接粘贴

### 摘要

我们报告 `tkhq/qos` 的 post-boot Nitro 远程证明流程中一个潜在重放弱点。`get_post_boot_attestation_doc` 构造 Nitro 远程证明请求时使用 `nonce: None`。该请求包含 `user_data` 和临时公钥，但没有包含由验证方提供的挑战值。

由于签名的远程证明文档中没有绑定验证方 nonce，一个将该文档当作“当前存活的 enclave 实例”证明的依赖方，可能无法区分新生成的远程证明文档与针对同一 manifest 和公钥捕获后重放的旧文档。

### 受影响组件

- 仓库：`tkhq/qos`
- 已复核 commit：`df1e355`
- 文件：`src/qos_core/src/protocol/services/attestation.rs`
- 函数：`live_attestation_doc`、`get_post_boot_attestation_doc`
- 复核链接：https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/attestation.rs#L23-L33

相关复核链接：

- `verify_attestation_doc_against_user_input` 拒绝已存在的 nonce：https://github.com/tkhq/qos/blob/df1e355/src/qos_nsm/src/nitro/mod.rs#L67-L148
- `proxy_re_encrypt_share` 验证远程证明文档并取出临时公钥：https://github.com/tkhq/qos/blob/b2ea15b/src/qos_client/src/cli/services.rs#L1239-L1291
- `attestation_doc_from_der` 验证证书链和 COSE 签名：https://github.com/tkhq/qos/blob/b2ea15b/src/qos_nsm/src/nitro/mod.rs#L186-L221

### 技术细节

已复核代码如下构造 Nitro 远程证明请求：

```rust
NsmRequest::Attestation {
    user_data: Some(manifest_hash),
    nonce: None,
    public_key: Some(ephemeral_public_key),
}
```

`user_data` 将远程证明文档绑定到 manifest 状态，`public_key` 将文档绑定到临时密钥。但是这两个字段都不是验证方现场生成的新鲜性挑战。它们提供的是状态绑定和密钥绑定，不提供依赖方会话级新鲜性。

在验证端，当前验证方行为看起来会拒绝包含 nonce 的文档。相关验证函数 `verify_attestation_doc_against_user_input` 会执行 PCR 和 `user_data` 检查，但包含一个分支：如果远程证明文档中存在 nonce，就返回 `UnexpectedAttestationDocNonce`。这意味着生成端和验证端当前共同采用了“无 nonce”的协议约定。

### 已定位的依赖方路径

此前在 main commit `b2ea15b` 上做的代码级复核定位到 `src/qos_client/src/cli/services.rs` 中四个 `verify_attestation_doc_against_user_input` 调用点：

- `services.rs:487`：创世仪式输出验证
- `services.rs:666`：`after_genesis`，从磁盘重新读取远程证明文档之前
- `services.rs:1166`：`boot_standard`，收到 `BootStandardResponse` 之后
- `services.rs:1267`：`proxy_re_encrypt_share`，密钥或份额释放路径

最强的疑似影响位于 `proxy_re_encrypt_share`：验证通过后，成员会把自己的仲裁份额重新加密给从远程证明文档中取出的临时公钥。

该路径的关键安全属性是：份额释放不是只验证 PCR / manifest，还会把份额交给远程证明文档中携带的公钥。如果文档是旧文档，且攻击者保留了对应私钥，那么重放的安全后果会变得具体。

### 安全影响

如果依赖方在不要求新鲜挑战的情况下接受此前捕获的 post-boot 远程证明文档，那么在有效时间窗口内可能存在重放风险。

最高影响场景如下：

1. 攻击者此前访问过一个合法 enclave 实例，其 PCR 与目标 manifest 匹配。
2. 攻击者保留了该旧实例的临时私钥。
3. 攻击者捕获了对应的 post-boot 远程证明文档。
4. 在 Nitro 终端实体证书有效窗口内，攻击者向依赖方重放旧远程证明文档。
5. 依赖方验证 PCR 和 `user_data`，但没有 nonce 要求，因此接受该文档。
6. 在 `proxy_re_encrypt_share` 流程中，依赖方将仲裁份额重新加密给被重放文档中的公钥，而攻击者仍控制对应私钥。

这需要几个非平凡前提，但这正是验证方提供的 nonce 应该防止的风险类型。

### 观察到的 freshness 限制

当前验证方看起来依赖证书链有效时间，而不是依赖远程证明文档自身签名时间戳，也不是依赖验证方挑战。证书链有效期可以限制重放时长，但不能证明某个文档是为当前依赖方会话生成的。

由于验证方当前会拒绝存在 nonce 的文档，修复必须同时更新协议两端。只在远程证明请求中增加 nonce 会破坏现有验证方预期。

### 攻击前提

- 攻击者可以捕获一个有效的 post-boot 远程证明文档。
- 被重放的文档具有依赖方预期的相同 manifest / PCR 值。
- 依赖方不要求新鲜 nonce，也不强制严格的文档时间戳新鲜性窗口。
- 对于最强的 `proxy_re_encrypt_share` 影响，攻击者控制或保留了被重放文档内嵌公钥对应的私钥。
- 重放发生在验证方接受的有效时间窗口内。

### 复现计划

重放 PoC 是判断是否达到 CVE 级别的决定性证据。预期 PoC 路径如下：

1. 启动一个合法 enclave 实例，并捕获目标 manifest 对应的有效 post-boot 远程证明文档。
2. 保留该文档内嵌公钥对应的临时私钥。
3. 之后将捕获的文档重放到调用 `verify_attestation_doc_against_user_input` 的依赖方流程中，优先选择 `proxy_re_encrypt_share`。
4. 确认验证方在没有新鲜挑战的情况下接受该文档。
5. 展示具体后果，例如仲裁份额或其他秘密材料被加密给被重放的公钥。

如果由于临时密钥始终新鲜且不可被攻击者保留，或依赖方强制执行了其他新鲜性属性，导致该重放无法通过，则该问题应降级为加固建议或协议设计风险。

### 修复建议

修复应同时修改生成端和验证端：

- 为 `live_attestation_doc` 和 `get_post_boot_attestation_doc` 增加由验证方提供的 nonce / challenge 参数。
- 将该 nonce 放入 `NsmRequest::Attestation`。
- 更新 `verify_attestation_doc_against_user_input`，要求传入预期 nonce。
- 将当前“nonce 存在则拒绝”的行为改为“nonce 缺失或不等于预期挑战值则拒绝”。
- 更新所有依赖方调用点，让它们每个会话生成新鲜 nonce，并传入验证逻辑。
- 考虑使用可信本地时钟，对远程证明文档自身时间戳强制执行严格新鲜性窗口。
- 保留 `user_data` 和 `public_key` 绑定，但不要把它们当成验证方新鲜性的替代品。

### 需要维护者确认的问题

1. post-boot 远程证明文档是否意图向远程依赖方证明“当前存活的 enclave 实例”？
2. 是否有任何依赖方会在 Nitro 证书有效窗口内接受复用的远程证明文档？
3. 临时公钥是否保证每次启动都新鲜生成，并且攻击者不可能从旧合法实例中保留对应私钥？
4. `proxy_re_encrypt_share` 是否仅基于该远程证明验证结果释放仲裁份额？
5. 增加验证方 nonce 是否兼容当前协议设计？
6. 潜在安全通报应使用哪个受影响版本范围？

## 发送前检查清单

- [x] 依赖方调用点已定位。
- [x] 验证方当前拒绝已存在 nonce 的行为已记录。
- [x] 此前复核的 main commit `b2ea15b` 上代码形态已确认。
- [ ] 提交前重新确认当前 `main` 和最新发布标签。
- [ ] 补重放 PoC，尤其是 `proxy_re_encrypt_share`。
- [ ] 确认受影响版本范围。
- [ ] 填写报告人署名或账号。
- [ ] 约定披露窗口，默认可用 90 天；无 PoC 时建议更谨慎。
