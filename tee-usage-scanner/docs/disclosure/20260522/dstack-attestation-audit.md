# Dstack TEE / Attestation 审计

审计对象：`Dstack-TEE/dstack`，本地浅克隆目录 `dstack-tee-dstack`。

- 上游仓库：<https://github.com/Dstack-TEE/dstack>
- 分支：`master`
- 审计 commit：`f67b4f67ebabef0a27795705121698280a1038dc`
- commit 时间：`2026-05-19 05:21:20 -0700`

范围：只看 TEE、TDX quote、RTMR/event log、RA-TLS、KMS key release、VMM/KMS/guest-agent 之间的 attestation 信任边界。没有做完整 fuzz、依赖库源码审计、智能合约形式化验证或 GPU TEE 路径审计。

## 总体判断

Dstack 的主线设计方向是正确的：TDX quote 绑定 `report_data`，RA-TLS 证书公钥绑定进 quote，KMS 在释放 app key / 签发 app cert 前会验证 quote、RTMR3 event log replay、OS image measurement 和 on-chain / webhook 授权。相关代码中也能看到 fail-closed 的关键检查：

- `dstack-attest/src/attestation.rs:807` 通过 DCAP/QVL 获取 collateral 并验证 quote；
- `dstack-attest/src/attestation.rs:810` 拒绝 debug TDX/SGX；
- `dstack-attest/src/attestation.rs:813` replay runtime events 并比较 RTMR3；
- `dstack-attest/src/attestation.rs:822` 检查 quote `report_data`；
- `dstack-attest/src/attestation.rs:627` RA-TLS 检查证书公钥和 quote `report_data` 绑定；
- `verifier/src/verification.rs:493` 起会按 VM config 计算 MRTD/RTMR0/1/2 并比对 OS image measurement。

但我发现几个会直接破坏“远端证明后再放密钥”的信任链问题。最严重的是 app 启动向 KMS 拉 key 的首跳 KMS 身份没有被证明，KMS onboarding 的 key handover 第二跳也没有绑定到已验证的 source KMS。它们都属于 TEE 系统里很危险的“先验证了 A，实际信任了 B”问题。

## DSTACK-ATT-001：app 启动取 KMS key 时先信任未认证的 `GetTempCaCert`

严重性：高

证据：

- `dstack-util/src/system_setup.rs:824`
- `dstack-util/src/system_setup.rs:828`
- `dstack-util/src/system_setup.rs:831`
- `dstack-util/src/system_setup.rs:836`
- `dstack-util/src/system_setup.rs:842`
- `dstack-util/src/system_setup.rs:844`
- `dstack-util/src/system_setup.rs:854`
- `dstack-util/src/system_setup.rs:927`
- `dstack-util/src/system_setup.rs:929`
- `dstack-util/src/system_setup.rs:1349`
- `dstack-util/src/system_setup.rs:1361`

应用启动阶段先执行：

```rust
let client = RaClient::new(kms_url.clone(), true)?;
kms_client.get_temp_ca_cert().await?
```

`true` 会关闭 TLS 证书校验。随后代码把这个未认证响应里的 `tmp_ca.ca_cert` 当成第二段 TLS 的 CA，并用未认证响应里的 `tmp_ca_key` 生成 RA client cert。第二段连接只验证服务端证书 `special_usage == "kms:rpc"`；如果证书里有 attestation，就把 KMS `mr_aggregated` 记入 RTMR3，但没有强制要求服务端 attestation 存在，也没有先证明第一段拿到的 CA 确实属于目标 KMS。

更关键的是，`key_provider_id` 为空时会直接通过：

```rust
if expected_key_provider_id.is_empty() {
    return Ok(());
}
```

因此默认/未 pin KMS provider 的部署中，网络中间人、恶意 VMM 配置或被劫持的 KMS URL 可以返回自己的临时 CA、根 CA 和 app keys，让 CVM 继续启动但使用攻击者控制的 key provider。远端 verifier 以后也许能从 event log 看到 key-provider 变了，但启动时的 app 自身已经没有 fail-closed。

影响：

- App disk key、env decrypt key、app k256 key、app CA trust anchor 都可能被替换。
- 远端用户若只验证 app compose / OS image，而没有 pin KMS key provider id，可能误信一个由攻击者 KMS 配发密钥的 CVM。
- 如果同时使用未验证的 VMM Web UI 输入 secrets，攻击者可以把 secrets 加密到自己的 KMS key。

建议：

- `GetTempCaCert` 的响应不能作为首个信任根。先用 RA-TLS/quote 验证 KMS RPC 证书和 KMS app identity，再接受其返回的 CA。
- KMS key release 客户端必须 pin KMS root/k256 public key 或 `key_provider_id`；KMS 模式下不应允许空 `key_provider_id` 静默通过。
- 第二段连接必须强制 `cert.attestation.is_some()`，并验证 `kms:rpc`、KMS app id / mr_aggregated / device / TCB policy 与预期匹配。
- `AppKeyResponse` 最好由 KMS 长期身份 key 对响应内容签名，客户端验证签名后再落盘。

## DSTACK-ATT-002：KMS onboarding 已验证 source KMS，但取根密钥的第二条连接不验证服务端

严重性：高

证据：

- `kms/src/onboard_service.rs:254`
- `kms/src/onboard_service.rs:257`
- `kms/src/onboard_service.rs:275`
- `kms/src/onboard_service.rs:277`
- `kms/src/onboard_service.rs:285`
- `kms/src/onboard_service.rs:290`
- `kms/src/main_service.rs:410`
- `kms/src/main_service.rs:416`
- `kms/src/main_service.rs:418`
- `kms/src/main_service.rs:419`
- `ra-rpc/src/client.rs:96`
- `ra-rpc/src/client.rs:103`
- `ra-rpc/src/client.rs:108`
- `ra-rpc/src/client.rs:115`

Onboarding 流程第一段连接确实通过 `cert_validator` 验证 source KMS 的 RA-TLS attestation，并把 source attestation 存入 `attestation_slot`。随后代码调用：

```rust
let tmp_ca = kms_client.get_temp_ca_cert().await?;
let (ra_cert, ra_key) = gen_ra_cert(tmp_ca.temp_ca_cert, tmp_ca.temp_ca_key).await?;
let ra_client = RaClient::new_mtls(other_kms_url.into(), ra_cert, ra_key, pccs_url)?;
```

问题在 `RaClient::new_mtls()`：

```rust
.tls_no_check(true)
.tls_built_in_root_certs(false)
.tls_client_cert(cert_pem)
.tls_client_key(key_pem)
```

它没有设置 `tls_ca_cert`，也没有 `cert_validator`。而 `RaClient::try_validate_attestation()` 在没有 `cert_validator` 时直接返回 `Ok(())`。也就是说，真正执行 `GetKmsKey`、拿 source KMS 根 CA 私钥和 root k256 key 的第二条连接没有验证服务端证书、没有验证服务端 attestation，也没有绑定到第一段已验证过的 source KMS。

影响：

- 中间人可在第二段连接返回自己的 `ca_key` / `k256_key` / `temp_ca_key`。
- 新 KMS 会把攻击者返回的根密钥持久化，导致 KMS 集群信任根被替换。
- `ensure_kms_allowed(cfg, &source_attestation)` 验证的是第一段连接看到的 source KMS，不证明第二段 `GetKmsKey` 响应来自同一个实体。

建议：

- 不要使用 `RaClient::new_mtls()` 处理 KMS key handover，或把它改成默认验证服务端。
- 第二段连接必须使用第一段已验证 source KMS 返回的 CA，并继续设置 `cert_validator`，校验 `special_usage == "kms:rpc"`、RA-TLS quote、KMS BootInfo 和第一段 source identity 一致。
- `GetKmsKey` 响应应由 source KMS 长期 identity key 签名，并把目的 KMS attested identity / nonce / session transcript 放入签名上下文。

## DSTACK-ATT-003：VMM Web UI 加密环境变量时不验证 KMS 公钥签名

严重性：高

证据：

- `vmm/ui/src/composables/useVmManager.ts:925`
- `vmm/ui/src/composables/useVmManager.ts:926`
- `vmm/ui/src/composables/useVmManager.ts:927`
- `vmm/src/console_v0.html:1843`
- `vmm/src/console_v0.html:1846`
- `vmm/src/console_v0.html:1847`
- 对比：`vmm/src/vmm-cli.py:685` 起 CLI 会验证 `signature_v1` 或 legacy signature。

VMM UI 从 VMM RPC 取 `GetAppEnvEncryptPubKey` 后直接使用 `response.public_key` 做 X25519 加密，没有验证 KMS 返回的 `signature_v1`、timestamp，也没有 pin KMS k256 signer。

如果用户在浏览器 UI 中输入 secrets，而 VMM 是不可信控制面，VMM 或中间人可以返回自己的 X25519 public key，让浏览器把 secrets 加密给攻击者。即使 KMS 后端本身正确，VMM 这一层也能替换响应。

影响：

- “client-side encrypted env” 对不可信 VMM 不成立。
- 这直接绕过 TEE/KMS 的密钥释放边界，因为 secrets 在进入 CVM 前已经泄露。

建议：

- Web UI 中至少实现和 CLI 一样的 `signature_v1` + timestamp 验证，并要求 signer pubkey 在用户本地 whitelist 中。
- 更严格地说，不应从不可信 VMM 动态加载执行处理 secrets 的 JS；应使用本地 CLI/SDK、签名静态 bundle、SRI/可复现 UI 或浏览器扩展式 trusted client。
- VMM RPC 代理返回 KMS public key 时不要裁剪签名字段；UI 必须展示 signer pubkey / chain id / KMS contract，并要求用户确认或 pin。

## DSTACK-ATT-004：RA client API 容易让调用方误以为已启用 attestation 验证

严重性：中

证据：

- `ra-rpc/src/client.rs:31`
- `ra-rpc/src/client.rs:33`
- `ra-rpc/src/client.rs:102`
- `ra-rpc/src/client.rs:103`
- `ra-rpc/src/client.rs:115`
- `ra-rpc/src/client.rs:132`

`RaClientConfig` 里 `verify_server_attestation` 默认是 `true`，但 `try_validate_attestation()` 首先检查是否存在 `cert_validator`：

```rust
let Some(validator) = &self.cert_validator else {
    return Ok(());
};
```

没有 validator 时，服务端 attestation 完全不会被解析和验证。`RaClient::new_mtls()` 同时设置 `tls_no_check(true)` 且不设置 validator，因此得到的是“既不验证 TLS 服务端证书，也不验证 RA-TLS attestation”的客户端。

这不是单独的利用点，但它是前两个高危链路形成的直接原因之一。

建议：

- 把 server attestation verification 和 user-supplied validator 解耦；`verify_server_attestation=true` 时，缺少 attestation 应默认失败。
- 把 `tls_no_check` / `new_mtls` 改名为显式 `insecure_*`，并在类型层面要求 caller 传入 verifier policy。
- 对所有 `tls_no_check(true)` call site 加测试，证明它们仍有 RA-TLS identity pinning。

## DSTACK-ATT-005：app TCB policy 默认/兼容路径可能接受非 `UpToDate`

严重性：中

证据：

- `dstack-attest/src/attestation.rs:1160`
- `dstack-attest/src/attestation.rs:1162`
- `dstack-attest/src/attestation.rs:1166`
- `kms/auth-eth/contracts/DstackKms.sol:170`
- `kms/auth-eth/contracts/DstackKms.sol:181`
- `kms/auth-eth/contracts/DstackApp.sol:170`
- `kms/auth-eth/contracts/DstackApp.sol:172`

Quote verification 后，Rust 侧 `validate_tcb()` 只拒绝 debug 和部分 TDX report 字段异常，没有在 verifier 层强制 `tcbStatus == UpToDate`。KMS 自身的合约策略要求 KMS TCB `UpToDate`，但 app 合约 `DstackApp` 只有在 `requireTcbUpToDate` 为 true 时才拒绝非 `UpToDate`；旧 factory overload 为兼容旧 SDK 会传 `false`。

这可能是有意给 app owner 留策略空间，但从 TEE 默认安全角度看，app key release 的默认路径不应因为兼容接口而接受带有 TCB 风险状态的 quote。

建议：

- 新 app 默认 `requireTcbUpToDate=true`，兼容接口应在文档和 UI 中明确标红。
- 若允许非 `UpToDate`，应要求显式 advisory allowlist，而不是只靠布尔开关。
- KMS 审计日志应记录 `tcb_status`、`advisory_ids`、策略判断和 caller app id。

## DSTACK-ATT-006：`auth-simple` 设备 allowlist 为空时实际允许任意设备

严重性：中

证据：

- `kms/auth-simple/index.ts:133`
- `kms/auth-simple/index.ts:136`
- `kms/auth-simple/index.ts:179`
- `kms/auth-simple/index.ts:182`
- 对比：`kms/auth-eth/contracts/DstackApp.sol:179` 起合约路径在 `allowAnyDevice=false` 时会检查 mapping，空 mapping 等价于拒绝。

`auth-simple` 中的设备检查是：

```ts
if (allowedDevices.length > 0 && !allowedDevices.includes(deviceId)) reject
```

因此 `allowAnyDevice=false` 且 devices 为空时会放行任意设备。这和 Solidity `DstackApp` 的语义不一致，也容易让小型 webhook / self-hosted 部署误以为已经启用设备绑定。

建议：

- `allowAnyDevice=false` 时，设备列表为空应拒绝启动或配置校验失败。
- 将 `auth-simple` 标记为 dev-only，或与合约策略保持完全同语义。

## DSTACK-ATT-007：raw quote API 仍允许无域分隔 report_data

严重性：低到中

证据：

- `guest-agent/src/rpc_service.rs:327`
- `guest-agent/src/rpc_service.rs:534`
- `guest-agent/src/rpc_service.rs:545`
- `guest-agent/rpc/proto/agent_rpc.proto:27`
- `guest-agent/rpc/proto/agent_rpc.proto:146`

新 `TdxQuote` 路径默认会用 `QuoteContentType::AppData` 做 `hash("app-data:" || payload)`，这是好的。但同时仍暴露 raw quote / `GetQuote` 路径，直接把调用方输入 padding 到 64 字节 report_data。proto 注释也提醒要加 application-specific identifier，否则有 quote repurposing 风险。

这类 API 本身不一定是漏洞，但在 SDK 和示例里如果用户直接把业务 hash / 公钥 / nonce 放进去且没有协议标签，quote 可能被跨协议复用。

建议：

- SDK 默认只暴露带域分隔的 quote API；raw API 改为 `unsafe_raw_quote` 或要求显式 prefix。
- 文档里的 verifier checklist 强制检查 `report_data = H(protocol || nonce || channel binding || payload)`。

## 结论

Dstack 的 attestation 基础组件比很多 TEE 项目完整：有 RA-TLS 公钥绑定、RTMR3 replay、OS image measurement、KMS policy 和 app compose hash。但当前代码里有几处“bootstrap trust”没有闭合：

1. App 启动取 KMS key 时，第一份 KMS CA/临时 CA 来自未认证连接。
2. KMS onboarding 验证 source KMS 后，真正取根密钥的第二条连接没有服务端验证。
3. VMM Web UI 在输入 secrets 时没有验证 KMS env encryption key。

这些问题的共同点是：底层 quote 验证做了，但结果没有绑定到后续真正被信任的 key / response / session。生产加固优先级应先修复这三条链路，再收紧 TCB/device policy 默认值和 raw quote API。
