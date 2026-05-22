# Apache Teaclave Attestation 审计记录

审计日期：2026-05-21

审计对象：Apache Teaclave 历史 FaaS 框架代码

仓库状态：

- 上游仓库：<https://github.com/apache/teaclave>
- 审计分支：`legacy`
- 审计提交：`65886ec4bb980f6f0a8a1c025478df570cd11b59`
- 提交日期：2025-07-17
- 说明：上游 `main` 分支当前主要是 Teaclave SDK 生态入口；历史 FaaS 框架已在仓库说明中标记为 legacy / 不再活跃维护。

## 总结

Teaclave 的 attested TLS 设计思路是合理的：把 TLS 证书公钥绑定进 SGX quote 的 `report_data`，再通过 IAS/DCAP report 签名、`MRENCLAVE/MRSIGNER`、auditor 签名的 enclave info 建立服务间信任。

但实现中存在明显边界问题，主要集中在四类：

1. Attestation report 的 `quote status` 处理过宽，默认 verifier 会接受多种 Intel/DCAP 明确标记为不可信或风险状态的 quote。
2. 不可信 runtime config 输入和可信 auditor endorsement 之间的边界没有收紧，存在空签名绕过；Frontend 甚至没有校验 auditor 签名。
3. Freshness 只在文档和结构体中存在，实际 verifier 不检查；后台刷新后的证书也没有被装回正在运行的 rustls 配置。
4. SDK / 公共 API 提供了容易误用的不安全默认值，例如 client TLS 默认 `NoServerAuth`。

整体判断：该 legacy 框架的 attestation 链路不能按“默认安全”使用；若直接用于生产，会存在被伪造服务、过期/风险 quote、被篡改 enclave info 绕过的风险。

## 关键发现

### ATTEST-001：默认 quote status 校验过宽

严重性：高

位置：

- `attestation/src/verifier.rs:43`
- `attestation/src/report.rs:239`
- `attestation/src/report.rs:329`

问题：

`universal_quote_verifier` 只拒绝 `UnknownBadStatus`：

```rust
report.sgx_quote_status != crate::report::SgxQuoteStatus::UnknownBadStatus
```

这意味着以下状态都会被默认接受：

- `SIGNATURE_INVALID`
- `GROUP_REVOKED`
- `SIGNATURE_REVOKED`
- `KEY_REVOKED`
- `SIGRL_VERSION_MISMATCH`
- `GROUP_OUT_OF_DATE`
- `OUT_OF_DATE`
- `OUT_OF_DATE_CONFIGURATION_NEEDED`
- `CONFIGURATION_NEEDED`
- `SW_HARDENING_NEEDED`
- `CONFIGURATION_AND_SW_HARDENING_NEEDED`

这些状态中不少在同一文件注释里已经写明“quote 内容不可信”，但默认 verifier 仍继续信任 quote body 中的 `MRENCLAVE/MRSIGNER`。

影响：

攻击者如果能让 attestation service 返回一个非 unknown 但实际失败/撤销/过期的状态，Teaclave 默认链路仍可能建立 attested TLS。特别是 `SIGNATURE_INVALID`、`KEY_REVOKED` 这类状态不应被默认放行。

建议：

- 默认 verifier 改为 fail-closed，只接受 `SgxQuoteStatus::OK`。
- 对 `CONFIGURATION_NEEDED`、`SW_HARDENING_NEEDED`、`OUT_OF_DATE` 等状态引入显式 policy 配置，不能作为默认行为。
- 为所有 quote status 添加单元测试，证明坏状态会失败。

### ATTEST-002：`enclave_info` auditor 签名可被空签名绕过

严重性：高

位置：

- `types/src/attestation.rs:72`
- `types/src/attestation.rs:81`
- `types/src/attestation.rs:111`
- `config/src/runtime.rs:108`

问题：

`EnclaveInfo::verify_and_new` 只检查：

```rust
signatures.len() <= public_keys.len()
```

随后 `verify` 遍历每个 signature。若 `signatures` 为空，循环不会执行，最终直接返回 `true`。

runtime config 中 `auditor_signatures` 是运行时从不可信文件路径读取的输入。攻击者可以提供一个不含签名的配置，让任意伪造的 `enclave_info.toml` 通过 `verify_and_new`。

影响：

服务端用于校验 peer enclave identity 的 `MRENCLAVE/MRSIGNER` 可以被不可信 host 替换。只要攻击者能提供一个通过 IAS/DCAP attestation 的 enclave，并把其 measurement 填进伪造 `enclave_info`，内部服务可能接受错误 peer。

建议：

- `verify_and_new` 必须要求签名非空。
- 签名策略应在 build config 中显式定义：require-all、threshold，或具体 auditor key set。
- 校验 public key / signature 一一对应或至少去重，避免重复签名/重复 key 弱化 threshold。
- 对空签名、重复签名、少于阈值签名添加测试。

### ATTEST-003：Frontend 没有校验 auditor 签名

严重性：高

位置：

- `services/frontend/enclave/src/lib.rs:69`
- 对比：`services/authentication/enclave/src/lib.rs:98`
- 对比：`services/management/enclave/src/lib.rs:55`
- 对比：`services/storage/enclave/src/lib.rs:57`

问题：

其他多个内部服务使用：

```rust
EnclaveInfo::verify_and_new(...)
```

但 Frontend 直接使用：

```rust
teaclave_types::EnclaveInfo::from_bytes(&config.audit.enclave_info_bytes)
```

没有验证 auditor signatures。

影响：

Frontend 是外部请求进入平台的重要入口，同时会主动连接 authentication、management、access_control。若 host 篡改 runtime config 中的 `enclave_info` 和 advertised address，Frontend 可能把内部请求发给攻击者控制的 enclave，只要该 enclave 能产生合法 SGX attestation。

建议：

- Frontend 与其他服务保持一致，改为 `EnclaveInfo::verify_and_new`。
- 对所有从 runtime config 读取的 `enclave_info` 建立统一 helper，禁止直接 `from_bytes` 用在信任决策路径。
- 加测试覆盖 Frontend 在签名缺失/错误时启动失败。

### ATTEST-004：Attestation freshness 没有被强制执行

严重性：高 / 中

位置：

- `attestation/src/report.rs:565`
- `attestation/src/verifier.rs:43`
- `attestation/src/attestation.rs:123`
- `rpc/src/config.rs:115`
- `rpc/src/config.rs:155`
- `rpc/src/config.rs:168`

问题：

代码解析了 report timestamp 并计算 `freshness`，但默认 verifier 不检查 freshness。文档声称 attestation report 默认 3600 秒刷新，但实际运行时存在两个问题：

1. verifier 不拒绝过期 report。
2. 后台 `AttestationFreshnessKeeper` 更新的是共享 `AttestedTlsConfig`，而 rustls server/client config 在创建时已经把 cert/key 拷贝进 `AlwaysResolvesChain`。`refresh_server_config` 虽然存在，但没有生产路径调用。

影响：

长期运行的服务可能一直使用启动时的 attestation report。即使平台 TCB 状态、撤销状态或 DCAP collateral 状态后续变化，连接方默认也不会因 report 陈旧而拒绝。

建议：

- verifier 中强制检查 `report.freshness <= ATTESTATION_VALIDITY_SECS`。
- TLS cert resolver 应动态读取最新 `AttestedTlsConfig`，或服务端定期重建并替换 rustls config。
- client cert 也需要同样刷新机制。
- 添加测试：构造过期 timestamp 的 report 必须失败。

### ATTEST-005：client TLS 默认 `NoServerAuth`，容易误用

严重性：中

位置：

- `rpc/src/config.rs:203`
- `rpc/src/config.rs:228`
- `rpc/src/config.rs:251`

问题：

`SgxTrustedTlsClientConfig::default()` 安装的是 `NoServerAuth`，它直接返回 `ServerCertVerified::assertion()`。只有调用 `.attestation_report_verifier(...)` 后才会替换成 attestation verifier。

核心服务路径大多显式调用 verifier，但这个公共 API 的默认值非常危险。扩展服务、测试代码或 SDK 使用者只要调用 `SgxTrustedTlsClientConfig::new().into()`，就会得到无服务端身份认证的 TLS。

影响：

被动加密仍存在，但服务端身份完全不校验，MITM 或恶意服务可以被接受。

建议：

- 默认 client config 不应可直接连接；应要求调用 `with_attestation_verifier` 或显式 `insecure_no_server_auth`。
- 将 `NoServerAuth` 标记为测试/开发专用，并在类型名和 API 上体现不安全语义。
- CI 中搜索生产代码路径禁止 `SgxTrustedTlsClientConfig::new().into()`。

### ATTEST-006：Python SDK attestation 校验弱于 Rust SDK

严重性：中

位置：

- `sdk/python/teaclave.py:180`
- `sdk/python/teaclave.py:195`
- `sdk/python/teaclave.py:239`
- `sdk/python/teaclave.py:268`

问题：

Python SDK 做了证书链、report 签名、公钥绑定、`MRENCLAVE/MRSIGNER` 比对，但缺少：

- report `version` 检查；
- quote status 检查；
- freshness 检查；
- auditor signature 校验；
- 对 extension OID 的明确校验，只取 `cert.extensions[0]`。

另外，`SGX_MODE=SW` 时直接跳过 verification。

影响：

外部用户如果从不可信渠道获取 `enclave_info.toml`，或连接到返回风险 quote status 的服务，Python SDK 仍可能通过校验。

建议：

- 与 Rust verifier 对齐，至少检查 version、quote status、freshness。
- `enclave_info` 应附带并校验 auditor signatures。
- 查找 SGX RA extension 应按 OID 定位，而不是使用第一个 extension。
- `SGX_MODE=SW` 跳过校验必须显式标记为 insecure/dev-only。

### ATTEST-007：DCAP reference attestation service 的信任根是自建 demo key

严重性：中 / 部署风险

位置：

- `dcap/src/main.rs:39`
- `dcap/src/main.rs:127`
- `config/build.config.toml:20`
- `config/keys/dcap_root_ca_cert.pem`
- `config/keys/dcap_server_cert.pem`

问题：

DCAP service 用本地配置的 RSA key 对 quote verification result 签名。仓库包含 demo root/server cert/key，文档也说明 `config/keys` 仅用于演示，生产不可使用。

这本身不一定是代码漏洞，但信任边界需要说清楚：客户端最终信任的是 Teaclave DCAP signing certificate，而不是直接信任 Intel DCAP collateral。若 signer key 泄漏或误用 demo key，攻击者可以伪造 DCAP attestation report。

建议：

- 生产部署必须替换 DCAP root/server key，并用 HSM/KMS 或等价机制保护 signer。
- build config 中 pin 住生产 DCAP root。
- 文档中明确 DCAP service 是新的 trust anchor，不能把它视为透明代理。

## 边界问题归纳

### 不可信 runtime config 边界

`runtime.config.toml` 明确被设计为不可信输入，但当前以下字段会影响安全决策：

- `audit.enclave_info`
- `audit.auditor_signatures`
- internal advertised address
- attestation service algorithm / URL / key / SPID

其中 `enclave_info` 只有在 auditor signature 校验严格时才可作为信任输入。空签名绕过和 Frontend 直接 `from_bytes` 破坏了这个边界。

### Attestation service result 边界

IAS/DCAP 返回的 report 不只是“签过名的 quote body”，还包含 quote status、timestamp、TCB/撤销/配置风险。当前默认 verifier 把这些状态压缩成“不是未知坏状态就行”，边界过宽。

### TLS 证书绑定边界

证书公钥与 quote `report_data` 的绑定做了，这是正确的：

- Rust：`attestation/src/report.rs:595`
- SGX report data 生成：`attestation/src/platform/sgx.rs:107`

但绑定只证明“这个 TLS key 属于某个 attested enclave instance”，不证明该 instance 的 quote status 可接受、freshness 可接受、measurement 经 auditor 批准。因此必须和前面的 policy 一起成立。

## 建议修复优先级

1. 修复 `universal_quote_verifier`，默认只接受 `OK`。
2. 修复 `EnclaveInfo::verify_and_new`，禁止空签名，并实现明确 threshold。
3. Frontend 改为校验 auditor signatures。
4. 在 verifier 中强制检查 freshness。
5. 修复 TLS cert runtime refresh，确保服务端/客户端实际使用新证书。
6. 移除或显式隔离 `NoServerAuth` 默认路径。
7. 对 Python SDK 补齐 Rust 路径的校验项。
8. 明确 DCAP signer 是生产 trust anchor，并禁止 demo key 进入生产配置。

## 可验证测试建议

- 构造每一种 `SgxQuoteStatus`，断言只有 `OK` 默认通过。
- `EnclaveInfo::verify_and_new` 输入空 signatures，必须失败。
- Frontend 使用缺失/错误 auditor signature 启动，必须失败。
- report timestamp 超过 `ATTESTATION_VALIDITY_SECS`，必须失败。
- 启动服务超过 refresh 周期后，新 TLS handshake 使用新证书。
- `SgxTrustedTlsClientConfig::new().into()` 在生产 feature 下不可编译或不可连接。

## 结论

Teaclave legacy FaaS 框架的 attestation 机制有较完整的设计框架，但实现没有做到 fail-closed。核心风险不是“没有 attestation”，而是 attestation 的结果和 runtime 信任输入没有被严格解释：

- 坏 quote status 被接受；
- 未签名 enclave info 可被接受；
- Frontend 信任未经 auditor 背书的 measurements；
- freshness 没有实际强制；
- SDK/API 存在不安全默认值。

因此，该版本不能直接按生产级 attestation 安全边界使用。若要继续基于此代码演进，必须先收紧 verifier policy、runtime config 校验和 TLS refresh 机制。
