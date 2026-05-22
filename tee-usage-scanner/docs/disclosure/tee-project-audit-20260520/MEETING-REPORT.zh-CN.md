# TEE 项目安全扫描阶段性报告

会议日期：2026-05-22  
整理日期：2026-05-21  
范围：TEECheck 对 10 个 TEE 相关开源项目的 LLM 扫描结果与人工复核结论

## 一句话结论

本轮扫描发现了 2 个最值得优先推进的潜在安全问题：Fabric Private Chaincode 的 proposal/request 绑定缺失，以及 Teaclave SGX SDK mutual-ra 示例缺少 enclave 身份校验。其余发现多数属于 sample hardening、API footgun 或 threat model clarification，暂不建议直接按 CVE 处理。

## 扫描范围

| 项目 | 仓库 | 复核结果 |
| --- | --- | --- |
| Apache Teaclave SGX SDK | `apache/teaclave-sgx-sdk` | 有一个 sample 级高价值 issue |
| Apache Teaclave | `apache/teaclave` | 证据不足，不建议上报 |
| Gramine | `gramineproject/gramine` | demo 代码问题，不建议上报漏洞 |
| Open Enclave | `openenclave/openenclave` | 本轮无 findings |
| Occlum | `occlum/occlum` | MAA demo 可做安全硬化 issue |
| Microsoft CCF | `microsoft/CCF` | 需要协议级复核，当前不能确认漏洞 |
| OP-TEE OS | `OP-TEE/optee_os` | Veraison identity 需要设计澄清；另一个发现疑似误报 |
| Dstack | `Dstack-TEE/dstack` | key provider 边界需要澄清，当前不是确认漏洞 |
| Fabric Private Chaincode | `hyperledger/fabric-private-chaincode` | 最值得优先推进，可能是真漏洞 |
| Intel DCAP | `intel/confidential-computing.tee.dcap` | QvE-less API footgun，可发 hardening issue |

## 风险分级

| 优先级 | 项目 | 问题 | 当前判断 |
| --- | --- | --- | --- |
| P0 | Fabric Private Chaincode | `SignedProposal` 未绑定实际执行的 `ChaincodeRequestMessage` | 最像真实漏洞，建议优先上报 |
| P1 | Fabric Private Chaincode | IAS quote status 接受过宽，debug/attributes 未检查 | 高价值 attestation policy issue |
| P1 | Teaclave SGX SDK | mutual-ra sample 不校验 `MRENCLAVE`/`MRSIGNER` | 适合 GitHub issue，暂不建议 CVE |
| P2 | Intel DCAP | Rust wrapper 默认 API 可进入 QvE-less 验证 | API footgun / hardening issue |
| P2 | Occlum | MAA demo 不强制 nonce/freshness | sample hardening issue |
| P2 | OP-TEE OS | Veraison PTA hardcoded identity | design clarification |
| P2 | Dstack | VMM/key-provider-client 只转发 quote | threat model clarification |
| P3 | CCF | quote freshness 需要协议级确认 | 暂不确认 |
| P3 | Gramine | hello-world 示例无鉴权 | demo，不按漏洞处理 |

## P0：Fabric Private Chaincode proposal/request 绑定缺失

### 问题概述

Fabric Private Chaincode enclave 会验证 `SignedProposal` 的签名，但实际执行的 chaincode request 来自另一个独立输入 `cc_request_message_bytes`。代码中有 TODO 明确表示还没有从 signed proposal 中 unwrap `ChaincodeRequestMessage`，也没有完成 binding 计算。

如果外层协议没有补充校验，攻击者可能构造一个签名合法的 proposal，同时替换实际传入 enclave 执行的 encrypted request，导致 enclave 执行未被 proposal 签名绑定的请求。

### 核心证据

位置：`ecc_enclave/enclave/enclave.cpp`

签名验证存在：

```cpp
ByteArray signature = ByteArray(signed_proposal.signature->bytes,
    signed_proposal.signature->bytes + signed_proposal.signature->size);
ByteArray message = ByteArray(signed_proposal.proposal_bytes->bytes,
    signed_proposal.proposal_bytes->bytes + signed_proposal.proposal_bytes->size);

b = validate_message_signature(signature, message, encoded_signer_cert);
COND2LOGERR(!b, "signature validation failed");
```

但是 proposal/request 绑定尚未实现：

```cpp
// TODO unwrap ChaincodeRequestMessage from signed proposal
// once this is in place we can remove ChaincodeRequestMessage from ecall

// TODO implement me
// ByteArray binding_data;
// ...
// b = compute_message_hash(binding_data, ctx->binding);
```

实际执行的 request 来自独立输入：

```cpp
istream = pb_istream_from_buffer(
    (const unsigned char*)cc_request_message_bytes, cc_request_message_bytes_len);

b = pb_decode(&istream, fpc_ChaincodeRequestMessage_fields, &cc_request_message);
COND2LOGERR(!b, PB_GET_ERROR(&istream));
```

随后解密并执行：

```cpp
b = decrypt_message(request_encryption_key, encrypted_request, clear_request);
COND2LOGERR(!b, "message decryption failed");

b = pb_decode(&istream, fpc_CleartextChaincodeRequest_fields, &cleartext_cc_request);
COND2LOGERR(!b, PB_GET_ERROR(&istream));

invoke_ret = invoke(response, response_len, &response_len_out, &ctx);
```

### 安全影响

核心风险是 signed authorization 与实际执行内容脱钩。TEE 场景里 enclave 应该是最终可信执行边界，如果 enclave 只验证 proposal 签名，但没有验证 proposal 和执行 request 是同一个对象，那么外部不可信组件可能影响 enclave 执行内容。

### 建议动作

- 优先写 GitHub issue。
- 同步确认外层 Fabric/FPC endorsement flow 是否在 enclave 外部强制比较 request hash。
- 如果确认外层没有强制绑定，可以准备 CVE 预申请。
- 修复方向：在 enclave 内从 `SignedProposal.proposal_bytes` 解出 request，执行前比较 request hash 或直接移除独立 `cc_request_message_bytes` 输入。

## P1：Fabric Private Chaincode attestation policy 过宽

### 问题概述

IAS evidence verification 接受多个非 OK quote status，并且源码中有 TODO 明确说明还没有检查 attestation attributes，例如 release 模式下应该拒绝 debug enclave。

### 核心证据

位置：`common/crypto/attestation-api/evidence/verify-evidence.cpp`

```cpp
const unsigned int flags = QSF_ACCEPT_GROUP_OUT_OF_DATE | QSF_ACCEPT_CONFIGURATION_NEEDED |
                           QSF_ACCEPT_SW_HARDENING_NEEDED |
                           QSF_ACCEPT_CONFIGURATION_AND_SW_HARDENING_NEEDED;
COND2LOGERR(VERIFY_SUCCESS !=
                verify_enclave_quote_status(ias_report.c_str(), ias_report.length(), flags),
    "invalid quote status");
```

```cpp
// TODO: check attributes of attestation (e.g., DEBUG flag disabled in release mode)
```

### 人工复核修正

扫描器原始结论里提到 freshness/replay，但这个说法不够准确。代码确实会比较 `report_data` 和 `expected_statement` 的 hash，因此调用方可以把 challenge 放入 `expected_statement`。更准确的漏洞表述应聚焦在 quote status policy 和 attributes/debug flag。

### 建议动作

- 可以和 P0 合并成同一个 Fabric Private Chaincode issue 的 attestation policy 部分。
- 也可以单独发 issue，标题聚焦：quote status policy accepts non-terminal results and does not enforce debug attribute policy。

## P1：Teaclave SGX SDK mutual-ra sample 缺少 enclave 身份校验

### 问题概述

`samplecode/mutual-ra` 完成了 IAS report 验证和 TLS public key 的 `report_data` 绑定，但没有检查 `MRENCLAVE`、`MRSIGNER`、`ISVSVN` 或 debug flag。

这会导致 verifier 只知道“对方是某个真实 SGX enclave”，但不知道“对方是我预期的那个 enclave”。

### 核心证据

位置：`samplecode/mutual-ra/enclave/src/cert.rs`

```rust
let quote = base64::decode(&quote_raw).unwrap();
println!("Quote = {:?}", quote);
// TODO: lack security check here
let sgx_quote: Quote = unsafe{ptr::read(quote.as_ptr() as *const _)};

unsafe{
    println!("sgx quote report_data = {:02x}", sgx_quote.report_body.report_data.d.iter().format(""));
    println!("sgx quote mr_enclave = {:02x}", sgx_quote.report_body.mr_enclave.m.iter().format(""));
    println!("sgx quote mr_signer = {:02x}", sgx_quote.report_body.mr_signer.m.iter().format(""));
}
println!("Anticipated public key = {:02x}", pub_k.iter().format(""));
if sgx_quote.report_body.report_data.d.to_vec() == pub_k.to_vec() {
    println!("Mutual RA done!");
}
```

### 安全影响

攻击者可以运行自己的 SGX enclave，生成合法 quote，并把自己的 TLS public key 写入 `report_data`。在没有 identity allowlist 的情况下，verifier 可能接受这个 enclave。

### 建议动作

- 发 GitHub issue。
- 暂不建议直接 CVE，因为代码在 sample 中。
- 建议维护者加入 policy callback 或 allowlist 示例，至少检查 `MRENCLAVE`、`MRSIGNER`、`ISVSVN` 和 debug flag。

## P2：Intel DCAP Rust wrapper 暴露 QvE-less 弱验证模式

### 问题概述

Rust wrapper 的默认 quote verification API 接受 `qve_report_info: Option<_>`。当传入 `None` 时，会走 QVL-only 模式，文档明确说明该模式的结果不能被 cryptographically authenticated。

### 核心证据

位置：`QuoteVerification/dcap_quoteverify/sgx-dcap-quoteverify-rs/src/lib.rs`

```rust
/// - if qve_report_info is None, the API will use QVL library to perform quote verification,
/// note that the results can not be cryptographically authenticated in this mode.
pub fn sgx_qv_verify_quote(
    quote: &[u8],
    quote_collateral: Option<&QuoteCollateral>,
    expiration_check_date: i64,
    qve_report_info: Option<&mut sgx_ql_qe_report_info_t>,
    supplemental_data_size: u32,
    supplemental_data: Option<&mut sgx_ql_qv_supplemental_t>,
) -> Result<(u32, sgx_ql_qv_result_t), quote3_error_t> {
    ...
}
```

sample 中也演示了 `None`：

```rust
match tee_verify_quote(
    quote,
    collateral.ok().as_ref(),
    current_time,
    None,
    p_supplemental_data,
) {
    ...
}
```

### 人工判断

这是 documented weak mode，不是隐藏漏洞。更准确地说，它是 API 安全默认值问题。建议发 hardening issue，而不是 CVE。

## P2：Occlum MAA demo 不强制 freshness

### 问题概述

MAA demo 把 `Sha256(user_data)` 放入 report data，但不强制 `user_data` 必须包含 verifier challenge，也没有本地校验 MAA 返回 token 是否绑定当前请求。

### 核心证据

位置：`demos/remote_attestation/azure_attestation/.../maa.rs`

```rust
pub fn maa_generate_json(user_data: &[u8]) -> Result<serde_json::Value, &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(user_data);
    let hash = hasher.finalize();

    let quote_base64 = maa_get_quote_base64(&hash).unwrap();
    ...
    *maa_json.pointer_mut("/runtimeData/data").unwrap() =
        serde_json::Value::String(base64::encode(&user_data));
}
```

```rust
let resp = client.post(att_url).json(&request_body).send()?;

match resp.status() {
    reqwest::StatusCode::OK => Ok(resp.json().unwrap()),
    s => Err("maa attestation failed".into())
}
```

### 人工判断

如果调用方传入一次性 challenge，这个设计可以成立。如果调用方传固定 `user_data`，freshness 就不成立。建议按 sample hardening issue 处理。

## P2：OP-TEE Veraison PTA hardcoded identity

### 问题概述

Veraison PTA 中 `SIGNER_ID` 和 `INSTANCE_ID` 是静态常量。若这些值只是 reference/demo placeholder，则风险较低；若生产固件复用，会削弱设备身份唯一性。

### 核心证据

位置：`core/pta/veraison_attestation/veraison_attestation.c`

```c
#define SIGNER_ID { ... }
#define INSTANCE_ID { ... }
```

```c
ubc_cbor_evidence = generate_cbor_evidence(
    eat_profile,
    psa_client_id,
    psa_security_lifecycle,
    psa_implementation_id,
    psa_implementation_id_len,
    measurement_type,
    signer_id,
    SIGNER_ID_LEN,
    psa_instance_id,
    INSTANCE_ID_LEN,
    nonce,
    nonce_sz,
    measurement_value,
    TEE_SHA256_HASH_SIZE);
```

### 人工判断

generator 不做 verifier 侧验证是正常设计。真正需要问的是 identity provisioning：生产部署是否会注入设备唯一 identity。

## P2：Dstack key provider 边界需要澄清

### 问题概述

VMM 和 key-provider-client 本地只转发 quote，不做验证。但 KMS 服务端代码显示存在 quote verification、auth API、image hash 校验。因此当前不是确认漏洞，而是跨组件 trust boundary 需要澄清。

### 核心证据

client 只转发：

```rust
pub async fn get_key(quote: Vec<u8>, address: IpAddr, port: u16) -> Result<QuoteResponse> {
    if quote.len() > 1024 * 1024 {
        bail!("Quote is too long");
    }
    ...
    let payload = QuoteRequest { quote: &quote };
    ...
}
```

KMS 服务端有校验链：

```rust
let attestation = csr
    .attestation
    .clone()
    .into_v1()
    .verify_with_ra_pubkey(&csr.pubkey, self.state.config.pccs_url.as_deref())
    .await
    .context("Quote verification failed")?;
let app_info = self
    .ensure_app_attestation_allowed(&attestation, false, true, &request.vm_config)
    .await?;
```

### 人工判断

需要确认所有 key provider 路径是否都经过 KMS 服务端验证。若存在只相信 VMM 转发结果的路径，才可能变成漏洞。

## 排除或暂缓项

### Apache Teaclave 主仓

本轮发现是目录级 `needs_review`，缺少具体源码和行号。不能作为 issue。

### Open Enclave

本轮没有 findings。

### Gramine

命中的是 CI hello-world 示例。没有鉴权是事实，但不是生产安全边界。

### Microsoft CCF

扫描器认为 quote freshness/replay 需要复核，但当前代码能看到 PAL verifier、report data、store policy 等检查。需要协议级分析，不能直接说漏洞。

### OP-TEE `attestation.c` 私钥泄漏

扫描器原结论说可能释放 attestation key，但人工看公开 command 只返回 public key 的 `e` 和 `n`，不是 private key `d`。当前倾向误报。

## 会议建议讲法

1. 先讲范围：这不是完整人工审计，而是 TEECheck 扫描加人工 triage。
2. 强调结论分层：不是所有 finding 都是漏洞，已经按“可上报程度”分级。
3. 重点讲两个高价值方向：
   - Fabric Private Chaincode：proposal/request 绑定缺失，最值得推进。
   - Teaclave SGX SDK：mutual-ra sample 缺少 enclave identity policy，适合发 issue。
4. 再讲几个中优先级 hardening：
   - Intel DCAP QvE-less mode。
   - Occlum MAA nonce/freshness。
   - OP-TEE Veraison hardcoded identity。
   - Dstack key provider 边界。
5. 最后讲下一步：先写 Fabric 和 Teaclave 两个 issue；Fabric 继续确认外层协议是否补绑定；如没有补绑定，再准备 CVE 预申请。

## 下一步工作计划

| 优先级 | 动作 | 产出 |
| --- | --- | --- |
| 1 | 深挖 Fabric Private Chaincode 外层 endorsement flow | 确认是否可形成完整攻击路径 |
| 2 | 起草 Fabric Private Chaincode GitHub issue | issue 正文和复现/影响说明 |
| 3 | 起草 Teaclave SGX SDK issue | sample mutual-ra 身份校验缺失说明 |
| 4 | 将 Intel DCAP、Occlum、Dstack、OP-TEE 写成 hardening/design clarification issue | 低风险公开 issue |
| 5 | 记录误报样本 | 反哺 TEECheck planner/arbiter 规则 |

