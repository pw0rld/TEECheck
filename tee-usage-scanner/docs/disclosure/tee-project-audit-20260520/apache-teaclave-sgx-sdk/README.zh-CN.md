# Apache Teaclave SGX SDK

## 扫描元信息

- 仓库：`https://github.com/apache/teaclave-sgx-sdk`
- Commit：`b635249a1cbf55d5eb15819b4578827f2a27d8a0`
- 本地克隆：`/tmp/teecheck-clone-2876055468`
- Run：`runs/scan-20260520-teaclave-sgx-sdk`

## 结论

本项目有一个值得上报的安全问题，但位置在 `samplecode/mutual-ra`，不是核心 SDK runtime。问题是 mutual RA 示例验证 IAS report 和 TLS public key 绑定后，没有强制校验被证明 enclave 的身份策略，例如 `MRENCLAVE`、`MRSIGNER`、`ISVSVN` 或 debug flag。

建议作为 GitHub issue 上报，暂不建议直接作为 CVE 申请。理由是代码位于 sample，除非维护者确认它是生产推荐模板，或者能证明大量下游项目直接复用该逻辑，否则 CVE 说服力不足。

## 发现 1：mutual-ra sample 缺少 enclave 身份策略校验

TEECheck 状态：`confirmed_candidate`，严重性 `high`，置信度 `high`。

源码位置：`samplecode/mutual-ra/enclave/src/cert.rs`

关键代码片段：

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

这里验证了 `report_data == pub_k`，说明 TLS public key 与 quote 绑定成立。但 `mr_enclave` 和 `mr_signer` 只是打印，没有与可信 allowlist 或策略比较。

### 影响解释

这类验证只能证明三件事：

- quote 来自一个真实 SGX enclave。
- IAS report 的签名和 quote status 通过了当前代码的检查。
- TLS public key 被写入 `report_data`，因此当前 TLS 连接和该 enclave 实例有关。

它不能证明：

- enclave 是预期的应用代码。
- enclave 由预期 signer 签名。
- enclave 不是 debug build。
- enclave 的 `ISVSVN` 满足最低版本要求。

攻击者如果能运行自己的 SGX enclave，就可以生成合法 quote，并把自己的 TLS public key 放进 `report_data`。在缺少 `MRENCLAVE`/`MRSIGNER` 策略校验时，verifier 会把“任意真实 enclave”误当成“目标可信 enclave”。

## 发现 2：`AlignReport::verify` 只校验 MAC，属于 API footgun

TEECheck 状态：`needs_review`，严重性 `high`，置信度 `high`。

源码位置：`sgx_trts/src/se/report.rs`

关键代码片段：

```rust
// This function verifies the report's MAC using the provided
// implementation of the verifying function.
pub fn verify<F>(&self, check_mac: F) -> SgxResult
where
    F: FnOnce(&Key128bit, &[u8; AlignReport::TRUNCATED_SIZE], &Mac) -> SgxResult,
{
    ensure!(self.is_enclave_range(), SgxStatus::InvalidParameter);

    let req = AlignKeyRequest(KeyRequest {
        key_name: KeyName::Report,
        key_id: self.0.key_id,
        ..Default::default()
    });
    let key = req.egetkey()?;
    check_mac(&key.key, self.mac_data(), &self.0.mac)
}
```

这个函数的行为是清楚的：它只验证 report MAC，不检查 report body 里的 `mr_enclave`、`mr_signer`、`isv_svn`、`report_data` 或 freshness。单独看它不构成漏洞，因为这是底层 primitive，身份策略通常由调用方处理。

但它有误用风险：开发者看到 `verify()` 可能误以为完成了完整 attestation policy check。建议维护者加强文档或提供高层 API，例如 `verify_report_and_policy()`。

## 发现 3：`sgx_tseal` 不是问题

TEECheck 最终状态：`no_issue_observed`。

源码位置：`sgx_tseal/src/internal.rs`

关键代码片段：

```rust
ensure!(plaintext.is_enclave_range(), SgxStatus::InvalidParameter);

let report = Report::get_self();
let key_request = KeyRequest {
    key_name: KeyName::Seal,
    key_policy,
    isv_svn: report.body.isv_svn,
    cpu_svn: report.body.cpu_svn,
    attribute_mask,
    key_id,
    misc_mask,
    config_svn: report.body.config_svn,
    ..Default::default()
};

let result = Self::seal_data_helper(plaintext, aad, &key_request);
```

这里的 sealing key 派生绑定到当前 enclave identity 和 key policy，并且检查 plaintext 位于 enclave 内存。缺少“enclave 内部模块级授权”不是 sealing primitive 的职责，因此不建议作为漏洞上报。

## 建议上报 issue 草稿要点

英文标题建议：

`mutual-ra sample verifies IAS report but does not enforce enclave identity policy`

正文重点：

- 指出 `verify_mra_cert` 完成 IAS report 验证和 `report_data` public key binding。
- 指出代码明确有 `TODO: lack security check here`。
- 指出 `mr_enclave` 和 `mr_signer` 只打印未比较。
- 说明影响：verifier 可能接受任意合法 SGX enclave，而不是预期应用 enclave。
- 建议修复：增加 allowlist 或 policy callback，至少检查 `MRENCLAVE`/`MRSIGNER`/`ISVSVN`/debug flag；如果 sample 有意保持泛化，应在 README 和代码注释中明确警告。
