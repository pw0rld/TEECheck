# Intel Confidential Computing TEE DCAP

## 扫描元信息

- 仓库：`https://github.com/intel/confidential-computing.tee.dcap`
- Commit：`3aa24f6df004f092556aef10e0ab422cb0395e38`
- 本地克隆：`/tmp/teecheck-clone-930627677`
- Run：`runs/scan-20260520-intel-dcap`

## 结论

TEECheck 的主要发现是 Rust DCAP quote verification wrapper 允许调用方传 `None` 作为 `qve_report_info`，从而走 QVL-only 模式。文档明确说明这种模式的 verification result 不能被 cryptographically authenticated。

这属于 documented weak mode/API footgun，不是传统意义上的隐藏漏洞。适合发 hardening issue，建议把弱模式拆成显式危险 API，或在生产 feature 下强制 QvE。

## 发现 1：`sgx_qv_verify_quote` 支持 QvE-less 模式

TEECheck 状态：`likely_issue`，严重性 `high`，置信度 `high`。

源码位置：`QuoteVerification/dcap_quoteverify/sgx-dcap-quoteverify-rs/src/lib.rs`

关键代码片段：

```rust
/// - **qve_report_info**\
/// This parameter can be used in 2 ways.\
///     - If qve_report_info is NOT None, the API will use Intel QvE to perform quote verification, and QvE will generate a report using the target_info in sgx_ql_qe_report_info_t structure.\
///     - if qve_report_info is None, the API will use QVL library to perform quote verification, note that the results can not be cryptographically authenticated in this mode.
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

## 发现 2：`tee_verify_quote` 同样支持 QvE-less 模式

源码位置：同上。

关键代码片段：

```rust
pub fn tee_verify_quote(
    quote: &[u8],
    quote_collateral: Option<&QuoteCollateral>,
    expiration_check_date: i64,
    qve_report_info: Option<&mut sgx_ql_qe_report_info_t>,
    supp_data_descriptor: Option<&mut tee_supp_data_descriptor_t>,
) -> Result<(u32, sgx_ql_qv_result_t), quote3_error_t> {
    ...
    let p_qve_report_info = qve_report_info.map_or(ptr::null_mut(), |p| p);
    ...
}
```

## 发现 3：sample 显式演示 trusted 和 untrusted 两种模式

源码位置：`SampleCode/RustQuoteVerificationSample/src/main.rs`

trusted mode：

```rust
match tee_verify_quote(
    quote,
    collateral.ok().as_ref(),
    current_time,
    Some(&mut qve_report_info),
    p_supplemental_data,
) {
    ...
}
```

untrusted mode：

```rust
// if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib'
// to verify quote, this mode doesn't rely on SGX capable system, but the results
// can not be cryptographically authenticated
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

## 影响解释

在 verifier 运行环境本身不可信、或攻击者可能篡改 verifier 进程/OS 的 threat model 下，QVL-only 的返回值不能作为高强度 attestation 结论。QvE 模式的意义是让验证结果由 enclave 生成 report，从而由调用方验证 QvE report 和 identity。

由于 Rust API 用 `Option` 暴露强/弱模式，开发者很容易为了兼容性传 `None`，然后把结果当成强证明使用。

## 人工判断

这不是隐藏漏洞，因为代码注释已经说明弱模式风险。更准确的 issue 类型是安全默认值问题：

- 标准 API 同时支持强/弱模式。
- 弱模式只需要传 `None`，没有显式危险函数名。
- sample 虽然有注释，但仍可能被复制到生产。

## 建议修复

- 将 QvE-less mode 拆成单独函数，例如 `verify_quote_unauthenticated_qvl_only`。
- 在默认 `verify_quote` API 中要求 `qve_report_info` 必填。
- 增加 feature flag，例如 `allow-unauthenticated-qvl`，默认关闭。
- 在 sample 的 untrusted mode 输出中明确写出“not production secure unless verifier process/OS is trusted”。

## 建议状态

- 不建议 CVE。
- 可发 hardening issue。
- 英文 issue 标题建议：`Rust DCAP wrapper exposes unauthenticated QVL-only verification through the default quote verification API`。
