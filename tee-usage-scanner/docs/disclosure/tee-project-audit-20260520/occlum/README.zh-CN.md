# Occlum

## 扫描元信息

- 仓库：`https://github.com/occlum/occlum`
- Commit：`690d5dbf34f3b08e4b5e48e16ce16231550e78c4`
- 本地克隆：`/tmp/teecheck-clone-1511663286`
- Run：`runs/scan-20260520-occlum`

## 结论

本轮发现两个点：

- `tools/toolchains/dcap_lib/src/occlum_dcap.rs` 是 DCAP ioctl wrapper，TEECheck 认为它把 quote 生成/验证委托给外部接口，缺少本地校验。人工复核后认为这是 wrapper 的正常设计，但 FFI buffer 边界和 threat model 需要说明。
- `demos/remote_attestation/azure_attestation` 的 MAA 示例没有强制 nonce/freshness，成功条件主要依赖 MAA HTTP 结果和调用方传入的 `user_data`。这个更适合作为 sample hardening issue。

## 发现 1：DCAP ioctl wrapper 的信任边界需要澄清

TEECheck 状态：`needs_review`，严重性 `medium`，置信度 `medium`。

源码位置：`tools/toolchains/dcap_lib/src/occlum_dcap.rs`

关键代码片段：

```rust
pub struct IoctlGenDCAPQuoteArg {
    pub report_data: *const sgx_report_data_t,
    pub quote_size: *mut u32,
    pub quote_buf: *mut u8,
}

pub fn generate_quote(
    &mut self,
    quote_buf: *mut u8,
    report_data: *const sgx_report_data_t,
) -> Result<i32, Error> {
    let quote_arg = IoctlGenDCAPQuoteArg {
        report_data: report_data,
        quote_size: &mut self.quote_size,
        quote_buf: quote_buf,
    };

    let ret = unsafe { libc::ioctl(self.fd, IOCTL_GEN_DCAP_QUOTE, &quote_arg) };
    ...
}

pub fn verify_quote(&mut self, verify_arg: *mut IoctlVerDCAPQuoteArg) -> Result<i32, Error> {
    let ret = unsafe { libc::ioctl(self.fd, IOCTL_VER_DCAP_QUOTE, verify_arg) };
    ...
}
```

人工判断：这段代码本身更像底层 FFI wrapper。它不负责 policy、nonce 或 identity allowlist。风险点不是“必然漏洞”，而是调用方如果把 ioctl 结果当作完整安全结论，可能缺少上层绑定检查。

建议：

- 文档明确说明 host/driver/DCAP 组件在 threat model 里的角色。
- 对 `quote_buf`、`quote_size`、`report_data` 的调用约束写清楚。
- 高层 sample 或 API 应提醒调用方校验 quote 中的 `report_data` 和业务 nonce。

## 发现 2：MAA demo 新鲜度依赖调用方

TEECheck 状态：`likely_issue`，严重性 `medium`，置信度 `medium`。

源码位置：

- `demos/remote_attestation/azure_attestation/maa_attestation/azure_att/src/maa.rs`
- `demos/remote_attestation/azure_attestation/maa_init/init/src/maa.rs`

关键代码片段：

```rust
pub fn maa_generate_json(user_data: &[u8]) -> Result<serde_json::Value, &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(user_data);
    let hash = hasher.finalize();

    let quote_base64 = maa_get_quote_base64(&hash).unwrap();
    ...
    *maa_json.pointer_mut("/runtimeData/data").unwrap() =
        serde_json::Value::String(base64::encode(&user_data));

    Ok(maa_json.to_owned())
}

pub fn maa_attestation(
    url: String,
    request_body: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let resp = client.post(att_url).json(&request_body).send()?;

    match resp.status() {
        reqwest::StatusCode::OK => Ok(resp.json().unwrap()),
        s => Err("maa attestation failed".into())
    }
}
```

这里把 `Sha256(user_data)` 放入 `report_data`，并把原始 `user_data` 放入 MAA runtime data。设计上可以支持 nonce，但函数没有强制 `user_data` 必须包含 verifier challenge，也没有验证返回 token 中的 claim 是否绑定当前请求。

## 影响解释

如果调用方每次传入 verifier 生成的一次性 challenge，那么这段 demo 可以完成 freshness binding。如果调用方传固定 `user_data`，则同一个 quote/runtimeData 组合可能被重复使用，freshness 完全依赖 MAA 服务端或外层协议。

因此问题应表述为：

“MAA demo does not enforce nonce/challenge freshness or response-claim binding by default.”

不要表述成：

“Occlum attestation is broken.”

## 建议状态

- 不建议 CVE。
- 可发普通 GitHub issue，要求 demo 明确加入 nonce/challenge 参数、校验 MAA 返回 JWT 中 runtime data/nonce 绑定，或者在 README 中强调调用方必须传入唯一 challenge。

