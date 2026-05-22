# Dstack

## 扫描元信息

- 仓库：`https://github.com/Dstack-TEE/dstack`
- Commit：`f67b4f67ebabef0a27795705121698280a1038dc`
- 本地克隆：`/tmp/teecheck-clone-2156312579`
- Run：`runs/scan-20260520-dstack`

## 结论

TEECheck 把 key provider client 和 VMM host API 标成 `likely_issue`：它们接收 guest quote 后直接转发给 key provider，client 侧只做长度限制。人工复核后认为这不能直接算漏洞，因为 KMS 主服务侧存在 quote verification、attestation authorization、image hash 校验和 self authorization。

当前更准确的表述是：这是一个跨组件 trust boundary，需要确认 key provider/KMS 是否总是在服务端独立验证 quote，而不是依赖 VMM 或 client。

## 发现 1：key-provider-client 只转发 quote

TEECheck 状态：`likely_issue`，严重性 `high`，置信度 `medium`。

源码位置：`key-provider-client/src/host.rs`

关键代码片段：

```rust
pub async fn get_key(quote: Vec<u8>, address: IpAddr, port: u16) -> Result<QuoteResponse> {
    if quote.len() > 1024 * 1024 {
        bail!("Quote is too long");
    }
    let mut tcp_stream = TcpStream::connect((address, port))
        .await
        .context("Failed to connect to key provider")?;
    let payload = QuoteRequest { quote: &quote };
    let serialized = serde_json::to_vec(&payload)?;
    ...
    let response: QuoteResponse =
        serde_json::from_slice(&response).context("Failed to deserialize response")?;
    Ok(response)
}
```

这段 client 代码没有本地验证 quote，只做长度限制并把 quote 发给 key provider。单独看确实是薄边界，但 client 不一定应该承担最终验证职责。

## 发现 2：VMM host API 把 guest quote 传给 key provider

TEECheck 状态：`likely_issue`，严重性 `medium`，置信度 `high`。

源码位置：`vmm/src/host_api_service.rs`

关键代码片段：

```rust
async fn get_sealing_key(self, request: GetSealingKeyRequest) -> Result<GetSealingKeyResponse> {
    let key_provider = &self.app.config.key_provider;
    if !key_provider.enabled {
        bail!("Key provider is not enabled");
    }
    let response = get_key(request.quote, key_provider.address, key_provider.port)
        .await
        .context("Failed to get sealing key from key provider")?;

    Ok(GetSealingKeyResponse {
        encrypted_key: response.encrypted_key,
        provider_quote: response.provider_quote,
    })
}
```

VMM 层没有验证 quote，而是作为转发层。这是否安全取决于 key provider/KMS 服务端是否独立验证 quote、授权 app、绑定 boot/config/image。

## 反证：KMS 服务端存在校验链

源码位置：`kms/src/main_service.rs`

关键代码片段 1：必须已经有 attestation。

```rust
fn ensure_attested(&self) -> Result<&VerifiedAttestation> {
    let Some(attestation) = &self.attestation else {
        bail!("No attestation provided");
    };
    Ok(attestation)
}
```

关键代码片段 2：调用 auth API，并校验 OS image hash。

```rust
async fn ensure_app_attestation_allowed(
    &self,
    att: &VerifiedAttestation,
    is_kms: bool,
    use_boottime_mr: bool,
    vm_config_str: &str,
) -> Result<BootConfig> {
    let boot_info = build_boot_info(att, use_boottime_mr, vm_config_str)?;
    let response = self.state.config.auth_api
        .is_app_allowed(&boot_info, is_kms)
        .await?;
    if !response.is_allowed {
        bail!("Boot denied: {}", response.reason);
    }
    self.verify_os_image_hash(vm_config_str.into(), att).await?;
    ...
}
```

关键代码片段 3：证书签发路径验证 RA public key 绑定。

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

这些代码说明最终安全性主要在 KMS 服务端，而不是 VMM/client。

## 进一步需要确认的问题

- key provider 接口是否总是路由到 KMS 这套 verification/authorization 逻辑。
- 是否存在一个简化 key provider 只相信 VMM 转发结果。
- `get_sealing_key` 返回的 `encrypted_key` 是否绑定 quote 里的 guest key，攻击者能否替换 quote 后拿到可用 key。
- 服务端是否检查 quote freshness 或业务 challenge，而不只是验证静态 measurement。

## 建议状态

- 暂不发 CVE。
- 暂不直接发漏洞 issue。
- 可发架构澄清 issue。英文标题可写：`Clarify trust boundary and server-side quote verification requirements for key-provider-client and VMM get_sealing_key`。
