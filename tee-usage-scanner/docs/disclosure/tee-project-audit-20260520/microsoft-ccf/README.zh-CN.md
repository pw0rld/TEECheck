# Microsoft CCF

## 扫描元信息

- 仓库：`https://github.com/microsoft/CCF`
- Commit：`712207f9a3367fa25c97ded8c8e9102d27314748`
- 本地克隆：`/tmp/teecheck-clone-498460039`
- Run：`runs/scan-20260520-ccf`

## 结论

本轮 TEECheck 对 CCF 的主要疑点是 quote verification 路径没有显式 freshness/replay 检查。人工复核后，这个结论还不能作为漏洞：CCF 的路径会调用 PAL verifier，并把 report data 解析为 node public key hash，再结合 store 中的 host data、TCB policy 等检查。

当前状态是 `needs_review`，不是确认漏洞。若要继续推进，需要理解 CCF 节点加入协议里 quote 是否必须和当前 join request 的 node public key、网络状态、endorsement freshness 绑定。

## 发现：quote verification freshness 需要协议级复核

TEECheck 状态：`needs_review`，严重性 `high`，置信度 `medium`。

源码位置：

- `src/node/node_state.h`
- `src/node/quote.cpp`
- `src/pal/attestation.cpp`

关键代码片段：

```cpp
QuoteVerificationResult verify_quote(
  ccf::kv::ReadOnlyTx& tx,
  const QuoteInfo& quote_info_,
  const std::vector<uint8_t>& expected_node_public_key_der,
  pal::PlatformAttestationMeasurement& measurement,
  const std::optional<std::vector<uint8_t>>& code_transparent_statement,
  std::shared_ptr<NetworkIdentitySubsystemInterface> network_identity_subsystem) override
{
  return AttestationProvider::verify_quote_against_store(
    tx,
    quote_info_,
    expected_node_public_key_der,
    measurement,
    code_transparent_statement,
    network_identity_subsystem);
}
```

```cpp
try
{
  pal::verify_quote(quote_info, measurement, report_data);
  quoted_hash = report_data.to_sha256_hash();
}
catch (const std::exception& e)
{
  LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
  return QuoteVerificationResult::Failed;
}
```

```cpp
void verify_quote(
  const QuoteInfo& quote_info,
  PlatformAttestationMeasurement& measurement,
  PlatformAttestationReportData& report_data)
{
  if (quote_info.format == QuoteFormat::insecure_virtual)
  {
    verify_virtual_attestation_report(quote_info, measurement, report_data);
  }
  else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
  {
    verify_snp_attestation_report(quote_info, measurement, report_data);
  }
  else
  {
    throw std::logic_error(
      "CCF 7.0.0 only supports SNP and Virtual attestation formats");
  }
}
```

## 人工判断

TEECheck 的担忧点是：调用处没有看到 nonce/timestamp/replay cache。但这不等于漏洞，因为 CCF 的 quote 可能通过 `report_data` 绑定 node public key，节点加入协议可能再用 store 状态和网络治理流程防止旧 quote 被滥用。

目前可以确认的事实：

- `node_state.h` 把 verification 委托给 `AttestationProvider::verify_quote_against_store`。
- `quote.cpp` 调用 `pal::verify_quote` 得到 `measurement` 和 `report_data`。
- `pal::verify_quote` 根据 quote format 分派到 SNP 或 virtual verifier。

目前不能确认的点：

- quote 是否绑定一次性 challenge。
- 如果复用旧 quote 和旧 public key，节点加入流程是否会拒绝。
- endorsement freshness/TCB policy 是否覆盖了 replay 风险。

## 建议状态

- 不发 CVE。
- 暂不发安全 issue。
- 后续若要继续，应该专门做协议审计：节点 join request、node certificate/public key、quote report data、ledger store policy、SNP endorsement cache 的绑定关系。

