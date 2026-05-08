# 私有安全通报草稿：QOS-UNVERIFIED-TIME

**发送渠道**：GitHub Security Advisory 或维护者 security contact，不建议公开 Issue。  
**建议提交地址**：https://github.com/tkhq/qos/security/advisories/new  
**状态**：CVE 预申请候选；需要 PoC 或维护者 threat model 确认。  

## 表单字段

**标题**

Trusted attestation verification time is derived from an unsafe-parsed Nitro attestation document without signature validation

**严重性，暂定**

Medium，条件是攻击者可以影响 `NsmProvider`、NSM response，或生产代码允许不可信 provider 实现。暂定：

`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = 5.5

如果远程流程可以影响 provider response，严重性可能更高。如果 production `Nsm` 永远直接使用可信 Nitro Secure Module，且 OS / device boundary 在 TCB 内，严重性应下调。

**CWE 候选**

- CWE-345 Insufficient Verification of Data Authenticity
- CWE-347 Improper Verification of Cryptographic Signature
- CWE-829 Inclusion of Functionality from Untrusted Control Sphere

**受影响产品**

`tkhq/qos`

**受影响版本**

待确认。当前复核锚点为 commit `df1e355`。

## 正文，可直接粘贴

### Summary

We are reporting a potential trust-boundary issue in `tkhq/qos`. The `NsmProvider::timestamp_ms` implementation for `Nsm` requests a Nitro attestation document with no nonce, parses it with `unsafe_attestation_doc_from_der`, and returns the embedded timestamp as trusted current time. That timestamp is later used as the validation time when verifying another attestation document.

The concern is that the timestamp is extracted before verifying the local attestation document signature or certificate chain. If an attacker can influence the `NsmProvider` response, replace the provider implementation, or otherwise control the DER bytes parsed by `unsafe_attestation_doc_from_der`, they may influence the time used for attestation verification.

### Affected component

- Repository: `tkhq/qos`
- Reviewed commit: `df1e355`
- File: `src/qos_nsm/src/nsm.rs`
- Function: `NsmProvider::timestamp_ms` implementation for `Nsm`
- Reviewed permalink: https://github.com/tkhq/qos/blob/df1e355/src/qos_nsm/src/nsm.rs#L41-L54

Related consumer:

- File: `src/qos_core/src/protocol/services/key.rs`
- Function using the derived current time: `verify_and_extract_attestation_doc_from_der`
- Reviewed permalink: https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/key.rs#L280-L290

### Technical details

The reviewed `timestamp_ms` path requests a Nitro attestation document using:

```rust
types::NsmRequest::Attestation {
    user_data: None,
    nonce: None,
    public_key: None,
}
```

It then parses the returned DER with:

```rust
nitro::unsafe_attestation_doc_from_der(&document)?
```

and returns:

```rust
Ok(attestation_document.timestamp)
```

The function name `unsafe_attestation_doc_from_der` suggests that this parse step does not perform full authenticity validation. The extracted timestamp is then used as the current time for validating another attestation document. This means a value obtained from an unverified attestation document may influence a later security decision.

### Security impact

If the `NsmProvider` output can be forged, replaced, or controlled, an attacker may be able to manipulate the effective validation time used for attestation verification.

Potential consequences:

- a stale or expired attestation document may be accepted by backdating validation time;
- a valid attestation document may be rejected by forwarding validation time;
- freshness and certificate-validity decisions may depend on attacker-influenced metadata;
- production code using an alternative or mock `NsmProvider` may accidentally weaken attestation verification.

If the production implementation always communicates directly with a trusted local Nitro Secure Module and the OS / NSM device path is in the TCB, practical exploitability may be limited. We are reporting this because the boundary and provider abstraction make the security assumption important to confirm.

### Attack preconditions

- The attacker can influence `nsm_process_request` output, replace or implement `NsmProvider`, compromise the NSM device path, or otherwise control the DER returned to `unsafe_attestation_doc_from_der`.
- The returned timestamp is used as the validation time for a security-sensitive remote attestation document.
- There is no independent trusted time source or monotonicity check.

### Reproduction plan

The PoC requirement is the main open item. Expected reproduction path:

1. Implement or inject a malicious `NsmProvider` that returns an attestation response with an attacker-chosen timestamp.
2. Trigger the code path that calls `verify_and_extract_attestation_doc_from_der`.
3. Show that the attacker-chosen timestamp becomes the `current_time_seconds` or equivalent validation time.
4. Demonstrate that an attestation document outside the intended validity window is accepted, or that a valid one is rejected.

Without this PoC or a maintainer-confirmed untrusted provider boundary, this may be better classified as a hardening issue.

### Suggested fix

- Do not derive trusted current time from an unsafe-parsed attestation document.
- Use a trusted monotonic or platform time source appropriate to the threat model.
- If an attestation document must be used as a time source, verify its signature and certificate chain before trusting its timestamp.
- Include a nonce / challenge in the local attestation request so the timestamp cannot be replayed independently.
- Narrow the `NsmProvider` abstraction or document that production code must not use untrusted provider implementations for time.
- Add tests showing that forged provider timestamps cannot influence verification decisions.

### Questions for maintainers

1. Can production code use any `NsmProvider` implementation other than the hardware-backed `Nsm`?
2. Is the NSM device path considered inside the trusted computing base?
3. Which security decisions rely on `timestamp_ms`?
4. Is there an existing trusted time source or monotonicity check elsewhere in the architecture?
5. Should `unsafe_attestation_doc_from_der` outputs ever be used for security decisions before signature validation?
6. Would you consider changing this to use trusted local time or verified attestation document time?

## 发送前检查清单

- [ ] 在当前 `main` 上重新确认 `timestamp_ms` 和 consumer 代码。
- [ ] 尽量补一个 malicious `NsmProvider` 单测或 harness。
- [ ] 明确此问题是 CVE 候选，还是 hardening concern。
- [ ] 填写报告人 credit / handle。
- [ ] 约定披露窗口。

