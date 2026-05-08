# 私有安全通报草稿：PHALA-MASTERKEY-DOS

**发送渠道**：GitHub Security Advisory，或先用私密渠道确认 threat model。  
**建议提交地址**：https://github.com/phala-network/phala-blockchain/security/advisories/new  
**状态**：CVE 预申请候选；严重性依赖 sealed storage 是否在 untrusted host 边界外。  

## 表单字段

**标题**

Master-key seal/unseal path panics on malformed sealed data, enabling denial of service against pRuntime

**严重性，暂定**

Medium。对于本地 untrusted storage tampering，暂定：

`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = 5.5

如果低权限或远程路径可以影响 sealed master key 数据，严重性可能上调。如果 sealed storage 完全在 TCB 内，可能更适合作为 robustness hardening。

**CWE 候选**

- CWE-248 Uncaught Exception
- CWE-755 Improper Handling of Exceptional Conditions

**受影响产品**

`phala-network/phala-blockchain`

**受影响版本**

待确认。当前复核锚点为 commit `654b1b6`。

## 正文，可直接粘贴

### Summary

We are reporting a potential denial-of-service issue in the master-key recovery path of `phala-network/phala-blockchain`. The code in `crates/phactory/src/system/master_key.rs` uses `expect()` and `assert!()` while sealing, unsealing, decoding, and integrity-checking master key data.

If the sealed master-key storage is malformed, truncated, corrupted, replaced, or has an invalid signature, the process panics instead of returning a structured error. In deployments where sealed storage is controlled by, stored on, or writable by an untrusted host, this can be used as a denial-of-service vector against pRuntime startup or recovery.

### Affected component

- Repository: `phala-network/phala-blockchain`
- Reviewed commit: `654b1b6`
- File: `crates/phactory/src/system/master_key.rs`
- Functions: `seal`, `try_unseal`
- Reviewed permalink: https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/phactory/src/system/master_key.rs#L45-L117

### Technical details

The reviewed code includes panic-on-error behavior in security-critical state recovery:

- `sys.seal_data(...).expect("Seal master key failed")`
- `sys.unseal_data(...).expect("Unseal master key failed")`
- `MasterKeySeal::decode(...).expect("Failed to decode sealed master key")`
- `assert!(identity_key.verify_data(...), "Broken sealed master key")`
- `assert!(identity_key.verify_data(...), "Broken sealed master key history")`

There is also a source comment above `try_unseal` noting that the function "could panic a lot". That accurately describes the observed behavior, but it means malformed persisted state can terminate the process rather than producing a controlled fail-closed error.

### Security impact

If an attacker can modify or corrupt the sealed master key file, the service can be forced to panic during startup, key handover, or recovery. This prevents normal recovery and can put the service into a crash loop or unavailable state.

Potential impact:

- pRuntime cannot start after sealed key storage is corrupted.
- Key recovery / handover paths terminate unexpectedly.
- An untrusted host with storage write capability can deny availability.
- Operators receive a process crash instead of a typed security error that can be handled or reported.

This issue does not appear to directly expose master key material. The impact is availability.

### Attack preconditions

- The attacker can modify, replace, truncate, or corrupt the sealed master key file, or can influence the sealing backend to return malformed data.
- The affected service later calls `try_unseal` during startup, recovery, or handover.
- A panic terminates the process or causes meaningful service outage.

### Reproduction plan

A live deployment PoC has not been attached. The expected reproduction path is:

1. Locate the file referenced by `master_key_file_path`.
2. Replace it with random bytes, a truncated blob, or a structurally valid `MasterKeySeal` with an invalid integrity signature.
3. Start the affected pRuntime component or trigger a recovery path that calls `try_unseal`.
4. Observe a panic at decode, unseal, or signature verification instead of a returned `Result` / typed error.
5. Confirm whether the process exits, restarts, or enters an unavailable state.

### Suggested fix

- Change `seal` and `try_unseal` to return `Result`.
- Replace `expect()` and `assert!()` with typed errors.
- Treat invalid sealed data as a security event: log it, fail closed, surface it to operations, but do not panic the process.
- Add tests for malformed sealed data, truncated data, invalid signature, and sealing backend failure.
- Consider separating irrecoverable corruption handling from normal startup so operators can distinguish tampering from local state loss.

### Questions for maintainers

1. Is sealed master-key storage considered attacker-controlled, host-controlled, or trusted in the production threat model?
2. Can an untrusted host or compromised volume modify the sealed key file?
3. Does a panic terminate pRuntime or trigger clean supervised recovery?
4. Are there existing filesystem permissions, measured storage protections, or host policies that prevent this attack precondition?
5. Is malformed sealed data expected to be treated as tampering, operational corruption, or both?
6. Which release first included the current panic-on-error behavior?

## 发送前检查清单

- [ ] 确认 `main` 和最新 release tag 是否仍使用 `expect` / `assert!`。
- [ ] 最好先问维护者 sealed storage 是否在 TCB 内。
- [ ] 如果可能，补一个本地 corrupted sealed file PoC。
- [ ] 填写报告人 credit / handle。
- [ ] 约定披露窗口。

