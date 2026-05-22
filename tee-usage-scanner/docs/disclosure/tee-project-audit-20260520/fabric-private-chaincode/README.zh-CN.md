# Hyperledger Fabric Private Chaincode

## 扫描元信息

- 仓库：`https://github.com/hyperledger/fabric-private-chaincode`
- Commit：`716cde030b78a9826c822c68bbf63a0c05a4c916`
- 本地克隆：`/tmp/teecheck-clone-3600054879`
- Run：`runs/scan-20260520-fabric-private-chaincode`

## 结论

这是本轮最值得优先深挖和上报的项目。TEECheck 给出两个 `confirmed_candidate`：

- IAS evidence verification 接受多个非 OK quote status，并且 TODO 明确未检查 attributes/debug flag。
- enclave 内部验证了 signed proposal 签名，但没有把 signed proposal payload 和实际执行的 `ChaincodeRequestMessage` 强绑定；实际 request 是从另一个 ECALL 参数解析并执行的。

第二个点更强，可能形成真实攻击路径：攻击者提供一个合法签名的 proposal，同时替换实际进入 chaincode 执行的 encrypted request，使 enclave 对未被 proposal 签名绑定的请求执行 chaincode。

## 发现 1：IAS quote status 接受过宽，attributes/debug flag 未检查

TEECheck 状态：`confirmed_candidate`，严重性 `high`，置信度 `high`。

源码位置：`common/crypto/attestation-api/evidence/verify-evidence.cpp`

关键代码片段：

```cpp
const unsigned int flags = QSF_ACCEPT_GROUP_OUT_OF_DATE | QSF_ACCEPT_CONFIGURATION_NEEDED |
                           QSF_ACCEPT_SW_HARDENING_NEEDED |
                           QSF_ACCEPT_CONFIGURATION_AND_SW_HARDENING_NEEDED;
COND2LOGERR(VERIFY_SUCCESS !=
                verify_enclave_quote_status(ias_report.c_str(), ias_report.length(), flags),
    "invalid quote status");
```

```cpp
// check report data
std::string hex_report_data, expected_hex_report_data_str;
COND2ERR(false ==
         extract_hex_from_report(ias_report,
             offsetof(sgx_quote_t, report_body) + offsetof(sgx_report_body_t, report_data),
             sizeof(sgx_report_data_t), hex_report_data));
expected_hex_report_data_str =
    ByteArrayToHexEncodedString(pdo::crypto::ComputeMessageHash(expected_statement));
expected_hex_report_data_str.append(expected_hex_report_data_str.length(), '0');
COND2LOGERR(0 != hex_report_data.compare(expected_hex_report_data_str),
    "expected statement mismatch");

// TODO: check attributes of attestation (e.g., DEBUG flag disabled in release mode)
```

人工判断：

- TEECheck packet 里“freshness/replay missing”的说法不完全准确，因为代码会把 `expected_statement` 的 hash 和 quote `report_data` 比较；调用方可以把 nonce/challenge 放进 `expected_statement`。
- 更准确的问题是 quote status policy 太宽，且 attributes/debug flag 明确 TODO 未完成。

影响：

- 可能接受 out-of-date、configuration-needed、software-hardening-needed 等状态。
- 如果 release 环境没有拒绝 debug enclave，远程方可能信任可调试 enclave。

## 发现 2：signed proposal 与实际执行 request 缺少强绑定

TEECheck 状态：`confirmed_candidate`，严重性 `high`，置信度 `high`。

源码位置：`ecc_enclave/enclave/enclave.cpp`

关键代码片段 1：验证 signed proposal 签名，但 TODO 未从 proposal payload 解出 request。

```cpp
ByteArray signature = ByteArray(signed_proposal.signature->bytes,
    signed_proposal.signature->bytes + signed_proposal.signature->size);
ByteArray message = ByteArray(signed_proposal.proposal_bytes->bytes,
    signed_proposal.proposal_bytes->bytes + signed_proposal.proposal_bytes->size);
...
b = validate_message_signature(signature, message, encoded_signer_cert);
COND2LOGERR(!b, "signature validation failed");

// TODO unwrap ChaincodeRequestMessage from signed proposal
// once this is in place we can remove ChaincodeRequestMessage from ecall

// TODO implement me
// ByteArray binding_data;
// ...
// b = compute_message_hash(binding_data, ctx->binding);
```

关键代码片段 2：实际执行的 request 来自独立的 `cc_request_message_bytes`。

```cpp
istream = pb_istream_from_buffer(
    (const unsigned char*)cc_request_message_bytes, cc_request_message_bytes_len);

b = pb_decode(&istream, fpc_ChaincodeRequestMessage_fields, &cc_request_message);
COND2LOGERR(!b, PB_GET_ERROR(&istream));
COND2LOGERR(cc_request_message.encrypted_request->size == 0, "zero size request");
```

关键代码片段 3：解密实际 request 后执行 chaincode。

```cpp
b = decrypt_message(request_encryption_key, encrypted_request, clear_request);
COND2LOGERR(!b, "message decryption failed");

istream = pb_istream_from_buffer(
    (const unsigned char*)clear_request.data(), clear_request.size());
b = pb_decode(&istream, fpc_CleartextChaincodeRequest_fields, &cleartext_cc_request);
COND2LOGERR(!b, PB_GET_ERROR(&istream));
COND2LOGERR(!cleartext_cc_request.has_input, "no input in cleartext request");

invoke_ret = invoke(response, response_len, &response_len_out, &ctx);
```

关键代码片段 4：response 里后来加入 request hash，但这是执行后绑定，不能替代执行前校验。

```cpp
ByteArray ba_cc_request_message(
    cc_request_message_bytes, cc_request_message_bytes + cc_request_message_bytes_len);
ByteArray ba_cc_request_message_hash;
b = compute_message_hash(ba_cc_request_message, ba_cc_request_message_hash);
...
crm.chaincode_request_message_hash->size = ba_cc_request_message_hash.size();
```

## 攻击思路假设

如果协议期望 signed proposal 决定 chaincode invocation 的内容，那么当前流程可能允许：

1. 攻击者提交一个签名合法的 `SignedProposal`。
2. 攻击者在独立 ECALL 参数中放入另一个 `ChaincodeRequestMessage`。
3. enclave 验证 proposal 签名通过。
4. enclave 没有从 proposal payload 中解出并比较实际 request。
5. enclave 解密并执行独立传入的 request。
6. response 中虽然包含 request hash，但执行已经发生，不能阻止未授权 request 被执行。

最终是否可利用，取决于 Fabric/FPC 的外层 endorsement flow 是否在 enclave 外部强制比较了 proposal、request hash 和 response。如果外层没有强制，则这是高价值漏洞。

## 建议修复

- 在 enclave 内从 `SignedProposal.proposal_bytes.payload` 解出 `ChaincodeRequestMessage`。
- 删除或废弃单独传入的 `cc_request_message_bytes`，或者要求它与 proposal payload 中的 request hash 完全一致。
- 恢复/实现 binding 计算，至少绑定 `nonce || creator || epoch || channel_id || tx_id || request_hash`。
- 在执行 chaincode 前完成绑定校验，不能只在 response 阶段附带 hash。
- attestation verification 中收紧 quote status policy，并在 release 模式拒绝 debug enclave。

## 建议状态

- 建议优先准备 issue。
- 如果能确认外层协议没有补充绑定校验，可以考虑进一步准备 CVE 预申请。
- 英文 issue 标题建议：`Enclave verifies SignedProposal but does not bind it to the ChaincodeRequestMessage executed inside the enclave`。
