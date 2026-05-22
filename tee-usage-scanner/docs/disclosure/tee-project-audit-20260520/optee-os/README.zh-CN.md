# OP-TEE OS

## 扫描元信息

- 仓库：`https://github.com/OP-TEE/optee_os`
- Commit：`97865fe8b164fe2941b26c2bf696f1699e04d535`
- 本地克隆：`/tmp/teecheck-clone-4209523830`
- Run：`runs/scan-20260520-optee-os`

## 结论

本轮有两个发现：

- `core/pta/attestation.c` 被 TEECheck 标为 `likely_issue`，说可能泄漏 attestation private key。人工复核认为这是误报倾向很强：公开命令只返回 public key，private key 用于内部签名。
- `core/pta/veraison_attestation/veraison_attestation.c` 是 `needs_review`，主要问题是 identity 常量硬编码，以及模块是 evidence generator，不做 verifier 侧 freshness/policy。这里更适合设计复核，不是直接漏洞。

## 发现 1：`attestation.c` 私钥泄漏结论很可能是误报

TEECheck 状态：`likely_issue`，严重性 `high`，置信度 `medium`。

人工复核状态：不建议按漏洞处理。

源码位置：`core/pta/attestation.c`

关键代码片段：

```c
static TEE_Result cmd_get_pubkey(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	...
	res = init_key();
	if (res)
		return res;

	sz = crypto_bignum_num_bytes(key->e);
	if (*e_out_sz >= sz)
		crypto_bignum_bn2bin(key->e, e);

	sz = crypto_bignum_num_bytes(key->n);
	if (*n_out_sz >= sz)
		crypto_bignum_bn2bin(key->n, n);

	params[2].value.a = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
	return res;
}
```

```c
switch (cmd_id) {
case PTA_ATTESTATION_GET_PUBKEY:
	res = cmd_get_pubkey(param_types, eparams);
	break;
case PTA_ATTESTATION_GET_TA_SHDR_DIGEST:
	res = cmd_get_ta_shdr_digest(param_types, eparams);
	break;
case PTA_ATTESTATION_HASH_TA_MEMORY:
	res = cmd_hash_ta_memory(param_types, eparams);
	break;
case PTA_ATTESTATION_HASH_TEE_MEMORY:
	res = cmd_hash_tee_memory(param_types, eparams);
	break;
default:
	break;
}
```

TEECheck packet 提到 `cmd_get_attestation_key` 会释放敏感 RSA key material，但实际公开 command handler 里没有这个命令。`cmd_get_pubkey` 返回的是 RSA exponent `e` 和 modulus `n`，不是 private exponent `d`。

因此不建议发 issue，除非后续发现另一个命令能触发 `serialize_key()` 输出私钥。

## 发现 2：Veraison PTA hardcoded identity 需要设计复核

TEECheck 状态：`needs_review`，严重性 `medium`，置信度 `high`。

源码位置：`core/pta/veraison_attestation/veraison_attestation.c`

关键代码片段：

```c
#define SIGNER_ID {                                                \
		0xac, 0xbb, 0x11, 0xc7, 0xe4, 0xda, 0x21, 0x72,    \
		0x05, 0x52, 0x3c, 0xe4, 0xce, 0x1a, 0x24, 0x5a,    \
		0xe1, 0xa2, 0x39, 0xae, 0x3c, 0x6b, 0xfd, 0x9e,    \
		0x78, 0x71, 0xf7, 0xe5, 0xd8, 0xba, 0xe8, 0x6b     \
	}
#define INSTANCE_ID {                                              \
		0x01, 0xce, 0xeb, 0xae, 0x7b, 0x89, 0x27, 0xa3,    \
		...
	}
```

```c
if (!nonce || !nonce_sz)
	return TEE_ERROR_BAD_PARAMETERS;

status = get_hash_ta_memory(measurement_value);
...
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

人工判断：

- generator 不验证 evidence 是正常架构，验证应该由外部 verifier 完成。
- nonce 由 verifier 生成再传入 PTA，PTA 负责签入 evidence，这也符合常见 attestation flow。
- 真正需要复核的是 `SIGNER_ID` 和 `INSTANCE_ID` 是否只是 reference/demo 值。如果生产固件也静态复用这些值，会削弱设备唯一性和身份可信度。

## 建议状态

- `attestation.c` 不发 issue。
- Veraison PTA 可以发 design clarification issue：询问 hardcoded identity 是否只是示例，以及生产集成应如何注入设备唯一 identity。

