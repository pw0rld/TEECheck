# Occlum TEE/Attestation 审计记录

审计日期：2026-05-21

审计对象：`occlum/occlum`，本地克隆 `occlum`，`master` 分支。

仓库状态：

- 上游仓库：<https://github.com/occlum/occlum>
- 审计提交：`690d5dbf34f3b08e4b5e48e16ce16231550e78c4`
- 提交日期：2025-06-12
- 提交摘要：`fix issue 1686`

范围：只看 SGX TEE 边界、remote/local attestation、RA-TLS、Init-RA/KMS、quote/report/key 暴露、默认安全配置。没有做完整 syscall fuzz、Rust unsafe 全量审计或文件系统实现深挖。

## 总体判断

Occlum 的核心信任模型是“一个 Occlum 实例等于一个 SGX enclave”：LibOS、init、应用 rootfs 和多个进程都被放在同一个 enclave 身份下。构建阶段会把 init FS/root FS/config MAC 纳入受保护配置，启动时再逐层校验，这个方向是对的。

但从 attestation 视角看，当前仓库里的默认配置和 RA-TLS/Init-RA 参考实现不能按“默认安全”使用。最严重的问题在 gRPC RA-TLS：DCAP quote verification 的 terminal failure 只被打印，没有转换为 TLS 认证失败；同时 verifier callback 直接把 peer certificate 拷贝进固定 16KB 栈数组，存在远端可触发的内存破坏风险。

此外，Init-RA 模板默认关闭 measurement/debug 校验，`/dev/sgx` 对实例内所有进程开放 quote/report/sealing key 能力，意味着远程证明只能证明“这个 Occlum enclave 实例”，不能证明其中某个具体进程或应用没有被同实例内其他代码冒充。

## 关键发现

### OCCLUM-ATT-001：gRPC RA-TLS 会接受 DCAP terminal verification result

严重性：高

位置：

- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1976`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1992`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:2006`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:2010`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:2022`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:2031`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:2052`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:2053`
- `src/libos/src/util/sgx/dcap/quote_verifier.rs:91`
- `src/libos/src/util/sgx/dcap/quote_verifier.rs:92`

问题：

`occlum_verify_quote()` 调用 `dcap_verify_quote()` 后，会检查 `quote_verification_result`。但对于 `SGX_QL_QV_RESULT_INVALID_SIGNATURE`、`SGX_QL_QV_RESULT_REVOKED`、`SGX_QL_QV_RESULT_UNSPECIFIED` 等 terminal result，代码只打印错误，不修改返回值：

```c
case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
case SGX_QL_QV_RESULT_REVOKED:
case SGX_QL_QV_RESULT_UNSPECIFIED:
default:
    grpc_printf("\tError: App: Verification completed with Terminal result: %x\n",
           quote_verification_result);
}
...
return ret;
```

上层 `occlum_verify_cert()` 只在 `ret != 0` 时失败。底层 `QuoteVerifier::verify_quote()` 在 QvE report/identity 校验通过后会返回 `Ok((collateral_expiration_status, quote_verification_result, ...))`，并不要求 `quote_verification_result == OK`。

同仓库的 DCAP demo 在 terminal result 上会 `goto CLEANUP`，说明正确的调用方策略应该显式拒绝这些状态。

影响：

RA-TLS 客户端或服务端可能把撤销、签名无效、不明确、过期 collateral 的 quote 当成认证成功。Init-RA 场景下，这会直接影响 KMS/image key/业务 secret 的释放。

建议：

- `occlum_verify_quote()` 默认 fail-closed：只有 `collateral_expiration_status == 0` 且 `quote_verification_result == SGX_QL_QV_RESULT_OK` 才返回 0。
- 对 `CONFIG_NEEDED`、`OUT_OF_DATE`、`SW_HARDENING_NEEDED` 等非 OK 状态做显式 policy 配置，不能默认通过。
- 在 RA-TLS 单元测试中构造每一种 `sgx_ql_qv_result_t`，证明 terminal result 会让握手失败。

### OCCLUM-ATT-002：RA-TLS authorization callback 对 peer certificate 存在栈缓冲区溢出

严重性：高

位置：

- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1470`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1473`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1474`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1475`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:2034`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:2036`

问题：

`TlsAuthorizationCheck::Schedule()` 把攻击者可控的 `peer_cert()` 拷贝到固定 16KB 栈数组：

```c++
char der_crt[16000] = "";
auto peer_cert_buf = arg->peer_cert();
peer_cert_buf.copy(der_crt, peer_cert_buf.length(), 0);
```

没有检查 `peer_cert_buf.length() <= sizeof(der_crt) - 1`。随后 `occlum_verify_cert()` 也忽略传入的 `len`，用 `strlen()` 写入 BIO。

影响：

恶意 TLS peer 可以发送超长 certificate，触发 verifier 进程内存破坏。若 verifier 运行在 Occlum enclave 内，这就是 enclave 内远端内存破坏入口；即使运行在非 enclave 侧，也会造成 RA-TLS 认证路径崩溃或潜在代码执行。

建议：

- 不使用固定栈数组，直接用 `std::string`/`std::vector<uint8_t>` 持有 `peer_cert()`。
- `BIO_write()` 使用真实长度，禁止 `strlen()` 处理证书 buffer。
- 设置最大证书长度并在超限时返回 `GRPC_STATUS_UNAUTHENTICATED`。
- 加入超长 certificate 的负向测试。

### OCCLUM-ATT-003：Init-RA/gRPC 默认模板关闭所有 measurement 和 debug 校验

严重性：高/中，取决于部署是否直接沿用模板

位置：

- `etc/template/init_grpc_ratls.json:9`
- `etc/template/init_grpc_ratls.json:10`
- `etc/template/init_grpc_ratls.json:15`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1342`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1348`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1399`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1401`
- `tools/toolchains/grpc_ratls/ra_tls/0001-Add-Occlum-SGX-tls-function.patch:1437`
- `tools/init_grpc_ratls/src/main.rs:135`
- `tools/init_grpc_ratls/src/main.rs:136`
- `tools/init_grpc_ratls/src/main.rs:181`

问题：

`init_grpc_ratls.json` 默认：

- `verify_mr_enclave = off`
- `verify_mr_signer = off`
- `verify_isv_prod_id = off`
- `verify_isv_svn = off`
- `verify_config_svn = off`
- `verify_enclave_debuggable = off`

RA-TLS verifier 的逻辑是：遍历 `sgx_mrs`，先把 `status = true`，只有某个 verify flag 为 true 时才比较对应字段。如果所有 flag 都是 off，只要 `sgx_mrs` 数组非空，任意 peer measurement 都会通过。

Init-RA 还允许 `OCCLUM_INIT_RA_KMS_SERVER` 环境变量覆盖配置中的 KMS 地址，然后用 RA-TLS 去获取 `image_key` 和业务 keys。

影响：

用户如果按模板创建 `occlum new --init-ra grpc_ratls` 后忘记打开 policy，Init-RA client 会信任任意能完成 RA-TLS 证书结构的 KMS server。结合 ATT-001，错误 quote 状态也可能被接受，最终导致 image key 或业务 secret 被错误来源注入。

建议：

- 模板改为 fail-closed：默认开启 `verify_mr_signer`、`verify_enclave_debuggable`，并要求用户填入非空 allowlist。
- 若所有 verify flag 都是 off，`parse_sgx_config_json()` 或 `verify_measurement()` 应直接失败，除非显式设置 `insecure_allow_any_enclave`。
- KMS 地址覆盖应只来自受保护 config；若允许环境覆盖，必须明确要求该环境变量不在 Occlum `untrusted` env 列表中。
- 文档把“可忽略 measurement”改成开发/测试专用说明。

### OCCLUM-ATT-004：AECS Init-RA 默认策略为空，文档允许跳过 KMS measurement pinning

严重性：中/高，取决于 AECS/KMS 外部部署

位置：

- `etc/template/init_aecs.json:11`
- `etc/template/init_aecs.json:20`
- `etc/template/init_aecs.json:36`
- `tools/init_aecs/src/main.rs:167`
- `tools/init_aecs/src/main.rs:170`
- `tools/init_aecs/src/main.rs:177`
- `tools/init_aecs/src/main.rs:196`
- `docs/readthedocs/docs/source/init_ra.md:70`
- `docs/readthedocs/docs/source/init_ra.md:72`

问题：

AECS 模板中的 `ua_policy_*` 字段全部为空。`init_aecs` 把这些字段写到 `/etc/kubetee/unified_attestation.json` 供外部 AECS client 使用，然后从 KMS 获取 `image_key` 和业务 keys。

文档写明如果 `kms_server` 被认为可信，用户可以忽略 measurement policy。这对 demo 可以接受，但在 TEE/attestation 安全模型里，网络地址本身不是可信根。

影响：

如果业务把 AECS Init-RA 当作安全 key release 链路，但没有 pin KMS/AECS 的 TEE identity，攻击者只要影响 KMS 地址、DNS、service discovery 或网络路径，就可能让 client 从错误服务获取 image key/secret。

建议：

- AECS 模板至少要求 `ua_policy_hex_ta_measurement` 或 signer/prod_id/min_svn/debug_disabled 等关键字段非空。
- `init_aecs` 在关键 policy 全空时 fail-closed，除非显式启用开发模式。
- 文档把“ignore this part”改为“仅限已通过外部安全信道固定 KMS 身份的场景”。

### OCCLUM-ATT-005：`/dev/sgx` 对实例内所有进程开放 quote/report/sealing key 能力

严重性：中/高，取决于是否运行互不信任的进程

位置：

- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:27`
- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:38`
- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:120`
- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:133`
- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:163`
- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:178`
- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:201`
- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:245`
- `src/libos/src/fs/dev_fs/dev_sgx/mod.rs:261`
- `src/libos/src/util/sgx/sgx_key.rs:10`
- `src/libos/src/util/sgx/sgx_key.rs:12`

问题：

`/dev/sgx` metadata 暴露为 `mode: 0o666`。任何 Occlum 实例内进程都可以：

- 生成 local report；
- 生成 EPID/DCAP quote，并任意控制 `report_data`；
- 调用 `SGX_CMD_NUM_KEY`，把自选 `sgx_key_request_t` 传给 `sgx_get_key()`。

这符合“实例内应用是一个信任域”的设计，但对多进程/多租户场景是危险默认值。远程 verifier 只能看到同一个 enclave measurement，无法区分 quote 是由哪个应用进程、哪个脚本或哪个 sidecar 生成的。

影响：

同一 Occlum 实例内的低权限或被攻陷进程可以为自己的 TLS key 生成合法 quote，冒充“这个 Occlum enclave”；也可以尝试派生该 enclave 可访问的 sealing keys。若 KMS 或 peer verifier 把 Occlum measurement 等同于某个具体应用身份，就会出现跨进程冒充和 secret 越权。

建议：

- 文档和 API 明确：一个 Occlum 实例是一个 attestation/security domain，不要在同一实例内运行互不信任 workload。
- 对 `/dev/sgx` 增加权限控制或 capability gate；至少把 `SGX_CMD_NUM_KEY` 和 quote generation 与进程 UID/GID/配置绑定。
- KMS policy 绑定更细粒度的 KSS `config_id/config_svn`、init/root FS MAC、应用级公钥或启动参数，而不是只看 `MRENCLAVE/MRSIGNER`。

### OCCLUM-ATT-006：DCAP verification freshness 依赖不可信墙钟

严重性：中

位置：

- `src/libos/src/util/sgx/dcap/quote_verifier.rs:36`
- `src/libos/src/util/sgx/dcap/quote_verifier.rs:37`
- `src/libos/src/time/mod.rs:100`
- `src/libos/src/time/mod.rs:102`
- `src/libos/src/time/mod.rs:105`

问题：

DCAP quote verification 使用：

```rust
let current_time = time::do_gettimeofday().as_duration().as_secs() as time_t;
```

代码旁边已有 FIXME：生产模式需要 trusted time。Occlum 的 `do_gettimeofday()` 来自 VDSO/slow clock path，本质上不应被当作 SGX 内可信时间源。

影响：

如果 verifier 在 enclave 内执行，恶意 host 可以通过时间回拨影响 collateral expiration 判断，让过期 collateral 看起来仍未过期，或制造拒绝服务。ATT-001 中 RA-TLS 甚至只是打印 collateral 过期状态，这进一步放大风险。

建议：

- 在 verifier policy 中要求远端提供 nonce + 当前时间窗口，由可信 verifier/KMS 服务判断 freshness。
- enclave 内 DCAP verify 只能把时间相关结果作为未受信输入，不能单独决定 key release。
- 若必须 enclave 内验证，使用可证明的可信时间源或外部 signed time token。

### OCCLUM-ATT-007：默认 Occlum 实例是 debug enclave，且默认挂载 untrusted HostFS

严重性：中，主要是产品化误用风险

位置：

- `etc/template/Occlum.json:24`
- `etc/template/Occlum.json:27`
- `etc/template/Occlum.json:45`
- `etc/template/Occlum.json:67`
- `etc/template/Occlum.json:69`
- `docs/readthedocs/docs/source/filesystem/fs_overview.md:120`
- `docs/readthedocs/docs/source/filesystem/fs_overview.md:121`

问题：

默认模板：

- `metadata.debuggable = true`；
- 默认挂载 `/host`，类型是 `hostfs`。

文档正确说明 HostFS 没有保护或校验。但默认 debug enclave 与 Init-RA/gRPC 默认关闭 debug 校验叠加时，很容易让测试配置进入 key release 路径。

影响：

如果用户直接用默认模板上生产，远程 verifier 可能接受 debug enclave；应用如果把 secret、模型、证书或中间文件写入 `/host`，数据会直接暴露给 host。

建议：

- 提供 `production` 模板：`debuggable=false`、默认不挂载 HostFS、KSS/版本字段显式配置。
- RA/KMS 示例拒绝 debug enclave，除非 policy 显式允许开发模式。
- 对写入 `/host` 的路径做文档和 lint 提醒，Init-RA 获取的 secrets 禁止写入 HostFS。

### OCCLUM-ATT-008：EPID demo 禁用 IAS HTTPS 校验，且没有验证 IAS report 签名/状态

严重性：中/低，前提是用户复制 demo 作为生产 attestation client

位置：

- `demos/remote_attestation/epid/lib/src/ra_ias.cpp:143`
- `demos/remote_attestation/epid/lib/src/ra_ias.cpp:144`
- `demos/remote_attestation/epid/lib/src/ra_ias.cpp:159`
- `demos/remote_attestation/epid/lib/src/ra_ias.cpp:280`
- `demos/remote_attestation/epid/app/ra_main.cpp:18`
- `demos/remote_attestation/epid/app/ra_main.cpp:22`

问题：

IAS client 明确设置：

```c++
curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);
```

demo app 只获取 IAS report 并打印成功，没有验证 IAS report signing certificate、report signature、quote status、timestamp/freshness 或 report body 与本地 quote 的绑定。

影响：

作为 demo 可以理解，但若用户把这段库代码复制到真实 verifier 中，网络 MITM 或伪造 IAS response 会破坏 attestation 结果。

建议：

- Demo 中也启用 TLS peer/host 校验，或显式标注“不用于生产验证”。
- 提供完整 verifier 示例：验证 IAS signing cert chain、report signature、quote status、timestamp、quote body、`report_data` 和 expected measurements。

### OCCLUM-ATT-009：DCAP Rust wrapper 用不可变局部变量承接 ioctl 输出

严重性：低，主要是可靠性/FFI 正确性问题

位置：

- `tools/toolchains/dcap_lib/src/occlum_dcap.rs:67`
- `tools/toolchains/dcap_lib/src/occlum_dcap.rs:68`
- `tools/toolchains/dcap_lib/src/occlum_dcap.rs:69`
- `tools/toolchains/dcap_lib/src/occlum_dcap.rs:101`
- `tools/toolchains/dcap_lib/src/occlum_dcap.rs:102`
- `tools/toolchains/dcap_lib/src/occlum_dcap.rs:103`

问题：

`get_quote_size()` 和 `get_supplemental_data_size()` 定义 `let size: u32 = 0`，再把 `&size` 传给会写输出的 `ioctl`。这依赖 C 侧修改 Rust 不可变绑定背后的内存，属于不稳健的 FFI 写法。

影响：

在优化或工具链变化下可能表现为 size 始终为 0、未定义行为或难定位的 DCAP 初始化失败。

建议：

- 改为 `let mut size: u32 = 0;`，传 `&mut size`。
- 为 quote size/supplemental size 获取添加回归测试。

## 加固优先级

1. 先修 gRPC RA-TLS：quote result fail-closed、collateral 过期 fail-closed、超长证书拒绝。
2. Init-RA 模板改成默认需要 measurement/debug policy；所有 policy 为空时拒绝启动。
3. 明确 Occlum instance 是单一 attestation domain；限制 `/dev/sgx` 或禁止同实例多租户。
4. 生产模板默认 `debuggable=false`、不挂 HostFS、KMS secrets 只写 trusted FS。
5. 给 DCAP/RA-TLS/Init-RA 增加负向测试：bad quote status、expired collateral、debug enclave、空 allowlist、超长 cert。

