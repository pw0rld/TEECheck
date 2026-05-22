# Microsoft CCF TEE/Attestation Audit

审计对象：`microsoft/CCF`，本地浅克隆 `microsoft-ccf`，commit `ac8c38318af60c6fa846a18dee80a0592e24c524`，`main` 分支。

范围：只看 TEE、remote attestation、node join attestation policy、SNP host data/UVM endorsements/TCB、virtual mode 相关安全边界。当前主线代码提示 `CCF 7.0.0 only supports SNP and Virtual attestation formats`，SGX 枚举和旧 schema 仍存在，但 SGX quote 生成/验证在当前主线不是有效安全路径。

## 总体判断

CCF 的核心 attestation 设计比很多 TEE 项目更完整：节点启动时把节点 signing public key 的 SHA-256 放进 attestation `report_data`，加入网络时验证 quote 签名链、measurement、host_data、TCB policy，并把这些信任输入放入治理表。也就是说，主路径不是“只验 quote 签名就信任”。

但从 fail-closed 和运维误用角度看，仍有几类安全问题：

1. SNP VCEK/ASK/ARK 证书链没有做 CRL/OCSP revocation 检查。
2. Virtual fake attestation 是默认 fallback，生产误跑 virtual 的风险偏高。
3. 已配置的 SNP security policy / UVM endorsements 文件读取失败只打日志并继续，容易静默降级。
4. UVM endorsements 和 transparent statement 的 DID x509 证书链解析显式忽略证书时间。
5. 节点 quote 没有 verifier challenge/nonce，quote freshness 依赖节点私钥不泄漏。

## ATTEST-001：SNP VCEK 证书链未检查 CRL/撤销状态

风险等级：High/Medium

相关代码：

- `microsoft-ccf/src/pal/attestation.cpp:245`
- `microsoft-ccf/src/pal/attestation.cpp:262`
- `microsoft-ccf/src/pal/attestation.cpp:293`
- `microsoft-ccf/src/crypto/openssl/verifier.cpp:98`

CCF 对 SNP quote 的验证流程包括：

- 解析 quote endorsements 中的 3 张证书：VCEK、ASK、ARK；
- 校验 ARK public key 是否匹配内置 AMD root signing key；
- 校验 ARK 自签；
- 校验 `ARK -> ASK -> VCEK` 证书链；
- 用 VCEK 验 quote 签名；
- 继续检查 VCEK/quote 中的 TCB、chip id、guest policy 等字段。

问题是 `verify_certificate()` 只建立 OpenSSL `X509_STORE` 并调用 `X509_verify_cert()`，没有加载 CRL，也没有 OCSP 或 KDS CRL 检查。仓库内 `rg "CRL|OCSP|revocation"` 也没有发现 SNP attestation 证书撤销验证路径。

AMD VCEK/KDS 规范提供 `/vcek/v1/{product_name}/crl` 用于获取 CRL。如果某个 VCEK/ASK 被撤销，但证书链签名和有效期仍成立，当前 CCF 代码仍可能接受该 quote，除非治理层 TCB minimum 正好覆盖该风险。

影响：

- 被撤销的 VCEK 仍可能签出被 CCF 接受的 attestation report。
- 如果撤销原因是 key compromise 或平台风险，CCF 的“硬件 genuine”判断会被削弱。

建议：

- 在 SNP attestation 验证中引入 AMD KDS/THIM CRL 获取与缓存。
- 校验 VCEK/ASK 链上撤销状态，CRL 缺失或过期时生产模式 fail-closed。
- 将 CRL `thisUpdate/nextUpdate`、来源、验证状态记录到审计表或节点 quote metadata，方便离线审计。

## ATTEST-002：Insecure Virtual 是默认 fallback，容易生产误用

风险等级：Medium

相关代码/文档：

- `microsoft-ccf/include/ccf/pal/platform.h:24`
- `microsoft-ccf/include/ccf/pal/platform.h:33`
- `microsoft-ccf/include/ccf/pal/platform.h:38`
- `microsoft-ccf/src/pal/quote_generation.h:23`
- `microsoft-ccf/src/pal/quote_generation.h:63`
- `microsoft-ccf/doc/operations/platforms/virtual.rst:4`
- `microsoft-ccf/doc/operations/start_network.rst:129`

平台探测逻辑是：

```cpp
if (ccf::pal::snp::supports_sev_snp())
{
  return Platform::SNP;
}

return Platform::Virtual;
```

Virtual quote 是 JSON fake attestation，measurement 为硬编码字符串，host_data 是进程可执行文件 hash。文档明确说 Virtual mode 没有安全保证、只应用于开发，但运行时代码在没有 SNP 时自动 fallback 到 Virtual。

影响：

- 生产环境缺少 `/dev/sev-guest`、内核/容器权限配置错误、硬件探测失败时，节点会进入 virtual，而不是直接拒绝启动。
- 如果初始网络就在 virtual 模式启动，后续治理表也会信任 virtual measurement/host_data，整个服务没有 TEE 安全边界。
- `CCF_PLATFORM_OVERRIDE` 也可强制覆盖平台，进一步提高误配置风险。

建议：

- 生产配置中增加显式 `expected_platform: SNP`，平台不匹配时 abort。
- Virtual mode 要求显式 `--insecure-virtual` 或专用开发 build，避免默认 fallback。
- 开网前治理脚本检查所有节点 quote format，禁止 `Insecure_Virtual`。

## ATTEST-003：SNP attestation 输入文件读取失败会静默降级

风险等级：Medium

相关代码/测试：

- `microsoft-ccf/src/host/run.cpp:258`
- `microsoft-ccf/src/host/run.cpp:269`
- `microsoft-ccf/src/host/run.cpp:271`
- `microsoft-ccf/src/host/run.cpp:278`
- `microsoft-ccf/src/host/run.cpp:289`
- `microsoft-ccf/src/node/node_state.h:708`
- `microsoft-ccf/src/node/node_state.h:744`
- `microsoft-ccf/src/service/internal_tables_access.h:834`
- `microsoft-ccf/src/service/internal_tables_access.h:847`
- `microsoft-ccf/tests/code_update.py:422`

`configure_snp_attestation()` 中如果用户配置了 `snp_security_policy_file` 或 `snp_uvm_endorsements_file`，读取失败只 `LOG_FAIL_FMT`，不会中止启动。随后：

- 没有 `security_policy` 时，`launch_node()` 只打印“skipping check against attestation host data”；
- 没有 UVM endorsements 时，启动节点会跳过本地 measurement endorsement 检查；
- 初始/recovery 节点会把 host_data 记录为可信，但可能只存空 policy metadata。

测试中也覆盖了“没有 security policy 的节点可加入”这个行为。

影响：

- 文件路径拼错、环境变量未展开、security context 未挂载，可能不会导致启动失败，而是变成不可审计/弱审计状态。
- 初始节点或 recovery 节点一旦把这种状态写入治理表，后续节点可以沿用同一个 host_data，而成员无法从 ledger 中看到原始 security policy。

建议：

- 如果配置项显式存在但读取失败，应 fail-closed。
- 生产模式要求 `snp_security_policy_file` 和 `snp_uvm_endorsements_file` 必须存在并通过本地验证。
- 即使允许只存 hash，也应要求成员/审计工具在 open network 前确认原始 policy 可获取并与 host_data 匹配。

## ATTEST-004：UVM endorsements / transparent statement 的 DID x509 验证忽略证书有效期

风险等级：Medium/Low

相关代码：

- `microsoft-ccf/src/node/uvm_endorsements.cpp:267`
- `microsoft-ccf/src/node/uvm_endorsements.cpp:271`
- `microsoft-ccf/src/node/uvm_endorsements.cpp:294`
- `microsoft-ccf/src/node/quote.cpp:321`
- `microsoft-ccf/src/node/quote.cpp:333`
- `microsoft-ccf/3rdparty/exported/didx509cpp/didx509cpp.h:1138`
- `microsoft-ccf/3rdparty/exported/didx509cpp/didx509cpp.h:1140`

UVM endorsements 的 COSE x5chain 解析调用：

```cpp
didx509::resolve_jwk(pem_chain, did, true /* ignore time */)
```

`ignore_time=true` 会设置 `X509_V_FLAG_NO_CHECK_TIME`。transparent statement 验证中解析签名证书链也使用同样的 ignore-time 模式。

UVM endorsements 路径后续会检查：

- COSE 签名；
- payload 中的 UVM measurement 是否等于 quote measurement；
- DID/feed/SVN 是否匹配治理表中的 roots of trust。

但没有看到等价的证书有效期、endorsement 有效期、或当前时间窗口检查。这样过期证书链仍可能用于签署可被接受的 UVM endorsement，只要 DID/feed/SVN 匹配。

影响：

- 过期的 UVM endorsement signing certificate 仍可被接受。
- 如果旧签名 key 在过期后泄漏，证书过期本身无法限制风险。
- transparent statement 这条路径可能由 JS code update policy 进一步约束，但默认 C++ 验证本身不会做时间约束。

建议：

- 对 join-time UVM endorsements 启用证书时间校验，或要求 payload/CWT 中包含签名有效期并检查。
- transparent statement 如果因历史 receipt 需要忽略证书时间，应把 `iat/nbf/exp` 作为强制 policy 输入，并在默认 policy 中验证。
- 增加过期 x5chain 的单元测试，明确预期是拒绝还是仅历史验证可接受。

## ATTEST-005：节点 attestation 没有 verifier challenge/freshness

风险等级：Low/Medium

相关代码：

- `microsoft-ccf/src/node/node_state.h:945`
- `microsoft-ccf/src/node/node_state.h:948`
- `microsoft-ccf/src/node/quote.cpp:595`
- `microsoft-ccf/src/node/quote.cpp:647`

节点 quote 的 `report_data` 是：

```cpp
ccf::crypto::Sha256Hash((node_sign_kp->public_key_der()))
```

加入网络时，验证方提取 quote report data，再比较它是否等于加入节点 TLS client certificate public key DER 的 SHA-256。这个绑定是正确的，能防止“拿别人的 quote 配自己的 TLS key”。

但 report_data 没有包含验证方 nonce、join challenge、epoch 或时间窗口。也就是说 quote 可以长期与同一个节点 key 复用。当前安全性主要依赖“节点私钥只在 TEE 内生成且不泄漏”。

影响：

- 如果节点 signing key 后续泄漏，攻击者可重放旧 quote，让非 TEE 进程证明“这个 key 曾经在 TEE 中出现过”。
- CRL/TCB policy 更新能缓解一部分陈旧 quote 风险，但不能证明 quote 是本次 join 现场生成。

建议：

- join 流程增加 challenge：目标节点先发 nonce，joiner 生成 `hash(node_pubkey || nonce || service_id)` 写入 report_data。
- 对当前一阶段 join API，至少记录 quote 获取时间和 endorsement 获取时间，并在治理/审计工具中检查 quote 过旧风险。
- 周期性 re-attestation 或在节点 certificate renewal 时重新生成 quote。

## 做得比较好的点

- 节点 quote 绑定的是节点 signing public key，加入时从 TLS client certificate 提取 public key 后比较 quote report data，避免 quote/key 换绑。
- SNP quote 验证检查了 AMD root public key、证书链、VCEK 对 report 的签名、VCEK signing key、`mask_chip_key`、VMPL、debug、migration、TCB、chip id。
- 加入节点必须同时满足 measurement、host_data、TCB policy；SNP UVM endorsements 可由治理表中的 DID/feed/SVN root 约束。
- `host_data` 不可信时可要求 transparent statement，并把 statement payload 绑定到 host_data，再校验 receipt 和 JS policy。

## 结论

当前 CCF 主线的 attestation 主路径不是简单或明显的 fail-open，实现上有较完整的 SNP 检查和治理表约束。但如果按生产安全边界使用，我会优先要求修复或加固：

1. SNP VCEK/ASK revocation/CRL 检查。
2. 禁止默认 virtual fallback 进入生产。
3. SNP security context 文件读取失败时 fail-closed。
4. 明确 UVM/transparent statement x5chain 时间语义。
5. 为 node join attestation 增加 challenge freshness。

这些问题多数不是“立刻能伪造任意节点”的单点漏洞，但会在硬件撤销、运维误配置、旧 endorsement/key 泄漏、生产环境降级时破坏 TEE/attestation 的预期安全边界。
