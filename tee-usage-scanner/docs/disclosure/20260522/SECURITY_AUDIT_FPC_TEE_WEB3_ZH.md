# Hyperledger Fabric Private Chaincode TEE/Attestation/Web3 安全审计记录

审计日期：2026-05-21
审计对象：`hyperledger/fabric-private-chaincode`
审计版本：`716cde030b78a9826c822c68bbf63a0c05a4c916`，提交时间 `2026-03-17 16:22:43 +0100`

## 1. 范围与结论

本次审计重点关注 Fabric Private Chaincode 中与 attestation、TEE/SGX、链上交易语义相关的专属风险。代码中未发现原生 Ethereum、Solidity、ethers.js、viem 或其他直接 Web3 代码路径，因此“Web3 专属漏洞”在本项目里主要体现为区块链+TEE 组合场景下的链上状态新鲜度、背书重放、注册链码信任根、密钥生命周期和跨参与方信任边界问题。

官方 README 明确说明该仓库是 proof-of-concept/prototype，尚不适合生产使用：`README.md:35-38`。审计结果与这个定位一致：当前实现适合研究和演示，不应在真实资产、隐私数据、金融结算或强一致交易场景中直接部署。

总体风险：高。核心原因是 ERCC 可接受 simulated attestation、真实 attestation 缺少 freshness/nonce、FPC Lite 缺少 rollback/commitment proof、enclave 签名响应可被重复提交，以及默认 SGX 构建配置偏开发模式。

## 2. 关键攻击面

- `ercc`：enclave registry，负责验证并登记 enclave credentials。
- `ecc`：FPC chaincode package，负责 `__invoke` 与 `__endorse` 分发和 enclave endorsement validation。
- `ecc_enclave`：C/C++ SGX enclave 逻辑，负责解密请求、执行 chaincode、签名响应和维护加密状态密钥。
- `ecc_go`：Go chaincode support，包含模拟/Go 版 enclave shim 与 attestation。
- `internal/attestation`：attestation 转换和验证。
- `internal/endorsement`：验证 enclave 签名响应并重放读写集。
- Client SDK：初始化 enclave、查询 ERCC encryption key、加密请求并提交 `__endorse`。

## 3. 主要发现


### FPC-TEE-002: Attestation 缺少 freshness/nonce，旧 quote 和旧 credentials 可重放

严重性：High
类别：Replay / stale attestation

证据：

- `internal/attestation/epid/ias.go:25-29` 定义了 IAS nonce 字段，但 `RequestAttestationReport` 在 `ias.go:106-109` 只提交 quote，没有设置 nonce。
- `common/crypto/attestation-api/ocalls/attestation-ocalls.c:39-45` 调用 `sgx_get_quote` 时 nonce 参数为 `NULL`。
- `common/crypto/attestation-api/evidence/verify-evidence.cpp:136-210` 验证签名、quote status、MRENCLAVE、report_data，但没有校验挑战 nonce、时间窗口或 ledger-bound freshness。

影响：

合法 enclave 在某个时间点生成的 attestation evidence 可以在之后被重放。即使 enclave 之后被销毁、私钥泄露、TCB 过期、部署关系变化，旧 evidence 仍可能被再次用于注册或欺骗客户端。对 Web3/链上场景而言，一个“曾经有效”的 quote 不等于“当前在线、状态最新、仍由正确 operator 控制”。

利用条件：

- 攻击者能获得历史 credentials/evidence。
- ERCC 没有记录 evidence 使用状态、时间窗口或 challenge。
- 链码定义的 MRENCLAVE/sequence 未变化。

修复建议：

- ERCC 或客户端生成唯一 challenge，challenge 必须进入 SGX report_data 或被 attested data hash 覆盖。
- 验证 IAS report timestamp，并设置最大有效期。
- 在 ERCC 状态中记录 attestation id、nonce、registration tx id，防止重复注册。
- 将 `channel_id`、`chaincode_id`、`sequence`、`expected endpoint`、`creator MSP` 和 challenge 一起纳入被 quote 绑定的数据。

### FPC-TEE-003: FPC Lite 缺少 rollback/commitment proof，应用可被旧状态或未提交状态影响

严重性：High
类别：TEE rollback / stale ledger state / Web3 state freshness

证据：

- `ecc_enclave/enclave/shim.h:20-49` 明确说明 FPC Lite 不提供 proof-of-commitment-on-ledger，也不支持 rollback protection。
- `protos/fpc/trusted_ledger.proto:11-41` 只存在 trusted ledger metadata 接口定义，当前代码路径未实现完整 TLCC。
- `ercc/registry/registry.go:353-356` 中 TLCC MRENCLAVE、channel hash、deployment policy 等检查仍是 TODO。

影响：

恶意 peer/host 可向 enclave 提供旧的或不一致的 ledger state。enclave 即使能证明自己运行了正确代码，也无法证明输入状态是最新、已提交、与其他键一致的链上状态。对拍卖、清算、余额转移、托管和机密投票这类 Web3/链上业务，这会导致结果被操纵或隐私在错误状态下被释放。

利用条件：

- 使用 FPC Lite 路径。
- 应用根据 private ledger data 释放敏感结果或做不可逆业务动作。
- 缺少 commit-then-reveal 或应用层状态版本检查。

修复建议：

- 不要在 FPC Lite 中让 enclave 基于私有状态直接释放高价值结果。
- 实现并启用 TLCC/ledger metadata proof，至少提供 key/value hash 的可信新鲜度证明。
- 在应用层加入 monotonic counter、block height、commit hash、two-phase commit/reveal。
- 文档和 SDK 层显式标记 FPC Lite API 的安全限制，避免开发者误用。



### FPC-TEE-008: ERCC 对 host/operator 绑定不足，只检查 creator MSP

严重性：Medium/High
类别：Identity binding / endpoint spoofing

证据：

- `protos/fpc/fpc.proto:35-50` 中 `HostParameters.certificate` 被标记为 Post-MVP。
- `ercc/registry/registry.go:338-351` 只检查 `HostParams.PeerMspId` 与交易 creator MSP 一致。
- `ercc/registry/registry.go:353-356` 中 deployment policy、channel hash、TLCC MRENCLAVE 等仍为 TODO。
- `ecc/chaincode/utils.go:121-140` 将 peer endpoint 从 init message 直接写入 host params。

影响：

同一 MSP 内任意有权限身份可能注册 endpoint 指向自己控制的服务，或把 enclave 与错误 peer/endpoint 绑定。ERCC 中的 endpoint 会被客户端用于 `__invoke` 选择目标 peer，可能导致请求被错误路由。

修复建议：

- 使用 peer TLS/identity certificate 对 `enclave_vk + CCParameters + endpoint` 做组织签名。
- ERCC 验证 creator 是否满足指定 admin/peer role，而不仅是 MSPID。
- 将 endpoint、peer certificate、TLS root、channel id、chaincode id 纳入 attested data。
- 增加 deployment restriction policy。

### FPC-TEE-009: 客户端不验证 enclave 签名响应即解密和返回明文结果

严重性：Medium
类别：Client-side response authenticity

证据：

- `internal/crypto/client_encryption.go:79-105` 的 `Reveal` 只 base64 decode、unmarshal、用 response key 解密 encrypted response，不验证 signed response 的 enclave signature。
- 服务端 `__endorse` 会验证签名，但 `EvaluateTransaction` 路径不会提交到 `__endorse`：`client_sdk/go/pkg/core/contract/contract.go:77-100`。

影响：

对 query/evaluate 场景，客户端依赖 response key 机密性和目标 peer 行为，而没有验证该响应确实来自已注册 enclave。若 key transport 或响应上下文被误用，客户端可能接受伪造/重放响应。

修复建议：

- Client SDK 查询 ERCC credentials，验证 `SignedChaincodeResponseMessage` 的 enclave signature 和 enclave id。
- 将响应绑定到 request hash、channel、chaincode id、transaction/proposal id。
- `EvaluateTransaction` 与 `SubmitTransaction` 都应执行相同的本地响应认证。


## 5. 建议修复优先级

P0：

- 生产模式禁用 simulated attestation。
- ERCC/verifier 检查 SGX debug flag、TCB status、MRENCLAVE、ISVSVN、attestation type。
- 增加 nonce/challenge freshness，禁止旧 evidence 重放。
- 修复 `QueryChaincodeEncryptionKey` 的敏感日志。

P1：

- 为 `__endorse` 增加 signed response/proposal tx id 消费记录。
- Client SDK 本地验证 enclave signature。
- 禁止或隔离 partial/range/rich query，直到实现完整证明。
- 强制生产构建 `SGX_MODE=HW`、`SGX_BUILD=RELEASE`、`DisableDebug=1`。

P2：

- 实现 key distribution、key export/import、rotation、sealed recovery。
- 实现 deployment restriction policy、peer certificate binding、endpoint attestation。
- 实现 TLCC 或等价 ledger metadata proof。
- 为 demo/sample 增加风险提示，避免把 FPC Lite 示例直接复制到生产。

## 6. 需要进一步验证的点

- 在真实 Fabric 网络中复现 signed response 重放，确认不同 read/write 模式下 MVCC 的实际阻断范围。
- 在 SGX HW 环境中生成 debug/release quote，验证当前 verifier 对 attributes 的处理。
- 对 C/C++ enclave parser、nanopb decode、OCALL buffer 边界做内存安全 fuzzing。
- 对 sample chaincode 做业务层审计，尤其 auction、confidential-escrow、cc-tools integration。

## 7. 安全上报建议

若要向上游提交安全问题，仓库的 `SECURITY.md:3-9` 建议通过 `security@hyperledger.org` 或 confidential JIRA bug 上报。建议不要在公开 issue 中直接披露可利用细节，尤其是 simulated attestation bypass、response replay 和 range-query manipulation。
