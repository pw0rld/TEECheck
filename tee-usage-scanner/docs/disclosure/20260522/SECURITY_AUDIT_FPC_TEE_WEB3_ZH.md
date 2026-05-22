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

### FPC-TEE-001: ERCC 默认接受 simulated attestation，且 simulated verifier 是 no-op

严重性：Critical
类别：Attestation bypass / registry poisoning

证据：

- `ercc/attestation/simulation.go:11-12` 无条件注册 `simulation.NewSimulationVerifier()`。
- `internal/attestation/simulation/verifier.go:13-20` 中 verifier 直接返回 nil，没有任何验证。
- `internal/attestation/verifier.go:69-81` 使用 credentials 中的 evidence type 分发 verifier。
- `ercc/registry/registry.go:333-335` 将 verifier 通过作为登记条件之一。
- README 说明 simulation mode 可通过 `SGX_MODE=SIM` 使用：`README.md:191-196`。

影响：

攻击者只要能提交 `registerEnclave` 交易，并构造与 chaincode definition 中 `version`/MRENCLAVE 和 `sequence` 匹配的 attested data，就可以绕过真实 SGX 远程证明，让 ERCC 记录非真实 TEE 的 enclave credentials。后续客户端会从 ERCC 获取该 enclave 的 endpoint、enclave verification key、chaincode encryption key，导致请求被导向攻击者控制的伪 enclave。

利用条件：

- 攻击者拥有能调用 ERCC 的 Fabric 身份。
- 对应 MSP/endorsement policy 允许其提交注册交易，或部署环境使用过宽 policy。
- ERCC 构建包含 simulated verifier，且没有运行环境策略禁止 simulated evidence。

修复建议：

- 生产构建中彻底移除 simulated verifier；至少通过 build tag 或环境策略使 ERCC 在非测试链上拒绝 `attestation_type=simulated`。
- 在 ERCC 层增加 allowlist：只接受 `epid-linkable`、`epid-unlinkable` 或未来 DCAP 类型。
- 将 chaincode definition/package metadata 中的 SGX mode 与 ERCC 验证绑定，防止 `HW` 声明下注册 simulated evidence。
- 针对 `RegisterEnclave` 增加负面测试：simulated evidence 在生产模式必须失败。

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

### FPC-TEE-004: Partial composite key/range 查询缺少完整读集合证明，可能出现 phantom read

严重性：High
类别：Phantom read / query result manipulation

证据：

- C shim 中 `get_public_state_by_partial_composite_key` 仅通过 OCALL 取 JSON 并解析：`ecc_enclave/enclave/shim.cpp:248-263`，没有把查询边界或完整结果证明写入 read set。
- Go shim 中 iterator 逐项记录读 hash：`ecc_go/chaincode/enclave_go/utils.go:55-57`，但 `internal/endorsement/validation.go:93-96` 对 range query 明确返回未实现，缺少范围完整性验证。
- 示例 auction 根据 partial composite key 查询所有 bid 决定赢家：`samples/chaincode/auction/auction_cc.cpp:280-283` 和 `samples/chaincode/auction-go/chaincode/auction.go:178-193`。

影响：

恶意 peer 可以漏掉某些 key、返回旧集合、改变集合顺序或插入/删除未被读集合捕获的 phantom key，从而影响 enclave 计算结果。例如拍卖中漏掉最高出价，enclave 仍会签名一个看似合法的结果。

利用条件：

- 业务逻辑依赖 `GetStateByPartialCompositeKey`、range query 或 rich query 结果完整性。
- 缺少 TLCC 或应用层集合承诺。

修复建议：

- 在生产安全 API 中禁用 partial/range/rich query，除非有完整集合证明。
- 引入 Merkle accumulator、range proof 或 ledger metadata proof。
- validation 阶段不仅验证每个返回值 hash，还要验证查询范围、结果数量和不存在性证明。
- 对示例 auction 加警告或改为 commit/reveal 加显式 bid index。

### FPC-TEE-005: `__endorse` 接受可转让的 enclave 签名响应，缺少一次性消费/反重放记录

严重性：High
类别：Transaction replay / bearer endorsement

证据：

- Client SDK 先 `__invoke` 获取 enclave 签名响应，再把该响应提交到 `__endorse`：`client_sdk/go/pkg/core/contract/contract.go:103-132`。
- `__endorse` 从参数中解析任意 signed response 并验证：`ecc/chaincode/ecc.go:137-192`。
- `internal/endorsement/validation.go:145-189` 只验证 enclave signature 和 request hash 与 proposal 中请求一致，没有检查当前提交者、当前 tx id、proposal 是否已消费。
- `ecc_enclave/enclave/enclave.cpp:328-347` 签入的是 request message hash；未包含 `__endorse` tx id 或一次性提交上下文。

影响：

签名响应本质上像 bearer token。拿到它的人可以重复提交到 `__endorse`，或在部分条件下转交他人提交。对包含读集的交易，Fabric MVCC 可挡住一部分重复提交；但 write-only、重复写相同值、外部副作用或业务层非幂等语义仍可能被重放。

利用条件：

- 攻击者获取 signed chaincode response。
- 业务交易可重复执行或 read set 不能有效阻止重放。
- 没有应用层 nonce/sequence。

修复建议：

- 在 `__endorse` 成功后记录 `hash(signedResponse)` 或 proposal tx id 为 consumed。
- enclave 签名内容中绑定 Fabric proposal tx id、creator、channel、chaincode id、sequence、function args。
- Client SDK 在提交前后验证 signed response 只用于当前交易上下文。
- 对 write-only 交易要求应用层 nonce 或 monotonic sequence。

### FPC-TEE-006: 默认 SGX 配置偏开发模式，debug enclave 未被 verifier 拒绝

严重性：High
类别：TEE misconfiguration / debug enclave

证据：

- 默认 `SGX_MODE=SIM`、`SGX_BUILD=DEBUG`：`config.mk:40-42`。
- enclave 配置 `DisableDebug=0`：`ecc_enclave/enclave/enclave.config.xml:17-18`。
- SGX verifier TODO 未检查 debug flag/attributes：`common/crypto/attestation-api/evidence/verify-evidence.cpp:212`。
- README 提醒默认以 SGX simulation mode 构建：`README.md:168-169`。

影响：

如果误将 debug enclave 或 simulation mode 部署到生产，宿主机可能通过调试能力访问 enclave 内存，读取 chaincode 私钥、state encryption key、请求明文和业务数据。由于 verifier 不检查 attributes，客户端/ERCC 很难从 attestation 层发现配置错误。

修复建议：

- 生产 profile 强制 `SGX_MODE=HW`、`SGX_BUILD=RELEASE`、`DisableDebug=1`。
- verifier 检查 SGX attributes：debug 必须关闭，MRSIGNER/ISVSVN/TCB policy 必须满足最小要求。
- CI 增加 release attestation fixture，验证 debug enclave 被拒绝。
- Docker/K8s manifests 禁止默认 `SGX_MODE=SIM` 用于非 demo 环境。

### FPC-TEE-007: Chaincode/state 密钥只在 enclave 初始化时生成，缺少持久化、恢复、轮换和多 enclave 分发

严重性：Medium/High
类别：Key lifecycle / availability / recovery

证据：

- `common/enclave/cc_data.cpp:29-43` 每次生成 enclave signing key、chaincode encryption/decryption key 和 state encryption key。
- `ercc/registry/registry.go:186-241` 直接从第一个已注册 credentials 取 `chaincode_ek`。
- `ercc/registry/registry.go:361-384` 的 `RegisterCCKeys`、`PutKeyExport`、`GetKeyExport` 均未实现。
- `ecc/chaincode/enclave/enclave.go:96-105` 和 `ecc_go/chaincode/enclave_go/enclave.go:110-122` 中 key export/import 仍未实现。

影响：

enclave 或 peer 重启后可能无法恢复旧 state encryption key，导致 ledger 上已有密文不可解密，形成永久性 DoS 或业务中断。多 peer/multi enclave 也无法安全共享同一 chaincode state key。

修复建议：

- 实现 key generation、export、import、rotation 全流程，并通过 attestation 验证接收方 enclave。
- 使用 seal-to-enclave 或 seal-to-MRSIGNER 策略持久化必要密钥，并考虑 ISVSVN 升级。
- ERCC 存储 key registration 状态，而不是在 `RegisterEnclave` 中默认视为 provisioned。
- 增加重启恢复、升级、密钥轮换和灾备测试。

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

### FPC-TEE-010: 调试日志可能泄露 enclave 内业务明文、attestation evidence 和密钥材料

严重性：Medium
类别：Confidentiality leakage / logging

证据：

- `ecc_enclave/enclave/shim.cpp:102-103` 打印读到的 state value。
- `ecc_enclave/enclave/shim_internals.cpp:51-78` 打印 read/write set 的 key/value hash 或 value。
- `common/crypto/attestation-api/attestation/attestation.cpp:67` 打印 attestation params。
- `common/crypto/attestation-api/evidence/verify-evidence.cpp:30-38` 打印 IAS signature/cert/report。
- `ercc/registry/registry.go:239` 打印 chaincode encryption key。
- 示例 auction 打印 bidder/value：`samples/chaincode/auction/auction_cc.cpp:297-318`。

影响：

enclave 通过 OCALL logging 把明文业务数据或敏感验证材料输出到不可信宿主日志。即使不是生产默认日志级别，debug 构建和 demo 环境容易误配置。

修复建议：

- 生产构建中禁用 enclave 内明文日志。
- 删除 ERCC 中 chaincode encryption key 日志。
- 对 logging API 增加敏感字段审计规则。
- CI 扫描 `LOG_DEBUG`/`Debugf` 中的 key、value、credentials、evidence、attestation、signature 等敏感关键词。

## 4. Web3/链上语义专项风险

本项目不是 EVM/Web3 项目，但存在典型链上系统风险：

- Valid quote 不等于 valid current state。Attestation 只能说明某段代码曾在某硬件中运行，不能证明输入 ledger state 最新。
- Enclave signature 不等于不可重放交易授权。签名响应需要消费记录和交易上下文绑定。
- 隐私计算结果不应在 commit 前释放。FPC Lite 里未提交状态、旧状态、局部状态都可能影响 enclave 输出。
- Operator/deployment pipeline 是信任根之一。只验证 MRENCLAVE 不足以覆盖 endpoint、组织身份、升级历史、debug 配置、TCB 状态和 key custody。
- 多参与方链上业务必须考虑 phantom read。范围查询、集合查询、rich query 需要完整性证明。

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
