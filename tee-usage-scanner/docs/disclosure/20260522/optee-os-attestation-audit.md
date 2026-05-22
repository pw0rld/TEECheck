# OP-TEE OS TEE/Attestation 审计记录

审计日期：2026-05-21

审计对象：`OP-TEE/optee_os`，本地浅克隆 `optee_os`，`master` 分支。

仓库状态：

- 上游仓库：<https://github.com/OP-TEE/optee_os>
- 审计提交：`1b0bc6d026c2e6276c65eaa692ca637cfd11ed5b`
- 提交摘要：`core: arm: plat-sunxi: add support for Allwinner A133`

范围：只看 TEE、attestation、TA measurement、TA 签名加载、HUK/secure storage/RPMB 这些会影响远程证明可信度的路径。没有做完整内核内存安全 fuzz，也没有审计所有平台驱动。

## 总体判断

OP-TEE OS 的主线默认并不是一个完整的硬件远程证明栈。`CFG_ATTESTATION_PTA` 默认关闭；开启后，传统 attestation PTA 会用 OP-TEE 内部生成并存储的 RSA key 对 TEE/TA digest 签名。这个设计只有在设备制造/注册阶段把 attestation 公钥安全绑定到设备身份时才有安全意义，否则远端 verifier 无法仅凭 PTA 返回的公钥判断它来自真实设备。

Veraison attestation PTA 更明确地是 PoC：代码和 README 都说明它缺少 Root of Trust 绑定，并且必须启用内置 test key 才能构建。该 PoC 路径里还存在可由 TA 触发的 secure heap 泄漏和 PAN 配置下的潜在 secure-world DoS。

整体风险主要集中在：

1. Veraison PTA 不适合生产，且有实现级 DoS 缺陷。
2. Attestation key/public key 没有硬件证书链背书，安全性依赖外部 provisioning。
3. 默认开发配置里存在公开 TA 签名私钥、`CFG_INSECURE=y`、REE FS 默认无 RPMB 回滚保护等容易被产品化误用的点。
4. measurement 语义较弱，很多关键运行时状态和信道绑定不在证明内容中。

## 关键发现

### OPTEE-ATT-001：Veraison PTA COSE 编码路径存在 secure heap 泄漏，可被 TA 反复调用打满 TEE 内存

严重性：高，前提是启用 `CFG_VERAISON_ATTESTATION_PTA=y`

位置：

- `core/pta/veraison_attestation/cbor.c:92`
- `core/pta/veraison_attestation/cbor.c:107`
- `core/pta/veraison_attestation/cbor.c:206`
- `core/pta/veraison_attestation/cbor.c:223`
- `core/pta/veraison_attestation/cbor.c:240`
- `core/pta/veraison_attestation/cbor.c:302`

问题：

`build_encoded_buffer()` 会先调用一次 `encode_func()` 计算 CBOR/COSE 长度，再调用一次真正编码。`generate_cose_evidence()` 传入的是 `encode_cose_evidence()`。

`encode_cose_evidence()` 内部每次都会分配：

- `protected_header = build_protected_header()`
- `tbs_payload = build_tbs_structure(...)`

错误路径会释放它们，但成功路径在 `QCBOREncode_AddBytes(context, signature_payload)` 后直接 `QCBOREncode_CloseArray(context)` 返回，没有释放 `protected_header.ptr` 和 `tbs_payload.ptr`。由于 size pass 和 encode pass 都会执行一次签名和分配，单次 evidence 生成至少泄漏两轮临时 buffer。

影响：

恶意或被攻陷的 TA 只要循环调用 `PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE`，即可消耗 OP-TEE secure heap/mempool，导致后续 TA 调用、密码操作或系统 PTA 服务失败，形成 TEE 内部 DoS。

建议：

- 在 `encode_cose_evidence()` 成功路径统一释放 `protected_header` 和 `tbs_payload`。
- 避免 size pass 执行有副作用的签名/分配：先构造 deterministic 长度，或重构为一次性编码到动态 buffer。
- 增加重复调用 Veraison evidence 的内存回归测试。

### OPTEE-ATT-002：Veraison TA memory hash 在 PAN 配置下缺少 `enter_user_access()`，可能触发 secure-world fault/DoS

严重性：高/中，前提是启用 `CFG_VERAISON_ATTESTATION_PTA=y` 且平台启用 PAN 相关保护

位置：

- `core/pta/veraison_attestation/hash.c:42`
- `core/pta/veraison_attestation/hash.c:85`
- `core/pta/veraison_attestation/hash.c:91`
- `core/pta/veraison_attestation/hash.c:117`
- 对比：`core/pta/attestation.c:554`
- 对比：`core/pta/attestation.c:571`

问题：

Veraison PTA 的 `hash_regions()` 会直接对调用 TA 的 user VA 做 `memcmp()` 和 `crypto_hash_update()`，但没有像传统 `attestation.c` 那样在访问 TA user mapping 前调用 `enter_user_access()`，访问完成后调用 `exit_user_access()`。

影响：

在启用 PAN 的构建/平台上，secure kernel 直接读取 user TA 地址可能触发权限异常。恶意 TA 可以主动调用该 PTA 触发 secure-world fault，从而造成 TEE 服务不可用。

建议：

- 复用 `core/pta/attestation.c` 的 user access 模式，在排序和 hash user region 前后包裹 `enter_user_access()` / `exit_user_access()`。
- 给 `CFG_PAN=y` 场景加调用 Veraison PTA 的测试。

### OPTEE-ATT-003：Veraison PTA 强制使用源码内嵌 test private key，任何人可伪造 evidence

严重性：高，前提是 verifier 把该 PoC evidence 当成生产 attestation

位置：

- `mk/config.mk:1287`
- `mk/config.mk:1295`
- `mk/config.mk:1298`
- `core/pta/veraison_attestation/sign.c:20`
- `core/pta/veraison_attestation/sign.c:22`
- `core/pta/veraison_attestation/sign.c:51`
- `core/pta/veraison_attestation/sign.c:59`
- `core/pta/veraison_attestation/README.md:7`
- `core/pta/veraison_attestation/README.md:17`

问题：

`CFG_VERAISON_ATTESTATION_PTA` 默认关闭，但一旦开启，`CFG_VERAISON_ATTESTATION_PTA_TEST_KEY` 默认必须为 `y`，否则构建报错。签名私钥直接写在 `sign.c` 的 `PRIVATE_KEY` 宏中。README 也明确说明该 PTA 不能建立对 PTA 自身的信任。

影响：

任何拿到源码的人都能用同一私钥签署格式正确的 COSE evidence。远端 verifier 如果信任该公钥，相当于信任公开私钥，attestation 可被离线伪造。

建议：

- 生产构建中禁止启用 `CFG_VERAISON_ATTESTATION_PTA`，除非实现了硬件/制造注入的 attestation key。
- 移除“必须启用 test key 才能工作”的生产路径，改成 fail-closed。
- Evidence 的 signing key 必须由设备唯一 Root of Trust 派生或由硬件安全单元持有，并由可验证证书链背书。

### OPTEE-ATT-004：传统 attestation PTA 的公钥没有硬件背书，远程信任完全依赖外部 provisioning

严重性：中/高，取决于部署协议

位置：

- `lib/libutee/include/pta_attestation.h:17`
- `lib/libutee/include/pta_attestation.h:49`
- `lib/libutee/include/pta_attestation.h:51`
- `core/pta/attestation.c:52`
- `core/pta/attestation.c:299`
- `core/pta/attestation.c:321`
- `core/pta/attestation.c:347`
- `core/pta/attestation.c:359`

问题：

传统 attestation PTA 首次使用时在 TEE 内生成 RSA key，并把私钥序列化后写入 `TEE_STORAGE_PRIVATE`。公钥通过 `PTA_ATTESTATION_GET_PUBKEY` 返回，头文件也写明通常在设备 provisioning 阶段取出。

代码没有把该公钥绑定到 SoC 厂商证书、secure boot measurement、DICE/CDI、TPM quote 或其他硬件证书链。也就是说，远端如果在线调用 `GET_PUBKEY` 并立刻信任它，攻击者可以用任意 OP-TEE 实例或仿真实现生成自己的 key 和 measurement。

影响：

- 没有安全 provisioning 的部署中，attestation 只能证明“某个持有该软件私钥的环境签了这个 hash”，不能证明是真实设备或特定安全启动链。
- 如果 normal world 能删除/回滚 backing storage，可能迫使 PTA 生成新 key；若 verifier 自动接受新公钥，会被替换信任根。

建议：

- 把 attestation 公钥注册放到制造/首次启动受控流程，并由设备证书或外部资产库绑定。
- Verifier 禁止在业务连接中 TOFU 接受 `GET_PUBKEY`。
- 更好的方案是用 DICE/CCA/TPM/厂商 attestation service 对 OP-TEE attestation key 做 endorsement。

### OPTEE-ATT-005：默认 TA 签名私钥随源码公开，产品若沿用默认 key 可加载攻击者签名 TA

严重性：高，前提是产品构建未替换 `TA_SIGN_KEY` / `TA_PUBLIC_KEY`

位置：

- `mk/config.mk:244`
- `mk/config.mk:248`
- `mk/config.mk:249`
- `mk/lib.mk:49`
- `mk/lib.mk:79`
- `keys/default_ta.pem`
- `core/sub.mk:10`
- `core/sub.mk:13`
- `core/crypto/signed_hdr.c:70`
- `core/crypto/signed_hdr.c:107`
- `core/kernel/ree_fs_ta.c:277`

问题：

OP-TEE 默认用 `keys/default_ta.pem` 签 TA，同时把对应公钥编进 OP-TEE core。这个私钥在源码仓库中公开，只适合作为开发默认值。TA 加载时确实会验证签名，但如果产品没有替换默认 key，攻击者可以用公开私钥签任意 TA 并让设备加载。

影响：

任意 TA 代码执行于 S-EL0，能调用系统 PTA、访问自己权限范围内的 secure storage/API，并可能作为进一步攻击 secure kernel 或其他 TA 的入口。Attestation 视角下，攻击者还能生成“由默认 key 签过”的 TA digest，弱化 TA 身份策略。

建议：

- 产品构建必须替换 `TA_SIGN_KEY` 和 `TA_PUBLIC_KEY`，私钥保存在 HSM/离线签名系统。
- CI/产线检查禁止 `keys/default_ta.pem` 出现在 release artifact 或 dev kit。
- Verifier 不应只信 TA digest，还应绑定签名 key/版本/回滚策略。

### OPTEE-ATT-006：默认 secure storage 使用 REE FS 且 RPMB 关闭，attestation key/存储对象缺少默认回滚保护

严重性：中/高，取决于平台是否启用 RPMB 和 secure boot

位置：

- `mk/config.mk:157`
- `mk/config.mk:161`
- `mk/config.mk:169`
- `mk/config.mk:170`
- `mk/config.mk:172`
- `mk/config.mk:174`
- `core/pta/attestation.c:299`
- `core/pta/attestation.c:321`
- `mk/config.mk:221`
- `mk/config.mk:227`

问题：

默认配置 `CFG_REE_FS=y`、`CFG_RPMB_FS=n`。传统 attestation PTA 的 RSA private key 存在 `TEE_STORAGE_PRIVATE`，默认落到 normal world 提供的 REE FS。REE FS 有 HMAC/加密完整性保护，但没有 RPMB 时无法防止 normal world 回滚或删除旧对象。

影响：

- Attestation key、TA secure storage metadata 等可能被 normal world 回滚到旧版本。
- 若业务把 attestation public key 当成长期设备身份，存储删除导致重新生成 key 会造成身份重置；若 verifier 自动接受重置，就会形成信任根替换。
- 若产品错误启用 `CFG_RPMB_TESTKEY` 或 `CFG_RPMB_WRITE_KEY`，还会削弱 RPMB key 保密性。

建议：

- 生产设备启用 RPMB 或等价 replay-protected storage，并关闭 test/write-key 选项。
- 对 attestation key 加入不可回滚版本/证书状态；检测 key 重置并进入重新 provisioning 流程。
- Verifier 对设备 attestation public key 做资产库 pinning，不接受静默变化。

### OPTEE-ATT-007：`GET_TA_SHDR_DIGEST` 只签 signed header 中的 hash，不验证当前 TA payload 确实匹配该 hash

严重性：中

位置：

- `core/pta/attestation.c:398`
- `core/pta/attestation.c:420`
- `core/kernel/ree_fs_ta.c:515`
- `core/kernel/ree_fs_ta.c:526`
- `core/kernel/ree_fs_ta.c:531`
- `core/kernel/ree_fs_ta.c:634`
- `core/kernel/ree_fs_ta.c:741`
- `core/kernel/ree_fs_ta.c:742`

问题：

`cmd_get_ta_shdr_digest()` 调用 `hash_binary()`，后者对 TA store 调用 `ops->get_tag()`。在默认非 buffered REE FS TA 路径中，`ree_fs_ta_get_tag()` 只是把 signed header 里的 `SHDR_GET_HASH(handle->shdr)` 拷出来。真正对 payload 逐块 hash 并调用 `check_digest()` 是 `ree_fs_ta_read()` 读完整个 TA 时发生的。

因此，一个 normal world 攻击者可以提供“合法 signed header + 同长度垃圾 payload”。`GET_TA_SHDR_DIGEST` 仍会返回并签署合法 digest，但该 TA 实际加载执行会在完整读取后失败。

影响：

如果远端 verifier 把 `GET_TA_SHDR_DIGEST` 当成“设备当前安装且可执行某 TA”的证明，就会被误导。它最多证明 OP-TEE 看到一个带合法签名 header 的 TA 容器，并不证明 payload 当前可加载。

建议：

- Attestation 命令若语义是证明 TA 存在/可执行，应触发完整 payload hash 校验，或只对 buffered/secure-storage 已验证路径返回。
- 文档中明确 `GET_TA_SHDR_DIGEST` 的语义限制，推荐 verifier 使用 running TA memory hash 或业务级 challenge-response。
- 对 REE FS 非 buffered 路径增加“header 合法但 payload 篡改”的测试。

### OPTEE-ATT-008：runtime TA memory measurement 不包含地址/权限/段边界/可变状态，容易被上层协议误解

严重性：中

位置：

- `core/pta/attestation.c:490`
- `core/pta/attestation.c:505`
- `core/pta/attestation.c:516`
- `core/pta/attestation.c:560`
- `core/pta/attestation.c:566`
- `lib/libutee/include/pta_attestation.h:68`
- `lib/libutee/include/pta_attestation.h:86`

问题：

TA runtime hash 只覆盖符合条件的 read-only region，并按 region size/content 排序以规避 ASLR。hash 输入不包含 region 地址、权限、段边界、入口点、加载参数、TA writable data、secure storage 状态、PTA 返回的配置或 RPC 输入。

影响：

这适合做“代码/rodata 近似 measurement”，但不适合直接证明完整运行状态。对于解释器型 TA、数据驱动策略 TA、从 secure storage 读取策略的 TA，攻击者可能在相同代码 measurement 下改变实际行为。

建议：

- Verifier 把 runtime memory hash 视为代码身份，不要视为业务状态证明。
- TA 应在自己的 attestation 协议中把配置版本、策略 hash、会话公钥、nonce、关键 secure storage 对象版本一起签入 challenge response。
- 更完整的 measurement 应加入 region metadata，至少包括长度/权限/类型，避免结构歧义。

### OPTEE-ATT-009：attestation evidence 没有内建信道绑定，容易被中继到其他 TLS/业务会话

严重性：中

位置：

- `lib/libutee/include/pta_attestation.h:39`
- `core/pta/attestation.c:431`
- `core/pta/attestation.c:444`
- `core/pta/attestation.c:447`
- `core/pta/attestation.c:478`

问题：

传统 PTA 签名的是 `SHA256(nonce | hash)`。接口只要求 nonce 是随机非空 buffer，用于防 replay；它没有强制把 TLS exporter、客户端 ephemeral public key、业务会话 ID 或请求上下文绑定进被签数据。

影响：

如果上层协议只发送随机 nonce，攻击者可以把 evidence 从真实设备中继给另一个 verifier 或另一个会话。签名本身不能证明“当前 TLS 连接对端就是这个 TEE/TA”。

建议：

- 上层协议把 nonce 定义为结构化 challenge：`random || transcript_hash || verifier_pubkey || purpose || expiry`。
- 如果用于 TLS，使用 TLS exporter/channel binding，并把 exporter value 放入 PTA 输入。
- Verifier 拒绝没有 domain separation/purpose 字段的 evidence。

## 加固清单

- 生产构建关闭 `CFG_VERAISON_ATTESTATION_PTA`，除非替换 test key 并补齐 RoT endorsement。
- 生产构建设置 `CFG_INSECURE=n`，替换平台 HUK 实现，替换 `TA_SIGN_KEY`/`TA_PUBLIC_KEY`。
- 启用 RPMB 或等价防回滚存储，禁止 `CFG_RPMB_TESTKEY=y`，只在受控产线临时使用 `CFG_RPMB_WRITE_KEY=y`。
- Attestation public key 通过制造证书、DICE/CCA/TPM quote 或资产库 pinning 建立信任，不做在线 TOFU。
- Evidence challenge 必须绑定业务会话和用途，不只放随机 nonce。
- 对 TA 证明同时检查 signed header digest、running memory digest、TA 自身业务状态签名。
- Verifier policy 记录 OP-TEE commit/build config/TA signing key/version/rollback counter，而不只记录 hash。

