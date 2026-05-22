# TEE 项目扫描整理

本文档整理 2026-05-20 使用 TEECheck 对一组 TEE 框架和工业项目的扫描结果。每个项目单独建目录，目录内文档包含扫描元信息、发现摘要、人工复核结论、源码片段和建议处理方式。

## 总览

| 项目 | 仓库 | 扫描 run | 复核结论 |
| --- | --- | --- | --- |
| Apache Teaclave SGX SDK | `apache/teaclave-sgx-sdk` | `scan-20260520-teaclave-sgx-sdk` | `samplecode/mutual-ra` 存在较明确的 enclave 身份策略缺失，适合发 GitHub issue；暂不建议直接申请 CVE。 |
| Apache Teaclave | `apache/teaclave` | `scan-20260520-apache-teaclave` | 扫描结果为目录级 `needs_review`，缺少具体代码证据，不建议发 issue。 |
| Gramine | `gramineproject/gramine` | `scan-20260520-gramine` | 命中 CI hello-world 示例，缺少授权/证明逻辑但属于 demo，不建议作为漏洞上报。 |
| Open Enclave | `openenclave/openenclave` | `scan-20260520-openenclave` | 本轮没有生成 findings。 |
| Occlum | `occlum/occlum` | `scan-20260520-occlum` | MAA demo 依赖调用方提供新鲜 `user_data`，可作为样例安全硬化 issue；DCAP wrapper 属于 threat model/FFI 风险复核项。 |
| Microsoft CCF | `microsoft/CCF` | `scan-20260520-ccf` | 有 attestation freshness 的复核点，但代码存在 report_data 和 store policy 检查；目前不是确认漏洞。 |
| OP-TEE OS | `OP-TEE/optee_os` | `scan-20260520-optee-os` | `attestation.c` 的密钥泄漏结论很可能是误报；Veraison PTA 的 hardcoded identity 值得做设计复核。 |
| Dstack | `Dstack-TEE/dstack` | `scan-20260520-dstack` | key provider client/VMM 边界看起来薄，但 KMS 侧有 quote 和授权校验；目前是架构核对项，不是确认漏洞。 |
| Fabric Private Chaincode | `hyperledger/fabric-private-chaincode` | `scan-20260520-fabric-private-chaincode` | 证据最强：宽松 quote status、debug/attributes TODO、proposal 与实际 chaincode request 绑定缺失，建议优先深挖和上报。 |
| Intel DCAP | `intel/confidential-computing.tee.dcap` | `scan-20260520-intel-dcap` | Rust wrapper 暴露 QvE-less 验证模式，属于 documented weak mode/API footgun；可发 hardening issue。 |

## 建议优先级

1. 优先复核并准备上报 `fabric-private-chaincode`，尤其是 signed proposal 与实际执行 request 的绑定缺失。
2. 上报 `teaclave-sgx-sdk` 的 `mutual-ra` sample：IAS 验证完成后没有强制检查 `MRENCLAVE`/`MRSIGNER`。
3. 对 `occlum` MAA demo、`intel-dcap` QvE-less mode、`dstack` key provider 边界写成安全硬化或 threat model clarification issue。
4. `apache/teaclave`、`openenclave`、`gramine`、`microsoft/CCF`、`OP-TEE attestation.c` 暂不按漏洞处理，除非后续拿到更强的协议上下文或可复现攻击路径。

