# CVE 预申请 / 私有安全通报发送稿索引

这些文档是基于 TEECheck example review 整理出来的 CVE 预申请和私有安全通报草稿。它们用于提交给项目维护者、GitHub Security Advisory、CNA 或安全联系人前的人工作业，不应作为最终漏洞结论直接公开发布。

## 发送原则

- **不要公开开 GitHub Issue**。这些内容包含潜在可利用路径，应优先通过 GitHub Security Advisory、security email 或维护者指定的私密渠道发送。
- **先声明是预申请 / coordinated disclosure**。部分候选仍依赖部署 threat model 或 PoC 验证，措辞应保持“candidate / suspected impact / needs confirmation”。
- **优先发送最成熟的候选**。`PHALA-DCAP-ATTRS` 最适合优先披露；`QOS-NONCELESS-ATTESTATION` 如果能补 replay PoC，会明显增强。
- **提交前重新确认当前 main / release**。现有锚点 commit 是 review anchor，不等于完整受影响版本范围。

## 草稿列表

| 文件 | 项目 | 候选问题 | 建议渠道 | 准备度 |
| --- | --- | --- | --- | --- |
| [PHALA-DCAP-ATTRS-ISSUE.zh-CN.md](PHALA-DCAP-ATTRS-ISSUE.zh-CN.md) | `phala-network/phala-blockchain` | DCAP verifier 跳过 `misc_select` / `attributes` policy 检查 | GitHub Security Advisory | 高 |
| [PHALA-MASTERKEY-DOS-ISSUE.zh-CN.md](PHALA-MASTERKEY-DOS-ISSUE.zh-CN.md) | `phala-network/phala-blockchain` | master key sealed data 异常触发 panic 导致 DoS | GitHub Security Advisory 或先私下确认 threat model | 中 |
| [QOS-UNVERIFIED-TIME-ISSUE.zh-CN.md](QOS-UNVERIFIED-TIME-ISSUE.zh-CN.md) | `tkhq/qos` | 从 unsafe-parsed Nitro attestation doc 派生 trusted time | GitHub Security Advisory / security contact | 中低 |
| [QOS-NONCELESS-ATTESTATION-ISSUE.zh-CN.md](QOS-NONCELESS-ATTESTATION-ISSUE.zh-CN.md) | `tkhq/qos` | post-boot attestation document 缺少 verifier nonce，存在 replay 风险 | GitHub Security Advisory | 中到高，取决于 PoC |

## 建议发送顺序

1. `PHALA-DCAP-ATTRS`：代码证据直接，安全边界明确，是最强候选。
2. `QOS-NONCELESS-ATTESTATION`：relying party 已定位到 secret-release path，但最好补 replay PoC。
3. `PHALA-MASTERKEY-DOS`：确认 sealed storage 是否在 untrusted host 边界外后再正式提交。
4. `QOS-UNVERIFIED-TIME`：更依赖 threat model，需要证明 attacker influence。

