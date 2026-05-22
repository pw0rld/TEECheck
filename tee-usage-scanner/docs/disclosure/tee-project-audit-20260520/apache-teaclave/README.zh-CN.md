# Apache Teaclave

## 扫描元信息

- 仓库：`https://github.com/apache/teaclave`
- Commit：`48b297e478f51dd489b9829d21b890f90394acdf`
- 本地克隆：`/tmp/teecheck-clone-186338507`
- Run：`runs/scan-20260520-apache-teaclave`

## 结论

本轮没有拿到可确认漏洞。TEECheck 生成了 3 个 `needs_review`，但目标路径是目录级别的 `sgx`、`crates`，review packet 明确写了缺少源码上下文和 citation-anchored facts。

因此不建议对 Apache Teaclave 主仓发漏洞 issue。这个结果应记录为“扫描证据不足”，不是“确认存在漏洞”。

## 扫描发现摘要

| 分类 | 状态 | 严重性 | 置信度 | 文件 |
| --- | --- | --- | --- | --- |
| attestation | `needs_review` | high | low | `sgx` |
| key_management | `needs_review` | high | low | `crates` |
| boundary | `needs_review` | medium | medium | `sgx`, `crates` |

## 证据缺口

本仓本次 clone 只暴露了很粗的目录结构：

```text
/tmp/teecheck-clone-186338507
├── crates
├── sgx
└── trustzone
```

扫描 packet 中没有具体函数、具体行号或可验证代码片段。attestation case 的含义可以概括为：

```text
状态：需要人工复核。
主要阻塞点：提供给 review 的上下文里缺少实际源码。
可确认事实：没有带源码引用的事实。
```

key management case 也是同样问题：

```text
状态：无法得出结论。
可确认事实：没有经过源码引用验证的事实。
```

## 人工判断

这类结果不能直接转成 issue，因为漏洞上报至少要说明：

- 具体入口函数在哪里。
- 哪个安全义务缺失。
- 缺失如何导致攻击路径。
- 正常代码路径和异常代码路径分别是什么。
- 维护者能按路径复现或验证。

目前这几个条件都不满足。建议后续如果继续审 Apache Teaclave 主仓，先扩大代码获取范围或确认仓库是否使用子模块、LFS、历史分支或生成代码。

## 建议状态

- 不发 CVE。
- 不发安全 issue。
- 可保留为 TEECheck 工具质量样本：目录级 candidate 太粗，容易产生不可操作结论。
