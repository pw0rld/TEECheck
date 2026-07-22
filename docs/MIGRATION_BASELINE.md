# 融合迁移基线

> 记录时点：PR-00 完成时，integration branch `merge/tee-audit-integration`
> 用途：后续 PR 改动 CLI、artifact schema 或 benchmark 时，用本文件判断是否发生了
> 计划外的破坏。见 `TEECHECK_TEE_AUDIT_MERGE.zh-CN.md` §18。

## 基线 commit

| 项 | 值 |
|---|---|
| TEECheck integration base | `7fd1206`（*benchmark: source-backed only*） |
| tee-audit 导入基线 | `f8053a18190d5e6c4cfe0da3e66e0df770832dfe` |
| 分支 | `merge/tee-audit-integration`，从 `agent/benchmark-quality-68-cases` 分出 |

## 构建与测试

```text
go build ./...   成功
go test ./...    349 个测试通过，52 个包，0 失败
```

任何 PR 使这两项退化都必须在该 PR 内说明原因。

## CLI 表面

`cmd/` 下有两个二进制：`teecheck`、`twescan`。

`teecheck` 当前子命令：

```text
run                 <url-or-path> [--mode heuristic|llm] [--focus NAME] [--max-cases N]
                    [--llm-provider openai|glm] [--llm-base-url URL] [--llm-model NAME]
knowledge-init      [--knowledge-root DIR]
collab-run          --repo-url URL --local-path PATH --commit SHA --graph-json FILE ...
init-run            --repo-url URL --local-path PATH --commit SHA ...
preprocess          --run-dir DIR
mapper              --run-dir DIR --graph-json FILE [--max-hotspots N]
map                 --run-dir DIR --graph-json FILE
hotspots            --run-dir DIR [--max-hotspots N]
cases               --run-dir DIR [--knowledge-root DIR] [--max-cases N]
expert              --run-dir DIR [--agent-id ID] [--mode heuristic|llm] ...
challenge           --run-dir DIR [--agent-id ID] [--mode heuristic|llm] ...
verifier            --run-dir DIR [--agent-id ID] [--mode heuristic|llm] ...
arbiter             --run-dir DIR [--agent-id ID] [--max-findings N]
curator             --run-dir DIR [--knowledge-root DIR] [--mode heuristic|llm] ...
review              --run-dir DIR [--knowledge-root DIR]
feedback            --run-dir DIR [--knowledge-root DIR]
```

融合文档 §12 提出的目标 CLI（`teecheck run --facts auto` 等）尚未实现。`--facts`
取代原提案 `--trustir` 的改名也未落地。

## Artifact schema

`schemas/` 下 8 份 canonical JSON schema：

| 文件 | title |
|---|---|
| `project-profile.v2.json` | TEECheck ProjectProfile v2 |
| `architecture.v1.json` | TEECheck ArchitectureModel v1 |
| `project-invariant.v1.json` | TEECheck ProjectInvariant v1 |
| `twe-playbook.v1.json` | TEECheck TWE Prior-Knowledge Playbook v1 |
| `twe-knowledge-manifest.v1.json` | TEECheck TWE Knowledge Manifest v1 |
| `twe-investigation.v1.json` | TEECheck TWEInvestigation v1 |
| `trustir-tool.v1.json` | TEECheck TrustIR Tool Protocol v1 |
| `finding.v3.json` | TEECheck UnifiedFinding v3 |

`trustir-tool.v1.json` 按融合文档 §19 将更名并调整语义为 `ToolFact v1`——PR-05 把
TrustIR 从 operation 式接口改为事实层后，原 request/result 语义不再适用。

## TWE 知识

`tee-usage-scanner/knowledge/twe/` 当前内容：

```text
binding.yml              旧 Entry 格式（可执行规则式）
config.yml               旧 Entry 格式
playbooks/rollback.yml   新 Playbook 格式（经验型）
```

即 7 个 family 中只覆盖 Binding、Config 与 State(rollback) 三项。`flow.yml` 与
`guard.yml` 已随 `00e7d69` 退场。

PR-02 将从 tee-audit `spec/twe_catalog.yml` 搬入全部 16 个 TWE 定义与事实词表，
补齐到 7 族完整覆盖。

## Benchmark

44 个 source-backed 数据集，全部带 `case.yaml` + `oracle.yaml`。

平台分布：

| 平台 | 数量 |
|---|---|
| OP-TEE | 27 |
| Trusted Firmware-M | 9 |
| Open Enclave | 4 |
| Intel SGX | 1 |
| AMD SEV-SNP | 1 |
| 未标注 | 2 |

其中 43 个是 C 项目——这是 v1 目标语言定为 C/TEE OS 的依据（融合文档 §0 修订 1、§4.2）。

PR-09 的门禁主案例是 `CVE-2026-44362`（OP-TEE，subkey 版本未传播）；其余 43 个
构成对照组，用于测 rollback family 的误报率。
