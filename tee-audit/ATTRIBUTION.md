# tee-audit — 来源、许可与资产三分

## 来源

| 项 | 值 |
|---|---|
| 上游仓库 | `git@github.com:pinshenxu/tee-audit.git` |
| 导入基线 commit | `f8053a18190d5e6c4cfe0da3e66e0df770832dfe` |
| 基线 commit 标题 | *Add TrustIR/TWE pipeline: deterministic TEE weakness analysis* |
| 上游分支 | `main`（12 个提交，全部保留） |
| 导入方式 | `git subtree add --prefix=tee-audit` 的等价手工操作（`merge -s ours --allow-unrelated-histories` + `read-tree --prefix`），因本机未安装 git-subtree |
| 许可 | MIT，见 `LICENSE`，原样保留 |

上游历史完整保留在提交图中——导入提交有两个父提交，其一即 `f8053a18`。可用
`git merge-base --is-ancestor f8053a18190d5e6c4cfe0da3e66e0df770832dfe HEAD` 验证。

## 定位

融合形态为**吸收式**：合并后只有单一 `teecheck` CLI 与单一流程，tee-audit 不再作为
独立产品发布。因此导入时已移除 `pyproject.toml`——它同时声明了可安装包、`tee-audit`
CLI 入口点（`tee_audit.cli:main`）和 pytest 测试路径（`testpaths = ["tests"]`）。
移除后本目录不在任何构建或测试路径中，内容仅作资产来源与实现对照。

需要查看原始 `pyproject.toml` 时用 `git show f8053a18:pyproject.toml`。

## 资产三分

导入的 Python 代码不是整体可用。按下表分类处置，详见
`docs/TEECHECK_TEE_AUDIT_MERGE.zh-CN.md` §15.5。

### A 类 · 原样搬入主线

语言无关，是本次融合最稀缺的资产。将在 PR-02 / PR-03 / PR-04 迁入
`tee-usage-scanner/knowledge/` 与相应 Go 包。

| 文件 | 行数 | 去向 |
|---|---|---|
| `src/tee_audit/trustir/spec/twe_catalog.yml` | 81 | `knowledge/twe/catalog.yml`（16 个 TWE 定义） |
| `src/tee_audit/trustir/spec/enum_registry.yml` | 181 | `knowledge/twe/enum_registry.yml`（事实词表） |
| `src/tee_audit/trustir/spec/taxonomy.yml` | 49 | `knowledge/twe/taxonomy.yml`（七族分类） |
| `src/tee_audit/trustir/spec/exclusion.yml` | 38 | `knowledge/twe/exclusion.yml`（scope 排除规则） |
| `src/tee_audit/patterns/tee_signals.py` | 77 | `internal/preprocessor/`（PR-03） |
| `src/tee_audit/patterns/search_patterns.py` | 64 | 同上 |
| `src/tee_audit/utils/manifest_parsers.py` | 347 | 同上 |
| `src/tee_audit/stages/dossier.py` | 97 | `internal/architecture/` 的 prompt 起点（PR-04） |
| `src/tee_audit/stages/invariants.py` | 77 | `internal/invariants/` 的 prompt 起点（PR-04） |

另有一项非文件资产：`src/tee_audit/trustir/generator/annotation_facts.py` 的 docstring
记录了 v1 的两个致命 bug（exact-line `asExpr().getLocation()` 定位过脆、role enum
mismatch）。这两条已固化为 PR-05 的设计约束，见融合文档 §23.4。

### B 类 · 架构照搬，实现按 C 重写

`annotate → facts → fixed-queries` 架构可用，但查询资产绑死语言，对 C 目标不可复用。
保留作图纸，不进构建。

| 内容 | 规模 | 说明 |
|---|---|---|
| `codeql/trustir/{rust,go,javascript}/` | 60 个 `.ql` + 30 个 `.qll` | 每语言 20 个查询，覆盖七族。C 版需新写，见 PR-05 |
| `src/tee_audit/trustir/generator/annotation_facts.py` | 518 | 事实表生成器，clause 生成部分绑定语言 |
| `src/tee_audit/trustir/extractor/enumerate_classify.py` | 791 | LLM 标注抽取，含约 44 处语言相关降噪补丁 |
| `src/tee_audit/trustir/{resolver,binder}/` | 803 | 符号解析与绑定 |

上游 `annotation_facts.py` 自述真正端到端验证过的只有 Go：
*"Go is fully implemented (primary validation language); Rust mirrors the same
predicates...; JS would emit Go-style clauses per the known gap."*
`codeql_runner.py` 对 go/javascript/rust 之外的语言直接 `FileNotFoundError`。

### C 类 · 退场，不进主流程

TEECheck 已有更强的对应实现（`expert`/`challenger`/`verifier`/`arbiter`/`review`/`stats`）。

| 文件 | 行数 | TEECheck 对应 |
|---|---|---|
| `src/tee_audit/stages/report.py` | 2348 | `internal/report` + `internal/stats` |
| `src/tee_audit/stages/report_review.py` | 1419 | `internal/arbiter` + `internal/review` |
| `src/tee_audit/stages/deep_verify.py` | 1329 | `internal/expert` + `internal/challenger` + `internal/verifier` |
| `src/tee_audit/pipeline.py` | 404 | `internal/pipeline`（七阶段编排器退场） |
| `src/tee_audit/stages/triage.py` | 193 | `internal/solver` |

合计 5693 行，其中落在 `stages/` 的 5289 行占该目录 6193 行的 **85%**。

## 禁止移植的行为

`src/tee_audit/stages/report_review.py` 的 stage 7 ralph loop 自述行为是：

> *"Iteratively reviews the stage 6 report, generates findings from invariants
> when CodeQL produced nothing, and refines until quality threshold is met."*

即工具无产出时从 invariant 合成 finding，再迭代到「质量达标」。

这与融合架构的核心原则同源违规——一条是「工具失败或覆盖不完整不得解释为没有漏洞」，
这里是反向的「工具无产出不得解释为有漏洞」。两者都让结论脱离证据。

**该行为禁止以任何形式进入主流程**，不进入清理候选队列。见融合文档 §15.6。

## 第三方来源

本仓库内混合了多种许可的内容：

| 内容 | 许可 |
|---|---|
| TEECheck 根仓库 | **Apache-2.0**（见根目录 `LICENSE`、`NOTICE`） |
| `tee-audit/` | MIT（本文件记录，`tee-audit/LICENSE` 保留） |
| `teecheck-benchmark/datasets/` 中的上游源码切片 | 各自上游许可（OP-TEE OS 为 BSD-2-Clause），见各 `case.yaml` |

MIT 与 BSD-2-Clause 均可并入 Apache-2.0 项目，反向不可。根目录 `NOTICE` 汇总全部
第三方来源。
