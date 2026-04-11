# LLM 驱动的迭代式 Planner (Scanner Agent 重构)

**状态**: 草案 — 等待用户 review
**日期**: 2026-04-11
**作者**: Claude (与 pw0rld 共同设计)
**取代**: `internal/repomap/run.go` 和 `internal/hotspots/run.go` 中基于关键字打分的 hotspot 选择逻辑
**对应英文版**: `2026-04-11-llm-planner-design.md`

## 1. 动机

当前的 Scanner agent 是通过把文件和符号名跟一组硬编码的英文关键字列表打分来挑 hotspot 的 (`repomap/run.go:scoreValue` 和 `classifyBoundary`)。这套做法有几个结构性的问题,会导致真实的 TEE 漏洞在 LLM 看到之前就被静默过滤掉:

1. **命名没踩关键字就出局**: 用 `check`/`guard`/`ensure` 表达"校验"的代码打分为零,直接掉出 top-16 截断。
2. **硬上限 16 没有多样性约束**: 一个高分模块会吃掉所有名额,其他模块连一个 candidate 都进不去。
3. **只看名字不看内容**: 打分函数从不读文件内容,仅根据路径和符号名判断。
4. **图连接度当作重要性代理是有偏的**: 工具 util (高入度低相关性) 经常盖过窄入口的敏感函数。
5. **边界分类是第二道关键字过滤**: 打分通过的文件还要再过 `classifyBoundary` 的 7 类硬编码词表,漏网效应叠加。
6. **没有反馈闭环**: `knowledge/learned/` 的历史结果从未被打分阶段读取。

期望的模型是: **让 LLM 对代码仓库结构做粗略侦察,然后迭代式地决定要调用哪些静态分析工具、以及在哪里调用,把审计逻辑从"关键字正向过滤"改成"以 sink 为根的反向追溯"**。

## 2. 目标与非目标

### 目标

- 用 LLM 驱动的迭代 planner (brainstorming 里的 L3 方案) 替换基于关键字的 hotspot 选择。
- 引入真正的"从 sink 反向追 caller"能力 — sink 来自一份 curated 的目录 (FFI、`unsafe`、attestation verify、crypto、state mutation 等),v1 用 tree-sitter 作为解析引擎。
- 保留现有的 `kind → obligations` case 模板映射 — expert / challenger / verifier / arbiter 四个 agent 完全不动。
- Heuristic mode (`--mode heuristic`) 继续完整可用,作为 LLM-free 的快速路径、以及 planner 失败时的 fallback。
- 每一 round 都有完整可审计的执行轨迹。

### 非目标 (v1)

- 除 Rust 以外的多语言支持。Go / Solidity / Python / TypeScript 留给 v2。
- LSP 集成 (rust-analyzer / gopls)。超出 tree-sitter 语法层级的语义调用图是 v2。
- Joern / CodeQL 集成。那些 stub 继续保持 stub。
- 自动把 `proposed_sinks` 写回 `knowledge/sinks/`。v1 只记录 LLM 的提案,curator 审核要人工操作,闭环留 v2。
- 自写 semgrep 规则集。v1 不携带任何。

## 3. 架构总览

### 3.1 新 Pipeline 形态

```
repofetch → preprocessor(profile)
         → SCANNER AGENT (L3 Planner)
         │    seed state (profile + 粗树)
         │         │
         │         ▼
         │    ┌── round N ──┐
         │    │ LLM thought │ ← working memory
         │    │ + actions   │ ← sink catalog
         │    └──┬──────────┘ ← 迄今为止的 observations
         │       │
         │       ▼
         │    action executor (沙箱化)
         │       │
         │       ▼
         │    observations → 追加回 state
         │       │
         │       └── done? ── 否 → 下一轮
         │                  └── 是
         │         │
         │         ▼
         │    evidence_bundle.json
         └───────┬──────────────────────
                 ▼
         cases → expert → challenger → verifier → arbiter
```

Scanner agent 的职责从"跑 graph + 打分"变成"驱动 planner 循环"。老的 regex graph + keyword scoring 被保留成 planner action 菜单里的一个选项 (`legacy_keyword_scan`),LLM 自己决定要不要调用它。

### 3.2 Planner 状态机

状态: `SEEDED → PLANNING → EXECUTING → OBSERVING → (回到 PLANNING) → DONE`

每一 round 的流程:

1. **PLANNING** — LLM 看 `(working_memory, 最近 observations, action 历史, 剩余 budget)`,输出结构化响应,包含 `thought` 和一组要执行的 `actions`。
2. **EXECUTING** — Actions 按顺序执行。每个 action 有自己的超时和输出上限,失败不是 fatal。
3. **OBSERVING** — 结果塞回 state,过大的输出做 truncate,更新 candidate 列表。
4. **终止判定** — `done` action / budget 耗尽 / loop 检测 / 连续非法输出。

### 3.3 上下文窗口管理

`PlannerState` 是结构化对象,不是 append-only 的 transcript,避免 prompt 无限膨胀:

```
PlannerState {
  profile: ProjectProfile
  tree_summary: string        // 初始目录树 + 体积统计
  rounds: []RoundRecord       // 完整轨迹,落磁盘
  candidates: []Candidate     // 累积的嫌疑区域
  sinks_seen: []SinkHit       // 已发现的 sink 位置
  budget_state: BudgetState   // 剩余 rounds/tokens/wall_clock
}
```

每次 LLM prompt 只包含:

- 压缩过的 profile (~300 tokens)
- 最近 2 轮完整 observations (每轮 ~5-10k tokens)
- 所有已累积的 candidates (~2k tokens)
- 剩余 budget + 简短的 system prompt (~1k tokens)

完整轨迹持久化到 `04_planner/rounds.jsonl`,但**不喂回 LLM** — 那个文件是给人类和事后分析用的。

## 4. Action 菜单 (v1)

Planner 暴露 9 个 action。LLM 响应是严格 JSON,按 per-action schema 校验。非法 action 返 validation error 给 LLM,**不消耗 round**。

| Action | 作用 | 实现 |
|---|---|---|
| `list_dir(path, depth)` | 查看子树结构 | `os.ReadDir`,深度上限 3 |
| `read_file(path, start, end)` | 读指定行区间 | 纯 Go,上限 500 行 |
| `ripgrep(pattern, globs)` | 快速文本搜索 | `exec` ripgrep,匹配行上限 200 |
| `tree_sitter_outline(path)` | 提取文件结构大纲 (functions / structs / impls) | `go-tree-sitter` + Rust grammar |
| `reverse_trace(file, symbol, depth)` | 从 sink 反向 BFS | tree-sitter 查调用点,深度上限 3 |
| `legacy_keyword_scan()` | 跑老的 mapper + hotspots | 包装现有代码,返回 top-16 |
| `repomix_summarize(path)` | 子树 repomix 摘要 | 包装现有 `internal/repomix` |
| `sink_catalog_lookup(scope)` | 取 catalog 目录 / 整组 / 单个 category。`scope` 为 `"*"` / `"<group_id>"` / `"<group_id>.<category_id>"` | 读 `knowledge/sinks/rust.json` |
| `done(summary, candidates)` | 终止并输出 bundle | 最后一步 action |

**v2+ 延后**: LSP (rust-analyzer)、Joern、CodeQL、自写 semgrep 规则集、非 Rust 的 tree-sitter grammar。

### 4.1 Action Executor 沙箱

所有带路径参数的 action 都过 `planner/actions/sandbox.go`:

1. 所有路径参数先 `filepath.Clean` + `filepath.IsLocal` 归一化。
2. 归一化后的绝对路径必须 `strings.HasPrefix(abs, repoRoot)`。
3. 不跟随符号链接 (`os.Lstat`),任何 symlink 都视为越界。
4. 基于 `exec` 的 action (ripgrep) 用 argv 独立传参,**禁止 shell 字符串拼接**。
5. Planner 没有任何写入 action — 整个文件系统视图是只读的。

沙箱违规作为 action error 返回,**永不 panic**。

## 5. Sink Catalog

### 5.1 数据来源

v1 随代码发布手工策展的目录,放在 `knowledge/sinks/`:

```
knowledge/sinks/
├── rust.json          ← v1 核心
├── go.json            ← v2
└── README.md          ← sink 分类学说明
```

### 5.2 Schema (`rust.json`)

v1 范围**刻意收窄: 只覆盖 attestation 和 key lifecycle**。内存安全、host 泄漏、panic/debug smell、通用 runtime state 写入等全部不纳入 catalog。LLM 仍然可以用 `ripgrep` 或 `read_file` 调研 catalog 之外的东西,catalog 只是把 reverse_trace 的精力聚焦。

Categories 组织成 **groups**,让 LLM 先拉目录再按需深挖。v1 有 3 组: `attestation`、`tee_platform_syscalls`、`key_lifecycle`,共 13 个 category。

```json
{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id": "attestation",
      "description": "Quote/report 生成、验证、身份/TCB 检查、freshness — 完整的 RA 链路",
      "categories": [
        {
          "id": "attestation_report_creation",
          "description": "Quote/report 生成以及 report_data 字段的填充。审: 带进报告的是什么 (session pk / nonce / challenge)。",
          "match": {
            "kind": "symbol",
            "symbols": ["sgx_create_report", "sgx_quote_*", "sgx_qe_*", "*::create_report*", "*::generate_quote*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_verification_and_trust",
          "description": "验证入口 + 基于验证结果的 trust 决策点。具体决策点是项目特有的,必须由 LLM 通过 reverse_trace 从 verify 点反向追定位。",
          "match": {
            "kind": "symbol",
            "symbols": ["*::verify_quote*", "*::verify_report*", "*::verify_attestation*", "*::verify_evidence*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_identity_and_tcb_checks",
          "description": "MRENCLAVE/MRSIGNER 相等性比较,以及 TCB/QEIdentity/collateral/CRL 校验。审: 比对对象是否正确、过期/撤销是否被遵守。",
          "match": {
            "kind": "symbol",
            "symbols": ["*MRENCLAVE*", "*MRSIGNER*", "*::check_tcb*", "*::verify_tcb*", "*::qe_identity*", "*::collateral*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_freshness",
          "description": "Nonce 绑定、challenge-response 流程、时间窗口校验。审: replay 抵抗。",
          "match": {
            "kind": "symbol",
            "symbols": ["*::nonce*", "*::challenge*", "*::freshness*"]
          },
          "severity_hint": "high"
        }
      ]
    },
    {
      "id": "tee_platform_syscalls",
      "description": "Enclave 进出 + SGX 平台服务 — 信任边界交叉点",
      "categories": [
        {
          "id": "sgx_ecall",
          "description": "Enclave 入口 — 参数来自 host,不可信。",
          "match": { "kind": "symbol", "symbols": ["sgx_tstd::*", "sgx_urts::*", "#[ecall]"] },
          "severity_hint": "high"
        },
        {
          "id": "sgx_ocall",
          "description": "出 enclave 调用 — 返回值 host 可控,必须在 enclave 内部再次校验。",
          "match": { "kind": "symbol", "symbols": ["*::ocall_*", "sgx_ocall_*"] },
          "severity_hint": "high"
        },
        {
          "id": "sgx_platform_services",
          "description": "SGX 平台服务 QE / RA / AESM 通信。审: 错误和降级路径。",
          "match": { "kind": "symbol", "symbols": ["sgx_qe_*", "sgx_ra_*", "aesm_*", "*::aesm*"] },
          "severity_hint": "medium"
        }
      ]
    },
    {
      "id": "key_lifecycle",
      "description": "密钥生成、派生、封存、签名/验签、AEAD、secret 卫生 — 完整 key 生命周期审计",
      "categories": [
        {
          "id": "key_generation",
          "description": "Key pair / secret key 生成,以及使用的 RNG 来源。TEE 里 RNG 必须是 attested (OsRng/getrandom 配平台硬件熵源),不能是 thread_rng 或 seeded PRNG。",
          "match": {
            "kind": "symbol",
            "symbols": ["KeyPair::generate", "*::SecretKey::random", "*::generate_keypair*", "OsRng", "thread_rng", "getrandom::*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "key_derivation_and_exchange",
          "description": "HKDF、KDF、derive_key、ECDH、X25519、key_agreement。审: context/info/salt 绑定是否防止 cross-context 碰撞;peer 身份是否绑定 attested key。",
          "match": {
            "kind": "symbol",
            "symbols": ["*::derive_key*", "*::hkdf*", "*::kdf*", "*::key_agreement*", "*::diffie_hellman*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "key_sealing",
          "description": "SGX sealing、runtime sealing、unsealing。审: sealing policy 是绑 MRENCLAVE 还是 MRSIGNER;unseal 结果是否再次校验。",
          "match": { "kind": "symbol", "symbols": ["sgx_seal_data", "sgx_unseal_data", "*::seal*", "*::unseal*"] },
          "severity_hint": "high"
        },
        {
          "id": "signature_ops",
          "description": "签名和验签。审: 签名密钥是否 attested/sealed;验签失败路径是否可能落通;验签公钥是否可信。",
          "match": {
            "kind": "symbol",
            "symbols": ["*::sign", "*::sign_message*", "*::verify_signature*", "ed25519::*", "k256::*", "secp256k1::*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "aead_encryption",
          "description": "AEAD seal/open (ChaCha20-Poly1305、AES-GCM 等)。审: nonce 唯一性、key 生命周期、associated data 绑定。",
          "match": {
            "kind": "symbol",
            "symbols": ["*::seal_in_place*", "*::open_in_place*", "chacha20poly1305::*", "aes_gcm::*"]
          },
          "severity_hint": "medium"
        },
        {
          "id": "secret_hygiene",
          "description": "Zeroize trait、secret wrapper 类型,以及它们的缺失。审: secret 类型是否缺 Zeroize/ZeroizeOnDrop,是否通过 Debug/Display/serde 泄漏。",
          "match": {
            "kind": "syntax",
            "patterns": ["Zeroize", "ZeroizeOnDrop", "Secret<", "secrecy::", "#[derive(Debug)]"]
          },
          "severity_hint": "medium"
        }
      ]
    }
  ]
}
```

两种匹配模式:

- **`syntax`** — tree-sitter 节点文本匹配 (例如检测 `Zeroize` 存在)
- **`symbol`** — 符号名 glob (例如 `*::verify_quote*`)

部分 category 的 match pattern 刻意写得宽松 (比如 `attestation_verification_and_trust`)。trust-decision 点和具体 caller 的精确定位留给 LLM 通过 `reverse_trace` 来完成,**不硬编码进 catalog**。

### 5.3 LLM 怎么用 Catalog

Catalog 是**给 LLM 看的审计清单**,不是自动执行的规则集。`sink_catalog_lookup` 支持三种 scope 级别:

- `sink_catalog_lookup("*")` — 只返 group id + description (~300 tokens)。LLM 第一次调用,拉目录。
- `sink_catalog_lookup("attestation")` — 返整组 (~1.5k tokens)。决定了某组相关后调用。
- `sink_catalog_lookup("attestation.quote_verification")` — 返单个 category 定义 (~300 tokens)。精准深挖用。

LLM 典型流程: 先调 `*` → 挑 1-2 个 group → 调 group → 挑 category → 对 match 命中的符号调 `reverse_trace(file, symbol, depth)` 定位真正的 trust-decision 点。

### 5.4 LLM 提案的 Sink

`evidence_bundle.proposed_sinks[]` 记录 LLM 在 run 过程中"发明"的新 sink 分类。v1 **不自动回写**到 `knowledge/sinks/` — 仅标记供人工 curator review。回写闭环是 v2。

## 6. Artifact Schema

### 6.1 Evidence Bundle

Planner 的最终产物,也是 `cases` 阶段的主要输入:

```json
{
  "schema_version": "teecheck.evidence_bundle.v1",
  "run_id": "2026-04-11-...",
  "repo": { "url": "...", "commit": "...", "focus": "tee" },

  "planner_meta": {
    "rounds_used": 6,
    "rounds_budget": 8,
    "tokens_used": 42000,
    "wall_clock_ms": 138000,
    "termination_reason": "llm_done | budget_exhausted | loop_detected | llm_malformed | planner_failed",
    "truncated": false
  },

  "candidates": [
    {
      "id": "candidate-001",
      "kind": "attestation",
      "priority": "high",
      "paths": ["runtime-sdk/src/modules/rofl/attestation.rs"],
      "symbols": ["verify_enclave_rak_pub"],
      "why_selected": [
        "sink:attestation_verify 在 runtime-sdk/src/modules/rofl/attestation.rs:142 命中",
        "reverse_trace 深度 2: verify_enclave_rak_pub -> handle_register -> dispatch",
        "dispatch 到 verify 之间没有 caller-binding 校验"
      ],
      "evidence_refs": ["round-3.obs-2", "round-4.obs-1"],
      "sink_category": "attestation_verify",
      "confidence": 0.78
    }
  ],

  "sinks_observed": [
    {
      "category": "unsafe_block",
      "hits": [ { "path": "...", "line": 42, "snippet": "unsafe { ... }" } ]
    }
  ],

  "proposed_sinks": [
    {
      "category_id_suggested": "rofl_appd_message_decode",
      "rationale": "LLM 观察到 appd 消息解码有现有 catalog 未覆盖的信任影响",
      "example_symbols": ["appd::decode_message"]
    }
  ],

  "errors": [ { "round": 2, "action": "tree_sitter_outline", "error": "..." } ],
  "final_summary": "..."
}
```

### 6.2 Rounds Log

`runs/<run-id>/04_planner/rounds.jsonl` — 每一轮一个 JSON 对象,包含完整 LLM thought 和每个 action 的完整输入/输出 (truncation 之前的原始数据,在可能的情况下)。用于调试和事后分析,**永不喂回 LLM**。

### 6.3 Hotspot Index Shim

v1 继续往 `runs/<run-id>/04_hotspots/hotspot_index.json` 写一份"降级版本":把 evidence bundle 的 candidate 列表反向映射成老 schema。理由:

- 避免一次性修改所有现有 fixture 和测试
- 如果有外部脚本直接读 hotspot_index.json,不破坏兼容
- 迁移成本可控

v2 可以把 hotspot_index.json 标记为 deprecated。

### 6.4 目录布局

```
runs/<run-id>/
├── 00_manifest.json
├── 01_profile/project_profile.json
├── 02_graph/graph.json              # 可能为空 (planner 没调用 legacy_keyword_scan)
├── 03_repo_map/repo_map.json        # 同上
├── 04_planner/                      # 新增
│   ├── rounds.jsonl                 # 完整审计轨迹
│   ├── evidence_bundle.json         # 主产物
│   └── sink_hits.json               # 给人看的 sink 命中汇总
├── 04_hotspots/hotspot_index.json   # v1 back-compat shim
├── 05_cases/case-NNN.json           # 从 evidence_bundle 读
├── 04_expert/...
├── 05_challenger/...
├── 06_verifier/...
└── 07_arbiter/...
```

## 7. Pipeline 集成

### 7.1 模式分发

- `--mode heuristic` → Scanner agent 走老的 mapper+hotspots 路径,planner 完全跳过。
- `--mode llm` (已有) → Scanner agent 调用 `planner.Run`,planner 写 evidence bundle,cases 阶段读 bundle。

### 7.2 cases 阶段改动

`internal/cases/run.go`:

```go
func Run(cfg) error {
  // 1. 如果 evidence_bundle.json 存在,从中读 candidates
  // 2. 否则 fallback 读 hotspot_index.json (heuristic mode)
  // 3. 对每个 candidate 调 caseTemplate(kind) 拿义务模板
  // 4. 输出 case-NNN.json
}
```

`caseTemplate(kind)` 映射**不变**。candidates 携带的 `kind` 值和 classifier 原先输出的值完全相同 (`attestation`、`authorization`、`state_machine`、`key_management`、`fallback`、`ffi_boundary`、`host_interface`、`runtime_entry`),所以 expert / challenger / verifier / arbiter **一行代码都不改**。

### 7.3 下游 Agent — 不改

Expert、challenger、verifier、arbiter 都在 case pack 上工作。case pack 的 schema 不变。Planner 影响的是**哪些区域会生成 case pack**和**附带什么证据**,但不影响下游 pipeline。

## 8. Budget 和终止

### 8.1 默认值

| 维度 | 默认值 | CLI flag | 作用 |
|---|---|---|---|
| max rounds | 8 | `--planner-max-rounds` | 防无限循环的硬顶 |
| max LLM tokens | 120000 | `--planner-max-tokens` | 成本控制 (所有 round 的 input + output token 合计) |
| per-action timeout | 30s | `--planner-action-timeout` | 单工具失控保险 |
| total wall clock | 10min | `--planner-wall-clock` | 端到端硬停 |

这组默认值可以在 provider config 里按 provider 设 (例如本地 GLM 不限 tokens,Claude Opus rounds=6 / tokens=60k)。

### 8.2 自动终止条件

1. `done(...)` — LLM 主动终止 (正常路径)。
2. 任一 budget 维度触顶 — planner 向最终 round 的 prompt 注入 `budget_exhausted` 信号。如果 LLM 还不听话输出 `done`,executor 用当前 candidates **合成**一个 `done` action。
3. **Loop 检测** — 同一 action + 同一参数连续出现 3 次被拒绝;LLM 收到 "你在重复,换个思路" 作为 observation。
4. 连续 2 轮 candidates 列表无变化 → 强制终止 (LLM 在原地打转)。
5. 连续 2 次 LLM 输出非法 → 降级到 `legacy_keyword_scan`,bundle 标 `termination_reason = "llm_malformed"` 和 `truncated = true`。

## 9. 错误处理

### 9.1 硬性不变量

**Planner 永远产出一份 `evidence_bundle.json`,即便失败**。下游 cases / expert / challenger / verifier / arbiter 要么拿到真的 candidates,要么 fallback 到 heuristic 路径。默认情况下 planner 错误不会让 `teecheck run` 以非零码退出。

Opt-in 的 `--strict-planner` flag 反转这个行为 (CI 用): planner 失败 → run 非零退出。

### 9.2 Action 级错误

每个 action 返回 `ActionResult { ok: bool, output: string, error: string }`。LLM 看到的是 `error` 字符串,可以根据错误决定换工具或继续。

- 工具缺失 (rg / tree-sitter 绑定) → `ok: false, error: "tool X not installed"`
- 超时 → `ok: false, error: "timeout after 30s"`,保留部分输出
- 输出 > 50KB → 截断到 50KB,保留 head + tail,标记 `truncated: true`
- 路径非法 / 越界 → schema 校验失败,action 不执行

### 9.3 LLM 级错误

- JSON 解析失败 → 重试 1 次,把解析错误塞进 prompt
- Action schema 校验失败 → 返 validation error 给 LLM,**不消耗 round**
- LLM API 超时 → 本轮计为失败,进入 loop detection 计数
- 连续 2 次失败 → 按 8.2 第 5 条降级

### 9.4 Pipeline 级错误

- Planner 整体失败 (罕见) → 空 evidence bundle + `termination_reason = "planner_failed"`,详细错误打印到 stdout 配醒目警告:
  ```
  ⚠  Planner failed after N rounds (reason: ...). Falling back to heuristic hotspots.
      Full trace: runs/<run-id>/04_planner/rounds.jsonl
  ```
- Pipeline 继续。cases 阶段发现 bundle 为空后 fallback 读 `hotspot_index.json` shim (如果存在)。

## 10. 测试策略

### 10.1 单元测试

每个 action 配一个 `_test.go`,用 `testdata/` 里的 fixture 仓库跑:

- **Action 正确性** — 每个 action 一个 happy path fixture。
- **Sandbox** — 专门一组 `TestActionExecutor_PathEscape`,覆盖 `../`、绝对路径、symlink 和其他 ~20 种恶意输入。
- **Budget exhaustion** — mock LLM 一直返回更多 actions;断言 `max_rounds`、`max_tokens`、`wall_clock` 各自触顶时正确终止。
- **Loop detection** — mock LLM 重复同一 action;断言第 3 次被拒。
- **Malformed JSON** — mock LLM 返回坏 JSON;断言 retry 逻辑。
- **Sink catalog loader** — schema 校验,非法 pattern 拒绝。

### 10.2 集成测试 (Mocked LLM)

`internal/planner/planner_integration_test.go`:

- 准备一个 Rust testdata 仓库,包含 `unsafe`、`extern "C"` 和一个假的 attestation 函数。
- Mock LLM 给定固定脚本化响应序列 (round 1 `list_dir`,round 2 `sink_catalog_lookup`,round 3 `reverse_trace`,round 4 `done`)。
- 断言: evidence bundle 的 candidates 包含预期 paths / symbols,`rounds_used == 4`,`termination_reason == "llm_done"`。

### 10.3 Live LLM Smoke Test

`internal/planner/live_test.go`,靠 `TEECHECK_LIVE_LLM` 环境变量开启:

- 跑在一个小型 Rust 仓库 (testdata 或 oasis-sdk 的单个 crate)。
- 用真实配置的 provider (GLM / OpenAI / ...)。
- 断言: candidates 非空、rounds 在 [2, 8] 之间、wall clock < 5 min、至少一个 candidate 的 `sink_category` 来自 `rust.json`。

### 10.4 故意不测的东西

- tree-sitter 解析本身的正确性 (上游的责任)
- repomix (已有自己的测试)
- LLM 输出的语义正确性 (不是单测该管的)

## 11. 代码组织

```
internal/
├── planner/                       # 新增,核心
│   ├── planner.go                 # Run(ctx, cfg) 入口 + 主循环
│   ├── state.go                   # PlannerState + 持久化
│   ├── prompt.go                  # system prompt + round prompt 构造
│   ├── budget.go                  # BudgetState + 终止判定
│   ├── loop_detect.go             # 重复 / 原地打转检测
│   ├── planner_test.go
│   ├── planner_integration_test.go
│   └── live_test.go
│
├── planner/actions/               # 新增,每个 action 一个文件
│   ├── registry.go                # action 名 → handler + schema 校验
│   ├── sandbox.go                 # 路径归一化 / 越界 / symlink 检查
│   ├── list_dir.go
│   ├── read_file.go
│   ├── ripgrep.go
│   ├── tree_sitter_outline.go
│   ├── reverse_trace.go
│   ├── legacy_keyword_scan.go     # 包装现有 mapper + hotspots
│   ├── repomix_summarize.go       # 包装现有 internal/repomix
│   ├── sink_catalog_lookup.go
│   ├── done.go
│   └── *_test.go
│
├── planner/sinks/                 # 新增
│   ├── loader.go                  # 读 knowledge/sinks/*.json
│   ├── matcher.go                 # syntax / symbol 匹配
│   └── loader_test.go
│
├── artifacts/types.go             # 修改: 增加 EvidenceBundle / Candidate / SinkHit
├── scanner/scan.go                # 修改: llm mode 分支到 planner.Run
├── cases/run.go                   # 修改: 优先读 evidence bundle,fallback 读 hotspot_index
├── config/config.go               # 修改: 增加 --planner-* flags 和 --strict-planner
└── runfs/paths.go                 # 修改: 增加 bundle / rounds log / sink hits 路径

knowledge/
├── sinks/                         # 新增
│   ├── rust.json                  # v1 主要内容
│   └── README.md
└── wiki/                          # 不变
```

### 代码量预估

- `internal/planner/*.go` — ~600 行
- `internal/planner/actions/*.go` — ~900 行 (9 个 action × 平均 100 行)
- `internal/planner/sinks/*.go` — ~300 行
- `knowledge/sinks/rust.json` — ~200 行
- 现有文件修改 — ~200 行
- 测试 — ~1500 行
- **总计 ~3700 行**

预估工期: 3–5 天 (乐观, tree-sitter Go 绑定顺畅) 到 1–2 周 (悲观, cgo 工具链 / grammar 版本问题)。

## 12. 实施 Milestone

PR 尺寸,每一个都可独立 review 和 revert:

### M1 — Artifact schema + sandbox + 基础读 actions

- `artifacts.EvidenceBundle`、`Candidate`、`SinkHit` 类型。
- `internal/planner/actions/sandbox.go` 配完整的路径越界测试套件。
- `list_dir`、`read_file`、`ripgrep` actions 配 per-action 单测。
- Planner 主循环还没有 — actions 可独立单测。

### M2 — Sink catalog + tree-sitter outline

- `knowledge/sinks/rust.json` 种子内容。
- `internal/planner/sinks/{loader,matcher}.go` + 测试。
- `tree_sitter_outline` action,用 `go-tree-sitter` + Rust grammar。
- **技术风险最高的 milestone** — cgo / grammar 版本问题会在这里暴露,最坏情况 M3 之前我们重新评估工具选择。

### M3 — Planner 主循环 + 剩余 actions

- `internal/planner/{planner,state,prompt,budget,loop_detect}.go`。
- `reverse_trace`、`legacy_keyword_scan`、`repomix_summarize`、`sink_catalog_lookup`、`done` actions。
- `planner_integration_test.go` 配 mocked LLM,端到端通过。

### M4 — Pipeline 接线

- `scanner/scan.go`: `--mode llm` 分发到 `planner.Run`。
- `cases/run.go`: 读 evidence bundle,fallback 读 hotspot index。
- `config/config.go`: `--planner-*` flags 和 `--strict-planner`。
- `runfs/paths.go`: 新路径。
- Heuristic mode 保持完全不变。

### M5 — Live smoke test + 文档

- `live_test.go` 跑 oasis-sdk + 真实 LLM provider。
- 更新 `README.md`,加 planner flags 和行为说明。
- 更新 `docs/MULTI_AGENT_HARNESS.md`。

(Prompt 调优是 M5 之后的持续活动,不单独算 milestone。)

## 13. 风险与 Mitigation

| 风险 | 可能性 | Mitigation |
|---|---|---|
| tree-sitter Go 绑定 / cgo 工具链问题 | 中 | M2 隔离;那里失败触发工具选择的 revisit,不触碰 M3+ |
| LLM prompt 不稳定 (重复、坏 JSON) | 高 | Loop detection、malformed 重试、强制降级到 `legacy_keyword_scan` |
| 大仓库上成本超支 | 中 | 四维 budget 硬墙,per-provider 默认值调优 |
| 静默降级 (用户以为走 llm 实则 heuristic) | 中 | Fallback 时 stdout 醒目警告;CI 用户用 `--strict-planner` opt-in |
| Evidence bundle 和 cases 阶段 schema 漂移 | 低 | `kind` 值和老 classifier 输出保持完全一致;在 `artifacts` 里共享常量集合 |
| 构造路径绕过 sandbox | 低 | 专门的 sandbox 测试套件、拒绝 symlink、argv-only exec |

## 14. 未来工作的开放问题 (不在 v1)

- `proposed_sinks` → `knowledge/sinks/` 的 curator 闭环回写。
- LSP 集成拿语义调用图 (rust-analyzer、gopls)。
- Go / Solidity / Python / TypeScript 的 tree-sitter grammar。
- Per-run 学习式调整 (TP/FP 历史影响 candidate 排序)。
- Joern / CodeQL 作为重型 action 选项。

## 15. 成功判据

v1 视为成功当:

1. `teecheck run --mode llm <oasis-sdk>` 产出一份 `evidence_bundle.json`,其中至少有 5 个高质量 candidate,人类审计员同意值得深入调查。
2. 上述至少有 2 个 candidate 所在的文件,其路径 / 符号名在老的关键字系统下不会高分 (也就是老系统会漏的)。
3. 端到端运行时间不超过当前 heuristic mode 的 2 倍。
4. 现有 fixture 上 `--mode heuristic` 输出无回归。
5. Live smoke test 在 GLM 和一个 OpenAI 兼容 provider 上稳定通过。
