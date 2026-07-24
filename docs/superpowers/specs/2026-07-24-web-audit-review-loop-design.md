# Web 审计评审闭环 — 设计文档

> 日期：2026-07-24
> 分支：`merge/tee-audit-integration`
> 状态：设计已确认，待落实现计划
> 关联：本设计是架构快照 §4「待 PR-08：Finding v3 → SARIF → 人工复核」中**人工复核**部分的落地方案。

---

## 1. 背景与目标

当前人工复核是**终端交互 + 文件归档**：`internal/review/` 在终端里把 finding 分四块渲染给人看，`internal/feedback/` 把人的 true-positive / false-positive 判定归档到 `knowledge/learned/`。

目标：把这条闭环改造成 **web 评审台 + 后台扫描**，形成一个"issue/PR 式"的人机回合：

1. Agent 审计完成 → 每个 finding 成为一个可评审的"issue"。
2. 人在浏览器里审阅 → 提交裁决 + 评论（像 GitHub review comment）。
3. 人要求返工时，agent **迭代该 finding**；人给最终裁决时，把"为什么对/错"**沉淀为通用经验**。
4. 扫描可后台挂起，扫完再回来看。

核心价值：人不用守在终端；评审有结构、可回合迭代；每次评审都反哺后续审计质量。

---

## 2. 核心设计决策（已确认）

| 轴 | 决策 | 说明 |
|---|---|---|
| **承载平台** | TEECheck 内部拟态 | 不接真 GitHub/git。finding=issue，human verdict=追加记录，"PR/commit"是语义模型，落在 typed artifact 上。 |
| **优化目标** | 双轨 | 先迭代当前 finding（needs-work 回合），再把最终裁决沉淀进 `learned/` 改善未来审计。 |
| **评审内容** | 裁决 + 自由评论 | 人给 `accept / reject / needs-work` + 一段自由文字；agent 自行理解评论。 |
| **交互形态** | Web 评审台 + 后台扫描 | 换掉终端 `review/` 那层展示/交互；扫描后台跑，扫完在浏览器看。 |
| **状态存储** | SQLite 只存工作流+索引 | 证据/产物仍在文件（SoT，可 replay）；DB 存任务状态、finding 复核状态、review 线程、finding 索引。 |
| **入口** | CLI 与 web 并存 | 同一条 pipeline、两个入口。CLI 永远 standalone；daemon 只为 web 后台任务；DB 可选。 |

---

## 3. 架构总览

```
  teecheck scan <repo>   ── 进程内直接跑 pipeline(前台或 --background)
  (CLI, standalone)          顺带写 jobs 行 + 索引 findings 进 DB
        │                                              │
        │                                              │
  web "新建扫描"表单 ─▶ POST /jobs ─▶ daemon 取走 ──────┤ 跑同一条 pipeline
        │                                              ▼
        │                          ┌──────────────────────────────────────┐
        │                          │  pipeline  preprocess→…→arbiter         │
        │                          │  产出 Finding v3 → 写 runs/<id>/ 文件    │  ← 证据 SoT，可 replay
        │                          └───────────────┬──────────────────────┘
        │                                          │ 写任务状态 / 建 finding 索引 / 初始 revision
        ▼                                          ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  SQLite  (工作流 + 索引面，可选)                                          │
  │  jobs · findings_index · review_thread                                 │
  └───────────────┬──────────────────────────────────────────────────────┘
                  │ 读/写
  ┌───────────────▼──────────────────────────┐
  │  HTTP API (Go, 内嵌 teecheckd)             │
  │  GET /jobs  POST /jobs  GET /findings      │
  │  GET /findings/{id}  POST /findings/{id}/review  POST /findings/{id}/refine │
  └───────────────┬──────────────────────────┘
                  ▼
  ┌──────────────────────────────────────────┐
  │  Web 评审台  (3 屏)                         │
  │  任务列表 · finding 列表 · finding 详情/批注 │
  └──────────────────────────────────────────┘
```

**一句话**：CLI 和 web 是"同一引擎、两个入口"，不是两套实现。证据永远在文件，SQLite 只承载可变的工作流状态与查询索引。

---

## 4. 数据流（双轨闭环）

1. **启动**：`teecheck scan <repo>`（CLI）或 web `POST /jobs` → `jobs` 插一行 `queued`，立即返回。CLI 进程内直接跑；web 由 daemon 取走跑。
2. **扫描**：跑现有 pipeline，Finding v3 落 `runs/<id>/` 文件。完成后：
   - `jobs.status = done`，填 `run_id`。
   - 每个 finding 索引进 `findings_index`（`status = proposed`）。
   - `review_thread` 为每个 finding 插一条 agent 初始 `revision` 条目。
3. **查看**：人打开 web → 任务列表看到 `done` → 进 finding 详情：复用 `review/` 四块（裁决摘要 / 锚定证据 / 未锚定上下文 / verifier 判断）+ review 线程。
4. **评审**：人提交 `accept / reject / needs-work` + 自由评论 → `POST /findings/{id}/review` → `review_thread` INSERT 一条 human 条目。
   - `needs-work` → `findings_index.status = needs_work`。
   - `accept / reject` → 进第 6 步收尾。
5. **迭代（refine）**：对 `needs_work` 的 finding，web 按钮触发或 daemon 轮询 → `internal/refine` 读**整条线程 + 人的评论**，做**定向重查**（复用 Expert/Verifier，不重跑整条 pipeline）→ 产出新 revision（文件追加 + `review_thread` INSERT），`status = revised` 回到待复核。**每个 finding 最多 N 回合（默认 3）**，到顶强制人 accept/reject。
6. **沉淀**：`accept / reject` 时，`feedback/` 把整条线程沉淀进 `knowledge/learned/`（`true-positive` / `false-positive`，含"为什么对/错"），供后续审计。`findings_index.status = accepted | rejected` 收尾。最终 verdict 可选回写一份文件供 replay。

---

## 5. 数据模型

### 5.1 边界原则

- **文件（source of truth，不变）**：ProjectProfile、ArchitectureModel、ProjectInvariants、ToolFact、CasePack、Finding v3 —— 不可变、可 replay 的证据链（events + content-addressed blob）。**不进 DB。**
- **SQLite（工作流 + 索引面，新增，可选）**：任务状态、finding 复核状态、review 线程、finding 索引。存的是**指针 + 可变工作流状态**。

### 5.2 三张表

**`jobs`** — 后台任务
| 列 | 类型 | 说明 |
|---|---|---|
| `id` | text pk | 任务 id |
| `repo` | text | 仓库 URL / 路径 |
| `params` | json | mode / focus / samples… |
| `status` | text | `queued` / `running` / `done` / `failed` |
| `run_id` | text null | 指向 `runs/<id>/`，启动后填 |
| `source` | text | `cli` / `web`（区分入口） |
| `error` | text null | 失败原因 |
| `created_at` / `started_at` / `finished_at` | ts | 时间戳 |

**`findings_index`** — finding 索引 + 复核状态
| 列 | 类型 | 说明 |
|---|---|---|
| `finding_id` | text pk | 来自 Finding v3 |
| `job_id` / `run_id` | text fk | 归属任务/运行 |
| `title` / `severity` / `category` | text | 冗余列，列表页秒出 |
| `artifact_path` | text | 指向文件 SoT |
| `status` | text | `proposed` / `needs_work` / `revised` / `accepted` / `rejected` |
| `round` | int | 当前回合数（0 起） |
| `updated_at` | ts | |

**`review_thread`** — **只 INSERT** 的 issue 线程
| 列 | 类型 | 说明 |
|---|---|---|
| `id` | int pk autoinc | |
| `finding_id` | text fk | |
| `round` | int | 第几回合 |
| `author` | text | `human` / `agent` |
| `kind` | text | `revision` / `verdict` / `comment` |
| `verdict` | text null | `accept` / `reject` / `needs_work`（仅 human verdict 条目） |
| `body` | text | 评论 或 revision 摘要 |
| `artifact_ref` | text null | 该 revision 落地文件 |
| `created_at` | ts | |

**三层纪律**：`review_thread` **只增不改**（无 UPDATE/DELETE）；ToolFact 不进 DB、不可改写；`agent_revision` = AgentAssessment，`human verdict/comment` = HumanVerdict（追加）。

---

## 6. 状态机（单个 finding）

```
                 ┌──────────────────────────────────┐
                 ▼                                  │ refine 产出新 revision
  proposed ──▶ (人评审) ──needs-work──▶ needs_work ──┴──▶ revised ──▶ (人评审)
     │              │                                                   │
     │              ├── accept ──▶ accepted ──▶ feedback 沉淀 learned    │
     │              └── reject ──▶ rejected ──▶ feedback 沉淀 learned    │
     └───────────────────────────────────────────────────────────────┘
  收敛：round 达到 N(默认 3) → 禁用 refine，强制人 accept/reject。
```

---

## 7. HTTP API（MVP）

| 方法 | 路径 | 作用 |
|---|---|---|
| `GET` | `/jobs` | 任务列表 + 状态/进度 |
| `POST` | `/jobs` | 新建扫描（body: repo + params）→ 入队 |
| `GET` | `/jobs/{id}` | 单任务详情/进度 |
| `GET` | `/findings?job={id}&status=` | finding 列表（可按任务/状态过滤） |
| `GET` | `/findings/{id}` | finding 详情：四块展示 + 完整线程 |
| `POST` | `/findings/{id}/review` | 提交裁决 + 评论（body: `verdict`, `comment`） |
| `POST` | `/findings/{id}/refine` | 触发一次定向重查（needs_work 且未到回合上限时） |

鉴权：MVP 本地单用户，先不做鉴权；预留后续加。

---

## 8. Web 屏（评审台 MVP，3 屏）

1. **任务列表**（`jobs`）：`新建扫描`按钮（填 repo + mode/focus）+ 每行状态/进度。
2. **Finding 列表**（按 job 过滤）：title / severity / status 徽章，点进详情。
3. **Finding 详情**：复用 `review/` 四块展示 + review 线程（人机往复）+ 批注框（`accept` / `reject` / `needs-work` + 自由评论）+ `refine` 按钮（到回合上限时禁用）。

前端形态：先最简（server-rendered 或轻 SPA），自包含、无重框架。UI 细节在实现阶段再定。

---

## 9. Go 包与复用

**新增**
- `cmd/teecheckd` — daemon + HTTP server（消费 web 入队的任务、提供 API）。
- `internal/store` — SQLite 封装（启动时建表 / 加列；三张表的读写）。
- `internal/refine` — 读线程 + 评论做**定向重查**，复用 Expert/Verifier 逻辑。
- `web/` — 前端资源。

**复用（不重写）**
- `internal/pipeline` — 被 CLI 与 daemon **共同调用**的同一条引擎。
- `internal/review` — 四块展示逻辑 → 抽出 API 序列化形态。
- `internal/feedback` — accept/reject 时沉淀 `knowledge/learned/`。

**改动**
- CLI 扫描入口（`cmd/teecheck` 的 run/scan）：跑完顺带写 `jobs` + 索引 `findings_index` + 初始 `review_thread`——**仅当配置了 DB**。
- 抽出一个共享 hook「pipeline 完成 → 记录到 DB」，CLI 与 daemon 都调它。

---

## 10. CLI / web 并存与 DB 可选（关键约束）

- **CLI 永远 standalone**：不依赖 daemon、不依赖 web，独立跑完一次审计。
- **daemon 只为 web 后台任务存在**：web `POST /jobs` 入队，daemon 消费。
- **DB 可选**：未配置 SQLite 时，CLI 完全等同今天的纯文件行为 → **benchmark / CI 一行不受影响**。
- 两入口共用同一条 pipeline + 同一个「记录到 DB」hook，杜绝两套实现。

---

## 11. 非目标（Out of Scope，本期不做）

- 真 GitHub / git 集成（issue/PR/commit 只是内部语义模型）。
- Finding v3 本体迁进 DB（证据仍是文件 SoT）。
- 历史运行浏览、统计仪表盘、`learned` 知识库在线编辑（更重的"完整控制台"）。
- 多用户 / 鉴权 / 权限（MVP 本地单用户）。
- SARIF 导出（PR-08 的另一块，本设计只覆盖"人工复核"部分）。
- 人直接 push 代码 patch（评审内容限定为裁决 + 自由评论）。

---

## 12. 验收标准

1. `teecheck scan <repo>`（CLI）无 daemon、无 DB 时行为与今天一致；配置 DB 后额外写入 `jobs` / `findings_index` / `review_thread`。
2. web `POST /jobs` 能后台启动扫描，任务在 web 上可见状态从 `queued → running → done`。
3. finding 详情页展示四块 + 线程；提交 `needs-work` + 评论后，`refine` 能产出一条新 agent revision 并回到待复核。
4. `refine` 到第 N 回合（默认 3）被禁用，强制 accept/reject。
5. `accept` / `reject` 后 `knowledge/learned/` 出现对应沉淀记录。
6. `review_thread` 全程只增不改；ToolFact 不进 DB。
7. 现有 `go test ./...` 全绿，benchmark 不受影响。

---

## 13. 待实现阶段决定的细节

- refine 的定向重查具体复用 Expert 还是 Verifier、prompt 如何吃"整条线程 + 评论"。
- 前端框架/形态（server-rendered vs 轻 SPA）。
- job 进度上报粒度（阶段级 vs 细粒度）。
- `params` 支持的字段集合。
