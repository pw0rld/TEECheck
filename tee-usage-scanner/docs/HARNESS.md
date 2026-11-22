# TEECheck 运行主线

本文描述默认扫描流程和工程边界。契约及结果语义见 [CONTRACTS.md](CONTRACTS.md)，
模型路由见 [ROLE_MODELS.md](ROLE_MODELS.md)，评测命令见
[benchmark README](../../teecheck-benchmark/README.md)。

## 扫描范围与索引

`teecheck run <input>` 获取源码后建立 `ScannedScope`，后续索引、Planner、源码复核和
引用校验使用同一源码目录。对于没有 Git 元数据的本地 fixture，可通过 `--repo-url`
与 `--commit`（或 `TEECHECK_REPO_URL` / `TEECHECK_COMMIT`）提供上游身份。身份可用时，
pipeline 尝试获取该版本的完整 checkout，成功后用它替代 fixture 作为统一源码根；获取
失败才回退本地目录并记录覆盖限制。元数据本身不会补齐裁剪文件，最终实际扫描的源码根和
范围以 `00_manifest.json` 为准。

CodeQL 生成 `RepoFacts` 和中性 `ProjectMapV0`：仓库、模块与函数卡片、调用关系以及
`EntrySurfaces`。入口特征包括外部链接函数、函数指针分发表目标、缓冲区/长度形参等。
这些是浏览优先级线索，不能直接视为外部可达或安全结论。索引不完整时记录 coverage gap。

`project_map` 后的 `taint_prescan` 阶段只在同一 CodeQL 数据库已就绪时运行一次静态
`codeql/trustir/cpp/flow/EntrySurfaceToSink.ql`，不按入口循环调用 `trace_taint`，也不建第二个库。
查询覆盖函数指针全局初始化、带指针及整型形参的外部接口，到内存操作、数组偏移和指针
算术解引用的可能数据流；这些结构信号不证明输入不可信或缺少语义守卫。

完整去重 witness 写为 `02_tool_facts/trustir/taint-prescan-<hash>.json`
（`cpp.taint.prescan`）。排序按源函数、汇点函数和位置合并线索，并让同一源函数、汇点文件
最多占两个摘要候选；跨函数/文件、分发表来源和内存操作优先，同文件底层密码库的数组
查表降权但不删除证据。Planner 收到最多 10 条、每条最多 10 跳、合计至多 12 KiB 的摘要。
这是已返回 witness 的排序，不是全程序最短路径或穷尽分析。

预扫默认独立超时 5m，沿用 `TEECHECK_CODEQL_ANALYZE_THREADS` 和 `TEECHECK_CODEQL_RAM`。
没有就绪数据库、查询失败或路径为空都保留覆盖说明，主流程继续。预扫不能直接生成
CasePack 或 Finding；模型仍须读入口及汇点源码，再开 Lead、挂载真实 fact_ref 并形式化契约。
摘要不获得源码阅读或广度侦察覆盖信用。多次采样和 Resume 复用同一份
`01_context/taint_prescan.json` 上下文，恢复时校验引用，不重复执行预扫。

已验证的预扫线索允许定向开 Lead：必须引用该事实，目标位于事实路径，且入口与汇点的
真实源码已经读过。此入口不算作广度侦察达标，也不放宽零 Lead `done` 的全仓覆盖门控。

## Planner 的两个 pass

Pass A 先理解项目，浏览入口和源码并打开 `AuditLead`；Pass B 注入紧凑 TWE 契约索引，
补充调查并输出 `CaseInvariantV2`。完整 TWE 细节通过 `twe_playbook_detail` 按需读取。
默认关闭的 legacy architecture/invariants 阶段不参与这条主线。

Planner 的主要循环是：

```text
PRE-SCANNED TAINT CANDIDATES / list_entry_surfaces / 函数卡片
  → read_file / 调用关系 / trace_taint
  → open_audit_lead
  → update_lead（源码、工具证据、下一步问题）
  → formalize_contract 或 close_lead
```

`trace_taint` 在 Pass A 就可调用，无需先打开 Lead；source 或 sink 必须已被当前 pass
观察到，避免盲扫。工具事实可以随后绑定到新 Lead。

零 Lead 的 `done` 需要满足基础侦察门控；有入口索引时还需实际阅读入口函数源码，
默认要求至少 3 个不同入口、分布于 2 个模块（按可用数量缩减）。只看函数卡片或重复
读取同一窗口不算新覆盖。预算耗尽仍可退出，但必须留下不完整覆盖状态。

`update_lead` 将短笔记和证据持久化；`formalize_contract` 即时校验 scope、真实源码锚点
与注册查询参数。校验失败反馈给 Planner 修正，不把失败的契约升级为已形式化。
收口时允许一次受预算限制的契约补全请求，仍需绑定真实 Lead 和已读源码。

## 污点查询与负面证据

`trace_taint` 由白名单参数填充固定的 `TaintTracking::Global<Config>` 模板。
源函数、形参、sink 和可选 barrier 受校验；不会执行模型提供的任意 QL。
查询与程序索引复用数据库。相同参数的运行内缓存命中不再消耗查询配额。

结果写入 `02_tool_facts/trustir/taint-<hash>.json`，操作名为 `cpp.taint.trace`。
Planner 只接收至多 32 KiB 的路径摘要；落盘保存 CodeQL 实际返回的 witness、参数、
scope、内容哈希和 coverage gaps。引擎每个 alert 的路径数有上限，因此不能宣称枚举了
全部可能路径或求得了全程序最短路径。

`0 paths` 只说明当前建库、模型和参数下未得到路径；宏、函数指针、汇编、头文件缺失
等因素都可能破坏分析。barrier 仅是语法过滤。两者都不能自动产生 `satisfied`，必须交由
独立源码复核。路径引用在 Lead、契约和 review 加载时校验来源及内容哈希。

## 默认预算与资源

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--planner-max-tokens` | 240,000 | 每次 Planner pass 输入和输出合计；0 关闭总上限 |
| `--planner-max-recon-tokens` | 100,000 | Pass A 输入和输出合计；0 关闭本阶段上限 |
| `--planner-max-investigation-tokens` | 140,000 | Pass B 输入和输出合计，内含 20,000 收口预留；0 关闭本阶段上限 |
| 侦察 / 调查轮数 | 10 / 8 | 侦察额度追加于调查额度 |
| `--planner-wall-clock` | 10m | 每个 pass 的上限；显式 0 关闭总墙钟限制 |
| 普通工具超时 | 30s | 不适用于独立污点查询 |
| `--taint-query-timeout` | 5m | 同时受剩余墙钟预算约束 |
| `--max-taint-queries` | 8 | 未缓存调用；0 表示无单独限次 |

三个 token 上限独立生效：只将总上限设为 0 不会关闭 Pass A / Pass B 上限。
需要禁用所有累计 token 限制时，必须同时传入三个 0，例如：

```sh
teecheck run <input> --llm-model glm-5.3 --llm-stream \
  --planner-max-tokens=0 \
  --planner-max-recon-tokens=0 \
  --planner-max-investigation-tokens=0 \
  --planner-wall-clock=40m
```

这不会关闭角色配置的单次 `max_output_tokens`（或 `--llm-max-tokens`）、轮数、墙钟和
工具配额。已用 token 仍照常统计；解析后的上限写入 manifest 并参与 resume 一致性校验。
需要关闭 Planner 总墙钟限制时可显式传 `--planner-wall-clock=0`；省略仍使用 10m。
轮数、各次 HTTP 请求超时及预扫的独立超时仍然生效。

开启累计上限时，输入采用近似估算：ASCII 约 3 字节/token，非 ASCII 按字符分别估算，
再加消息封装余量。它不是精确 tokenizer，也不保证严格上界；实际费用与超额消耗仍按
服务端 usage 记录。[常见英文估算](https://help.openai.com/en/articles/4936856-understanding-and-counting-tokens)
不能直接用于所有语言或模型。

已识别的推理模型（包括 GLM-5.x、GLM-4.7）通常至少保留 16,384 输出 token；若角色的
单次上限更小，则尊重该上限。剩余预算不足时先切换阶段、压缩收口输入，仍不足就记录
覆盖缺口并停止，不向模型发送过小的剩余额度。未知模型别名使用通用最低值。
契约补全使用同一输出规则，不再另设 8,192 上限或提前扣除 8,192。

全量 OP-TEE 等大库可显式使用 `--planner-wall-clock 40m`；这增加允许时间，不保证完成。
`TEECHECK_CODEQL_RAM` / `TEECHECK_CODEQL_THREADS` 控制 CodeQL 资源，
`TEECHECK_CODEQL_ANALYZE_THREADS` 可单独覆盖查询线程数。建库遇到已识别的瞬态 JVM/TRAP
错误会清理本次不完整数据库并以单线程重试一次；其他错误不盲目重试。

OpenAI 兼容 Chat Completions 可用 `--llm-stream`（或
`TEECHECK_LLM_STREAM=true`）启用 SSE；角色文件可单独设置 `"stream": true/false`。
默认关闭，`responses` 与 `glm` 预设的 Anthropic 通道不支持此选项。SSE 开始发送数据后
可以缓解网关空闲超时，但不能保证上游及时发送首个 chunk。最终内容仍完整交给 Agent，
同时保留流末尾的 token usage；流式配置会记录在 manifest，并参与 resume 一致性校验。
`--llm-timeout-seconds` 仍限制整次 HTTP 请求，收到 chunk 不会重置此上限。
瞬态错误默认最多尝试 5 次（含首次），使用带轻微抖动的退避；已返回的各次尝试 usage
会累计，未收到的 usage 不会被伪造为精确统计。策略拒绝与其他非瞬态错误立即停止。

网络策略拒绝停止当前调查并保留 Lead 与覆盖缺口，不对同一拒绝连续重试，也不会自动
改写提示或切换模型。角色路由在启动时通过配置明确指定。

## 跨运行缓存

可选 `--codeql-cache-dir <dir>`（或 `TEECHECK_CODEQL_CACHE_DIR`）保存固定源码和数据库
主副本；未配置时保持单次运行隔离。源码身份解析到完整 commit，数据库键还包含源码树
内容、CodeQL 版本、`cpp` / `build-mode=none`、平台和相关提取环境摘要。

并发构建由文件锁串行化，成功构建通过临时目录原子发布并写完成标记。共享源码和数据库
主副本设为只读并校验内容；每次运行得到独立数据库副本，CodeQL 查询不会直接写共享库。
因此仍有复制、内容校验和每个 run 的磁盘开销；实际收益需用相同样本测量。缓存损坏会
拒绝复用，不能仅因为目录存在就认为构建成功。

## 恢复中断的 Planner

本版运行在每轮边界原子写 `04_planner/state.json`，保存 Planner/Recon 状态、Lead、
已用预算、已观察文件哈希、完整源码树摘要和日志边界。恢复时重复原有扫描、模型、知识库、
缓存及预算设置，只增加 `--resume --run-dir <existing-run>`，例如：

```sh
teecheck run --resume --run-dir /tmp/scan-001 \
  --role-config /path/to/roles.json --knowledge-root knowledge \
  --codeql-cache-dir /tmp/teecheck-codeql-cache --planner-wall-clock 40m
```

上例中的配置必须与该 run 的首次调用相同。也可写 `teecheck run /tmp/scan-001 --resume`。
恢复要求同一 scanner 可执行文件、CodeQL 版本、解析后的角色配置、知识库内容和完整源码
内容；任何已观察文件或源码树变化都拒绝恢复，`scope_hash` 本身不足以通过校验。
凭证不写入 checkpoint。策略拒绝属于终止状态，不能用 resume 重放。

只支持已生成本版 checkpoint 的 Planner 阶段：复用已完成 pass，恢复当前 pass，再重跑
下游复核。若原 run 已完成，则复用完成的 Planner 结果重跑下游，不是重新采样的独立实验。
回退日志边界前将旧事件和下游结果归档至 `04_planner/resume-history/*.tar`；旧版本或
尚未进入 Planner 的运行不能靠此选项恢复。中断的远端请求可能已计费但未返回 usage，
恢复需保守保留该请求的预算预留。

## 产物与校验

典型 bundle 包含：

```text
00_manifest.json                 固定范围、模型元数据与预期阶段
01_context/                      scope、索引、项目地图和知识上下文
02_tool_facts/                   可追溯工具结果
04_planner/                      轮次、Lead 与 Planner 状态
03_cases/                        案例与绑定契约
06_verifier/                     当前版本的核查结论
07_arbiter/findings.json          机械裁决结果
events.jsonl / blobs/             事件和完整大结果
```

具体阶段可能有更多目录；不要按旧目标架构的目录编号解析 bundle。
`teecheck validate-run --run-dir <run-dir>` 离线校验文件、事件和契约/assessment 的关联。
`teecheck verify-contract` 用另一个源码版本重新绑定并核查契约，不复用旧源码坐标作为新证据。
扫描成功退出、完整覆盖和发现漏洞是三个不同指标。
