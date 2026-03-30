# rofl-appd Socket 风险说明

参考仓库：

- [oasisprotocol/oasis-sdk @ 8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76](https://github.com/oasisprotocol/oasis-sdk/tree/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76)

## 一句话结论

从当前代码看，`rofl-appd` **没有做接口级的二次鉴权**。

更准确地说：

- `rofl-appd` 把能力暴露在 UNIX socket `/run/rofl-appd.sock` 上
- 代码里没有看到针对“调用方是谁”的额外认证逻辑
- 没有 token、没有 session、没有 API key、没有每路由的 caller 校验
- 实际上是把“能连上这个 socket”本身当成了授权条件

这是一种典型的 **bearer socket / ambient authority** 设计：

谁拿到 socket，谁就拿到这组应用能力。

## 它到底有没有鉴权

### 代码层面的结论

`rofl-appd` 在启动时直接把这些路由挂出来：

- [`rofl-appd/src/lib.rs:38`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/lib.rs#L38)
- [`rofl-appd/src/lib.rs:41`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/lib.rs#L41)
- [`rofl-appd/src/lib.rs:44`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/lib.rs#L44)
- [`rofl-appd/src/lib.rs:49`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/lib.rs#L49)
- [`rofl-appd/src/lib.rs:51`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/lib.rs#L51)

对应接口有：

- `/rofl/v1/app/id`
- `/rofl/v1/keys/generate`
- `/rofl/v1/metadata`
- `/rofl/v1/query`
- `/rofl/v1/tx/sign-submit`

但这些 route handler 本身都没有看到“调用方认证”逻辑。

例如：

- `keys/generate` 直接调用 KMS：
  [`rofl-appd/src/routes/keys.rs:8`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/keys.rs#L8)
- `query` 直接转发 query：
  [`rofl-appd/src/routes/query.rs:29`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/query.rs#L29)
- `metadata` 直接读写：
  [`rofl-appd/src/routes/metadata.rs:8`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/metadata.rs#L8)
- `tx/sign-submit` 直接拿 signer 发交易：
  [`rofl-appd/src/routes/tx.rs:200`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/tx.rs#L200)

### 所以它依赖的“鉴权”是什么

它依赖的是 **操作系统层面的 socket 访问控制**，而不是应用层鉴权。

也就是说，它的安全假设更像是：

- 只有可信进程/可信容器能接触到 `/run/rofl-appd.sock`

而不是：

- 就算多个进程都能接触到 socket，`rofl-appd` 也能区分谁能调什么接口

## 文档也说明了 socket 会被挂进容器

文档明确把这个 socket 当成容器集成入口：

- [`docs/rofl/features/appd.md:3`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/docs/rofl/features/appd.md#L3)
  说明 `rofl-appd` 暴露在 `/run/rofl-appd.sock`
- [`docs/rofl/features/appd.md:14`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/docs/rofl/features/appd.md#L14)
  直接给出 volume 挂载示例
- [`docs/rofl/workflow/test.mdx:98`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/docs/rofl/workflow/test.mdx#L98)
  也给了把 socket 挂进服务的 compose 片段

所以这里不是“理论上可能拿到 socket”，而是设计上就允许把 socket 分发给容器。

## 如果 socket 暴露了，攻击者能做什么

## 1. 确认当前是哪个 ROFL app

接口：

- [`rofl-appd/src/routes/app.rs:7`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/app.rs#L7)

作用：

- 读取 app ID
- 确认自己当前控制的是哪个应用实例

这个接口本身危害不大，但能帮助后续利用。

## 2. 调用 KMS 派生应用密钥

接口：

- [`rofl-appd/src/routes/keys.rs:8`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/keys.rs#L8)
- [`rofl-appd/src/services/kms.rs:249`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/services/kms.rs#L249)

这里不是简单返回随机 key，而是按 `key_id` 和 `kind` 派生稳定密钥：

- [`rofl-appd/src/services/kms.rs:90`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/services/kms.rs#L90)

这意味着：

- 如果攻击者知道某个内部组件使用的 `key_id`
- 或者能从代码、日志、配置里猜出 `key_id`

那么他就能导出**和应用内部相同的那把 key**

仓库里就有固定 `key_id` 的例子：

- [`rofl-containers/src/storage/mod.rs:25`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-containers/src/storage/mod.rs#L25)
  这里定义了 storage encryption key 的固定标识

危害：

- 导出 app-scoped 私钥/原始熵
- 复现内部长期使用的稳定密钥
- 破坏“只有 enclave 内可信代码能拿到这把 key”的信任模型

## 3. 读取和篡改 app metadata

接口：

- [`rofl-appd/src/routes/metadata.rs:8`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/metadata.rs#L8)
- [`rofl-appd/src/routes/metadata.rs:20`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/metadata.rs#L20)

攻击者能：

- 读当前 metadata
- 改 metadata
- 触发 registration refresh

危害：

- 污染应用对外发布的信息
- 干扰依赖 metadata 的链上/链下逻辑
- 做状态投毒或服务发现混淆

## 4. 做任意 runtime query

接口：

- [`rofl-appd/src/routes/query.rs:29`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/query.rs#L29)

这里没有看到方法白名单。

攻击者可以：

- 枚举 query method
- 读取运行时公开的状态
- 读取应用配置、运行环境相关数据

危害：

- 为后续攻击收集情报
- 更准确地构造交易或业务层攻击

## 5. 以 app 身份发交易

这是最危险的一项。

文档明确写了，这类交易会被自动认证为“来自 app 自己”：

- [`docs/rofl/features/appd.md:105`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/docs/rofl/features/appd.md#L105)
- [`docs/rofl/features/appd.md:107`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/docs/rofl/features/appd.md#L107)

代码也明确说明 signer 代表 ROFL app instance：

- [`rofl-appd/src/routes/tx.rs:198`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/tx.rs#L198)
- [`rofl-appd/src/routes/tx.rs:206`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/tx.rs#L206)

默认允许的方法包括：

- `accounts.Transfer`
- `consensus.Deposit`
- `consensus.Withdraw`
- `consensus.Delegate`
- `consensus.Undelegate`
- `evm.Call`
- `evm.Create`
- `rofl.Create`
- `rofl.Update`
- `rofl.Remove`

位置：

- [`rofl-appd/src/routes/tx.rs:20`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/tx.rs#L20)

并且交易费用通过 app 上下文来处理：

- [`rofl-appd/src/routes/tx.rs:289`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-appd/src/routes/tx.rs#L289)

危害非常直接：

- 以 app 身份调用合约
- 以 app 身份部署合约
- 转账或消耗 app 侧资产
- 持续刷交易、烧 gas，形成经济型 DoS
- 命中那些信任 `roflEnsureAuthorizedOrigin(roflAppID)` 的业务逻辑

## 最容易理解的攻击场景

假设有这样一个部署：

- 主业务容器挂了 `rofl-appd.sock`
- 旁边还有一个 sidecar，或者一个处理外部请求的 Web 服务
- 这个 Web 服务被 SSRF / RCE / 命令执行打穿

那攻击者一旦能访问这个 socket，就相当于拿到了：

- 应用级 KMS 使用权
- 应用级 query 能力
- 应用级 metadata 改写能力
- 应用级签名发交易能力

这在实际效果上，已经非常接近：

**“应用身份被接管”**

## 这个问题不是什么

为了表述准确，也要说明它不是什么：

- 不是“默认远程任意人都能直接打”
- 不是“所有容器天然都能访问”
- 不是“只要有这个接口就必然是漏洞”

真正的问题在于：

- 一旦 socket 被挂给了不够可信的进程
- 或者挂给了会处理攻击者输入的组件
- `rofl-appd` 自己没有第二道权限边界

所以“暴露 socket”这件事的后果会非常重。

## 严重性怎么判断

如果部署里：

- 只有一个极小、完全可信的进程持有 socket
- 没有 sidecar
- 没有 Web 层暴露点
- app 也没有高价值链上权限

那这个更像“强能力接口 + 强信任假设”。

但如果部署里存在以下任一情况，风险就明显上升：

- 多容器共享 socket
- sidecar/代理容器能碰 socket
- 业务容器会处理外部输入
- 存在 SSRF/RCE 面
- app 持有资金或特权合约权限
- app 是 oracle / bot / privileged caller

那这个点就很容易演变成高危后果。

## 最后一句

所以你的问题“这个接口没有做鉴权吗”，我的回答是：

**对，当前看到的代码里，没有做接口级、调用方级的二次鉴权。**

它采用的是：

**“谁拿到 socket，谁就被视为已授权”**

这不是传统意义上的“漏了 `if auth == false`”，而是一个明显的能力边界设计风险。
