# ROFL Scheduler `std` 登录消息可重放问题分析

参考仓库：

- [oasisprotocol/oasis-sdk @ 8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76](https://github.com/oasisprotocol/oasis-sdk/tree/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76)

## 一句话结论

这个问题是一个**真实存在的认证重放缺陷**，不是误报。

但它不是“无前提的远程高危漏洞”。更准确地说：

- 服务端在 `std` 登录流程里定义了 `nonce` 字段
- 但服务端并没有消费、记录或校验这个 `nonce` 是否被重复使用
- 因此，只要攻击者拿到一份仍在有效期内的合法 `body + signature`，就可以反复调用 `/auth/login` 换取新的 JWT

当前代码里，这个 JWT 主要用于访问 scheduler 的日志接口，所以**当前影响面主要是日志读取能力被重放获取**，而不是完整控制面接管。

## 漏洞位置

核心代码位于：

- [`rofl-scheduler/src/serverd/auth.rs`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/serverd/auth.rs)
- [`rofl-scheduler/src/serverd/mod.rs`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/serverd/mod.rs)
- [`rofl-scheduler/src/serverd/routes.rs`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/serverd/routes.rs)

## 代码证据

### 1. 登录消息结构里包含 `nonce`

`StdAuthBody` 定义如下：

```rust
pub struct StdAuthBody {
    pub v: u16,
    pub domain: String,
    pub provider: Address,
    pub signer: PublicKey,
    pub nonce: String,
    pub not_before: u64,
    pub not_after: u64,
}
```

位置：

- [`rofl-scheduler/src/serverd/auth.rs:161`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/serverd/auth.rs#L161)

这说明设计者本来是想让这份登录断言具备“唯一性”或“防重放”能力的。

### 2. `validate()` 完全没有使用 `nonce`

服务端校验逻辑是：

```rust
pub fn validate(&self, domain: &str, provider: Address) -> Result<(), anyhow::Error> {
    if self.v != 1 {
        return Err(anyhow!("unsupported version"));
    }
    if self.domain != domain {
        return Err(anyhow!(
            "mismatched domain (expected: {} got: {})",
            domain,
            self.domain
        ));
    }
    if self.provider != provider {
        return Err(anyhow!(
            "mismatched provider (expected: {} got: {})",
            provider,
            self.provider
        ));
    }
    let now = Utc::now().timestamp() as u64;
    if now < self.not_before {
        return Err(anyhow!("statement not yet valid"));
    }
    if now > self.not_after {
        return Err(anyhow!("statement has expired"));
    }
    Ok(())
}
```

位置：

- [`rofl-scheduler/src/serverd/auth.rs:173`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/serverd/auth.rs#L173)

可以看到，这里只校验了：

- 版本号
- 域名
- provider
- 生效时间
- 过期时间

但**没有任何一行代码处理 `nonce`**。

### 3. 登录成功后，每次都会重新签发 JWT

登录处理函数如下：

```rust
pub async fn login(
    extract::State(state): extract::State<Arc<State>>,
    extract::Json(request): extract::Json<AuthLoginRequest>,
) -> Result<response::Json<AuthLoginResponse>, Error> {
    let mut claims = request
        .verify(&state.domain, state.provider)
        .await
        .map_err(|_| Error::Forbidden)?;

    let expiry = Utc::now() + Duration::seconds(state.token_lifetime as i64);
    claims.exp = expiry.timestamp() as u64;

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let token = jsonwebtoken::encode(&header, &claims, &JWT_KEYS.encoding)?;

    Ok(response::Json(AuthLoginResponse {
        token,
        expiry: claims.exp,
    }))
}
```

位置：

- [`rofl-scheduler/src/serverd/auth.rs:212`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/serverd/auth.rs#L212)

这意味着：

- 只要 `verify()` 通过
- 服务端就会立刻签发一个新的 JWT
- 不会检查“这份登录材料是不是之前已经用过”

### 4. 仓库里没有看到任何 nonce 去重或 challenge 状态

在当前 `rofl-scheduler/src` 代码里，没有看到：

- 已使用 nonce 表
- challenge 缓存
- 一次性票据记录
- replay cache

`nonce` 只出现在 `StdAuthBody` 的字段里，没有后续消费逻辑。

因此，“可重放”不是猜测，而是这段代码的直接行为结果。

## 利用方式

### 攻击者需要什么

攻击者需要拿到一份合法的：

- `body`
- `signature`

也就是一次成功登录所使用的签名断言材料。

这通常意味着以下前提之一：

- 客户端日志记录了请求体
- 调试输出泄露了签名材料
- 某个前端/代理把登录请求落盘了
- 用户端被恶意脚本、扩展、XSS 窃取了登录数据
- 攻击者通过钓鱼拿到了一次合法签名

### 攻击者能怎么做

只要该 `StdAuthBody` 满足：

- 当前时间已经超过 `not_before`
- 当前时间还没有超过 `not_after`

攻击者就可以把同一份 `body + signature` 多次提交到：

- `/rofl-scheduler/v1/auth/login`

每次都能拿到一个新 JWT。

换句话说，这里被重放的不是旧 JWT，而是**旧的登录断言本身**。

## 当前实际影响

### 当前暴露的受保护接口很少

从路由注册代码看，当前 `serverd` 只挂了两个接口：

```rust
let app = Router::new()
    .route("/rofl-scheduler/v1/auth/login", post(auth::login))
    .route("/rofl-scheduler/v1/logs/get", post(routes::logs_get))
```

位置：

- [`rofl-scheduler/src/serverd/mod.rs:62`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/serverd/mod.rs#L62)

也就是说，当前 JWT 保护的业务接口主要就是：

- `/rofl-scheduler/v1/logs/get`

### JWT 当前主要用于读日志

`logs_get` 会从 JWT 里提取地址，然后检查该地址是否有 `log.view` 权限：

```rust
let address = Address::from_bech32(&claims.address)?;
if !instance.has_permission(ACTION_LOG_VIEW, address) {
    return Err(Error::Forbidden);
}
```

位置：

- [`rofl-scheduler/src/serverd/routes.rs:44`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/serverd/routes.rs#L44)

权限常量定义为：

- [`rofl-scheduler/src/types.rs:53`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/types.rs#L53)

并且实例管理员默认拥有全部权限：

```rust
if self.admin == address {
    return true;
}
```

位置：

- [`rofl-scheduler/src/state.rs:53`](https://github.com/oasisprotocol/oasis-sdk/blob/8a7f4414d4dd5fdc0ec24aef1db44cf7118dfb76/rofl-scheduler/src/state.rs#L53)

因此，这个重放缺陷当前最现实的危害是：

- 冒充某个合法地址获取 JWT
- 读取其有权限访问的实例日志

## 这个问题为什么值得记一条

虽然它当前不像“远程直接接管机器”那么重，但它依然值得作为安全问题记录，原因有三点：

### 1. 这是认证逻辑本身的缺陷

`nonce` 被定义出来，却没有参与一次性校验，这说明认证协议实现是不完整的。

### 2. 影响会随着接口扩展而放大

现在 JWT 只保护日志接口，所以影响相对有限。  
但如果以后在同一个认证体系下新增：

- 管理实例
- 重启实例
- 更新配置
- 读取更多敏感状态

那这个 replay bug 的价值会立刻上升。

### 3. 日志本身就可能很敏感

很多系统的日志里常常会出现：

- API token
- 调试信息
- 内网地址
- 服务依赖信息
- 部署细节
- 错误堆栈

所以即使当前“只是读日志”，也不一定是低风险。

## 这个问题不该怎么写

不建议把它写成：

- 任意未认证远程攻击者可直接接管 scheduler
- 无前提拿下全部 provider 控制权
- 高危 RCE

这些表述都过头了。

## 更准确的定性

我建议这样描述：

- `rofl-scheduler` 的 `std` 登录断言可被重放
- 根因是 `nonce` 未被服务端消费或记录
- 攻击者一旦获得一份有效期内的合法签名登录材料，即可重复换取新的 JWT
- 当前主要影响是未授权访问具备 `log.view` 权限的实例日志

如果按严重性分级，我会倾向于：

- **中低危到中危之间**

具体取决于你对“日志内容敏感性”和“签名材料泄露难度”的判断。

## 修复建议

### 方案 1：服务端发 challenge，并保存使用状态

这是最标准的修复方法：

- 服务端先下发一次性 challenge / nonce
- 客户端签名 challenge
- 服务端验证后把该 nonce 标记为已使用
- 同一 nonce 再出现就拒绝

### 方案 2：继续允许客户端自带 `nonce`，但服务端要做去重

如果不想引入 challenge 接口，至少也应当：

- 记录 `(signer, nonce)` 或 `(provider, signer, nonce)`
- 在 `not_after` 有效时间窗内拒绝重复值

### 方案 3：缩短断言有效窗口

这不是根治，但可以降低重放价值：

- 减小 `not_after - not_before`
- 缩短 token lifetime

不过这只能降低风险，不能消除 replay。

## 最终结论

这条问题可以成立，但要写得克制：

- 它是**真实存在的认证重放缺陷**
- 它的利用前提是攻击者先拿到一次合法签名登录材料
- 它当前的主要后果是**重复获取 JWT 并读取日志**
- 按当前代码现状，更像“中危以下但值得记录的 auth weakness”，而不是夸张的高危接管漏洞
