# Gramine

## 扫描元信息

- 仓库：`https://github.com/gramineproject/gramine`
- Commit：`ff71d7afea730dffd56a97af39bb6a73ee6c7662`
- 本地克隆：`/tmp/teecheck-clone-1941020125`
- Run：`runs/scan-20260520-gramine`

## 结论

本轮只命中 `CI-Examples/rust/src/main.rs` 的 hello-world HTTP 示例。它没有应用层授权、远程证明或 caller binding，但它绑定在 `127.0.0.1:3000`，并且明显是 CI 示例，不是生产安全边界。

建议不作为漏洞上报。最多作为文档建议：示例如果被复制到生产服务，应补充 attestation-aware authentication 或明确声明仅用于演示。

## 发现：CI 示例服务缺少应用层安全校验

TEECheck 状态：`needs_review`，严重性 `medium`，置信度 `high`。

源码位置：`CI-Examples/rust/src/main.rs`

关键代码片段：

```rust
async fn hello_world(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new("Hello, World".into()))
}

#[tokio::main(worker_threads = 4)]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let make_service = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(hello_world))
    });

    let server = Server::bind(&addr).serve(make_service);
}
```

## 人工判断

严格从 TEE 安全模型看，服务端没有检查请求来源、没有绑定 caller identity、没有把请求和 attestation session 绑定。但这里有三个降低风险的上下文：

- 文件位于 `CI-Examples`。
- handler 是固定 hello-world。
- server 绑定 `127.0.0.1`，不是公网接口。

所以这不是可报告漏洞，而是“示例代码不可直接当生产模板”的提醒。

## 建议状态

- 不发 CVE。
- 不发安全 issue。
- 若要发普通 issue，标题应偏文档硬化。英文标题可写：`Document that CI Rust HTTP example does not implement application-layer attestation or authorization`。
