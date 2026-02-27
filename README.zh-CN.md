# warp-link

[English](./README.md) | 简体中文

`warp-link` 是面向 PushGo 私有通道消息场景的 Rust 传输 SDK。

## 当前状态

`warp-link` 当前仅面向 PushGo 生态使用：

- 适用范围：主要用于 [pushgo](https://github.com/topics/pushgo) 下的仓库/项目
- 稳定性：尚未在 PushGo 生态外进行大规模、广泛场景验证

如果你计划在非 PushGo 的生产环境中使用，请按“早期阶段软件”评估风险。

## 工作区 Crates

- `warp-link-core`：核心模型、错误类型、抽象 trait、线协议抽象
- `warp-link-coordination`：租约/栅栏协调器
- `warp-link-transport`：QUIC / TLS-TCP / WSS 传输层
- `warp-link`：对外主入口 API（`client_run*`、`serve_*`）
- `warp-link-ffi`：给非 Rust 运行时使用的 C ABI
- `pushgo-warp-profile`：PushGo 线协议 profile 插件

## 工具链

- Rust `stable`
- 启用 `rustfmt`、`clippy`

## 传输特性

- `quic`
- `tcp`
- `wss`

默认启用全部传输特性。

## 验证命令

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo check -p warp-link --no-default-features
cargo check -p warp-link --no-default-features --features quic
cargo check -p warp-link --no-default-features --features tcp
cargo check -p warp-link --no-default-features --features wss
cargo check -p warp-link-ffi --no-default-features
cargo check -p warp-link-ffi --all-features
cargo audit # 需先安装：cargo install cargo-audit
```

## 文档

- `docs/client-state-machine.md`
- `docs/error-model.md`
- `docs/auth-and-tls-deployment.md`
- `docs/auth-lifecycle.md`

## 许可证

[MIT License](./LICENSE)
