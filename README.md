# warp-link

English | [简体中文](./README.zh-CN.md)

`warp-link` is a Rust transport SDK for PushGo private-channel messaging.

## Status

`warp-link` is currently intended for PushGo ecosystem usage only:

- Scope: repositories/projects under [pushgo](https://github.com/topics/pushgo)
- Maturity: not yet broadly validated at large scale outside PushGo

If you are evaluating this for non-PushGo production workloads, treat it as early-stage software.

## Workspace Crates

- `warp-link-core`: core models, errors, traits, wire abstractions
- `warp-link-coordination`: lease/fencing coordinator
- `warp-link-transport`: QUIC / TLS-TCP / WSS transports
- `warp-link`: public facade APIs (`client_run*`, `serve_*`)
- `warp-link-ffi`: C ABI for non-Rust runtimes
- `pushgo-warp-profile`: PushGo wire profile plugin

## Toolchain

- `stable` Rust toolchain
- `rustfmt`, `clippy` components enabled

## Transport Features

- `quic`
- `tcp`
- `wss`

Default enables all features.

## Verification

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
cargo audit # install first: cargo install cargo-audit
```

## Docs

- `docs/client-state-machine.md`
- `docs/error-model.md`
- `docs/auth-and-tls-deployment.md`
- `docs/auth-lifecycle.md`

## License

[MIT License](./LICENSE)
