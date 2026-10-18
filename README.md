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

## FFI Event Consumption

The host must continuously drain `wl_session_poll_event` or `wl_session_poll_event_v2` while a session runs. This poll queue is the primary event-consumption path. Registering `wl_session_set_event_callback` does not switch the session to callback-only delivery: callbacks are best-effort auxiliary notifications and may be dropped when their queue is full. A callback-only host will eventually fill the poll queue and stall message delivery.

## Toolchain

- Repository-pinned Rust toolchain (`rust-toolchain.toml`)
- `rustfmt`, `clippy` components enabled

## Transport Features

- `quic`
- `tcp`
- `wss`

Default enables all features.

## Private Frame Contract

`warp_link_core::MAX_FRAME_BYTES` is 131,072 bytes (128 KiB), including the
type/flags header and encoded content. TCP/QUIC's four-byte length prefix and
WebSocket envelope bytes are excluded. WSS also bounds individual frames and
reassembled messages. WELCOME advertises the same application-frame limit.
Old Private clients may reject this WELCOME and must be upgraded; WSS is not
a compatibility fallback. The Gateway's 48 KiB whole-HTTP-request limit is a
separate application-layer contract, not a Warp payload allowance.

See [the integration record](./PRIVATE128_INTEGRATION.md) for tested scope,
source identity, and downstream adoption limits.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo check --locked -p warp-link --no-default-features
cargo check --locked -p warp-link --no-default-features --features quic
cargo check --locked -p warp-link --no-default-features --features tcp
cargo check --locked -p warp-link --no-default-features --features wss
cargo check --locked -p warp-link-ffi --no-default-features
cargo check --locked -p warp-link-ffi --all-features
cargo audit --deny warnings # install first: cargo install --locked cargo-audit
cargo deny check -D warnings advisories bans licenses sources # cargo-deny 0.20.2
```

## Docs

- `docs/client-state-machine.md`
- `docs/error-model.md`
- `docs/auth-and-tls-deployment.md`
- `docs/auth-lifecycle.md`

## License

[MIT License](./LICENSE)
