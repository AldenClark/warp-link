# Warp main / C18 Private 128 KiB 整合（2026-10-18）

本轮仅在隔离候选整合 Warp，未改 Gateway、Android、Windows、Apple 的产品
源码或依赖 pin，未合并 main、推送、发布、操作数据库或修改系统信任。

## 来源与整合边界

| 对象 | 完整提交 |
|---|---|
| main 基底 | `2d901be4ff596e84d4a96efda327ef0441b0f640` |
| C18 来源 | `eeef2b4ded2773259dff26e4a588fcad421c110e` |
| 共同祖先 | `dbae3a80c8b796969cadc9045ee982a0a60c4d27` |
| 本轮运行/测试源码提交 | `396e4111e129001eb16041c3599b64987b81285c` |

隔离分支为 `codex/warp-main-private128-20261018`。上述运行提交是双亲 merge，
第一亲为当前 main，第二亲为 C18。其后的说明提交不改变运行源码、manifest
或 lock；对外采用时应记录交付的最终完整 HEAD，不能只依赖版本号 `0.1.0`。
主工作区 main 的未跟踪 `build/` 保持原状。未发现适用的 AGENTS.md。

整合前两边各有三个独有提交，共同修改 facade 的 `src/lib.rs`，但行为接缝不同：

- main 提取 `SessionMaintenance`、probe collector，保留候选连接所有权、取消、
  首次成功选择、失败回滚、成功切换后的 HELLO/游标/探测维护；本轮保留其实现。
- C18 增加共享完整帧常量、profile 编码/解码上限、WSS 配置复用和官方
  tungstenite 0.30.0。facade 的生产差异只有上限及默认 WSS 上限。
- Git 自动合并成功只是起点；另行核查了 WELCOME 校验先于 IO 交接、维护只在
  成功切换后刷新、失败/取消时旧连接与候选连接的责任，以及两组主线回归的保留。

## 合同与资源

完整 Private 帧上限为 **131,072 字节**，包含 type/flags 两字节及编码内容。
TCP/QUIC 外层 u32 长度前缀不计入，所以最大流记录为 131,076 字节；WebSocket
自身封装不计入，单帧/分片重组消息均有独立的 131,072 字节限制。
WELCOME 宣告该同一上限。QUIC 流控窗口不代表消息上限。

48 KiB（49,152 字节）是 Gateway 整个 `/message` JSON 请求的上层限制；本库
不创建 HTTP 入口，也不把它解释为正文容量。未增加分片、协商、旧版回退或运输实现。
旧 Private 客户端可能在 WELCOME 校验时拒绝，旧 WSS 也不是兼容旁路。

流读取器先验证声明长度再分配，初始只有四字节前缀状态；部分前缀/正文跨取消
保留，完整读取后释放正文缓冲并恢复前缀状态。WSS 读写缓冲保持 16 KiB，
最大写缓冲 256 KiB，未按最大帧给每条空闲连接预分配 128 KiB。
没有新增长期任务、缓存所有者、调度器或协调机制。

## 依赖及生产/测试改动

- `tokio-tungstenite` / `tungstenite`：官方 crates.io **0.30.0**，无 vendor 补丁。
- 保留 main 的 `quinn-proto` **0.11.19**，没有照搬 C18 的 0.11.16。
- lock 新增版本只有上述两个 0.30.0 和所需 `sha1 0.11.0`；删除不再被引用的
  旧 rand/digest 等依赖链。没有运行广泛依赖更新。
- 正常 manifest 无 patch、replace、临时绝对路径或 QA feature。构建未使用
  source replacement；`--offline` 仅复用 Cargo 自身 registry 缓存。
  检查的祖先/用户 Cargo 配置文件和 source 覆盖环境均为空。
- 生产 Rust 改动来自 C18：core 常量、profile 编解码边界、transport 的 WSS
  配置提取、facade 两个上限引用。main 的生命周期实现未被替换。
- 保留 C18 边界测试、固定旧 WELCOME 函数负例和 main 的 probe/cutover 回归。
  本轮新增 exact-128KiB cutover guard 交付/ACK/游标测试，以及取消大帧读取后
  续读和下一帧边界测试；原小消息切换测试继续运行。
- 相对 main，按根 cfg(test) 分区、包含空行注释的行差异：生产 Rust +38/-18，
  测试 Rust +459/-1。manifest/lock、说明文档另计；这不是性能或复杂度收益测量。

## 本轮实际执行

环境：macOS / `aarch64-apple-darwin`；仓库固定 Rust/Cargo 1.97.1。
所有测试和正常构建都使用相同环境：

```sh
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_BUILD_JOBS=2
cargo fmt --all -- --check
cargo test --offline --locked -p warp-link-transport --lib
cargo test --offline --locked -p pushgo-warp-profile --lib
cargo test --offline --locked -p warp-link --lib --all-features tests::welcome_must_select_offered_versions_and_a_bounded_frame_size -- --exact
cargo test --offline --locked -p warp-link --lib --all-features cutover_simplification_tests::
cargo test --offline --locked -p warp-link --lib --all-features probe_simplification_tests::
cargo build --offline --locked --workspace
cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings
cargo check --offline --locked -p warp-link --no-default-features
cargo check --offline --locked -p warp-link --no-default-features --features quic
cargo check --offline --locked -p warp-link --no-default-features --features tcp
cargo check --offline --locked -p warp-link --no-default-features --features wss
cargo check --offline --locked -p warp-link --all-features
cargo check --offline --locked -p warp-link-ffi --no-default-features
cargo check --offline --locked -p warp-link-ffi --all-features
```

| 检查 | 实际结果 |
|---|---|
| transport | 18/18，包括精确上限、超限、u64异常长度、WSS分片重组、截断、连续帧、取消续读、既有Pong路径 |
| profile | 9/9，精确131,072编码信封与131,073拒绝；opaque payload是codec证据，不冒充业务JSON |
| WELCOME | 1/1，新上限接受、固定旧函数拒绝；不是旧客户端二进制运行 |
| main cutover | 8/8，原7项保留，加1项精确上限交叉测试 |
| main probe | 12/12，全部保留 |
| 正常默认workspace构建 | exit 0；默认启用quic/tcp/wss；构建正常库及FFI产物 |
| fmt / 严格Clippy | exit 0 |
| facade五种 / FFI两种feature检查 | 7项均exit 0 |

共 **48项测试通过，0失败、0忽略**；上述15条验证命令全部exit 0。
没有重试挑选结果。运行前后所有相关源码/manifest/lock哈希一致。
构建期间持续监测可用空间，最低11,990,364,160字节（约11.17GiB），
未触及4GiB加512MiB保护线，未删除缓存或历史证据。

原始证据在此隔离工作树的忽略目录 `target/integration-evidence/`：

- `attempt01/results.json`：精确命令、退出码、耗时、最低磁盘和逐项日志路径；
  `01.log`–`15.log` 保存原输出。
- `attempt01/environment.json`、`source-before.json`、`source-after.json`：
  工具链、构建环境及源码绑定。
- `runtime-binding.json`：运行提交、三个测试二进制和五个正常库产物的SHA-256。
- `dependency-diff.json`、`cargo-metadata.json`、`change-classification.json`：
  依赖、feature和改动口径。证据和本地runner不属于正式依赖或发行配置。

最初辅助CLI预检使用系统Python时缺少tomllib，改用已安装Python3.13；未安装工具。
这不是产品构建/测试失败。实际验证未使用QA CA、故障relay或信任覆盖。

## 尚未验证及后续采用

本轮只验证macOS组件、局部loopback及编译组合，未执行Android/Windows产品
网络闭环、真实TLS/QUIC/WSS全路径、32位parser、真实Provider、数据库或性能。
cutover测试的raw WebSocket未走生产WSS配置，该配置由transport专项独立验证。
现有C18/C19客户端收据不自动覆盖此新revision，也不证明跨机器bit-identical构建。

未新增wire格式变化；相对C18接回main的probe/cutover实现，须在消费者随后更新pin时
重验实际TCP/TLS接收/持久化/ACK，以及ACK丢失后重投、重连/进程重启去重。
若实际启用主动切换，补取消/切换时连接关闭、ACK/游标交接场景；其他运输按目标部署
单列，不能从feature编译推导其产品通过。不需要因此重跑数据库或性能矩阵。

Android/Windows后续应把其正常Cargo manifest的全部Warp直接依赖统一固定为该
隔离分支最终完整提交，并有限更新/核对各自Cargo.lock，不能只改QA manifest。
现有消费者的quinn-proto 0.11.19需继续保留。本轮未执行这些改动。
本地提交不代表远端可解析；审查后须另行授权提供正式Git来源，才能以原Git URL
跨机器取得该revision。不得把临时绝对路径或QA overlay作为正式依赖方案。

本轮到此停止：不合并主线、不推送、不发布，也不自动启动消费者更新。
