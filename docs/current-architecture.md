# RustBox 当前实现

> 最后更新：2026-07-09

## 调用关系

```text
apps/rustbox (clap CLI) ─┐
                         ├─> rustbox::RustBox
rustbox-ffi (C ABI) ─────┘       |
                                 ├─ config compiler
                                 ├─ inbound / outbound modules
                                 ├─ kernel + route table
                                 └─ rustbox_host_api::TokioHost
```

CLI 与 FFI 使用相同的 `new/start/stop/reload/snapshot` 生命周期。内部的组合器和
运行图类型不再是公共 API。

## 主要 crate

| 位置 | 职责 |
|---|---|
| `apps/rustbox` | CLI 参数、输出、Ctrl-C |
| `crates/rustbox` | 公共 `RustBox` API 和内部装配 |
| `crates/ffi/rustbox-ffi` | C ABI、句柄表、同步 Tokio 桥接 |
| `crates/config/rustbox-config-file` | TOML 到 `SourceConfig` |
| `crates/control/rustbox-config` | 配置校验与编译 |
| `crates/kernel/*` | flow、路由、relay 和内部 engine |
| `crates/modules/*` | inbound、outbound、DNS、TUN、transport |
| `crates/host/rustbox-host-api` | Tokio host 及真实需要替换的测试/平台契约 |
| `crates/platform/*` | Linux/Windows TUN、路由、透明代理能力 |
| `crates/observability/*` | 结构化事件及输出 |

已删除独立的 `crates/runtime/rustbox-runtime-tokio`。Tokio 是普通依赖，不再
包装成一层可替换 runtime 架构。

## 当前数据路径

```text
HTTP / SOCKS5 / mixed / TUN inbound
  -> flow metadata
  -> ordered route table
  -> direct / HTTP / SOCKS5 / Shadowsocks / AnyTLS outbound
  -> Tokio TCP/UDP
```

VMess、VLESS 和 Trojan 目前只有配置模型，组合时会明确报未实现。

## 仍保留的抽象

- 字节流：同一 relay 需要处理 TCP、TLS、HTTP tunnel、SOCKS tunnel 和测试流。
- 网络 provider：测试 host 需要在不打开真实 socket 的情况下运行。
- packet device / network control：Linux、Windows 和移动平台实现不同。
- observability sink：console、file、内存查询和未来平台日志确实是多个输出。

这些边界有当前调用方或测试价值。新增抽象前应先给出第二个真实实现。

## 下一步可继续简化

1. 将 `rustbox-io` 的字节流接口改为直接基于 Tokio
   `AsyncRead + AsyncWrite`，减少手写 poll 转发。
2. 评估 `reload`、`plugin`、`registry` 等只有模型而没有运行时用途的 crate；
   没有近期调用方就移除。
3. 把 CLI 中控制 gRPC 的进程编排移入共享 `RustBox` option/service，进一步
   缩小 `main.rs`。
