# RustBox 当前实现

> 最后更新：2026-07-10

## 调用关系

```text
apps/rustbox (clap CLI) ─┐
                         ├─> rustbox::RustBox
rustbox-ffi (C ABI) ─────┘       |
                                 ├─ config compiler
                                 ├─ inbound / outbound modules
                                 ├─ kernel + route table
                                 ├─ optional control gRPC service
                                 └─ rustbox_host_api::TokioHost
```

CLI 与 FFI 使用相同的 `new/start/stop/reload/snapshot` 生命周期。可选共享服务通过
`RustBoxOptions` 配置；控制 gRPC 的状态同步、命令通道、任务和 shutdown 均属于
`RustBox` 生命周期。内部的组合器和运行图类型不再是公共 API。

CLI 的子命令直接承载自己的参数：

```text
run --config <FILE>
check-config --config <FILE>
platform-capabilities
```

Clap derive 负责子命令和必填参数校验。代码直接对 `CliCommand` 做行为路由，
不再有第二个 `RuntimeMode`、全局 `--config` 或手写参数冲突检查。无子命令时
Clap 显示帮助。CLI 不再提供内置的 `http-proxy` / `socks5-proxy` 启动路径；
HTTP、SOCKS5 和 mixed inbound 都必须写入 TOML，并通过 `run --config` 启动。

## 主要 crate

| 位置 | 职责 |
|---|---|
| `apps/rustbox` | CLI 参数、输出、Ctrl-C、option 翻译 |
| `crates/rustbox` | 公共 `RustBox` API、内部装配和可选进程服务生命周期 |
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
HTTP / SOCKS5 / mixed / TUN / transparent inbound
  -> Flow + FlowMeta
  -> metadata-only enrichment pipeline
  -> ordered route table
  -> direct / HTTP / SOCKS5 / Shadowsocks / AnyTLS outbound
  -> TCP/UDP relay（由 submit future 等待至结束）
```

`Engine::submit` 当前包含从 enrichment、route、outbound open 到 relay 结束的完整
生命周期。HTTP、SOCKS5 和 mixed listener 会为连接创建任务；TUN stack 和
transparent accept loop 当前直接等待 `submit`，因此一个长 flow 可能阻塞后续
接纳。这是待修复的并发边界，不是目标行为。

当前 UDP payload 使用可携带每包目标的 `DatagramSocket`，但 engine 在读取首个
数据报之前只根据一次 `FlowMeta.destination` 路由。SOCKS5 `UDP ASSOCIATE` 可以承载
多个目标，所以当前结构还不具备按真实目标建立、路由和淘汰 UDP session 的能力。

当前 `MetadataEnricher` 只能读取和返回 `FlowMeta`。`rustbox-inspect` 只有静态域名和
协议提示 enricher，没有读取 payload 的 TLS SNI、HTTP Host 或其他真实协议嗅探。

DNS crate 已有 resolver、规则、cache、FakeIP 和 FakeIP 反查模型，但 composition
尚未创建真实 DNS transport/runtime，也未把 DNS/FakeIP 反查接入 enrichment。

Selector 和 URLTest 当前在配置编译时解析为固定 child route decision；它们不是可
动态切换、探测或故障转移的运行时 outbound group。

观测层会在 flow 开始和结束时维护连接状态，但 relay bytes 在 relay 完成后一次性
发布。因此活跃长连接没有持续更新的实时 byte counter，也没有统一的连接取消句柄。

目标数据面、约束和分阶段升级顺序见
[`docs/architecture.md`](architecture.md#目标数据面)。

VMess、VLESS 和 Trojan 目前只有配置模型，组合时会明确报未实现。

AnyTLS 数据面使用精确锁定的 `anytls 0.2.3` crate。该版本保留标准的
`cmdSYN`、Session 内递增 stream ID、连接池与 `cmdSYNACK` 处理，同时允许
RustBox 注入 `NetworkProvider` 拨号。TCP 出站通过 sing-box 1.13.14 真实 E2E；
UDP-over-TCP 由模块回环测试覆盖。支持范围和升级门槛见
[`docs/anytls-support.md`](anytls-support.md)。

## 仍保留的抽象

- 字节流直接使用 Tokio `AsyncRead + AsyncWrite`；`ByteStream` 只提供可装箱的
  `Send + Unpin` trait-object 组合，不再定义另一套 poll 方法或错误类型。
- 网络 provider：测试 host 需要在不打开真实 socket 的情况下运行。
- packet device / network control：Linux、Windows 和移动平台实现不同。
- observability sink：console、file、内存查询和未来平台日志确实是多个输出。

这些边界有当前调用方或测试价值。新增抽象前应先给出第二个真实实现。

## 下一步可继续简化

1. 评估 `reload`、`plugin`、`registry` 等只有模型而没有运行时用途的 crate；
   没有近期调用方就移除。

简化工作不得先于数据面并发、UDP session 语义和关闭生命周期的正确性修复；也不应
把目标架构中的新职责拆成只有单一调用方的 pass-through crate。
