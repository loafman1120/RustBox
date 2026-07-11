# RustBox 架构

本文只记录稳定边界、关键数据流和近期演进方向；命令与配置示例见根目录 `README.md` 和 `examples/`。

## 设计目标

RustBox 是基于 Tokio 的模块化代理引擎。CLI、FFI 和未来 GUI 共用同一个 `RustBox` 生命周期，不各自维护引擎或配置编译逻辑。

```text
CLI / FFI / embedding
        │
        ▼
     RustBox ─── new / start / reload / snapshot / stop
        │
        ├── config + control + observability
        └── kernel + modules + platform
                         │
                         ▼
                       Tokio
```

架构遵循四条规则：

1. Tokio 是唯一运行时。
2. 路由是纯计算，不执行 DNS、进程查询或网络 I/O。
3. 平台能力留在 platform/host 边界，不能渗入可移植核心。
4. trait 只用于确有多个实现的边界；无独立职责的 pass-through crate 应合并。

## 代码边界

| 层 | 位置 | 职责 |
|---|---|---|
| 基础 | `crates/foundation/*` | 公共类型（`Endpoint`/`FlowMeta`/`RouteDecision`/`Host`/…）与 I/O trait（`ByteStream`/`DatagramSocket`/`PacketDevice`），零依赖、零运行时 |
| 应用 | `apps/rustbox` | CLI 参数、信号和输出 |
| 公共入口 | `crates/rustbox`、`rustbox-ffi` | 引擎装配、生命周期、C ABI |
| 控制与配置 | `crates/control/*`、`rustbox-config-file` | 解析、校验、编译、控制 API |
| 内核 | `crates/kernel/*` | flow、路由、relay |
| 模块：协议 | `crates/modules/protocol/*` | vendored 协议引擎（`rustbox-anytls`） |
| 模块：连接面 | `crates/modules/inbound/*`、`outbound/*` | inbound / outbound 适配层；DNS、inspection、TUN 用户态栈、transport 辅助分别落在 `dns/`、`inspect/`、`stack/`、`transport/` |
| 主机抽象 | `crates/host/*` | `rustbox-host-api` 定义 trait（`NetworkProvider` / `PacketDeviceProvider` / `NetworkControl` / `TransparentProxyProvider` / `ProcessLookup` / `Event` / `ObservabilitySink`），`rustbox-test-host` 提供测试实现 |
| 平台 | `crates/platform/*` | Linux / Windows / macOS 平台适配；TUN、路由、transparent redirect |
| 观测 | `rustbox-observability` | 事件、指标、连接快照及 sink |

允许的依赖方向是从上层装配到下层能力。协议模块不解析 CLI，FFI 不暴露 Rust 引用或 trait object，平台操作不进入 kernel/route。

## 配置与生命周期

```text
TOML → SourceConfig → normalize → validate → compile → RustBox
```

文件解析与运行模型分离，因此 FFI、GUI 和测试可直接提交 `SourceConfig`。

- `new`：校验配置并准备运行图。
- `start`：启动 inbound、后台任务和可选控制服务。
- `reload`：构建新图；新 flow 使用新图，存量 flow 继续持有旧资源。
- `snapshot`：向 CLI、FFI 和控制 API 提供统一只读状态。
- `stop`：停接纳，停后台任务，排空或取消会话，最后回滚平台配置；操作必须有界且幂等。

## 数据面

```text
inbound  ─►  Flow { meta, payload }  ─►  Engine.submit
                                       │
                                       ├─ enrich()          (EnrichmentPipeline)
                                       ├─ router.route()    (RouteTable)
                                       └─ outbound.open_stream / open_datagram
                                                  │
                                                  └─ relay_stream / relay_datagram
```

`Flow` 的载荷形态只分两种：`Stream`（TCP）与 `Datagram`（UDP），由 `FlowPayload` 显式二分以避免把 UDP 伪装成 TCP。`Engine` 既是 `FlowSink` 又持有 `outbounds: HashMap<OutboundId, Box<dyn Outbound>>`；路由返回 `Forward(id) | Reject(reason) | Hijack(service)` 三种决策。

UDP 路径目前**没有独立会话表**：`Engine` 收到 `FlowPayload::Datagram` 后直接调用 `outbound.open_datagram(ctx, target)`，再交给 `relay_datagram(inbound, outbound)` 双向转发。中心化的 session registry、容量上限、空闲超时与淘汰策略属于未来工作（见下文 TODO #1、#5）。

`rustbox-inspect` 当前只提供两个静态 enricher：`StaticDomainEnricher`、`StaticProtocolHintEnricher`，用于固定策略与测试。bounded prefix 重放、TLS SNI / HTTP Host 嗅探、process / DNS enricher 同样落在 TODO #3。

`router` 返回逻辑 outbound ID；编译层把 `selector` / `urltest` 折叠为 `default`（或首个 child）的静态 `RouteDecision`，**不在运行时切换**。循环检测、URLTest 健康检查、child 选择记录属于 TODO #4。

## 平台边界

TUN 路径为 `PacketDevice → packet-to-flow stack → dispatcher`；透明代理路径为 `OS redirect → original-dst lookup → dispatcher`。两者共享后半段数据面，但 TUN 额外需要 packet device 和网络栈。

`PacketDeviceProvider` 提供设备 I/O，`NetworkControl` 以 lease 表示可回滚的路由、DNS、防泄漏变更。`TransparentProxyProvider` 仅在 Linux 上实现，承载 transparent inbound 的 original-dst 查找；macOS / Windows 上的 transparent redirect 仍在规划中。TUN 设备在 Linux（`/dev/net/tun`，tun-rs）、Windows（wintun）与 macOS（utun，`Layer::L3`）三平台都已落地，路由控制通过 `net-route` 做事务式 lease。出站必须支持绕过自身捕获。不支持的能力在 composition 阶段返回结构化诊断，不静默降级。

## 观测与控制

kernel / modules 只产生结构化事件；sink 负责 console、file、recording、平台日志或远程导出。慢 sink 在自身内部缓冲，不能向 relay 施加背压。

`ObservabilityStore` 提供有界事件、指标和连接快照；`rustbox-control-api` 暴露基于 tonic 的 gRPC，命令集包括 `Reload` / `Stop` / `ReplaceRouteTable` / `EnableOutbound` / `DisableOutbound`，并支持 `Snapshot` / `QueryEvents` / `QueryMetrics` / `QueryConnections` 等只读接口。非 loopback 控制端点必须启用 token，凭证不得进入事件。

控制平面目前**不持久化每条活跃连接的句柄**：会话元数据通过事件流与可查询快照暴露，原子 byte / packet / drop 计数由 `Engine` 在 `TrafficRecorded` 事件中发出，主动取消一条具体 session 的能力属于 TODO #5。

## 当前能力

inbound：`http-connect` / `socks5` / `mixed` / `tun` / `transparent` / `anytls`。

outbound：`direct` / `block`（编译为 `Reject` 决策）/ `socks5` / `http` / `shadowsocks` / `vmess`（AEAD only，`alter_id` 必须为 0，仅 `tcp` transport） / `vless`（plain，禁用 Vision `flow`） / `trojan`（必须 TLS） / `anytls` ；`selector` / `urltest` 解析并编译，运行时按 `default`（或首个 child）静态选择。

横切：SourceConfig 四步 pipeline、CLI / FFI 共享 `RustBox` 生命周期、gRPC 控制 API、结构化观测、Linux / Windows / macOS TUN、Linux transparent redirect。配置型 `block` 决策也在 runtime graph 中生效。

## 近期工作

1. dispatcher / supervisor：把 TUN 和 transparent 的 accept loop 与长 flow 解耦，并补充 UDP / per-flow session 容量与超时淘汰。
2. UDP：按真实目标路由、限制并发、记录元数据。
3. inspection + DNS：bounded payload 重放、SNI / Host 提取、独立 resolver；接入 `ProcessLookup`。
4. runtime outbound graph：selector 切换、URLTest 健康检查、child 选择记录、循环检测。
5. session control：活跃连接句柄、取消命令、UDP 指标。
6. 性能基线：测量吞吐、延迟、RSS 与分配后再优化。

## AnyTLS

AnyTLS 客户端固定使用协议兼容的 `anytls 0.2.3`（MIT），保留可注入 `NetworkProvider` 的拨号边界，并以 sing-box 1.13.14 做真实端到端验证。当前覆盖 TLS / 密码认证、标准帧、递增 stream ID、session 池、TCP 代理及 UDP-over-TCP v2。CI 中 AnyTLS 走连续三次请求的 E2E，其它协议（vmess / vless / trojan / shadowsocks / http / socks5）各跑一次；任何升级都必须继续通过模块测试、E2E 与资源泄漏检查。

## 不变量

1. accept loop 不等待 relay 生命周期。
2. router 保持 `FlowMeta → RouteDecision` 纯函数。
3. 路由决策不发起 I/O，不查询 DNS / 进程。
4. 平台能力只在 `host-api` trait 与 `platform/*` 实现之间流动，不渗入可移植核心。
5. 新增 trait 前必须存在第二个真实实现。
