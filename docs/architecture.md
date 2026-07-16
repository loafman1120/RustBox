# RustBox 架构

代码组织、依赖方向和巨石模块的拆分准则见
[`code-structure.md`](code-structure.md)。

本文只记录稳定边界、关键数据流和近期演进方向；命令与配置示例见根目录 `README.md` 和 `examples/`。

## 设计目标

RustBox 是基于 Tokio 的模块化代理引擎。CLI 与 Flutter 插件共用同一个
`RustBox` 生命周期，不各自维护引擎或配置编译逻辑。

```text
CLI / async embedding       Flutter / Future API
        │
        ├──────────► RustBox ◄──── Flutter async bridge
        │              │          (uses the host Tokio executor)
        ▼              ▼
 async lifecycle    create / start / reload / snapshot / stop / close
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

Flutter bridge 直接暴露异步方法，并通过 Tokio `Mutex` 串行访问同一个 `RustBox`；
`flutter_rust_bridge` 将调用映射成 Dart `Future`。桥接层不创建线程、不持有第二套
runtime，也不使用 `block_on`。CLI 与 Flutter 都直接执行同一组异步生命周期方法。

## 仓库组织

当前 workspace 按“产品入口、可复用核心、语言包”分层：

```text
RustBox/
├── apps/
│   ├── rustbox-cli/                 # CLI 二进制（crate 名 rustbox-app）
│   └── rustbox-flutter/             # Flutter app、Native Assets hook、Rust bridge、示例
├── crates/
│   ├── foundation/                  # 稳定类型与共享 Tokio I/O 契约
│   ├── kernel/                      # 数据面、路由与平台能力端口
│   ├── control/                     # 配置模型、控制面与 gRPC API
│   ├── modules/                     # DNS、inspection、inbound/outbound、协议与栈
│   ├── platform/                    # 操作系统能力实现
│   ├── rustbox/                     # 组合根与公共异步生命周期
│   ├── rustbox-config-file/         # TOML/文件配置入口
│   └── rustbox-observability/       # 观测存储与 sink
├── examples/                        # 示例配置
├── scripts/
│   ├── build/                       # 构建脚本
│   └── test/                        # gRPC、代理、TUN、协议 smoke/E2E
├── docs/                            # 架构与代码边界
└── website/                         # 无依赖静态项目站点
```

相对早期布局，近期有四项较大的组织调整：

1. CLI 从 `apps/rustbox` 更名为 `apps/rustbox-cli`，应用入口统一放在 `apps/`。
2. 独立 `rustbox-host-api` 被移除；host trait、网络转换与 `TokioNetworkProvider` 归入
   `crates/kernel/rustbox-kernel/src/host/`，测试实现归入 `kernel/rustbox-test-host`。
3. `apps/rustbox-ffi` C ABI 与 `HostedRustBox` actor 已移除，由
   `apps/rustbox-flutter` 的异步 Future API 取代；其 Rust bridge
   `apps/rustbox-flutter/rust` 是 Cargo workspace 成员。
4. PowerShell 脚本收拢到 `scripts/build/` 与 `scripts/test/`；Flutter 的跨平台
   构建则由 package 内的 Native Assets hook 负责，不再使用 mobile/FFI 构建脚本。

## 代码边界

| 层 | 位置 | 职责 |
|---|---|---|
| 基础 | `crates/foundation/*` | `rustbox-types` 保存无依赖公共类型（`Endpoint`/`FlowMeta`/`RouteDecision`/`Host`/…）；`rustbox-io` 保存共享 I/O trait，其中 `ByteStream` 直接采用 Tokio `AsyncRead + AsyncWrite`，但不包含具体 socket、OS handle 或配置逻辑 |
| 外部入口 | `apps/rustbox-cli`、`apps/rustbox-flutter` | CLI 参数/信号以及基于 Native Assets 的 Dart/Flutter Future API；Flutter 的 Rust workspace 成员位于 `apps/rustbox-flutter/rust`，两者复用异步 `RustBox` 生命周期 |
| 公共入口 | `crates/rustbox` | 引擎装配与统一异步生命周期 |
| 控制与配置 | `crates/control/*`、`crates/rustbox-config-file` | 解析、校验、编译、控制 API |
| 内核 | `crates/kernel/*` | flow、路由、relay、host 能力接口与 Tokio 默认实现 |
| 模块：协议 | `crates/modules/protocol/*` | vendored 协议引擎（`rustbox-anytls`） |
| 模块：连接面 | `crates/modules/inbound/*`、`crates/modules/outbound/*` | inbound / outbound 适配层；DNS、inspection、TUN 用户态栈、transport 辅助分别落在 `crates/modules/dns/`、`inspect/`、`stack/`、`transport/` |
| 测试宿主 | `crates/kernel/rustbox-test-host` | kernel host 能力的内存测试实现 |
| 平台 | `crates/platform/*` | Linux / Windows / macOS 平台适配；TUN、路由、transparent redirect |
| 观测 | `crates/rustbox-observability` | 事件、指标、连接快照及 sink |

允许的依赖方向是从上层装配到下层能力。协议模块不解析 CLI，Flutter bridge
不复制运行图或生命周期逻辑，平台操作不进入 kernel/route。

## 配置与生命周期

```text
TOML → SourceConfig → normalize → validate → compile → RustBox
```

文件解析与运行模型分离。库调用者和测试可直接提交 `SourceConfig`；Flutter bridge
接收 TOML 字符串，经 `rustbox-config-file` 解析后再进入相同的 `SourceConfig` 生命周期。

- `new`：校验配置并准备运行图。
- `start`：启动 inbound、后台任务和可选控制服务。
- `reload`：构建新图；新 flow 使用新图，存量 flow 继续持有旧资源。
- `snapshot`：向 CLI、Flutter 和控制 API 提供统一只读状态。
- `stop`：停接纳，停后台任务，排空或取消会话，最后回滚平台配置；操作必须有界且幂等。

`RuntimeSupervisor` 持有当前 generation，并让旧 generation 在后台排空。
每一代有独立的 Tokio `TaskScope`：accept scope 在 reload/stop 时立即取消，session
scope 最多排空 30 秒后取消。`TaskScope` 直接由 `CancellationToken + TaskTracker`
组成；模块不创建 runtime，也不通过全局 spawner 隐藏任务所有权。

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

UDP 路径目前**没有独立会话表**：`Engine` 收到 `FlowPayload::Datagram` 后直接调用 `outbound.open_datagram(ctx, target)`，再交给 `relay_datagram(inbound, outbound)` 双向转发。SOCKS5 UDP ASSOCIATE 的初始目标为 unspecified，内核会先读取并重放首包，以真实包目标更新 `FlowMeta.destination` 后再执行 inspection、路由和 outbound 握手。中心化的 session registry、容量上限、空闲超时与淘汰策略属于未来工作（见下文 TODO #1、#5）。

`rustbox-inspect` 在每个 flow 路由前执行有界嗅探：TCP 最多读取 16 KiB，UDP 最多读取 4 个、合计 16 KiB 的数据报，统一受 300 ms deadline 约束；已读数据通过 `ReplayStream` / 数据报队列原样重放。TLS ClientHello SNI 由 `rustls::server::Acceptor` 解析，HTTP/1 Host 由 `httparse` 解析，DNS wire message 由 `hickory-proto` 解析，QUIC v1 Initial 的解密、CRYPTO 重组与 SNI 提取由 `clienthello` 负责。静态 enricher 仅保留给固定策略与测试。

DNS 查询被识别后，反向 relay 会观察同一 transaction ID 的 A / AAAA 响应，并把 `IP → 查询域名` 按 DNS TTL 写入每代运行图内的 4096 项有界表；主动 resolver 的回答也写入同一张表。后续以该 IP 为目标的 flow 在路由前恢复 `FlowMeta.domain`，但不改写原始目标 IP。反向表下沉在 `rustbox-dns-core`，由 DNS subsystem 与 inspection 共享。Engine 通过 `Engine<ProtocolSniffer>` 持有单个具体异步 stage，enrichment 不再使用 `BoxFuture`、trait object 或动态列表。当前 QUIC 解析仅覆盖 v1，不覆盖 QUIC v2；ECH、系统 DNS 缓存或绕过 RustBox 的 DNS 请求也无法提供可恢复域名。

`rustbox-dns-core` 已拆分为 `model / transport / resolver / cache / fake_ip / reverse / subsystem`。`HickoryTransport` 使用 Tokio connection provider，把 UDP、TCP、DoT、DoH、DoQ 映射到 Hickory 的 `Udp / Tcp / Tls / Https / Quic`，不在项目内手写五套 wire、TLS、HTTP/2 或 QUIC 实现。运行时构图会从编译配置实例化 rules → transport、FakeIP、cache 和 reverse recording 链，嵌入方可通过 `RustBox::resolve_dns` 使用。Hickory 自带缓存被关闭，由 RustBox cache 统一 TTL 策略。

加密 DNS 当前要求 endpoint 使用域名，以便同时提供 TLS server name；上游 endpoint 的 bootstrap 使用系统解析。outbound 的 `dial.domain_resolver` 可复用指定 Hickory transport 做 A/AAAA 解析。DNS transport 自身目前仍只允许 direct（显式指定 direct 可用），非 direct outbound 在 composition 阶段报错，不能静默绕过代理。`hijack-dns` 路由动作会把捕获到的 TCP/UDP DNS flow 终结到进程内 responder，并复用同一个规则、缓存、FakeIP 与反向映射链。

每个 concrete outbound 都编译出独立的 dial policy。无 `detour` 时由 `TokioNetworkProvider` 使用 Tokio readiness/timeout 与 `socket2` 应用源地址、接口、Linux/Android routing mark 和 TCP keepalive；有 `detour` 时构图器按依赖拓扑把协议服务器连接交给上游 outbound。配置阶段拒绝未知 detour、组/block detour 和环。共享所有权只保留在运行图节点边界，Engine 直接保存 `Arc<dyn Outbound>`，协议内部不再复制 dial fields。当前 detour 已覆盖 TCP 及基于 TCP 承载的 UDP；需要裸 UDP socket 的代理协议仍需 destination-aware datagram dial，不能回退为系统直连。

路由条件可通过 `protocol = ["http", "tls", "quic", "dns", "socks5"]` 消费 `FlowMeta.protocol_hint`；它与 inbound、network、domain、port 等其它字段保持 AND 语义。域名条件优先读取嗅探或 DNS 恢复出的 `FlowMeta.domain`，同时保留原始目标 IP 供 CIDR 条件匹配。

`router` 返回逻辑 outbound ID；普通 outbound 直接进入数据面，组 ID 则由 `OutboundGroupRegistry` 在每个新 flow 路由时解析成当前 child。`selector` 可通过控制 gRPC 查询和切换，切换后新连接立即生效，既有连接保持原 outbound；`urltest` 当前只暴露只读组状态并使用首个 child。组引用组在配置校验阶段被拒绝，因此运行时不存在递归选择环。URLTest 健康检查与选择持久化仍属于 TODO #4。

## 平台边界

TUN 路径为 `PacketDevice → packet-to-flow stack → dispatcher`；透明代理路径为 `OS redirect → original-dst lookup → dispatcher`。两者共享后半段数据面，但 TUN 额外需要 packet device 和网络栈。

`PacketDeviceProvider` 提供设备 I/O，`NetworkControl` 以 lease 表示可回滚的路由、DNS、防泄漏变更。`TransparentProxyProvider` 仅在 Linux 上实现，承载 transparent inbound 的 original-dst 查找；macOS / Windows 上的 transparent redirect 仍在规划中。TUN 设备在 Linux（`/dev/net/tun`，tun-rs）、Windows（wintun）与 macOS（utun，`Layer::L3`）三平台都已落地，路由控制通过 `net-route` 做事务式 lease。出站必须支持绕过自身捕获。不支持的能力在 composition 阶段返回结构化诊断，不静默降级。

## 观测与控制

kernel / modules 产生结构化事件，协议与应用诊断统一使用 `tracing`；应用入口安装 `tracing-subscriber`，并通过 `RUSTBOX_LOG` 配置过滤。sink 继续负责业务事件的 console、file、recording、平台日志或远程导出。慢 sink 在自身内部缓冲，不能向 relay 施加背压。

`ObservabilityStore` 提供有界事件、指标和连接快照；`rustbox-control-api` 暴露基于 tonic 的 gRPC。RustBox 自有服务提供 `Stop` 以及引擎、事件、指标和连接快照查询；出站组控制直接采用 sing-box 的 `daemon.StartedService/SubscribeGroups` 与 `SelectOutbound` wire contract。内部控制模型还保留 reload/route/outbound 命令类型供组合层演进。非 loopback 控制端点必须启用 token，凭证不得进入事件。

控制平面目前**不持久化每条活跃连接的句柄**：会话元数据通过事件流与可查询快照暴露，原子 byte / packet / drop 计数由 `Engine` 在 `TrafficRecorded` 事件中发出，主动取消一条具体 session 的能力属于 TODO #5。

## 当前能力

inbound：`http-connect` / `socks5` / `mixed` / `tun` / `transparent` / `anytls`。

outbound：`direct` / `block` / `socks5` / `http` / `shadowsocks` / `vmess` / `vless`（含 Vision） / `trojan` / `anytls` / `hysteria2` / `tuic` / `naive` / `shadow-tls` / `wireguard`；WireGuard 也可用顶层 `endpoint` 语义声明。VMess/VLESS/Trojan 共享 TCP、WebSocket、HTTP/2、gRPC、HTTPUpgrade transport 以及 Reality/ECH/mTLS/SPKI pinning TLS 配置。Mux.Cool 是支持 TCP 与 XUDP 的多载波有界 actor 池；UDP New frame 带稳定 Global ID，Keep frame 保留逐包目标/来源地址。`selector` 支持运行时查询与切换，`urltest` 当前按首个 child 静态选择并以只读组暴露。

横切：SourceConfig 四步 pipeline、CLI / Flutter 共享 `RustBox` 生命周期、gRPC
控制 API、结构化观测、TLS SNI / HTTP Host / QUIC v1 / DNS 嗅探与 TTL 域名恢复、Linux / Windows / macOS TUN、Linux transparent redirect。
配置型 `block` 决策也在 runtime graph 中生效。

## 近期工作

1. session limits：为 TCP/UDP flow 增加统一并发容量、空闲超时与淘汰策略。
2. UDP：限制并发、增加空闲超时并记录更完整的会话元数据。
3. inspection + DNS：增加 QUIC v2 与 ECH 可观测诊断；扩展非 direct DNS socket injection。
4. runtime outbound graph：URLTest 健康检查、选择持久化、切换事件与可选的既有连接中断。
5. session control：活跃连接句柄、取消命令、UDP 指标。
6. 性能基线：测量吞吐、延迟、RSS 与分配后再优化。

## AnyTLS

AnyTLS 客户端固定使用协议兼容的 `anytls 0.2.3`（MIT），保留可注入 `NetworkProvider` 的拨号边界，并以 sing-box 1.13.14 做真实端到端验证。当前覆盖 TLS / 密码认证、标准帧、递增 stream ID、session 池、TCP 代理及 UDP-over-TCP v2。CI 中 AnyTLS 走连续三次 TCP 请求；SOCKS5、Shadowsocks、AnyTLS、VMess、VLESS 与 Trojan 同时验证 TCP 和经 SOCKS5 UDP ASSOCIATE 发起的真实 UDP echo 往返，只有 stream-only HTTP 明确跳过 UDP；任何升级都必须继续通过模块测试、E2E 与资源泄漏检查。

## 不变量

1. accept loop 不等待 relay 生命周期。
2. router 保持 `FlowMeta → RouteDecision` 纯函数。
3. 路由决策不发起 I/O，不查询 DNS / 进程。
4. 平台能力只通过 `rustbox-kernel::host` 中的接口与 `platform/*` 实现之间流动。
5. 新增 trait 前必须存在第二个真实实现。
