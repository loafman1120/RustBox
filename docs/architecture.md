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
│   └── rustbox-cli/                 # CLI 二进制（crate 名 rustbox-app）
├── crates/
│   ├── foundation/                  # 稳定类型与共享 Tokio I/O 契约
│   ├── kernel/                      # 数据面、路由与平台能力端口
│   ├── control/                     # 配置模型、控制面与 gRPC API
│   ├── modules/                     # DNS、inspection、inbound/outbound、协议与栈
│   ├── platform/                    # 操作系统能力实现
│   ├── rustbox/                     # 组合根与公共异步生命周期
│   ├── rustbox-config-file/         # TOML/文件配置入口
│   └── rustbox-observability/       # 观测存储与 sink
├── packages/
│   └── rustbox_flutter/             # Dart API、Native Assets hook、Rust bridge、示例
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
   `packages/rustbox_flutter` 的异步 Future API 取代；其 Rust bridge
   `packages/rustbox_flutter/rust` 是 Cargo workspace 成员。
4. PowerShell 脚本收拢到 `scripts/build/` 与 `scripts/test/`；Flutter 的跨平台
   构建则由 package 内的 Native Assets hook 负责，不再使用 mobile/FFI 构建脚本。

## 代码边界

| 层 | 位置 | 职责 |
|---|---|---|
| 基础 | `crates/foundation/*` | `rustbox-types` 保存无依赖公共类型（`Endpoint`/`FlowMeta`/`RouteDecision`/`Host`/…）；`rustbox-io` 保存共享 I/O trait，其中 `ByteStream` 直接采用 Tokio `AsyncRead + AsyncWrite`，但不包含具体 socket、OS handle 或配置逻辑 |
| 外部入口 | `apps/rustbox-cli`、`packages/rustbox_flutter` | CLI 参数/信号以及基于 Native Assets 的 Dart/Flutter Future API；Flutter 的 Rust workspace 成员位于 `packages/rustbox_flutter/rust`，两者复用异步 `RustBox` 生命周期 |
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

UDP 路径目前**没有独立会话表**：`Engine` 收到 `FlowPayload::Datagram` 后直接调用 `outbound.open_datagram(ctx, target)`，再交给 `relay_datagram(inbound, outbound)` 双向转发。中心化的 session registry、容量上限、空闲超时与淘汰策略属于未来工作（见下文 TODO #1、#5）。

`rustbox-inspect` 当前只提供两个静态 enricher：`StaticDomainEnricher`、`StaticProtocolHintEnricher`，用于固定策略与测试。bounded prefix 重放、TLS SNI / HTTP Host 嗅探、process / DNS enricher 同样落在 TODO #3。

`router` 返回逻辑 outbound ID；编译层把 `selector` / `urltest` 折叠为 `default`（或首个 child）的静态 `RouteDecision`，**不在运行时切换**。循环检测、URLTest 健康检查、child 选择记录属于 TODO #4。

## 平台边界

TUN 路径为 `PacketDevice → packet-to-flow stack → dispatcher`；透明代理路径为 `OS redirect → original-dst lookup → dispatcher`。两者共享后半段数据面，但 TUN 额外需要 packet device 和网络栈。

`PacketDeviceProvider` 提供设备 I/O，`NetworkControl` 以 lease 表示可回滚的路由、DNS、防泄漏变更。`TransparentProxyProvider` 仅在 Linux 上实现，承载 transparent inbound 的 original-dst 查找；macOS / Windows 上的 transparent redirect 仍在规划中。TUN 设备在 Linux（`/dev/net/tun`，tun-rs）、Windows（wintun）与 macOS（utun，`Layer::L3`）三平台都已落地，路由控制通过 `net-route` 做事务式 lease。出站必须支持绕过自身捕获。不支持的能力在 composition 阶段返回结构化诊断，不静默降级。

## 观测与控制

kernel / modules 产生结构化事件，协议与应用诊断统一使用 `tracing`；应用入口安装 `tracing-subscriber`，并通过 `RUSTBOX_LOG` 配置过滤。sink 继续负责业务事件的 console、file、recording、平台日志或远程导出。慢 sink 在自身内部缓冲，不能向 relay 施加背压。

`ObservabilityStore` 提供有界事件、指标和连接快照；`rustbox-control-api` 暴露基于 tonic 的 gRPC，命令集包括 `Reload` / `Stop` / `ReplaceRouteTable` / `EnableOutbound` / `DisableOutbound`，并支持 `Snapshot` / `QueryEvents` / `QueryMetrics` / `QueryConnections` 等只读接口。非 loopback 控制端点必须启用 token，凭证不得进入事件。

控制平面目前**不持久化每条活跃连接的句柄**：会话元数据通过事件流与可查询快照暴露，原子 byte / packet / drop 计数由 `Engine` 在 `TrafficRecorded` 事件中发出，主动取消一条具体 session 的能力属于 TODO #5。

## 当前能力

inbound：`http-connect` / `socks5` / `mixed` / `tun` / `transparent` / `anytls`。

outbound：`direct` / `block`（编译为 `Reject` 决策）/ `socks5` / `http` / `shadowsocks` / `vmess`（AEAD only，`alter_id` 必须为 0，仅 `tcp` transport） / `vless`（plain，禁用 Vision `flow`） / `trojan`（必须 TLS） / `anytls` ；`selector` / `urltest` 解析并编译，运行时按 `default`（或首个 child）静态选择。

横切：SourceConfig 四步 pipeline、CLI / Flutter 共享 `RustBox` 生命周期、gRPC
控制 API、结构化观测、Linux / Windows / macOS TUN、Linux transparent redirect。
配置型 `block` 决策也在 runtime graph 中生效。

## 近期工作

1. session limits：为 TCP/UDP flow 增加统一并发容量、空闲超时与淘汰策略。
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
4. 平台能力只通过 `rustbox-kernel::host` 中的接口与 `platform/*` 实现之间流动。
5. 新增 trait 前必须存在第二个真实实现。
