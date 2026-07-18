# RustBox 架构

本文描述当前代码的稳定边界与运行数据流。命令、能力清单和配置入口见根目录
[`README.md`](../README.md)。

## 总览

```text
apps/rustbox-cli          apps/rustbox-flutter
          \                 /
           rustbox（组合根与异步生命周期）
              ├─ control / config / observability
              ├─ modules（inbound / outbound / DNS / inspect / transport）
              └─ platform（操作系统能力实现）
                         ↓
              kernel（flow / route / relay / host ports）
                         ↓
              foundation（types / Tokio I/O）
```

架构不变量：

1. Tokio 是唯一的生产运行时；CLI、Flutter 和模块不另建 runtime。
2. `rustbox` 是组合根；协议 crate 不反向依赖应用或配置文件格式。
3. 路由保持纯计算；DNS、进程和网络元数据在路由前完成补充。
4. 平台操作通过 kernel host ports 注入，不进入可移植的路由和协议核心。
5. 动态分派只保留在 service、outbound、I/O、观测 sink 和平台能力等异构边界。

## Workspace 边界

| 层 | 位置 | 所有权 |
| --- | --- | --- |
| 产品入口 | `apps/rustbox-cli`、`apps/rustbox-flutter` | 参数、信号、Dart API、应用打包 |
| 组合根 | `crates/rustbox` | 运行图装配和公共异步生命周期 |
| 文件配置 | `crates/rustbox-config-file` | TOML 文档、迁移、字段校验、诊断 |
| 控制面 | `crates/control` | 语义模型、编译、出站组和 gRPC API |
| 数据面 | `crates/kernel` | flow、route、relay、dial 和 host capability ports |
| 功能模块 | `crates/modules` | DNS、嗅探、协议、transport、inbound/outbound、用户态栈 |
| 平台 | `crates/platform` | Linux、macOS、Windows、Android 能力实现 |
| 基础 | `crates/foundation` | 公共类型和 Tokio I/O 契约；不持有 socket 或 OS handle |
| 观测 | `crates/rustbox-observability` | 事件、指标、连接快照和 sink |

`apps/rustbox-flutter/rust` 同时是 Flutter package 的桥接层和 Cargo
workspace 成员。生成代码留在 package 内，不上移为公共引擎接口。

## 配置与生命周期

```text
TOML → document → normalize → validate → compile → runtime graph
```

文件语法与运行模型分离：文件入口产生 `SourceConfig`，CLI、Flutter 和库调用者再走
同一个编译与装配流程。

- `new`：校验配置并准备运行图。
- `start`：启动 inbound、后台任务和可选控制服务。
- `reload`：发布新 generation；新 flow 使用新图，旧 flow 有界排空。
- `snapshot`：提供统一只读状态。
- `stop`：停止接纳、结束任务并回滚平台配置；操作有界且幂等。

每个 generation 持有独立 `TaskScope`。reload/stop 会先取消 accept scope，session
scope 最多排空 30 秒后取消。任务所有权由 `CancellationToken + TaskTracker` 明确
表达，模块不通过全局 spawner 隐藏长期任务。

## 数据面

```text
inbound
  → Flow { meta, Stream | Datagram }
  → metadata enrichment / protocol inspection
  → route table
  → selector or concrete outbound
  → open_stream | open_datagram
  → relay
```

TCP 与 UDP 通过 `FlowPayload` 显式区分。inspection 可从 HTTP Host、TLS/QUIC SNI
和 DNS 中补充元数据；DNS reverse mapping 可为后续 flow 恢复域名。路由结果只描述
outbound、reject 或 DNS hijack 等动作，具体网络 I/O 由 outbound 和 host capability
完成。

路由支持非终结的 `resolve`、`route-options`，以及终结的 outbound、reject、
`hijack-dns`。规则集加载和远程刷新由组合层管理，路由表只消费已发布快照。

## 控制面与平台

gRPC 控制面分为兼容层和原生层。兼容层复用 sing-box `daemon.StartedService` 的出站组
wire contract；原生 `rustbox.control.v1.RustBoxControl` 提供连接查询/单连接取消、实时日志、
连接变更和流量 server stream、按入站/出站聚合的流量、进程内存与引擎状态、rule-set
状态/手动刷新、URLTest 手动触发，以及 reload/stop。流式接口由 Tokio
`broadcast + mpsc + tonic server-streaming` 组合：数据面只发布结构化事件，不持有 gRPC
对象；慢订阅者只丢弃超出有界广播环的旧事件，不阻塞 relay。

`selector` 可切换且只影响新 flow。`urltest` 通过每个 child 的真实 outbound 周期执行
HTTP/HTTPS 探测，按延迟和 `tolerance_ms` 自动选择，并在连续失败达到阈值后摘除候选。
探测状态（延迟、错误、连续失败和最后成功时间）由 outbound group registry 持有，
控制 API 会发布最近测试时间和延迟。selector 和 URLTest 都可配置 `cache_path` 恢复选择。
`interrupt_exist_connections=true` 暂不支持且会在配置校验阶段明确拒绝；选择变化只影响新 flow。

平台层实现网络配置、TUN/packet device、transparent redirect、进程查询和网络元数据。
平台修改必须通过事务式 handle 回滚。普通代理 socket 不伪装成拥有原始 IP packet，
因此 ICMP 注入等能力只在确实持有原始 packet path 时成立。

## 模块维护准则

优先在现有 crate 内拆私有模块；只有需要独立依赖约束或被多个 crate 复用时才新增
crate。出现以下情况时应重新审视边界：

- 一个模块同时拥有多个生命周期；
- 解析、校验、编译和运行构造混在同一函数；
- 新增协议必须修改无关的平台或应用代码；
- 同一转换或错误映射复制到三个以上 crate；
- 平台文件同时承担能力探测、进程查询、packet I/O 和网络事务。

配置细节分别见 [路由与 transport](p1-routing-transport.md) 和 [DNS](dns-transports.md)。
