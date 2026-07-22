# 架构

RustBox 的核心约束是：应用拥有客户端，引擎拥有网络生命周期。CLI 和 Flutter 只负责
宿主交互，协议、路由与平台操作由同一运行图完成。

## 分层

```text
apps/rustbox-cli        apps/rustbox-flutter
          \                 /
             rustbox（组合根）
        /          |            \
 config/control  modules      platform
        \          |            /
          kernel（flow / route / relay）
                       |
          foundation（types / Tokio I/O）
```

| 层 | 位置 | 职责 |
| --- | --- | --- |
| 应用 | `apps/` | 参数、信号、Dart API 与打包 |
| 组合根 | `crates/rustbox` | 装配运行图，提供 `start/reload/snapshot/stop` |
| 配置与控制 | `crates/rustbox-config-file`、`crates/control` | TOML、语义配置、gRPC 与 Clash API |
| 数据面 | `crates/kernel` | flow、路由、拨号、relay 与 host ports |
| 模块 | `crates/modules` | DNS、嗅探、inbound、outbound、transport 与用户态栈 |
| 平台 | `crates/platform` | TUN、路由、进程与系统网络能力 |
| 基础 | `crates/foundation` | 公共类型、纯数据运行配置和 Tokio I/O 契约 |

依赖只能向下或指向组合根定义的接口。协议 crate 不依赖应用、文件格式或具体操作
系统；`target_os` 条件选择只应出现在平台层。

## 配置与生命周期

```text
TOML -> SourceConfig -> normalize -> validate -> CompiledConfig -> runtime graph
```

文件模型保留用户输入并产生字段级诊断；编译模型只保存已解析和已验证的数据。所有
引用、依赖环和协议约束都应在网络 I/O 开始前失败。

`RustBox` 是唯一生命周期所有者：

- `start` 启动 inbound、控制服务与后台任务；
- `reload` 发布新 generation，新 flow 使用新图，旧 flow 有界排空；
- `snapshot` 返回统一只读状态；
- `stop` 停止接纳、结束任务并回滚平台修改，且保持幂等。

每个 generation 使用独立的取消与任务跟踪作用域。模块不得通过全局 runtime 或隐藏的
spawner 持有长期任务。

## 数据流

```text
inbound
  -> Flow { metadata, Stream | Datagram }
  -> DNS / process / network metadata enrichment
  -> protocol inspection
  -> route
  -> selector or concrete outbound
  -> relay
```

路由是纯计算。它只产生 outbound、reject、DNS hijack 或连接选项等结果；DNS 查询、
socket 创建和平台操作在相应能力边界执行。规则集由组合层加载和刷新，路由只消费已
发布的快照。

控制传输同样共享一个服务层：gRPC 和 Clash HTTP/WebSocket 只做 wire 映射，不互相
调用，也不直接持有某个 generation 的运行对象。

## 维护原则

- 优先在现有 crate 内拆私有模块；只有独立依赖约束或多处复用时才新增 crate。
- 解析、校验、编译与运行构造保持分离。
- 动态分派只用于 service、outbound、I/O、观测 sink 和平台能力等异构边界。
- 平台修改必须返回可回滚 handle；普通 socket 不能声明其没有的 packet 能力。
- 同一转换或错误映射出现三次时，应提取到拥有该语义的层。

客户端侧的具体系统约束见[客户端网络](client-networking.md)。
