# RustBox TUN & Transparent Proxy

> 2026-07-10 · 见 `architecture.md`

核心原则：可移植核心不得包含原生 OS 设施（TUN、WFP、nftables、JNI、Network Extension）。

## 当前状态

| 区域 | 位置 | 状态 |
|---|---|---|
| Packet device I/O | `rustbox-io::PacketDevice` | 已实现 poll 接口 |
| Device provider | `rustbox-host-api::PacketDeviceProvider` | 已实现（name, addresses, MTU, route/dns mode） |
| Network control | `rustbox-host-api::NetworkControl` | 已实现 `AddRoute`，其余规划中 |
| Packet-to-flow | `rustbox-stack::NetworkStack` | ipstack 适配器，accept loop 待接入 dispatcher |
| Windows | `rustbox-platform-windows` | Wintun TUN + `AddRoute` |
| Linux | `rustbox-platform-linux` | TUN + transparent TCP redirect (SO_ORIGINAL_DST) |
| Transparent inbound | `rustbox-inbound-transparent` | 已解析/编译/组合，auto_rules=false 时需外部规则 |
| TUN inbound | `rustbox-inbound-tun` | 已解析/编译/组合，Linux + Windows |

## 目标数据路径

### TUN Inbound

```
platform PacketDevice → tun service → packet-to-flow adapter
  → FlowDispatcher → Flow + FlowMeta → inspection → route → outbound
```

### Transparent Inbound

```
platform redirect/TPROXY/WFP → transparent service → original-dst lookup
  → FlowDispatcher → Flow + FlowMeta → route → outbound
```

TUN 与 transparent 不是一回事：

| 模式 | 需 packet device | 需 packet-to-flow stack |
|---|---|---|
| TUN | 是 | 是 |
| Linux redirect | 否 | 否 |
| Linux TPROXY | 否 | 否 |
| Windows WFP | 通常否 | 否 |
| Android VpnService | 是 | 是 |

## 能力契约

### PacketDevice

```rust
pub struct PacketDeviceConfig {
    pub name: Option<String>,
    pub addresses: Vec<IpCidr>,
    pub mtu: Option<u16>,
    pub route_mode: RouteMode,
    pub dns_mode: TunDnsMode,
}
```

### NetworkControl

事务式、可回滚操作：`AddInterfaceAddress`、`SetInterfaceMtu`、`AddRoute`、`AddRouteRule`、`AddDnsServer`、`AddTransparentRedirectRule`、`AddLeakProtectionRule`、`ProtectSocket`。`apply` 返回 `NetworkLease`，stop 时幂等回滚。

### ProcessLookup（规划中）

```rust
pub trait ProcessLookup: Send + Sync {
    fn lookup(&self, key: ConnectionKey) -> BoxFuture<'_, Result<Option<ProcessInfo>, _>>;
}
```

由 `MetadataEnricher` 使用，router 只消费已填充 `FlowMeta` 字段。最佳努力、可缓存、非路由必需。

### Egress Protection

避免 RustBox 出站被自身 TUN/透明规则捕获：

```rust
pub enum EgressPolicy {
    Default,
    BypassRustBoxCapture,
    Interface(InterfaceRef),
}
```

平台实现映射为：Android `VpnService.protect`、Windows WFP 条件、Linux fwmark/策略路由。

## 配置

### TUN

```toml
[[inbounds]]
id = "tun"
type = "tun"
interface_name = "rustbox0"
addresses = ["172.18.0.1/30", "fdfe:dcba:9876::1/126"]
mtu = 9000
auto_route = true
strict_route = true
dns_hijack = ["any:53"]
```

校验：`type = "tun"` 需 `PacketDevice` + `NetworkControl` + `TaskSpawner`。`addresses` 至少一个 CIDR。`strict_route` 需平台防泄漏能力。

### Transparent（外部规则 MVP）

```toml
[[inbounds]]
id = "transparent"
type = "transparent"
listen = "127.0.0.1:12345"
network = "tcp"
mode = "redirect"
auto_rules = false
```

`redirect` 模式可从已接受 socket 恢复原始目标。`tproxy` (Linux)、`wfp-redirect` (Windows)、`network-extension` (Apple) 为平台限定模式。`auto_rules = true` 需 `NetworkControl`。

## Packet-to-Flow

```
PacketDevice read → 解析 IP → 送入 ipstack
  → TCP socket → FlowPayload::Stream → dispatch（不等待 relay）
  → UDP → 固定目标 DatagramSession → dispatch
  → 出站响应写回 IP 包
```

有界五元组 session 表，idle timeout + 容量淘汰。DNS hijack 作为路由/hijack 服务在 stack 之上，不在 kernel 做 ad hoc UDP 解析。SOCKS5 UDP `DatagramEndpoint` 的每个真实目标独立 session。

## 平台适配

### Linux (`rustbox-platform-linux`)

TUN 通过 `tun-rs`/`tokio-tun`；路由通过 `rtnetlink`；自动规则通过 `nftables`；TPROXY 需透明 socket + fwmark + 策略路由 + nftables；进程查询通过 sock diag/procfs；egress 保护通过 fwmark。

### Windows (`rustbox-platform-windows`)

TUN 通过 Wintun / `tun-rs`；路由通过 IP Helper API；透明代理/WFP/进程查询通过 WFP ALE 层；进程元数据从 IP Helper 表获取 PID 再查进程 API。

## 不变量

1. `rustbox-kernel` 不导入平台/TUN/WFP/netlink/JNI/Network Extension crate
2. `rustbox-route` 纯函数，不做进程/DNS/网络控制
3. `rustbox-stack` 拥有 packet-to-flow；kernel 只接收 Stream 或固定目标 datagram session
4. 平台能力通过 capability 矩阵声明，composition 期校验
5. 网络控制变更仅在 start 应用、stop 回滚
6. 不支持的平台特性返回结构化诊断，不静默降级
7. Stack 和 transparent accept loop 不等待 relay 完整生命周期
