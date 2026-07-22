# 客户端 DNS 与 Windows TUN 设计

本文定义 RustBox 面向桌面客户端的 DNS、Windows TUN 和系统网络状态管理。目标是把
当前“能够打开 TUN 并配置路由”的实现提升为可以随安装包交付、切网后自动收敛、异常
退出后可恢复的客户端能力。

当前实现使用现成 crate 组合，不维护私有 Win32 FFI：`tun-rs`/Wintun 负责 TUN，
`netdev` 选择默认接口，`socket2-ext` 绑定 Windows socket，`wfp` 管理动态过滤会话，
`netwatcher` 接收原生接口通知，`netstat2` 读取 owner-PID 表，`surge-ping` 处理 ICMP
echo，`object` 校验 PE 架构。系统 DNS 的配置/快照仍通过低频 PowerShell cmdlet 完成；
flow 热路径不启动 PowerShell。

## 目标与语义

| 能力 | 目标 | 优先级 |
| --- | --- | --- |
| Wintun 部署 | 安装包携带并校验当前架构的官方 `wintun.dll` | P0 |
| 出站防回环 | 自动发现物理默认接口，所有 direct/bootstrap DNS socket 显式绑定 | P0 |
| 自动路由 | 默认路由、代理节点和 DNS bootstrap 排除项随物理接口原子更新 | P0 |
| Windows strict route | WFP 阻止绕过 TUN 的明文 DNS和受管流量 | P0 |
| DNS 防泄漏 | 系统 DNS 指向 TUN DNS；其他接口的 TCP/UDP 53 默认拒绝 | P0 |
| 系统设置恢复 | 保存 DNS、系统代理和路由原值，停止时精确恢复 | P0 |
| 崩溃恢复 | 持久化变更日志，启动修复；可选守护进程处理进程崩溃 | P0 |
| 睡眠/切网 | 监听电源、接口、地址和路由变化并重新计算事务 | P0 |
| 进程识别 | 使用 IP Helper API 和完整连接键，禁止逐 flow 启动 PowerShell | P1 |
| ICMP | TUN 原始包路径支持 echo；按 outbound 能力明确降级 | P1 |

`strict_route = true` 保证阻止非 RustBox 路径上的 TCP/UDP 53。它不声称识别并阻止任意
HTTPS 中的 DoH，也不默认封锁 UDP/443 上的所有 QUIC。若产品需要“只允许指定加密 DNS”，
应另设企业策略，以域名/IP 列表或 TLS/QUIC 检查实现，不能混入基础 strict 语义。

## 总体结构

```text
Windows network/power notifications
                |
                v
       Network Coordinator --------------------+
       |          |           |                |
       v          v           v                v
 interface     route       DNS/proxy       recovery journal
 selector      planner     snapshot         + watchdog
       |          |           |
       +----------+-----------+----> platform transaction
                                      | routes / DNS
                                      | socket binding
                                      + WFP filters

application DNS -> TUN -> DNS hijack listener -> rules/cache/FakeIP -> upstream
                                                               |
                                                    bound physical socket
```

portable core 只描述意图和可回滚结果；`rustbox-platform` 的 Windows 实现持有 Win32、
IP Helper、WFP 和注册表细节。应用层负责安装资产、提权服务以及异常恢复触发，不把这些
职责塞进 DNS resolver。

## DNS 数据面

### 单一解析入口

启用 TUN DNS 后，从 TUN 子网中保留一个不会被 Windows 视为本机地址的稳定 peer 地址
作为 resolver（例如接口为 `172.19.0.1/30` 时使用 `172.19.0.2:53`），同时处理 UDP 和
TCP。系统接口 DNS 指向该地址；该地址必须路由进 TUN，不能绑定成宿主机 UDP socket。
TUN 中目的端口为 53 的包无论原目标为何都进入同一个 DNS hijack service。查询继续使用
现有流程：

```text
wire query -> DNS rules -> FakeIP / selected upstream -> TTL cache -> reverse map
```

不得把系统 resolver 同时作为 TUN DNS 的上游，否则会形成回环。上游 endpoint 是域名时，
bootstrap resolver 使用启动前快照中的物理接口 DNS，并绑定物理接口；解析结果在 TTL 内
缓存。配置 reload 不清空仍有效的 bootstrap 结果。

### 出站与失败策略

- UDP、TCP、DoT、DoH、DoQ 沿用现有 transport；每个 server 的 `outbound` 决定 socket。
- `direct` DNS、代理节点连接和 bootstrap 查询必须携带物理接口 LUID/index，不依赖默认
  路由碰巧正确。
- strict 模式在 WFP 生效前不得发布“已连接”状态；WFP 失败时整个启动事务回滚。
- 上游全部失败时返回 `SERVFAIL`，不得偷偷回退系统 DNS。只有显式
  `fallback = "system"` 且非 strict 模式才允许回退。
- TCP 请求保持 DNS message 边界和流水线顺序；UDP 超大响应按 EDNS 能力截断或转 TCP，
  不静默丢弃。

### 缓存与网络变化

正缓存按 RR TTL，负缓存按 SOA 语义，已有 min/max TTL 只作为配置边界。cache key 至少包含
规范化 qname、qtype、qclass、规则选择结果和 ECS 作用域。网络切换时：

- 保留与网络无关的普通/FakeIP cache；
- 清除 bootstrap、失败退避和绑定旧接口的连接池；
- 关闭旧 DoH/DoT/DoQ session，在新接口上懒重建；
- reverse map 与 FakeIP 持久状态不因切网丢失。

## 默认接口、出站绑定与自动路由

### 接口选择

Windows 通过 `netdev::get_default_interface` 在安装 TUN 路由前捕获物理默认接口；socket
绑定使用其 friendly name，packet/ICMP 使用 index。候选接口必须为 up、非 loopback、
非 RustBox TUN，并具有对应地址族。切网协调器会先停旧 TUN，再重新取样，避免把 TUN
自身的 `/1` 路由误识别为物理默认路径。

`auto_detect_interface = true` 时，direct socket 使用 `IP_UNICAST_IF`/
`IPV6_UNICAST_IF` 绑定 index；必要时同时绑定选出的源地址。代理节点、DNS 上游和远程
rule-set 地址在安装全局 TUN 路由前先建立更具体的物理路由。域名得到多个地址时，每个
实际尝试地址都必须有排除路由。

### 路由计划

普通 auto 模式可以添加 `/0`；Windows strict 模式使用两个 `/1`（IPv6 同理），以保留
系统 `/0` 供显式绑定和恢复。两者都必须：

1. 读取当前最佳物理路由；
2. 生成代理节点、bootstrap DNS、LAN 和用户 `route_excludes` 的具体路由；
3. 打开 TUN 并等待地址就绪；
4. 应用排除路由、TUN 路由、系统 DNS和 WFP；
5. 健康检查成功后提交 generation。

任一步失败都逆序回滚。用户排除项应复制应用事务前的最佳 route，而不是在停止时再次
查询当前 route 来猜测应删除哪个对象。

## WFP strict 与 DNS 防泄漏

WFP 使用 `wfp` crate 的动态 engine session；严格模式要求宿主已提权。runtime 持有会话，
进程退出时 Windows 自动删除动态 filter；独立 watchdog 负责恢复不属于动态 WFP 的路由、
DNS和代理状态。

最小过滤策略：

| 层 | 动作 |
| --- | --- |
| `ALE_AUTH_CONNECT_V4/V6` | 允许 RustBox AppID/PID 的上游连接 |
| `ALE_AUTH_CONNECT_V4/V6` | 允许 loopback、DHCP/NDP 和明确的 LAN bypass |
| `ALE_AUTH_CONNECT_V4/V6` | 阻止其他进程经非 TUN 接口发送 TCP/UDP 53 |
| `ALE_AUTH_CONNECT_V4/V6` | strict kill-switch 下阻止非 TUN 的受管公网连接 |
| `ALE_FLOW_ESTABLISHED_V4/V6` | 记录命中和诊断，不做数据面重定向 |

过滤条件使用 interface LUID、compartment、protocol、remote port 和 AppID，不能只按接口
名称或 PID。PID 会复用，长期 allow 规则必须以签名/服务 SID/AppID 为主。WFP allow 的
RustBox socket仍须显式绑定物理接口；allow 只解决防火墙许可，不解决路由回环。

启动顺序采用 fail-closed：先安装 RustBox allow，再安装 block，最后切换系统 DNS和默认
路由。停止顺序相反：先撤销默认路由和 DNS，再撤 block，最后撤 allow。这样不会出现
短暂的无保护窗口，也不会在 DNS listener 已停止后继续把系统请求送入 TUN。

## 可恢复的系统事务

当前 `NetworkLease` 只保存“希望执行的操作”，不足以精确恢复。应拆成：

```text
NetworkPlan     = desired mutations + preconditions
AppliedLease    = generation + owner + exact undo records
UndoRecord      = route row / DNS snapshot / proxy registry snapshot / WFP ids
```

DNS 快照需记录每个 adapter/address family 的来源（DHCP 或 static）、完整 server 顺序和
接口 identity；恢复 DHCP 必须恢复 DHCP 语义，而不是写回当时租约给出的地址。系统代理
快照记录 `ProxyEnable`、`ProxyServer`、`ProxyOverride` 的值、注册表类型以及键是否原本
存在。路由恢复保存实际创建行的 LUID、next hop、metric 和 protocol，只删除本会话拥有
且仍匹配的行。

journal 使用版本化、校验和保护的本地文件，原子替换写入：

```text
prepared(snapshot) -> applying -> committed(applied lease) -> reverting -> removed
```

每次系统写入后立刻追加 undo record。正常停止、下次启动和 broker 启动都会扫描未完成
journal；恢复操作幂等，并验证对象仍由 RustBox 拥有，避免覆盖用户在运行期间主动修改的
新设置。恢复有冲突时保留 journal 并产生可操作诊断。

安装版包含轻量 `rustbox-watchdog.exe`。strict 会话启动前记录父进程 PID 与 start time 并
启动 watchdog；父进程实例消失后，watchdog 执行同一套带校验、幂等回滚。下一次启动仍会
扫描 journal，作为 watchdog 未运行或机器断电后的第二道恢复路径。

## 睡眠、唤醒和切网

Windows 平台通过 `netwatcher` 使用 IP Helper 原生接口/地址通知；睡眠恢复和物理切网产生
的接口变化进入同一 coordinator。CLI 和 Flutter bridge 都持有 monitor：

1. 标记旧 generation draining，暂停新 direct dial；
2. 重新选择 IPv4/IPv6 物理接口；
3. 预建新的 endpoint 排除路由和 WFP allow；
4. 原子提交新 lease，更新 socket binder；
5. 关闭绑定旧接口的 DNS/transport 池并回收旧 lease。

网络短暂消失时保留 TUN 和 strict block，进入 `waiting-for-network`，不能为“恢复联网”而
撤掉 kill-switch。非 strict 模式可以按产品策略暂时旁路，但必须暴露状态。

## Wintun 交付

- CLI 压缩包和 Flutter Windows bundle 分别携带 x64、arm64（以及仍支持时的 x86）官方
  DLL，构建阶段按 target 只复制一个文件到主二进制旁。
- 发布流水线固定 Wintun 版本并校验 SHA-256 和 Authenticode 签名；产物清单记录版本、
  架构和 hash。
- 运行时解析顺序为显式受信路径、应用目录；`RUSTBOX_WINTUN_DLL` 只保留给开发/CI。
  安装版不得从当前工作目录搜索 DLL，防止 DLL search-order hijacking。
- 架构不匹配、签名或 hash 校验失败时给出明确诊断，不尝试联网下载 DLL。

## P1：原生进程识别与 ICMP

进程识别使用 `GetExtendedTcpTable` 和 `GetExtendedUdpTable` 的 owner-PID 表，按协议、
本地/远端地址及端口组成完整 `ConnectionKey`；TCP 必须匹配四元组，UDP 在系统只提供
本地 endpoint 时采用最窄匹配并标记 confidence。PID 到路径使用
`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW`，可选通过
`GetPackageFullName` 补 AppContainer package。表按短 TTL 批量缓存，网络变化时失效，
不再为每个 flow 创建 PowerShell。

ICMP 不是普通 stream/datagram flow。`ipstack` 将 ICMP 暴露为 unknown transport packet；
Windows 首期只接受 echo request，保留 family、identifier、sequence 和 payload，交给绑定
物理 interface index 的 `surge-ping` 直连发送，收到真实 reply 后再合成正确 checksum 并
注回 TUN。其他控制类 ICMP 和不能表达 ICMP 的代理 outbound 会明确拒绝，不伪造成功，
也不开放任意 raw packet 转发接口。

## 配置演进

保持现有字段兼容，增加显式客户端意图：

```toml
[[inbounds]]
id = "tun"
type = "tun"
addresses = ["172.19.0.1/30"]
auto_route = true
auto_detect_interface = true
strict_route = true
route_excludes = ["192.168.0.0/16"]
dns_hijack = [
  { endpoint = "172.19.0.2:53", network = "udp" },
  { endpoint = "172.19.0.2:53", network = "tcp" },
]

```

归一化规则：Windows 上 `strict_route = true` 隐含 `auto_route = true`、
物理接口自动绑定、平台 DNS和至少 UDP/TCP 53 hijack；只配置其中一种 DNS transport 时
会自动补齐同 endpoint 的另一种。strict 缺少 DNS hijack 时在校验阶段报错，不悄悄削弱
保护。同一 endpoint 的 UDP/TCP hijack 在写系统 DNS 时按 IP 去重。

## 已实施范围与验收

1. **P0a：事务正确性**：exact undo records、DNS/代理精确快照、SHA-256 journal、启动和
   watchdog 恢复。
2. **P0b：路由正确性**：默认接口选择、TCP/UDP socket binding、排除路由优先应用和
   CLI/Flutter network-change reconcile。
3. **P0c：防泄漏**：WFP 动态 session、TCP/UDP 53 block、strict fail-closed block，并保留
   loopback、link-local、DHCP 和 RustBox AppID。
4. **P0d：交付**：Flutter bundle 按 x64/arm64 携带 Wintun 与 watchdog；构建时校验固定
   Wintun ZIP SHA-256、Authenticode，运行时再校验 PE 架构。
5. **P1**：`netstat2` 原生表按 250 ms 批量缓存并匹配完整 TCP key；ICMPv4/v6 echo 通过
   绑定物理 interface index 的 `surge-ping` 转发。其他 ICMP 控制消息仍明确拒绝。

Windows 集成测试至少覆盖：正常启停后设置逐项相等；apply 每一步失败均完全回滚；强杀
runtime 后 watchdog 恢复；睡眠唤醒；Wi-Fi/以太网切换；IPv4-only、IPv6-only、双栈；
UDP/TCP 53 从非 TUN 接口失败；RustBox DNS 上游仍成功；代理节点地址变化不回环；两个
客户端实例竞争时只有一个获得系统 lease。发布门禁还应执行 DNS leak 探针、路由表/WFP
枚举和 Wintun 产物架构校验。
