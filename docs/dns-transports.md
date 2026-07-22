# DNS

桌面客户端的系统 DNS 接管、Windows WFP 防泄漏、切网和崩溃恢复设计见
[客户端 DNS 与 Windows TUN](client-dns-windows.md)。本文只描述可移植的 DNS resolver
与 transport 数据面。

RustBox 的 DNS 子系统使用 Hickory wire model 与 Tokio provider，不自行实现
UDP/TCP/DoT/DoH/DoQ 协议栈。

## 支持范围

| 配置 | 协议 |
| --- | --- |
| `udp` | DNS over UDP |
| `tcp` | DNS over TCP |
| `tls` | DoT |
| `https` | DoH，默认路径 `/dns-query` |
| `quic` | DoQ |

查询依次经过规则选择、FakeIP 或上游 transport、共享 TTL cache 和 reverse
recording。inspection 观察到的 DNS answer 也写入同一份 reverse map，供后续路由
恢复域名。route `hijack-dns` 可直接终止捕获的 TCP/UDP DNS flow，并返回 wire-format
响应。

```text
rules → FakeIP / upstream → cache → reverse mapping
                                  ↑
                         passive DNS inspection

内部查询与 hijack 路径保留 Hickory 的完整 RR 数据，支持 A、AAAA、CNAME、MX、NS、
PTR、SOA、SRV、TXT、CAA、HTTPS、SVCB、NAPTR、TLSA、DS、DNSKEY 和 ANY。地址答案
仍额外投影到统一的 `Host` 模型，供路由解析和 reverse mapping 复用。

FakeIP 可同时配置 `ipv4_pool` 与 `ipv6_pool`。设置 `state_file` 后，域名映射和两个
地址池游标会以原子替换方式持久化；文件读取、目录创建、写入和替换均使用 Tokio
异步文件 API，重启后保持既有映射。
```

## 代码位置

`crates/modules/dns/rustbox-dns-core/src/`：

- `model.rs`：配置和 query/response 类型；
- `transport.rs`：Hickory adapter 与协议映射；
- `resolver.rs`、`subsystem.rs`：规则选择和运行图装配；
- `cache.rs`、`fake_ip.rs`、`reverse.rs`：状态组件。
- `socket.rs`：DNS transport 消费的最小 socket capability；不依赖 router 或具体
  outbound 实现。

组合层把 DNS 与 outbound 的循环拆成两个阶段：先构造 DNS transport 和
`LateBoundDnsSocket`，再构造全部 runtime outbound，最后一次性绑定 socket。相关代码
分别位于 `compose/dns.rs` 与 `compose/dependency.rs`。后者把 outbound detour、outbound
bootstrap resolver、DNS server outbound 放入同一依赖图，配置阶段就会报告完整的循环
路径，而不是等查询超时。

指定 `dns.servers[].outbound` 后，UDP 使用该 outbound 的 datagram socket；TCP、DoT 和
DoH 使用其 stream socket。Hickory 仍负责 DNS framing、TLS、HTTP/2 和证书域名校验，
组合层只负责 socket 能力注入。DoQ 需要 QUIC runtime 的异步 UDP binder，目前 detour
配置会明确失败，不会回退 direct。

## 边界

- 加密上游使用 domain endpoint 完成证书名称校验；endpoint 域名 bootstrap
  暂时使用系统 DNS。
- transport socket 当前只能 direct；引用非 direct outbound 会在构图阶段失败。
- UDP/TCP 有本地 socket 测试；加密 transport 的单元测试不依赖公网服务。
