# sing-box 嗅探与域名恢复对照

本说明记录 RustBox 本轮实现所对照的 sing-box 能力与取舍，避免把协议解析细节重新手写进代理核心。

## sing-box 行为

- sing-box 的 `sniff` 已从 inbound 字段迁移为非终结 route action；默认启用全部 sniffer，默认超时为 300 ms。
- 官方支持表包含 TCP HTTP Host、TCP TLS Server Name、UDP QUIC Server Name，以及 TCP/UDP DNS 等协议提示；QUIC 还能识别客户端类型。
- `dns.reverse_mapping` 在回答 DNS 查询后保存 IP 反向映射，供后续路由恢复域名。官方同时提示：若应用使用系统代理 DNS 与系统缓存（尤其 macOS），请求未经过 sing-box 时映射可能缺失。

参考：

- [Protocol Sniff](https://sing-box.sagernet.org/configuration/route/sniff/)
- [Rule Action: sniff](https://sing-box.sagernet.org/configuration/route/rule_action/#sniff)
- [DNS: reverse_mapping](https://sing-box.sagernet.org/configuration/dns/#reverse_mapping)
- [迁移：旧 inbound sniff 字段](https://sing-box.sagernet.org/configuration/shared/listen/#sniff)

## RustBox 落地

| 能力 | 实现 | 边界 |
|---|---|---|
| TLS SNI | `rustls::server::Acceptor` | ClientHello 不完整时继续有界读取；ECH 不暴露真实 SNI |
| HTTP Host | `httparse` | HTTP/1.x；HTTPS 依靠 TLS/QUIC SNI |
| QUIC SNI | `clienthello 0.2.2` | QUIC v1 Initial，支持跨数据报 CRYPTO 重组；暂不支持 v2/客户端类型 |
| DNS 识别 | `hickory-proto` | TCP 长度前缀和 UDP message |
| 域名恢复 | 被动响应观察 + 主动 resolver 共享的 TTL 表 | 4096 项/运行代；只补充 `FlowMeta.domain`，不覆盖原目标 IP |
| 载荷安全 | Tokio deadline + replay wrapper | 16 KiB；UDP 最多 4 包；超时 fail-open |

TOML route matcher 可直接使用 `protocol = ["http", "tls", "quic", "dns", "socks5"]`。协议字段与其它 matcher 字段遵循现有 AND 语义；同字段中的多个协议为 OR。

选择这些 crate 的原因是它们已有对应的结构校验、分片/压缩处理或密码学实现。数据面只保留 Tokio 读取、预算、重放和元数据更新；QUIC Initial 密钥派生、TLS 扩展、HTTP header 与 DNS name compression 均不在 RustBox 内自行实现。

## 所有权

Engine 使用 `Engine<ProtocolSniffer>` 直接持有具体 Tokio 异步 stage；`MetadataEnricher` 返回 `impl Future`，不再使用 `BoxFuture`、`Box<dyn MetadataEnricher>` 或动态 pipeline。反向 DNS 表保留一个 `Arc`，因为它确实由 DNS subsystem、被动 DNS flow 与后续并发 flow 跨模块共享。stream/datagram 仍沿用全项目既有的 `FlowPayload` I/O trait object，但嗅探的 replay 与 response observation 已合并为单个 wrapper，不再额外套一层 Box。
