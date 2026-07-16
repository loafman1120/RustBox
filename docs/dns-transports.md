# DNS transport 调查与实现

## 结论

不从 meow-rs 复制 transport 实现。meow-rs 的 `meow-dns`（MIT）适合参考独立 resolver、缓存、FakeIP、in-flight/reverse mapping 的模块边界，但其公开实现重点不是同时覆盖 DoH/DoQ。RustBox 已经使用 Hickory wire model，因此直接采用 `hickory-resolver 0.25.2` 的 Tokio provider，减少重复协议代码与额外抽象。

Hickory feature 固定为 `tokio + tls-aws-lc-rs + https-aws-lc-rs + quic-aws-lc-rs + webpki-roots`，与 workspace 其余 rustls 使用统一的 `aws-lc-rs` provider：

| RustBox 配置 | Hickory protocol | 能力 |
|---|---|---|
| `udp` | `Udp` | DNS/UDP |
| `tcp` | `Tcp` | DNS/TCP |
| `tls` | `Tls` | DoT |
| `https` | `Https` | DoH（默认 `/dns-query`） |
| `quic` | `Quic` | DoQ |

参考：

- [Hickory Resolver](https://docs.rs/hickory-resolver/0.25.2/hickory_resolver/)
- [Hickory repository](https://github.com/hickory-dns/hickory-dns)
- [meow-rs](https://github.com/madeye/meow-rs)

## 模块结构

```text
rustbox-dns-core/src
├── model.rs       配置、query/response、Resolver/DnsTransport 契约
├── transport.rs   Hickory Tokio adapter 与协议映射
├── resolver.rs    rule selection 与 StaticResolver
├── cache.rs       RustBox TTL cache
├── fake_ip.rs     FakeIP 分配与反查
├── reverse.rs     IP → domain TTL 表、RecordingResolver
└── subsystem.rs   运行图装配入口
```

`DnsSubsystem` 是唯一组合入口。主动查询经过 rule → FakeIP/transport → cache → reverse recording；inspection 观察到的 DNS answer 写相同 `ReverseDns`。resolver、cache、recording 使用具体泛型组合，transport registry 直接保存 `HickoryTransport`；整个 DNS crate 不再使用 `Box`、`BoxFuture`、`Arc<dyn Resolver>` 或 `Arc<dyn DnsTransport>`。唯一保留的运行时 `Arc` 是需要跨 DNS 与 inspection 共享的 `ReverseDns`。

## 已知边界

- UDP/TCP 有本地真实 socket 单测；DoT/DoH/DoQ 复用同一 Hickory provider 和配置路径，不在单元测试中依赖公网服务。
- 加密上游要求 domain endpoint，用它完成证书名称校验；IP endpoint 需要未来新增显式 `server_name` 字段。
- endpoint 域名的 bootstrap 暂用系统 DNS。
- transport socket 目前只能 direct。配置引用非 direct outbound 会在运行时构图阶段明确失败。
- `dns.hijack` 的本地 responder 尚未实现；本轮接入的是上游 transport 和可调用的 resolver graph。
