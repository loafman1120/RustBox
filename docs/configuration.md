# 配置与协议

RustBox 原生配置可使用 TOML 或字段完全相同的 JSON 描述客户端运行图，也可导入
`.yaml` / `.yml` Clash 配置。CLI 根据扩展名选择格式；配置先完成规范化、引用检查和
协议约束验证，成功后才创建 socket 或修改系统网络。原生配置的完整字段示例见
[`examples/rustbox.toml`](../examples/rustbox.toml)，Clash 导入示例见
[`examples/clash.yaml`](../examples/clash.yaml)。

## Clash YAML 兼容范围

Clash 文档会先转换成统一的 `SourceConfig`，而不是把 Clash 字段带入运行时。目前支持：

- `port`、`socks-port`、`mixed-port`、`bind-address`、单用户 `authentication`；
- `ss`、`socks5`、`http`、`vmess`、`vless`、`trojan`、`hysteria2` 和 `anytls` 代理；
- `select`、`url-test` 代理组；
- domain、IP CIDR、端口、进程、inbound、TCP/UDP 和 `MATCH` 规则。

proxy/rule provider、`fallback`、`load-balance`、GeoIP/GeoSite 等尚无等价导入语义，
解析时会明确报错，不会静默改成 direct。Clash 的 DNS/TUN 配置暂未导入；需要这些能力时
使用原生 TOML/JSON。

## 路由

规则可匹配 inbound、TCP/UDP、嗅探协议、域名、IP、端口、rule set、进程、用户、
Android package、接口、Wi-Fi 和网络类型。进程与网络元数据在路由前补充。

`resolve` 和 `route-options` 是非终结 action；outbound、`reject` 和 `hijack-dns` 是
终结 action。

```toml
[[routes]]
type = "resolve"
domain_suffix = ["example.com"]
strategy = "prefer-ipv4"

[[routes]]
type = "rule"
domain_suffix = ["example.com"]
outbound = "proxy"
```

Rule set 可内联或从本地、远程、sing-box source JSON、SRS binary 加载。远程刷新失败
时继续使用最后一个有效快照。

## DNS

DNS 查询依次经过规则选择、FakeIP 或上游、TTL cache 和 reverse mapping。嗅探到的
DNS answer 也会写入 reverse map，供后续 flow 恢复域名；`hijack-dns` 可直接处理捕获
的 TCP/UDP DNS 流量。

支持 UDP、TCP、DoT、DoH 和 DoQ。FakeIP 可配置 IPv4/IPv6 地址池，并通过
`state_file` 持久化映射。加密上游必须保留域名用于证书校验；上游域名的首次
bootstrap 当前使用系统 DNS。

配置 `dns.servers[].outbound` 时，UDP 使用目标 outbound 的 datagram，TCP/DoT/DoH
使用 stream。DoQ detour 目前不支持，配置会明确失败而不会回退 direct。

## Transport 与协议

VMess、VLESS 和 Trojan 共享 TCP、WebSocket、HTTP/2、gRPC、HTTPUpgrade 与 TLS。
TLS 支持自定义 root、mTLS、SPKI pin、ECH 和 Reality；VLESS 支持
`xtls-rprx-vision`。Mux.Cool 提供 TCP/XUDP multiplexing。

Hysteria2、TUIC v5、NaiveProxy、ShadowTLS v3 和用户态 WireGuard 也可作为 outbound。
WireGuard 不创建设备级 TUN，而是通过 BoringTun 与用户态 TCP/UDP stack 提供可路由
节点。

浏览器式 TLS fingerprinting 是可选 feature，其 BoringSSL 后端需要 NASM：

```powershell
cargo build -p rustbox --features fingerprint
```

未启用 feature 时使用 `tls.fingerprint` 会在配置阶段报错。

## 配置维护约定

- `id` 引用必须在编译阶段解析，运行时不按字符串寻找对象。
- 依赖环应报告完整路径，而不是表现为连接超时。
- 不支持的组合必须明确失败，不能静默回退 direct。
- 示例 TOML 是面向用户的字段参考；本文只解释跨字段语义与稳定边界。
