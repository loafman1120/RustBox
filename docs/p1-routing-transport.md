# Routing and transports

本页记录路由、共享 transport 和现代协议的配置边界。TOML/JSON 会先转换成
`SourceConfig`，引用和协议约束在任何运行时 I/O 前完成校验。

## 路由

规则条件覆盖 inbound、TCP/UDP、嗅探协议、域名/IP/端口、rule set、进程、用户、
Android package、网络接口、Wi-Fi 和网络类型。进程与网络元数据在路由前并发补充。

`resolve` 和 `route-options` 是非终结 action，可修改目标或连接选项；outbound、
reject 和 `hijack-dns` 是终结 action。

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

Rule set 可内联或来自本地/远程文件，支持 RustBox TOML、sing-box source JSON 和
SRS binary。远程更新使用条件请求和原子替换；失败时继续使用最后一个有效快照。

## 共享 transport 与 TLS

VMess、VLESS 和 Trojan 共用 TCP、WebSocket、HTTP/2、gRPC、HTTPUpgrade transport
以及 TLS 配置。TLS 支持自定义 root、mTLS、SPKI pin、ECH 和 Reality；VLESS 支持
`xtls-rprx-vision`。Mux.Cool 提供 TCP/XUDP multiplexing，UoT framing 由协议适配器
共享。

```toml
[[outbounds]]
id = "proxy"
type = "vless"
server = "edge.example:443"
uuid = "00000000-0000-0000-0000-000000000001"
flow = "xtls-rprx-vision"
transport = { type = "grpc", service_name = "proxy" }
tls = { enabled = true, server_name = "edge.example" }
```

浏览器式 TLS fingerprinting 位于可选的 `fingerprint` Cargo feature；其
BoringSSL 后端需要 NASM。未开启 feature 时，配置 `tls.fingerprint` 会明确报错。

## 现代协议与 endpoint

可路由节点包括 Hysteria2、TUIC v5、NaiveProxy、ShadowTLS v3 和用户态
WireGuard。WireGuard 既可声明为 outbound，也可放在 `[[endpoints]]`；配置层会将
endpoint 降低到同一运行图。

```toml
[[endpoints]]
id = "wg"
type = "wireguard"
addresses = ["10.0.0.2/32"]
private_key = "BASE64_PRIVATE_KEY"
mtu = 1408
peers = [{ server = "vpn.example:51820", public_key = "BASE64_PUBLIC_KEY", allowed_ips = ["0.0.0.0/0", "::/0"] }]
```

WireGuard 使用 BoringTun、Tokio UDP loop 和用户态 TCP/UDP stack，不创建设备级
OS TUN。TUIC 与 Hysteria2 保留 QUIC datagram 边界；NaiveProxy 使用 HTTP/2
CONNECT pool；ShadowTLS 可作为共享 stream carrier。

长期 carrier state 由单一 task 所有，并通过有界 channel 通信；session 和 lifecycle
task 统一归属当前 generation 的 `TaskScope`。
