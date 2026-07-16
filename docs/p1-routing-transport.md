# P1 routing and transport guide

This page is the configuration contract for RustBox routing, shared transport,
TLS, and modern protocol support. TOML/JSON is normalized into `SourceConfig`;
the compiler validates references and protocol constraints before runtime I/O.

## Rule-set lifecycle

Rule sets may be inline, local, or remote. Local files are parsed at startup
and atomically replaced after their signature changes. Remote sets load a
valid cache during startup, use conditional `ETag`/`Last-Modified` requests,
publish only successfully parsed snapshots, and persist downloads through a
temporary-file rename. Failure keeps the last valid snapshot.

```toml
[[rule_sets]]
id = "local-private"
type = "local"
path = "rules/private.json"
format = "source"
reload_interval = "5s"

[[rule_sets]]
id = "remote-ads"
type = "remote"
url = "https://rules.example/ads.srs"
format = "binary"
update_interval = "1h"
cache_path = ".rustbox/rule-sets/ads.srs"
```

Formats are RustBox TOML, sing-box source JSON, and sing-box SRS binary. SRS
fields that cannot be represented safely by transport `FlowMeta` are rejected
instead of silently widening a rule.

## Route conditions and actions

Conditions cover inbound, TCP/UDP, sniffed protocol, domain/IP/port, rule-set,
process name/path, UID/user, Android package, interface, Wi-Fi SSID/BSSID, and
network type. Process and network lookups run concurrently before routing.
Windows and Linux provide process plus cached network metadata; Android maps
`/proc/net/*` UID data to process/package metadata when permissions allow it.
TUN flows preserve their configured interface name.

Actions use a route cursor. `resolve` and `options` are non-final and can update
the destination before later rules. Final actions are outbound, reject, and
`hijack-dns`.

```toml
[[routes]]
type = "resolve"
process_name = ["browser.exe"]
network_type = ["wifi"]
strategy = "prefer-ipv4"

[[routes]]
type = "route-options"
process_name = ["browser.exe"]
network_type = ["wifi"]
override_port = 8443
udp_timeout = "2m"

[[routes]]
type = "rule"
process_name = ["browser.exe"]
network_type = ["wifi"]
outbound = "proxy"

[[routes]]
type = "hijack-dns"
protocol = ["dns"]
```

Reject reasons distinguish drop, TCP reset, and ICMP host/port unreachable in
the route model. TCP reset uses abortive socket close. ICMP generation requires
ownership of the original packet path; a normal accepted proxy socket cannot
portably inject a corresponding IP control packet.

## Shared V2Ray transport and TLS

VMess, VLESS, and Trojan consume one shared layer:

- TCP, WebSocket, HTTP/2, gRPC, and HTTPUpgrade;
- custom roots, client certificate/key, SPKI SHA-256 pins, ECH, and Reality;
- VLESS `xtls-rprx-vision` flow;
- Mux.Cool TCP/XUDP and shared UoT framing.

```toml
[[outbounds]]
id = "vision"
type = "vless"
server = "edge.example:443"
uuid = "00000000-0000-0000-0000-000000000001"
flow = "xtls-rprx-vision"
transport = { type = "grpc", service_name = "proxy" }
tls = { enabled = true, server_name = "edge.example", reality = { public_key = "...", short_id = "0123456789abcdef" } }
dial = { multiplex = { enabled = true, protocol = "mux-cool", max_streams = 32, max_connections = 4, buffer_size = 65536 } }
```

TLS fingerprint shaping is behind the Cargo feature `fingerprint` because its
meow/BoringSSL backend needs NASM in the native build environment:

```powershell
cargo build -p rustbox --features fingerprint
```

Without that feature, `tls.fingerprint` is a configuration error; RustBox does
not silently perform an unshaped handshake.

## Modern protocols and endpoints

Implemented route-addressable nodes are Hysteria2, TUIC v5, NaiveProxy,
ShadowTLS v3, and userspace WireGuard. WireGuard can be declared under
`[[endpoints]]`; the frontend lowers it into the shared compiled graph so route
IDs, detours, and selection are not implemented twice.

```toml
[[endpoints]]
id = "wg"
type = "wireguard"
addresses = ["10.0.0.2/32"]
private_key = "BASE64_PRIVATE_KEY"
mtu = 1408
peers = [{ server = "vpn.example:51820", public_key = "BASE64_PUBLIC_KEY", allowed_ips = ["0.0.0.0/0", "::/0"], persistent_keepalive = "25s" }]
```

WireGuard uses BoringTun, a Tokio UDP event loop, and a userspace TCP/UDP
netstack; it does not create an OS TUN device. TUIC and Hysteria2 preserve QUIC
datagram boundaries. NaiveProxy uses pooled HTTP/2 CONNECT. ShadowTLS is a
shared stream transport and can be used as a detour carrier.

## Ownership and concurrency

Tokio is the only production executor. Long-lived carrier state is owned by a
single task and communicated through bounded channels. `TaskScope` owns all
session and lifecycle tasks. `Arc<dyn ...>` remains only at heterogeneous
runtime-graph and platform-capability boundaries; there is no per-flow
`Arc<Mutex<_>>` protocol state.
