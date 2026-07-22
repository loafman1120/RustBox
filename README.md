# RustBox

RustBox is a modular client-side proxy engine written in Rust and built on
Tokio. It is intended for local command-line clients and embedding in end-user
Flutter applications; the same engine powers both surfaces.

## Product scope

RustBox is designed for a single-user client running on an end-user device. Its
primary deployment model is a local desktop or mobile application that owns the
proxy engine, TUN/network integration, configuration, and local control UI.
Client features such as traffic routing, DNS handling, outbound selection,
network-change reconciliation, and crash-safe restoration of device networking
take priority over server hosting and multi-user administration.

RustBox assumes that the engine, its configuration, and its local control plane
belong to the same user and device. It is not designed as an Internet-facing
multi-tenant proxy service or as a security sandbox for untrusted protocol
modules. Keep proxy and control listeners on loopback by default. If remote
access is required, provide authentication and transport encryption at a
trusted network boundary.

> RustBox is under active development. Protocol support and configuration may
> change before the first stable release.

## Architecture

```text
CLI / Flutter
    -> rustbox (composition and lifecycle)
        -> config + control + protocol modules + platform adapters
            -> kernel (flows, routing, relay, host capability ports)
                -> foundation (shared types and Tokio I/O contracts)
```

- Tokio is the only production executor.
- `RustBox` owns the `start`, `reload`, `snapshot`, and `stop` lifecycle.
- Configuration follows `TOML -> normalize -> validate -> compile -> runtime`.
- TCP and UDP enter the kernel as explicit `Flow` payloads, then pass through
  inspection, routing, outbound selection, and relay.
- Shared addresses use the standard library's `IpAddr` and `SocketAddr` types;
  `Endpoint` only adds unresolved domain-name support where it is needed.
- Operating-system behavior stays behind platform and host capability
  boundaries.

See [Architecture](docs/architecture.md) for ownership, data flow, and the
workspace map.

## Workspace

| Path | Purpose |
| --- | --- |
| `apps/rustbox-cli` | CLI binary (`rustbox-app`) |
| `apps/rustbox-flutter` | Flutter package, Rust bridge, and example app |
| `crates/rustbox` | Public engine facade and composition root |
| `crates/foundation` | Shared types and async I/O contracts |
| `crates/kernel` | Flow engine, routing, relay, and host ports |
| `crates/control` | Semantic configuration and gRPC control plane |
| `crates/modules` | DNS, inspection, transports, inbounds, and outbounds |
| `crates/platform` | Linux, macOS, Windows, and Android adapters |
| `examples` | Runnable TOML configurations |
| `scripts` | Build and smoke/E2E helpers |
| `website` | Dependency-free project website |

## Quick start

Requires the Rust toolchain declared by the project. Build the workspace:

```powershell
cargo build --workspace
```

Run the example configuration (HTTP CONNECT on `127.0.0.1:18080`, SOCKS5 on
`127.0.0.1:1080`, and a mixed listener on `127.0.0.1:2080`):

```powershell
cargo run -p rustbox-app -- run --config examples/rustbox.toml

# Validate without starting
cargo run -p rustbox-app -- check-config --config examples/rustbox.toml
```

Verify the local listeners:

```powershell
curl.exe -x http://127.0.0.1:18080 https://example.com -I
curl.exe --socks5-hostname 127.0.0.1:1080 https://example.com -I
```

Set `RUSTBOX_LOG` to a `tracing-subscriber` filter such as `debug` or
`rustbox_app=info,rustbox_anytls=debug`.

## Capabilities

Inbound types:

`http-connect`, `socks5`, `mixed`, `tun`, `transparent`, `anytls`

Outbound types:

`direct`, `block`, `socks5`, `http`, `shadowsocks`, `vmess`, `vless`,
`trojan`, `anytls`, `hysteria2`, `tuic`, `naive`, `shadowtls`, `wireguard`,
`selector`, `urltest`

The routing layer supports inline, local, remote, sing-box source, and SRS rule
sets. Shared transports include TCP, WebSocket, HTTP/2, gRPC, HTTPUpgrade,
ShadowTLS, and Mux.Cool. DNS supports UDP, TCP, DoT, DoH, DoQ, caching, FakeIP,
reverse mapping, and route-level DNS hijacking.

Configuration examples and platform notes are in:

- [Routing, transports, and modern protocols](docs/p1-routing-transport.md)
- [DNS](docs/dns-transports.md)
- [`examples/rustbox.toml`](examples/rustbox.toml)
- [`examples/tun-transparent.toml`](examples/tun-transparent.toml)

Browser-style TLS fingerprinting is optional because its BoringSSL backend
requires NASM:

```powershell
cargo build -p rustbox --features fingerprint
```

## TUN and transparent proxy

Windows TUN requires an architecture-matched `wintun.dll` beside the binary,
or an absolute path in `RUSTBOX_WINTUN_DLL`. Linux uses `/dev/net/tun`; macOS
uses utun. Route and redirect changes require elevated privileges.

Start with `auto_route = false` while another VPN is active. See
[`examples/tun-transparent.toml`](examples/tun-transparent.toml) before
enabling route capture.

## Flutter

`apps/rustbox-flutter` exposes the shared async lifecycle through
`flutter_rust_bridge` and bundled native libraries. Android, iOS, Windows, and
Linux are supported; macOS, Web, and OHOS are not.

```powershell
cd apps/rustbox-flutter
flutter pub get
flutter_rust_bridge_codegen generate
cd example
flutter run
```

Generated bridge files are committed and must be regenerated when the bridge
API changes. See the [Flutter package README](apps/rustbox-flutter/README.md).

## Control API

Start the native/sing-box-compatible gRPC service and the Clash/Mihomo-compatible
HTTP/WebSocket service with:

```powershell
cargo run -p rustbox-app -- `
  --control-grpc 127.0.0.1:19090 `
  --clash-api 127.0.0.1:9090 `
  run --config examples/rustbox.toml
```

Add `--control-token <token>` for bearer authentication on both transports.
Use repeated `--clash-cors-origin <origin>` arguments when a browser dashboard
is hosted on another origin. Non-loopback listeners require a token.

The Clash listener serves code-generated OpenAPI 3.1 documentation at
`/docs/openapi.json` and a vendored, offline-capable Swagger UI at `/docs`.
The gRPC listener enables the standard v1 reflection service, so tools can discover
both RPC contracts without a separate schema path:

```powershell
grpcurl -plaintext 127.0.0.1:19090 list
grpcurl -plaintext 127.0.0.1:19090 describe rustbox.control.v1.RustBoxControl
```

When authentication is enabled, pass
`-H "authorization: Bearer <token>"` for RPC calls. Reflection and the generated
HTTP documentation expose schemas only; runtime API operations retain their normal
authorization policy.

The Clash API provides Mihomo-shaped version/config, traffic, memory, log,
connection, proxy/group, rule, and provider endpoints. Streaming endpoints work
over both newline-delimited HTTP and WebSocket; selector changes, connection
cancellation, rule-set refresh, TOML payload reload, and real outbound latency
tests are connected to the same runtime command/state graph as gRPC.

`daemon.StartedService`
keeps the sing-box-compatible selector/group wire contract. The native
`rustbox.control.v1.RustBoxControl` service additionally provides active connection
listing and cancellation, connection/log/traffic server streams, per-inbound and
per-outbound counters, process memory and engine status, rule-set status/manual
refresh, manual URLTest triggering, reload, and stop. URLTest probes use the real
outbound paths and can persist the selected child with `cache_path`.

The detailed compatibility contract and intentionally unsupported Mihomo host
management endpoints are documented in
[`docs/clash-api-compat.md`](docs/clash-api-compat.md).

## Development

Production workspace crates inherit `unsafe_code = "forbid"`. The generated
Flutter FFI bridge is the only approved exception. CI runs
`scripts/test/workspace-lints.ps1` so a newly added crate cannot silently omit
the workspace lint policy.

```powershell
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Protocol, proxy, gRPC, and TUN smoke scripts live in `scripts/test/`.

## License

MIT OR Apache-2.0.
