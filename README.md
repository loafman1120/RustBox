# RustBox
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Floafman1120%2FRustBox.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Floafman1120%2FRustBox?ref=badge_shield)


**A client-side network engine for applications that need a dependable local
proxy.**

RustBox brings routing, DNS, proxy protocols, TUN integration, and runtime
control into one Rust engine. It powers both a command-line client and an
embeddable Flutter package, so an application can use the same network behavior
on desktop and mobile.

> RustBox is under active development. Protocol support and configuration may
> change before the first stable release.

## The goal

RustBox is built for one user on one device. The client owns the engine, its
configuration, the local control plane, and any changes made to device
networking.

The project prioritizes the things a real client must do well:

- start, reload, and stop without leaking background tasks;
- route TCP, UDP, and DNS traffic through one consistent policy;
- react to network changes and restore system state after shutdown or failure;
- expose useful traffic, connection, and proxy state to a local UI;
- keep platform-specific behavior behind a portable application API.

RustBox is not an Internet-facing, multi-tenant proxy server or a sandbox for
untrusted modules. Proxy and control listeners should remain on loopback unless
authentication and transport security are provided by a trusted boundary.

## Try it

Build the workspace and start the example client:

```powershell
cargo build --workspace
cargo run -p rustbox-app -- run --config examples/rustbox.toml
```

The example opens HTTP CONNECT on `127.0.0.1:18080`, SOCKS5 on
`127.0.0.1:1080`, and a mixed listener on `127.0.0.1:2080`.

```powershell
# Validate configuration without starting the client
cargo run -p rustbox-app -- check-config --config examples/rustbox.toml

# Test a local listener
curl.exe -x http://127.0.0.1:18080 https://example.com -I
```

Set `RUSTBOX_LOG=debug` for detailed logs.

## Client surfaces

### CLI

`apps/rustbox-cli` is the reference host. It loads TOML, owns the engine
lifecycle, responds to network changes, and can expose local gRPC and
Clash/Mihomo-compatible control APIs.

### Flutter

`apps/rustbox-flutter` packages the same engine behind a small async lifecycle
API. Prebuilt native libraries let Flutter applications consume it without a
Rust toolchain. Android, iOS, Windows, and Linux are supported.

See the [Flutter package guide](apps/rustbox-flutter/README.md).

## What is included

- HTTP CONNECT, SOCKS5, mixed, TUN, transparent, and AnyTLS inbounds
- direct/block and common encrypted proxy outbounds, including Shadowsocks,
  VMess, VLESS, Trojan, Hysteria2, TUIC, WireGuard, and grouped selection
- domain, IP, process, network, and rule-set routing
- UDP, TCP, DoT, DoH, and DoQ DNS with caching, FakeIP, and DNS hijacking
- TCP, WebSocket, HTTP/2, gRPC, HTTPUpgrade, ShadowTLS, and Mux transports
- connection, traffic, log, selector, rule-set, reload, and stop controls

The examples are the configuration reference:

- [`examples/rustbox.toml`](examples/rustbox.toml) — proxy, routing, DNS, and
  outbound examples
- [`examples/tun-transparent.toml`](examples/tun-transparent.toml) — TUN and
  transparent networking

## Design at a glance

```text
CLI / Flutter
    -> rustbox (composition and lifecycle)
        -> config + control + modules + platform adapters
            -> kernel (flows, routing, relay, host capabilities)
                -> foundation (shared types and Tokio I/O)
```

Tokio is the only production executor. Configuration moves through
`TOML -> normalize -> validate -> compile -> runtime`, and operating-system
changes are represented by handles that can be rolled back.

## Documentation

Start with the [documentation index](docs/README.md):

- [Architecture](docs/architecture.md)
- [Configuration and protocols](docs/configuration.md)
- [Client networking and TUN](docs/client-networking.md)
- [Control APIs](docs/control-api.md)

## Development

```powershell
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Production crates forbid unsafe Rust; generated Flutter FFI glue is the only
approved exception. Smoke and end-to-end helpers live in `scripts/test/`.

## License

MIT


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Floafman1120%2FRustBox.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Floafman1120%2FRustBox?ref=badge_large)