# RustBox

Modular proxy engine in Rust, built on Tokio.

## Architecture

The repository is organized around one composition root and one async runtime:

```text
apps (CLI / Flutter)
    -> rustbox lifecycle and composition
        -> control + protocol modules + platform adapters
            -> kernel host ports
                -> foundation types and Tokio I/O contracts
```

Tokio is the only production executor. Accept and session tasks are owned by
generation-scoped `TaskScope`s (`CancellationToken` + `TaskTracker`), so reload
can stop accepting new flows while existing sessions drain for a bounded time.
The project does not expose a synchronous runtime facade or create a second
runtime for Flutter.

Dynamic allocation is kept at heterogeneous runtime boundaries: `Service`,
`Outbound`, byte/datagram I/O, observability sinks, and operating-system
capability providers. Routing and protocol inspection use concrete types where
runtime substitution is unnecessary. The workspace forbids handwritten
`unsafe` Rust; the Flutter bridge's generated native export is the only FFI
boundary.

Known cleanup work is deliberately narrower than a redesign: choose one
workspace-wide rustls crypto provider, remove or adopt the currently unused
`rustbox-transport` prototype, replace the SOCKS5 UDP association's hand-managed
waker, bring the VMess framing task under structured task ownership, and split
the largest SOCKS5/config/control modules without adding pass-through crates.
UDP session limits and idle eviction are not yet implemented. See
[architecture](docs/architecture.md) and
[code structure](docs/code-structure.md) for the stable boundaries and current
roadmap.

## Website design

`website/` is a dependency-free, static project showcase. It is designed as an
interactive technical whitepaper rather than a conventional product landing
page: the narrative follows a flow from request ingress, through routing and
runtime composition, to protocols and a runnable local setup.

```text
Hero / shared lifecycle
        ↓
Data plane / inbound → enrich → route → outbound → relay
        ↓
Composition boundaries / application → kernel → foundation
        ↓
Connection surfaces / inbound and outbound protocols
        ↓
Control plane / TOML → normalize → validate → compile → RustBox
        ↓
Getting started / build → run → verify
```

Its visual language is **engineering editorial × network debugger**:

- graphite background and fine technical rules keep the page close to a tool,
  not a SaaS dashboard;
- icy cyan denotes the data plane, while amber denotes configuration and
  control-plane signals;
- a transparent system box in the hero visualizes the shared RustBox
  lifecycle, with a moving packet path as the primary motion cue;
- architecture is shown with open diagrams, rails, and layers instead of
  marketing cards or unverified performance claims.

The page intentionally uses only HTML, CSS, and small native JavaScript
interactions (scroll progress, reveal transitions, packet motion, and command
copying). It can be hosted on GitHub Pages or any static file server without a
frontend build tool. Its technical copy is derived from `README.md` and
`docs/architecture.md`; update those facts alongside the page when protocol or
lifecycle support changes.

Preview it locally with a static server rooted at `website/`; see
[`website/README.md`](website/README.md) for an example.

## Build

```powershell
cargo build --workspace
```

## Flutter app

`apps/rustbox-flutter` sits beside `apps/rustbox-cli` as the supported
Dart/Flutter product entry. It
uses `flutter_rust_bridge` 2.13.0-beta.5 and Flutter Native Assets to compile
and bundle `rustbox-flutter-bridge` for Android, iOS, Windows, macOS, and Linux.
Web and OHOS are not supported because RustBox depends on native Tokio, socket,
TUN, and platform-control capabilities.

```powershell
cd apps/rustbox-flutter
flutter pub get
flutter_rust_bridge_codegen generate
cd example
flutter run
```

Applications initialize the bridge once, create an engine from TOML, then
await lifecycle completion directly:

```dart
await RustBox.initialize();
final engine = await RustBoxEngine.create(configToml: config);
await engine.start();
final snapshot = await engine.snapshot();
await engine.close();
```

Native Assets builds from Rust source, so consumers need the pinned Rust 1.97.0
toolchain. Generated Rust and Dart bridge files are committed; regenerate them
after changing the bridge API and include the output in the same change.

## Run

```powershell
# show help
cargo run -p rustbox-app

# default HTTP CONNECT proxy (127.0.0.1:18080)
cargo run -p rustbox-app -- http-proxy

# default SOCKS5 proxy (127.0.0.1:1080)
cargo run -p rustbox-app -- socks5-proxy

# from a TOML config
cargo run -p rustbox-app -- run --config examples/rustbox.toml

# validate a config without starting
cargo run -p rustbox-app -- check-config --config examples/rustbox.toml

# print platform capabilities
cargo run -p rustbox-app -- platform-capabilities
```

Stop with `Ctrl+C`.

## Logging

RustBox uses `tracing` for structured application and protocol logs. Set
`RUSTBOX_LOG` to a level or a `tracing-subscriber` filter directive:

```powershell
$env:RUSTBOX_LOG = "debug"
cargo run -p rustbox-app -- http-proxy
```

Levels: `trace`, `debug`, `info`, `warn`, `error`, `off`.

Crate-specific filters are also supported, for example
`RUSTBOX_LOG=rustbox_anytls=debug,rustbox_app=info`.

## Control gRPC

```powershell
cargo run -p rustbox-app -- --control-grpc 127.0.0.1:19090 http-proxy
# with auth:
cargo run -p rustbox-app -- --control-grpc 0.0.0.0:19090 --control-token secret http-proxy
```

The API can inspect outbound groups and switch a `selector` without reloading:

```powershell
grpcurl -plaintext -import-path crates/control/rustbox-control-api/proto `
  -proto started_service.proto 127.0.0.1:19090 `
  daemon.StartedService/SubscribeGroups

grpcurl -plaintext -import-path crates/control/rustbox-control-api/proto `
  -proto started_service.proto `
  -d '{"groupTag":"select","outboundTag":"ss-out"}' `
  127.0.0.1:19090 daemon.StartedService/SelectOutbound
```

Add `-H 'authorization: Bearer secret'` when a control token is configured.
The outbound-group API uses sing-box's `daemon.StartedService` wire contract;
`SubscribeGroups` stays open and publishes the initial state and later changes.
Only `selector` groups are manually selectable; `urltest` groups are reported
but remain read-only until active latency probing is implemented. See the
[sing-box behavior investigation](docs/sing-box-outbound-selection.md).

## Config

See `examples/rustbox.toml`. Inbound types: `http-connect`, `socks5`, `mixed`,
`tun`, `transparent`, `anytls`.

The configuration frontend uses Figment and Serde for typed TOML loading,
Garde for field-local validation, and Miette-compatible diagnostics. Existing
`load_toml_file` callers are file-only and deterministic. Applications that
need environment overrides can use `ConfigLoader::with_env_prefix("RUSTBOX_")`;
nested keys are separated with `__` (for example,
`RUSTBOX_OBSERVABILITY__LEVEL=debug`). Cross-reference and protocol checks are
performed later by `rustbox-config`, after the document has been normalized.
Outbound types: `direct`, `block`, `socks5`, `http`, `shadowsocks`, `vmess`,
`vless`, `trojan`, `anytls`, `selector`, `urltest`.

The `anytls` outbound uses the pinned, protocol-compatible `anytls 0.2.3`
client and is continuously tested against a sing-box AnyTLS server. See the
[architecture](docs/architecture.md#anytls).

The DNS subsystem supports rule-based UDP, TCP, DoT, DoH, and DoQ upstreams,
one bounded cache, FakeIP allocation, and TTL-based reverse domain recovery for
later routing. Upstream transports currently dial directly; DNS hijack targets
can be applied to TUN configuration, but a local port-53 responder is not yet
implemented. See [DNS transports](docs/dns-transports.md).

## Verify

```powershell
curl.exe -x http://127.0.0.1:18080 https://example.com -I
curl.exe --socks5-hostname 127.0.0.1:1080 https://example.com -I
```

## TUN

Windows TUN requires Administrator privileges and the official architecture-
matched `wintun.dll` from [wintun.net](https://www.wintun.net/). Put it beside
`rustbox-app.exe` or set `RUSTBOX_WINTUN_DLL` to its absolute path. Linux uses
`/dev/net/tun`; macOS uses utun.

Start with `auto_route = false` while another VPN is active. For a full tunnel,
stop the competing VPN, enable `auto_route`, and run with elevated privileges.
`strict_route` installs split `/1` routes, `route_excludes` preserve the current
best route, `dns_hijack` configures the TUN interface DNS servers, and
`platform_http_proxy` uses the first mixed/HTTP inbound in the same config.
`auto_redirect` is an alias for TUN route capture; WFP/nft redirect belongs to a
transparent inbound and is intentionally not stacked on a layer-3 TUN.

## Test

```powershell
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cd apps/rustbox-flutter/example
flutter analyze
flutter test integration_test/simple_test.dart -d windows
$env:RUSTBOX_SBOX_OUTBOUND = "anytls"
./scripts/test/outbound.ps1
```
