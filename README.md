# RustBox

Modular proxy engine in Rust, built on Tokio.

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

## Config

See `examples/rustbox.toml`. Inbound types: `http-connect`, `socks5`, `mixed`.

The configuration frontend uses Figment and Serde for typed TOML loading,
Garde for field-local validation, and Miette-compatible diagnostics. Existing
`load_toml_file` callers are file-only and deterministic. Applications that
need environment overrides can use `ConfigLoader::with_env_prefix("RUSTBOX_")`;
nested keys are separated with `__` (for example,
`RUSTBOX_OBSERVABILITY__LEVEL=debug`). Cross-reference and protocol checks are
performed later by `rustbox-config`, after the document has been normalized.
Outbound types: `direct`, `block`, `socks5`, `http`, `shadowsocks`, `anytls`.

The `anytls` outbound uses the pinned, protocol-compatible `anytls 0.2.3`
client and is continuously tested against a sing-box AnyTLS server. See the
[architecture](docs/architecture.md#anytls).

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
$env:RUSTBOX_SBOX_OUTBOUND = "anytls"
./scripts/test/outbound.ps1
```
