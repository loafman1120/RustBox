# RustBox

RustBox is a modular proxy engine written in Rust. The project is organized as
a portable core, host capability contracts, replaceable runtime/platform
adapters, protocol modules, and a composition root.

The repository currently includes a runnable minimum proxy graph:

```text
HTTP / mixed / SOCKS5 inbound -> RustBox kernel -> route table -> outbound -> Tokio host
```

For the full target architecture, see `docs/architecture.md`. For what exists
in code today, see `docs/current-architecture.md`. For the recommended
configuration and FFI direction, see `docs/config-ffi-architecture.md`. For the
TUN, transparent proxy, system routing, and process lookup design, see
`docs/tun-transparent-proxy-architecture.md`.

## Requirements

- Rust toolchain with edition 2024 support.
- Network access for any upstream hosts you test through the proxy.

## Build

```powershell
cargo build --workspace
```

## Run

Print the architecture summary:

```powershell
cargo run -p rustbox-app
```

Start the default HTTP CONNECT proxy:

```powershell
cargo run -p rustbox-app -- http-proxy
```

Start the default SOCKS5 proxy:

```powershell
cargo run -p rustbox-app -- socks5-proxy
```

Start from a TOML config file:

```powershell
cargo run -p rustbox-app -- --config examples/rustbox.toml
```

The default proxies listen on:

```text
HTTP CONNECT: 127.0.0.1:18080
SOCKS5:       127.0.0.1:1080
```

Stop it with `Ctrl+C`.

## Logging

`rustbox-app` writes structured runtime logs to stderr by default. Control the
minimum log level with `RUSTBOX_LOG`:

```powershell
$env:RUSTBOX_LOG = "debug"
cargo run -p rustbox-app -- http-proxy
```

Supported levels are:

```text
trace, debug, info, warn, error, off
```

The current log events cover service lifecycle, accepted TCP connections, flow
submission, route decisions, direct outbound connection attempts, relay traffic
bytes, flow completion, and failures.

When starting with `--config`, `[observability] level = "info"` in the TOML
file controls the console log level. `RUSTBOX_LOG` is still used as the fallback
when the file omits that setting.

Add `file = "target/rustbox.log"` under `[observability]` to append the same
structured event stream to a file. Metrics, connection statistics, bounded event
queries, platform log bridges, and remote telemetry exporter bridges are
implemented in `rustbox-observability`; the gRPC control API reads from that
same store.

## Control gRPC API

Start a local gRPC control service next to the proxy:

```powershell
cargo run -p rustbox-app -- --control-grpc 127.0.0.1:19090 http-proxy
```

The service exposes native RustBox observation/control methods for metrics,
connections, event queries, snapshots, and stop.

Loopback listeners may run without a token. Non-loopback listeners require a
bearer token:

```powershell
cargo run -p rustbox-app -- --control-grpc 0.0.0.0:19090 --control-token secret http-proxy
```

Clients can pass `authorization: Bearer <token>` metadata, or
`x-rustbox-token: <token>`.

## Config File

The app accepts TOML config files that are parsed by `rustbox-config-file` into
the same format-neutral `SourceConfig` used by FFI and built-in defaults.

```toml
schema_version = 1

[observability]
level = "info"
# file = "target/rustbox.log"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:18080"
# Optional inbound Basic proxy auth.
# username = "alice"
# password = "secret"

[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:1080"
# Optional inbound SOCKS5 username/password auth.
# username = "alice"
# password = "secret"

[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:2080"
# Optional auth is applied to both HTTP Basic and SOCKS5 password auth.
# username = "alice"
# password = "secret"

[[outbounds]]
id = "direct"
type = "direct"

# Drop matched traffic with a policy rejection.
[[outbounds]]
id = "block"
type = "block"

# Forward through an upstream SOCKS5 proxy.
[[outbounds]]
id = "socks-out"
type = "socks5"
server = "127.0.0.1:1081"
# username = "alice"
# password = "secret"

# Forward through an upstream HTTP CONNECT proxy.
[[outbounds]]
id = "http-out"
type = "http"
server = "proxy.example.test:8080"
# username = "alice"
# password = "secret"

# Forward through an upstream Shadowsocks server.
[[outbounds]]
id = "ss-out"
type = "shadowsocks"
server = "ss.example.test:8388"
method = "aes-128-gcm"
password = "test-password"

# Optional inline rule-set, referenced by ordered route rules.
[[rule_sets]]
id = "ads"
type = "inline"
rules = [
  { type = "rule", domain_keyword = ["ads", "tracker"] },
]

[[routes]]
type = "rule"
inbound = ["http", "mixed"]
network = ["tcp"]
domain_suffix = ["example.test"]
port = [443]
rule_set = ["ads"]
outbound = "block"

[[routes]]
type = "default"
outbound = "direct"
```

Supported inbound `type` values are `http-connect`, `socks5`, and `mixed`. Supported
outbound `type` values are `direct`, `block`, `socks5`, `http`, and
`shadowsocks`. The current runtime can instantiate `direct`, `socks5`, `http`,
and `shadowsocks`; `block` compiles to a policy rejection.

Route rules are evaluated in file order before the default route. Supported
match fields are `inbound`, `network`, `domain`, `domain_suffix`,
`domain_keyword`, `domain_regex`, `ip_cidr`, `source_ip_cidr`, `port`,
`port_range`, `source_port`, `source_port_range`, `rule_set`, and `invert`.
Rules can use `outbound = "..."` or `reject = "policy"`. `type = "logical"`
supports `mode = "and"` / `"or"` with nested rules. Rule-sets can be inline or
loaded from local TOML files with `[[rule_sets]] type = "local"`.

## FFI Compatibility

The C ABI convenience functions for default HTTP CONNECT and SOCKS5 proxies are
still available. Additional TOML-based entrypoints allow embedding hosts to
validate, create, and reload from the same config text accepted by the app:

```c
rustbox_validate_config_toml(...)
rustbox_engine_create_from_config_toml(...)
rustbox_engine_reload_config_toml(...)
```

## Verify The Proxy

In another terminal, send an HTTPS request through the proxy:

```powershell
curl.exe -x http://127.0.0.1:18080 https://example.com -I
```

Use an `https://` URL to exercise CONNECT tunnels, or an `http://` URL to
exercise ordinary absolute-form HTTP proxy requests.

Verify SOCKS5:

```powershell
curl.exe --socks5-hostname 127.0.0.1:1080 https://example.com -I
```

## Test And Lint

Run the workspace tests:

```powershell
cargo test --workspace
```

Check formatting:

```powershell
cargo fmt --all --check
```

Run clippy with warnings denied:

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

## Current Capabilities

- HTTP inbound over TCP with CONNECT tunnels, ordinary absolute-form proxy
  requests, and optional Basic authentication.
- SOCKS5 inbound over TCP with CONNECT, UDP ASSOCIATE, no-authentication, and
  username/password authentication.
- mixed inbound over TCP that accepts HTTP proxy and SOCKS5 connections on one
  listener.
- Direct TCP and UDP outbound through the host network capability.
- Portable kernel flow submission, ordered rule routing, metadata enrichment
  pipeline, and stream relay.
- Staged configuration model: source, parsed, validated, compiled.
- Structured observability through `ObservabilitySink`, with no-op, console,
  recording, metrics/query store, file, platform-bridge, and remote-telemetry
  bridge sinks.
- Native gRPC control API over `ObservabilityStore` and `ControlState`.
- Tokio-backed host adapter for TCP, UDP binding, clock, entropy, and task
  spawning.
- Test host, registry model, plugin manifest model, reload transaction model,
  FFI handle model, and Windows platform boundary.

## Current Limits

- SOCKS5 `BIND` is not implemented yet.
- Windows/Linux TUN packet devices are available through `tun-rs`; basic
  `AddRoute` network control uses `net-route`. TUN inbound, packet-to-flow
  stack, transparent proxy, process lookup, and fuller route control remain
  planned extension points.
- HTTP and Clash REST control compatibility APIs are not implemented yet.
- Concrete ETW, Android logcat, Apple unified logging, tracing, and OTLP
  exporter adapters are not implemented yet.

## Workspace Layout

```text
apps/rustbox                         application entrypoint
crates/compose/rustbox-compose       composition root
crates/control/rustbox-config        configuration pipeline
crates/control/rustbox-control       control commands and snapshots
crates/control/rustbox-control-api   gRPC control and stats API
crates/ffi/rustbox-ffi               FFI handle boundary
crates/foundation/rustbox-types      portable data types
crates/foundation/rustbox-io         runtime-neutral IO traits
crates/host/rustbox-host-api         host capability contracts
crates/host/rustbox-test-host        deterministic test host
crates/kernel/rustbox-kernel         flow, lifecycle, relay, engine
crates/kernel/rustbox-route          route decisions and tables
crates/kernel/rustbox-registry       construction-time registry
crates/modules/*                     protocol and subsystem modules
crates/observability/*               log and event sink adapters
crates/platform/*                    platform capability adapters
crates/runtime/rustbox-runtime-tokio Tokio host adapter
```
