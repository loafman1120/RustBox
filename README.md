# RustBox

RustBox is a modular proxy engine written in Rust. The project is organized as
a portable core, host capability contracts, replaceable runtime/platform
adapters, protocol modules, and a composition root.

The repository currently includes a runnable minimum proxy graph:

```text
HTTP CONNECT inbound -> RustBox kernel -> route table -> direct outbound -> Tokio host
```

For the full target architecture, see `docs/architecture.md`. For what exists
in code today, see `docs/current-architecture.md`.

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

The default proxy listens on:

```text
127.0.0.1:18080
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
submission, route decisions, direct outbound connection attempts, flow
completion, and failures.

## Verify The Proxy

In another terminal, send an HTTPS request through the proxy:

```powershell
curl.exe -x http://127.0.0.1:18080 https://example.com -I
```

Use an `https://` URL for this quick check. The current inbound supports HTTP
CONNECT tunnels; plain `http://` proxy requests that use absolute-form `GET`
are not implemented yet.

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

- HTTP CONNECT inbound over TCP.
- Direct TCP outbound through the host network capability.
- Portable kernel flow submission, routing, metadata enrichment pipeline, and
  stream relay.
- Staged configuration model: source, parsed, validated, compiled.
- Structured observability through `ObservabilitySink`, with no-op, console,
  and recording sinks.
- Tokio-backed host adapter for TCP, UDP binding, clock, entropy, and task
  spawning.
- Test host, registry model, plugin manifest model, reload transaction model,
  FFI handle model, and Windows platform boundary.

## Current Limits

- The app uses the built-in default config only; there is no CLI config file
  loader yet.
- The default listen address is fixed at `127.0.0.1:18080`.
- Direct UDP forwarding is not implemented yet.
- SOCKS5 exists as a portable codec, but SOCKS5 inbound/outbound runtime modules
  are not implemented yet.
- TUN, packet-to-flow stack, route control, transparent proxy, and process
  lookup are planned extension points.
- File, tracing, platform-native, and remote telemetry log sinks are not
  implemented yet.

## Workspace Layout

```text
apps/rustbox                         application entrypoint
crates/compose/rustbox-compose       composition root
crates/control/rustbox-config        configuration pipeline
crates/control/rustbox-control       control commands and snapshots
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
