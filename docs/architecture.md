# RustBox Architecture

> **Document status:** Draft
> **Architecture version:** 0.1
> **Project:** RustBox
> **Current implementation map:** `docs/current-architecture.md`
> **Configuration and FFI design:** `docs/config-ffi-architecture.md`
> **Observability design:** `docs/observability-architecture.md`

This document defines the stable architectural boundaries for RustBox. It is
intentionally short. Current implementation details, crate inventories, test
lists, and config/FFI API detail live in the companion documents above.

---

## 1. Purpose

RustBox is a modular proxy engine organized around:

```text
portable core + capability ports + host adapters + composition root
```

The key portability rule is:

> If a module claims to be platform-independent, it must not require native
> operating-system facilities in order to compile.

This does not mean RustBox must ship as WebAssembly. The WASM-like constraint is
a design test that keeps proxy logic separate from host effects.

---

## 2. Goals

RustBox should provide:

1. A platform-independent proxy core.
2. Replaceable OS, runtime, and platform adapters.
3. Independent inbound, outbound, transport, DNS, routing, and inspection modules.
4. Explicit dependency direction.
5. Explicit lifecycle ownership.
6. Testable modules without real sockets or real operating systems.
7. A clear FFI and mobile embedding boundary.

RustBox is not designed around these assumptions:

- Tokio is the architecture.
- TUN is part of the core.
- Configuration file formats define runtime architecture.
- Dynamic plugins are mandatory.
- Internal Rust traits are the external stable ABI.
- Protocol modules directly call OS sockets or platform APIs.

---

## 3. Dependency Rule

Dependencies point inward toward abstractions:

```text
Application
    -> Composition
    -> Modules
    -> Kernel
    -> Capability Contracts
    -> Foundation

Host adapters implement capability contracts from the side.
```

Forbidden examples:

```text
rustbox-kernel -> tokio
rustbox-kernel -> rustbox-platform-windows
rustbox-kernel -> std::net::TcpStream
```

Allowed examples:

```text
rustbox-kernel -> rustbox-host-api
rustbox-runtime-tokio -> rustbox-host-api
rustbox-platform-windows -> rustbox-host-api
```

---

## 4. Layer Model

| Layer | Responsibility |
|---|---|
| L5 Application and control | CLI, app lifecycle, FFI boundary, control commands |
| L4 Composition | Builds a concrete runtime graph from validated config |
| L3 Proxy modules | Inbounds, outbounds, transports, DNS, inspection, stack adapters |
| L2 Kernel | Flow lifecycle, routing coordination, relay, sessions, reload |
| L1 Capability contracts | Network, clock, entropy, tasks, packet device, platform control |
| L0 Foundation | Portable types and runtime-neutral I/O traits |

Host/runtime/platform adapters attach to L1. They do not become part of the
portable core.

---

## 5. Core Concepts

### Flow

A flow is network work entering the engine. Inbounds create flows; they do not
choose outbounds.

```text
Inbound -> Flow -> Metadata -> Router -> Outbound -> Transport -> Host capability
```

### Capability

A capability is an effect supplied by the host, such as TCP connect, UDP bind,
time, entropy, task spawning, packet-device access, route control, or
observability output.

Portable modules request effects through capabilities. They do not call native
APIs directly.

### Module

A module creates, transforms, observes, or executes flows. Examples:

```text
inbound-http
inbound-socks5
outbound-direct
outbound-http
outbound-shadowsocks
outbound-socks5
transport-tls
dns-core
inspect
stack
```

Protocol codec logic should be separated from runtime adapters when practical.
Codec crates should parse and encode protocol data, not open sockets.

### Kernel

The kernel owns flow coordination, routing decisions, session state, relay
primitives, lifecycle state, and controlled reload.

The kernel does not own protocol parsing, OS networking, config file parsing, or
platform route manipulation.

---

## 6. Configuration

All configuration frontends feed the same staged pipeline:

```text
File / CLI / GUI / FFI / remote control
        -> SourceConfig
        -> ParsedConfig
        -> ValidatedConfig
        -> CompiledConfig
        -> Composition root
        -> Runtime graph
```

Input formats are not runtime architecture. Runtime modules receive typed,
validated configuration only.

Detailed config and FFI rules live in `docs/config-ffi-architecture.md`.

---

## 7. Application and Control

`rustbox-app` owns the concrete process lifecycle:

- parse CLI input
- load and validate configuration
- choose the composition path
- start the runtime graph
- handle Ctrl-C and shutdown
- initiate future reload paths

CLI parsing belongs at this layer. The current app may use `clap` derive, but
CLI flags and subcommands must not leak into the kernel, protocol modules, or
runtime adapters.

The current runnable forms are:

```text
cargo run -p rustbox-app
cargo run -p rustbox-app -- http-proxy
cargo run -p rustbox-app -- socks5-proxy
cargo run -p rustbox-app -- --config examples/rustbox.toml
cargo run -p rustbox-app -- run --config examples/rustbox.toml
```

The no-argument form prints the architecture summary. The default proxy commands
start local HTTP CONNECT and SOCKS5 graphs. Config-file startup enters through
`rustbox-config-file` and then follows the shared configuration pipeline.

Control frontends, including CLI, HTTP, gRPC, GUI, mobile, or embedded hosts,
must interact with engine commands and snapshots rather than direct mutable
kernel internals.

---

## 8. Composition

Composition is where abstract components become a concrete RustBox instance.

It is the layer that selects:

- runtime adapter
- platform adapter
- observability sink
- enabled modules
- route table
- validated compiled configuration

RustBox prefers explicit construction over global context. Constructors should
not bind sockets, open packet devices, spawn background tasks, or mutate system
routes. Long-lived resources are acquired during explicit start/lifecycle
transitions.

---

## 9. Platform and Runtime Adapters

Runtime adapters implement executor and I/O details such as:

- task spawning
- timers
- TCP and UDP networking
- runtime-specific stream adapters

Platform adapters implement OS facilities such as:

- packet devices
- route control
- transparent proxy integration
- process metadata
- platform event monitoring

Unsupported capabilities must be explicit. The kernel must not infer platform
support from scattered `cfg(target_os)` branches.

---

## 10. FFI Boundary

FFI sits outside the kernel. It exposes coarse engine and configuration
operations through stable handles and versioned status codes.

FFI must not expose:

- Rust trait objects
- Tokio types
- Rust references
- internal module pointers
- internal Rust enums without explicit representation

Mobile and desktop embeddings are built on this boundary.

---

## 11. Observability

The core emits structured events through an observability capability. Detailed
implementation and API rules live in `docs/observability-architecture.md`.

Portable crates may define event kinds and attach flow identifiers. The
application or embedding host chooses the final sink, such as console, recording
sink, metrics/query store, platform-native logging, file logging, or remote
telemetry.

Runtime metrics and connection statistics are derived from the same structured
event stream. Control frontends, including HTTP, gRPC, GUI, mobile, FFI, or
compatibility APIs, query snapshots and bounded event history rather than direct
mutable kernel state.

High-frequency data-plane accounting should avoid synchronous formatted logging
and should not make remote telemetry part of the relay hot path.

---

## 12. Reload

Reload follows a compile-and-swap model:

```text
new source config
    -> parse
    -> validate
    -> compile runtime plan
    -> prepare replacement graph
    -> commit
    -> drain old graph
```

A reload must not mutate the live engine incrementally while validation is still
in progress. New flows use the new graph after commit; existing flows may
continue on the plan selected when they were created.

---

## 13. Testing

The architecture must allow core behavior to be tested without real OS
networking.

Required test styles:

- protocol codec unit tests
- module tests with fake capabilities
- kernel integration tests with a deterministic test host
- app and FFI boundary tests
- platform integration tests for real OS capabilities

---

## 14. Invariants

These rules are mandatory:

1. Portable core crates do not import OS implementation crates.
2. Portable core APIs do not expose native handles or Tokio types.
3. Inbounds create flows; they do not choose outbounds.
4. Routing consumes metadata and returns a decision.
5. OS metadata acquisition is an enrichment capability, not router logic.
6. TUN device creation belongs to a platform capability.
7. Stream, datagram, and packet I/O remain distinct abstractions.
8. Constructors do not acquire long-lived OS resources.
9. Background tasks have explicit lifecycle owners.
10. Config parsing is outside protocol runtime logic.
11. External FFI ABI is separate from internal Rust traits.
12. Platform support is expressed through capabilities.

---

## 15. Current Implementation

The current implementation map is maintained in `docs/current-architecture.md`.
That file owns crate lists, current module coverage, verification commands,
implemented tests, and known gaps.

At a high level, the current executable proof is:

```text
HTTP CONNECT or SOCKS5 inbound
    -> kernel flow submission
    -> route table
    -> direct outbound
    -> Tokio host network capability
```

Known planned areas include full TUN and packet stack integration, platform
route control, richer config handles, a networked HTTP/gRPC control API, and
concrete platform/remote telemetry adapters.
