# Code structure and refactoring boundaries

RustBox organizes code by responsibility rather than by file size alone. Large
files are a signal for review, not an automatic reason to introduce another
crate or trait.

## Dependency direction

The intended direction is:

```text
apps/rustbox-cli + apps/rustbox-flutter/rust
    -> rustbox composition root / async RustBox lifecycle
        -> control + module adapters + platform facade
            -> kernel + host capability ports
                -> foundation types and shared Tokio I/O contracts
```

`rustbox-types` remains runtime-neutral and dependency-free. `rustbox-io` may
use Tokio's `AsyncRead` and `AsyncWrite` traits because Tokio is the workspace's
single runtime, but foundation crates must not own concrete sockets,
operating-system handles, proxy protocols, or configuration formats. Protocol
crates must not depend on the application composition root. Platform crates
implement host capabilities and must not make routing decisions.

## Workspace layout

The top-level directories have distinct ownership rules:

| Location | Owns | Must not own |
|---|---|---|
| `apps/` | Product executables, Flutter entry, and process concerns | Reusable engine behavior |
| `crates/foundation/` | Runtime-neutral types and shared I/O contracts; Tokio stream traits are allowed in `rustbox-io` | Concrete sockets, OS handles, configuration formats |
| `crates/kernel/` | Data-plane primitives, routing, registries, host capability ports | CLI or Flutter concerns |
| `crates/control/` | Semantic configuration and control-plane APIs | Platform implementations |
| `crates/modules/` | Protocols, inbounds, outbounds, inspection, DNS, transport, stack | Application composition |
| `crates/platform/` | Target-specific implementations of kernel host capabilities | Routing policy |
| `crates/rustbox*` | Composition/lifecycle, file configuration, and observability | Product-specific UI behavior |
| `scripts/build/`, `scripts/test/` | Repository build and smoke/E2E entry points | Flutter app build logic |

`apps/rustbox-flutter/rust` is both part of the Flutter app and a Cargo
workspace member. Generated Flutter/bridge files stay with that package rather
than being promoted into reusable Rust crates.

## Module boundaries

- Application facade: public construction and async lifecycle only.
- Flutter bridge: serialize access with Tokio synchronization while reusing the
  executor supplied by `flutter_rust_bridge`.
- Composition: translate compiled configuration into runtime objects.
- Runtime: own an already composed engine and service collection.
- Control: own control-plane tasks and channels.
- Routing adapter: translate control-plane route models into kernel models.
- Platform adapter: select target-specific capabilities.
- Protocol module: wire format and protocol state machine.
- Inbound/outbound adapter: translate a protocol session into kernel I/O traits.

## Refactoring triggers

Review a module when one of these conditions is met:

- it contains more than one lifecycle owner;
- configuration parsing, validation, compilation, and runtime construction are
  mixed in the same function;
- adding one protocol requires edits in unrelated lifecycle or platform code;
- a value conversion or error mapping is copied into three or more crates;
- tests account for most of a production module and obscure its public surface;
- a platform file mixes capability reporting, process lookup, packet I/O, and
  network transaction execution.

The preferred correction is a private module inside the existing crate. Create
a new crate only when the code needs an independently enforceable dependency
boundary or is reused across multiple existing crates.

## Current audit

The `rustbox` crate root is now a facade. Application lifecycle, graph building,
inbound and outbound construction, routing, platform selection, control service,
runtime ownership, errors, and tests live in focused modules. Protocol capability
checks are validated in `rustbox-config` before composition. Standard-library
host capability contracts, Tokio implementations, and network conversions live
in `rustbox-kernel::host`; they are separated by files rather than thin crates.

The repository no longer contains a supported C ABI or a hosted synchronous
runtime facade. `apps/rustbox-ffi`, `rustbox-host-api`, `HostedRustBox`, and the
mobile/FFI scripts were removed. The supported non-CLI product surface is now
`apps/rustbox-flutter`, whose async bridge reuses the shared `RustBox`
lifecycle and keeps Flutter build/test concerns inside the package.

The completed bounded splits are:

1. `rustbox-config`: semantic models and compiler implementation.
2. `rustbox-config-file`: public facade, Figment providers, Serde document
   model, Garde leaf validation, migration, and Miette diagnostics,
   and tests.
3. Linux platform: network control, packet device, process lookup, and
   transparent proxy.
4. Windows platform: network control, packet device, and process lookup.
5. Observability: configuration/basic sinks, store/query model, host sinks, and
   event formatting.
6. Flutter bridge: stable Dart facade, generated flutter_rust_bridge glue,
   Native Assets build hook, direct async lifecycle calls, and five-platform
   lifecycle coverage.

The remaining candidates are deliberately outside this bounded pass:

- SOCKS5 inbound: service lifecycle, command handling, UDP association, and
  prefixed stream utilities.
These should be migrated in behavior-preserving batches. A batch is complete
only after formatting, `cargo check --workspace --all-targets`, and
`cargo test --workspace --all-targets` succeed.
