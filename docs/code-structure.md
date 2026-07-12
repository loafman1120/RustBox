# Code structure and refactoring boundaries

RustBox organizes code by responsibility rather than by file size alone. Large
files are a signal for review, not an automatic reason to introduce another
crate or trait.

## Dependency direction

The intended direction is:

```text
apps / ffi
    -> rustbox composition root
        -> control + module adapters + platform facade
            -> kernel + host capability ports
                -> foundation types and I/O contracts
```

Foundation crates must not learn about Tokio, operating-system handles, proxy
protocols, or configuration formats. Protocol crates must not depend on the
application composition root. Platform crates implement host capabilities and
must not make routing decisions.

## Module boundaries

- Application facade: public construction and lifecycle only.
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
network value conversions live in `rustbox-host-api::net`, keeping
`rustbox-types` independent of socket semantics.

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
6. FFI: ABI value types, panic-safe pointer boundary, per-engine registry and
   lifecycle ownership, exported calls, C header, and native header/link smoke
   coverage.

The remaining candidates are deliberately outside this bounded pass:

- SOCKS5 inbound: service lifecycle, command handling, UDP association, and
  prefixed stream utilities.
These should be migrated in behavior-preserving batches. A batch is complete
only after formatting, `cargo check --workspace --all-targets`, and
`cargo test --workspace --all-targets` succeed.
