# RustBox C binding

`rustbox-ffi` builds `cdylib` and `staticlib` variants and exposes the public
API declared in `include/rustbox.h`. The ABI is currently allowed to evolve;
call `rustbox_ffi_abi_version()` before using a dynamically discovered library.

## Ownership and threading

- Engine handles are opaque values. Zero is never returned as a valid handle.
- Calls for one engine are serialized. Calls for different engines may run in
  parallel and may be made from different native threads.
- Lifecycle calls are blocking. Do not call them from a UI/event-loop thread.
- Initialize diagnostics as `{ RUSTBOX_STATUS_OK, NULL }` and call
  `rustbox_diagnostic_clear` before reusing them.
- TOML input is borrowed only for the duration of the call and must be UTF-8.
- Output pointers must remain valid and writable for the duration of the call.
- `destroy` invalidates the handle. A second destroy returns `NOT_FOUND`.
- `rustbox_engine_metrics` reads the same in-memory metrics store used by the
  Rust application and control API. Default FFI engines are store-only and do
  not write to stderr; TOML-created engines honor file observability settings.
- Reload changes the runtime graph but keeps the engine's existing
  observability sink and store, so counters remain continuous.

See `examples/basic.c` for the minimal lifecycle. Consumers should compile
against `include/rustbox.h` and link `rustbox_ffi` (`rustbox_ffi.dll`,
`librustbox_ffi.so`, `librustbox_ffi.dylib`, or the corresponding static lib).

`cargo test -p rustbox-ffi --all-targets` compiles the files under `tests/c`
with the platform C compiler, links them to the Rust exports, and executes a
complete C-driven create/start/snapshot/metrics/stop/destroy lifecycle.
