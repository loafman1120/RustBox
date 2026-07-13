# RustBox C binding

`rustbox-ffi` builds `cdylib` and `staticlib` variants and exposes the v2 public
API declared in `include/rustbox.h`. The ABI is currently allowed to evolve;
call `rustbox_ffi_abi_version()` before using a dynamically discovered library.

## Ownership and threading

- Engine handles are opaque values. Zero is never returned as a valid handle.
- Calls for one engine are serialized. Calls for different engines may run in
  parallel and may be made from different native threads.
- Prefer `rustbox_engine_start`, `rustbox_engine_reload`,
  and `rustbox_engine_stop`. They enqueue work and immediately return a
  request handle, so they are safe to invoke from a Flutter UI isolate.
- Poll `rustbox_engine_request_poll` from a timer or background isolate. A
  completed request is consumed by the poll; polling it again returns
  `RUSTBOX_STATUS_NOT_FOUND`.
- Lifecycle mutation is exposed only through non-blocking request submission;
  there are no blocking `start`, `reload`, or `stop` ABI functions.
- Initialize diagnostics as `{ RUSTBOX_STATUS_OK, NULL }` and call
  `rustbox_diagnostic_clear` before reusing them.
- TOML input is borrowed only for the duration of the call and must be UTF-8.
- Output pointers must remain valid and writable for the duration of the call.
- `destroy` invalidates the handle. A second destroy returns `NOT_FOUND`.
- The FFI deliberately does not create console or file logging sinks on mobile
  hosts. Advanced telemetry should use a separate event API rather than expand
  the lifecycle ABI.
- Reload changes the runtime graph but keeps the engine's existing
  observability sink and store, so counters remain continuous.

See `examples/basic.c` for the minimal lifecycle. Flutter and other GUI consumers
should use the asynchronous lifecycle functions. Consumers should compile
against `include/rustbox.h` and link `rustbox_ffi` (`rustbox_ffi.dll`,
`librustbox_ffi.so`, `librustbox_ffi.dylib`, or the corresponding static lib).

`cargo test -p rustbox-ffi --all-targets` compiles the files under `tests/c`
with the platform C compiler, links them to the Rust exports, and executes a
complete C-driven create/start/snapshot/stop/destroy lifecycle.

CI also runs `scripts/test/ffi.ps1` on Linux, Windows, and macOS. This
builds the shared library, separately compiles a native C application, links
the two artifacts dynamically, and sends an HTTP request through the proxy
created by the public ABI. The test validates the response body before stopping
and destroying the engine.

## Mobile builds

Android is compiled in CI for `arm64-v8a`. For a local release build, install
`cargo-ndk`, set `ANDROID_NDK_HOME`, and run:

```powershell
./scripts/build/mobile.ps1 -Platform Android -Locked
```

This produces ABI-specific shared libraries under `dist/android` for
`arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`. Pass
`-AndroidTargets arm64-v8a` to build only the most common physical-device ABI,
or use `-AndroidApi 24` to change the minimum Android API (the default is 21).

iOS builds are available as a lightweight macOS/Xcode-only path:

```powershell
./scripts/build/mobile.ps1 -Platform IOS -Locked
```

The iOS command must run on macOS with Xcode. It builds arm64 device code plus
arm64 and x86_64 simulator code, then creates
`dist/ios/RustBoxFFI.xcframework` with the public C header included. The
XCFramework can be linked directly by a Flutter iOS plugin.

CI runs `mobile_lifecycle_smoke.c` as a real native consumer in an Android
x86_64 Emulator and an iOS arm64 Simulator. Both mobile jobs exercise ABI
version discovery and the complete asynchronous create, start, snapshot,
reload, stop, and destroy lifecycle. The existing desktop FFI E2E additionally
checks the HTTP proxy data path on Linux, Windows, and macOS.
