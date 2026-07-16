# RustBox Flutter

Flutter FFI bindings for the RustBox proxy runtime. The package exposes a
small, typed lifecycle API while the proxy engine, protocol implementations,
routing, DNS, and platform integration run in Rust.

Native libraries are precompiled and bundled with the package. Applications
using RustBox do not need Rust, Cargo, or a C toolchain to build.

## Features

- HTTP, SOCKS5, mixed, TUN, transparent, and AnyTLS inbounds
- Direct, block, HTTP, SOCKS5, Shadowsocks, VMess, VLESS, Trojan, AnyTLS,
  selector, and URL-test outbounds
- Typed start, reload, stop, close, and runtime snapshot operations
- Serialized calls per engine with support for multiple engine instances
- Stable error categories suitable for application UI and recovery logic

## Supported platforms

- Android
- iOS
- Windows
- Linux

macOS support is temporarily disabled while its precompiled bridge
packaging is stabilized. Web and OHOS are not supported. Consumers need
Flutter 3.44 or newer and Dart 3.12 or newer.

## Installation

```yaml
dependencies:
  rustbox_flutter: ^0.1.2
```

## Usage

```dart
import 'package:rustbox_flutter/rustbox_flutter.dart';

await RustBox.initialize();
final engine = await RustBoxEngine.create(configToml: config);

try {
  await engine.start();
  final snapshot = await engine.snapshot();
  print(snapshot.state);
  await engine.reload(nextConfig);
  await engine.stop();
} on RustBoxException catch (error) {
  print('${error.kind}: ${error.message}');
} finally {
  await engine.close();
}
```

`configToml` uses the same typed RustBox configuration accepted by the CLI.
A minimal configuration looks like this:

```toml
schema_version = 1

[[inbounds]]
id = "local"
type = "mixed"
listen = "127.0.0.1:2080"

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
```

Calls for one engine are serialized. Different engine objects may run
concurrently. Always call `close` when an engine is no longer needed; repeated
calls to `close` are safe.

## Errors

Native failures are translated to `RustBoxException`. Use `kind` to distinguish
invalid configuration, invalid lifecycle state, temporarily unavailable
resources, runtime failures, and unexpected bridge failures.

## Development

The Rust API is under `rust/src/api`; generated glue is under
`rust/src/frb_generated.rs` and `lib/src/rust`. After changing the Rust API:

```powershell
flutter_rust_bridge_codegen generate
cargo fmt --manifest-path rust/Cargo.toml --package rustbox-flutter-bridge
../../scripts/build/flutter-prebuilt.ps1
cd example
flutter analyze
flutter test integration_test/simple_test.dart -d windows
```

The Rust runtime, Dart runtime, and code generator use stable
`flutter_rust_bridge` 2.12.0. Upgrade them together, regenerate the bindings,
rebuild every native artifact, and validate every supported platform.
