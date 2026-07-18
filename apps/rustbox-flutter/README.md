# RustBox Flutter

Flutter FFI bindings for the RustBox proxy runtime. The Dart surface is a
small lifecycle API; proxy protocols, routing, DNS, and platform integration
remain in Rust.

Native libraries are precompiled and bundled with the package. Applications
using RustBox do not need Rust, Cargo, or a C toolchain to build.

## Supported platforms

- Android
- iOS
- Windows
- Linux

macOS, Web, and OHOS are not supported. Consumers need Flutter 3.44+ and Dart
3.12+.

## Installation

```yaml
dependencies:
  rustbox_flutter: ^0.1.4
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

`configToml` is the same TOML configuration accepted by the RustBox CLI. For
supported inbound, outbound, routing, and DNS options, use the repository
[configuration examples](https://github.com/loafman1120/RustBox/tree/main/examples).
A minimal configuration is:

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

Calls for one engine are serialized; separate engines may run concurrently.
Always call `close` when an engine is no longer needed. It is idempotent.

## Errors

Native failures become `RustBoxException`. Inspect `kind` to distinguish invalid
configuration or lifecycle state from unavailable resources, runtime failures,
and unexpected bridge failures.

## Development

The Rust API is in `rust/src/api`; generated glue is in `rust/src/frb_generated.rs`
and `lib/src/rust`. After changing the bridge API, regenerate bindings and
rebuild the native artifact for every supported platform:

```powershell
flutter_rust_bridge_codegen generate
cargo fmt --manifest-path rust/Cargo.toml --package rustbox-flutter-bridge
../../scripts/build/flutter-prebuilt.ps1
cd example
flutter analyze
flutter test integration_test/simple_test.dart -d windows
```

`flutter_rust_bridge` is pinned to the 2.12 release line. Upgrade the Rust and
Dart runtimes together, then regenerate and validate all artifacts.
