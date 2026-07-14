# rustbox_flutter

The supported Flutter/Dart bindings for the RustBox proxy runtime.

The package uses `flutter_rust_bridge` and Flutter Native Assets. A consumer's
normal `flutter run`, `flutter test`, or `flutter build` command compiles and
bundles the Rust workspace member for the selected native target.

## Supported platforms

- Android
- iOS
- Windows
- macOS
- Linux

Web and OHOS are intentionally unsupported. Consumers need Flutter 3.44 or
newer, Dart 3.12 or newer, and the Rust 1.97.0 toolchain selected by
`rust/rust-toolchain.toml`.

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

Calls for one engine are serialized by its Rust host actor. Different engine
objects have independent workers and may run concurrently. `close` is
idempotent, waits for shutdown, and releases the native handle. Calls after
close fail with `RustBoxExceptionKind.unavailable`.

## Development

The Rust-facing API is under `rust/src/api`; generated glue is under
`rust/src/frb_generated.rs` and `lib/src/rust`. After changing the Rust API:

```powershell
flutter_rust_bridge_codegen generate
flutter analyze
flutter test
```

The Rust runtime, Dart runtime, hooks, and code generator are all pinned to
`2.13.0-beta.5`. Upgrade them together and validate every supported platform.
The package is source-built and does not distribute precompiled native
binaries.
