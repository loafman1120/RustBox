## 0.1.3

- Updated the bundled Rust runtime with Hysteria2, TUIC, WireGuard, ShadowTLS,
  Naive, multiplexed transports, DNS hijacking, remote rule sets, and UoT fixes.
- Added host capability injection boundaries for physical network providers,
  packet devices, route control, process lookup, and network metadata so mobile
  platform adapters can provide VPN-owned resources.
- Fixed a packet-stack race that could retry a canceled socket command after
  the socket had already closed.

## 0.1.2

- Documented the complete public Dart API, including lifecycle operations,
  snapshots, engine states, and stable exception categories.
- Updated package documentation to reference the current release.

## 0.1.1

- Removed unsupported macOS plugin packaging.
- Reduced the iOS XCFramework to the device-only arm64 slice to keep the
  package within pub.dev's archive size limit.
- Fixed iOS CocoaPods packaging for the vendored XCFramework.

## 0.1.0

- Initial public release of the RustBox Flutter FFI bindings.
- Added managed engine lifecycle APIs for create, start, reload, snapshot,
  stop, and idempotent close.
- Added typed exception categories and engine snapshots.
- Added Android, iOS, Linux, and Windows support through precompiled native
  libraries. macOS support is temporarily deferred.
- Standardized generated bindings and runtime on stable
  `flutter_rust_bridge` 2.12.0.
