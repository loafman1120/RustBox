@_silgen_name("rustbox_flutter_enforce_bundling")
private func rustboxFlutterEnforceBundling() -> Int64

// Referencing a Rust symbol prevents release linkers from stripping the
// vendored bridge before flutter_rust_bridge resolves its symbols at runtime.
public func rustboxFlutterDummyMethodToEnforceBundling() -> Int64 {
    rustboxFlutterEnforceBundling()
}

let rustboxFlutterBundlingAnchor = rustboxFlutterDummyMethodToEnforceBundling()
