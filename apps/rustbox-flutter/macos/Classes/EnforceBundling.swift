@_silgen_name("rustbox_flutter_enforce_bundling")
private func rustboxFlutterEnforceBundling() -> Int64

// Referencing a Rust symbol keeps the vendored static library in the Pod
// framework, making flutter_rust_bridge symbols visible to DynamicLibrary.process().
public func rustboxFlutterDummyMethodToEnforceBundling() -> Int64 {
    rustboxFlutterEnforceBundling()
}

let rustboxFlutterBundlingAnchor = rustboxFlutterDummyMethodToEnforceBundling()
