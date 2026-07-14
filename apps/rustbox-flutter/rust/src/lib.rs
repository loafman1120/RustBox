pub mod api;
mod frb_generated;

// Referenced by the Apple platform shims so the linker retains the Rust static
// library and its flutter_rust_bridge entry points in the final application.
#[unsafe(no_mangle)]
pub extern "C" fn rustbox_flutter_enforce_bundling() -> i64 {
    0
}
